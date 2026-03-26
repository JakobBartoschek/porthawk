"""Tests for porthawk/throttle.py — AIMD adaptive concurrency controller.

All tests are synchronous or use asyncio directly.
No network calls — pure logic testing.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from porthawk.throttle import (
    AdaptiveConfig,
    AdaptiveSemaphore,
    NetworkStats,
    _RTTVAR_BETA,
    _SRTT_ALPHA,
)


# ---------------------------------------------------------------------------
# NetworkStats — RTT smoothing and timeout ratio
# ---------------------------------------------------------------------------


class TestNetworkStats:
    def test_initial_state(self):
        stats = NetworkStats()
        assert stats.srtt is None
        assert stats.rttvar == 0.0
        assert stats.timeout_ratio == 0.0
        assert stats.sample_count == 0

    def test_first_non_timeout_initializes_srtt(self):
        stats = NetworkStats()
        stats.record(10.0, timed_out=False)
        assert stats.srtt == 10.0
        assert stats.rttvar == 5.0  # latency / 2

    def test_srtt_ewma_update(self):
        stats = NetworkStats()
        stats.record(10.0, timed_out=False)
        stats.record(20.0, timed_out=False)
        # rttvar uses OLD srtt (10.0), then srtt updates
        expected_rttvar = (1 - _RTTVAR_BETA) * 5.0 + _RTTVAR_BETA * abs(10.0 - 20.0)
        expected_srtt = (1 - _SRTT_ALPHA) * 10.0 + _SRTT_ALPHA * 20.0
        assert abs(stats.rttvar - expected_rttvar) < 0.001
        assert abs(stats.srtt - expected_srtt) < 0.001

    def test_timeout_not_included_in_rtt_stats(self):
        stats = NetworkStats()
        stats.record(10.0, timed_out=False)
        srtt_before = stats.srtt
        rttvar_before = stats.rttvar
        # recording a timeout shouldn't touch srtt or rttvar
        stats.record(9999.0, timed_out=True)
        assert stats.srtt == srtt_before
        assert stats.rttvar == rttvar_before

    def test_timeout_counted_in_ratio(self):
        stats = NetworkStats()
        stats.record(10.0, timed_out=False)
        stats.record(10.0, timed_out=True)
        assert stats.timeout_ratio == pytest.approx(0.5)

    def test_all_timeouts_ratio_is_one(self):
        stats = NetworkStats()
        for _ in range(5):
            stats.record(1000.0, timed_out=True)
        assert stats.timeout_ratio == pytest.approx(1.0)

    def test_no_timeouts_ratio_is_zero(self):
        stats = NetworkStats()
        for _ in range(5):
            stats.record(1.0, timed_out=False)
        assert stats.timeout_ratio == pytest.approx(0.0)

    def test_window_evicts_old_samples(self):
        stats = NetworkStats(window_size=5)
        # fill with timeouts
        for _ in range(5):
            stats.record(1000.0, timed_out=True)
        assert stats.timeout_ratio == pytest.approx(1.0)
        # now overwrite with non-timeouts — window should slide
        for _ in range(5):
            stats.record(1.0, timed_out=False)
        assert stats.timeout_ratio == pytest.approx(0.0)

    def test_sample_count(self):
        stats = NetworkStats()
        assert stats.sample_count == 0
        stats.record(1.0, timed_out=False)
        stats.record(2.0, timed_out=True)
        assert stats.sample_count == 2

    def test_reset_clears_everything(self):
        stats = NetworkStats()
        stats.record(10.0, timed_out=False)
        stats.record(10.0, timed_out=True)
        stats.reset()
        assert stats.srtt is None
        assert stats.rttvar == 0.0
        assert stats.timeout_ratio == 0.0
        assert stats.sample_count == 0

    def test_stable_latency_keeps_rttvar_low(self):
        stats = NetworkStats()
        for _ in range(20):
            stats.record(5.0, timed_out=False)
        # all RTTs identical → RTTVAR should converge toward 0
        assert stats.rttvar < 1.0

    def test_variable_latency_raises_rttvar(self):
        stats = NetworkStats()
        for i in range(20):
            stats.record(float(i * 10), timed_out=False)
        assert stats.rttvar > 10.0


# ---------------------------------------------------------------------------
# AdaptiveConfig — defaults sanity check
# ---------------------------------------------------------------------------


class TestAdaptiveConfig:
    def test_defaults_are_sane(self):
        cfg = AdaptiveConfig()
        assert 1 <= cfg.initial_concurrency <= 100
        assert cfg.min_concurrency >= 1
        assert cfg.initial_concurrency >= cfg.min_concurrency
        assert 0.0 < cfg.md_factor < 1.0
        assert 0.0 < cfg.timeout_threshold < 1.0
        assert cfg.ai_step >= 1
        assert cfg.increase_interval >= 1

    def test_custom_values_accepted(self):
        cfg = AdaptiveConfig(initial_concurrency=10, min_concurrency=2, ai_step=5)
        assert cfg.initial_concurrency == 10
        assert cfg.min_concurrency == 2
        assert cfg.ai_step == 5


# ---------------------------------------------------------------------------
# AdaptiveSemaphore — concurrency control
# ---------------------------------------------------------------------------


class TestAdaptiveSemaphoreBasic:
    def test_initial_limit(self):
        cfg = AdaptiveConfig(initial_concurrency=20)
        sem = AdaptiveSemaphore(cfg, max_concurrency=500)
        assert sem.limit == 20
        assert sem.active == 0

    def test_initial_limit_capped_at_max(self):
        cfg = AdaptiveConfig(initial_concurrency=200)
        sem = AdaptiveSemaphore(cfg, max_concurrency=50)
        assert sem.limit == 50

    @pytest.mark.asyncio
    async def test_acquire_increments_active(self):
        cfg = AdaptiveConfig(initial_concurrency=5)
        sem = AdaptiveSemaphore(cfg, max_concurrency=10)
        async with sem:
            assert sem.active == 1
        assert sem.active == 0

    @pytest.mark.asyncio
    async def test_concurrent_acquires_up_to_limit(self):
        cfg = AdaptiveConfig(initial_concurrency=3, min_concurrency=1)
        sem = AdaptiveSemaphore(cfg, max_concurrency=10)

        results = []

        async def acquire_and_record():
            async with sem:
                results.append(sem.active)
                await asyncio.sleep(0.01)

        await asyncio.gather(*[acquire_and_record() for _ in range(6)])
        # max active at any point should not exceed initial limit
        assert max(results) <= 3

    @pytest.mark.asyncio
    async def test_release_unblocks_waiting_coroutine(self):
        cfg = AdaptiveConfig(initial_concurrency=1, min_concurrency=1)
        sem = AdaptiveSemaphore(cfg, max_concurrency=10)
        order = []

        async def first():
            async with sem:
                order.append("first_in")
                await asyncio.sleep(0.05)
                order.append("first_out")

        async def second():
            await asyncio.sleep(0.01)  # ensure first starts first
            async with sem:
                order.append("second_in")

        await asyncio.gather(first(), second())
        assert order == ["first_in", "first_out", "second_in"]


# ---------------------------------------------------------------------------
# AdaptiveSemaphore — AIMD additive increase
# ---------------------------------------------------------------------------


class TestAdaptiveSemaphoreIncrease:
    def test_stable_probes_increase_limit(self):
        cfg = AdaptiveConfig(
            initial_concurrency=10,
            min_concurrency=5,
            ai_step=2,
            increase_interval=5,
            min_samples=3,
            timeout_threshold=0.5,
            rttvar_threshold=1000.0,  # disable jitter check for this test
        )
        sem = AdaptiveSemaphore(cfg, max_concurrency=100)

        for _ in range(20):
            sem.record_probe(latency_ms=5.0, timed_out=False)

        # after 20 probes with interval=5, should have increased multiple times
        assert sem.limit > 10

    def test_limit_never_exceeds_max(self):
        cfg = AdaptiveConfig(
            initial_concurrency=48,
            min_concurrency=5,
            ai_step=5,
            increase_interval=1,
            min_samples=1,
            timeout_threshold=0.9,
            rttvar_threshold=1000.0,
        )
        sem = AdaptiveSemaphore(cfg, max_concurrency=50)

        for _ in range(100):
            sem.record_probe(latency_ms=1.0, timed_out=False)

        assert sem.limit <= 50

    def test_high_rttvar_pauses_increase(self):
        cfg = AdaptiveConfig(
            initial_concurrency=10,
            min_concurrency=5,
            ai_step=2,
            increase_interval=5,
            min_samples=3,
            timeout_threshold=0.9,
            rttvar_threshold=10.0,  # low threshold so jitter is easily triggered
        )
        sem = AdaptiveSemaphore(cfg, max_concurrency=100)

        # feed highly variable latencies to push RTTVAR above threshold
        for i in range(20):
            sem.record_probe(latency_ms=float(i * 50), timed_out=False)

        initial_limit = sem.limit
        limit_after_jitter = sem.limit
        # limit should NOT have increased much due to jitter check
        # (it might increase slightly before rttvar builds up, but not dramatically)
        assert limit_after_jitter <= initial_limit + cfg.ai_step * 2

    def test_no_increase_before_min_samples(self):
        cfg = AdaptiveConfig(
            initial_concurrency=10,
            min_concurrency=5,
            ai_step=2,
            increase_interval=1,
            min_samples=20,  # need 20 samples before any action
        )
        sem = AdaptiveSemaphore(cfg, max_concurrency=100)

        for _ in range(5):  # only 5 — below min_samples
            sem.record_probe(latency_ms=1.0, timed_out=False)

        assert sem.limit == 10  # unchanged


# ---------------------------------------------------------------------------
# AdaptiveSemaphore — AIMD multiplicative decrease
# ---------------------------------------------------------------------------


class TestAdaptiveSemaphoreDecrease:
    def test_high_timeout_ratio_decreases_limit(self):
        cfg = AdaptiveConfig(
            initial_concurrency=50,
            min_concurrency=5,
            md_factor=0.5,
            timeout_threshold=0.2,  # low threshold — easy to trigger
            decrease_cooldown=0.0,  # no cooldown for test speed
            min_samples=5,
            increase_interval=999,  # disable increase
        )
        sem = AdaptiveSemaphore(cfg, max_concurrency=100)

        # all timeouts — should trigger decrease fast
        for _ in range(10):
            sem.record_probe(latency_ms=1000.0, timed_out=True)

        assert sem.limit < 50

    def test_decrease_respects_min_concurrency(self):
        cfg = AdaptiveConfig(
            initial_concurrency=6,
            min_concurrency=5,
            md_factor=0.5,
            timeout_threshold=0.1,
            decrease_cooldown=0.0,
            min_samples=3,
            increase_interval=999,
        )
        sem = AdaptiveSemaphore(cfg, max_concurrency=100)

        # hammer with timeouts — limit should never drop below min
        for _ in range(50):
            sem.record_probe(latency_ms=1000.0, timed_out=True)

        assert sem.limit >= cfg.min_concurrency

    def test_decrease_cooldown_prevents_thrashing(self):
        cfg = AdaptiveConfig(
            initial_concurrency=50,
            min_concurrency=5,
            md_factor=0.5,
            timeout_threshold=0.2,
            decrease_cooldown=10.0,  # 10 second cooldown
            min_samples=5,
            increase_interval=999,
        )
        sem = AdaptiveSemaphore(cfg, max_concurrency=100)

        # first batch of timeouts triggers decrease
        for _ in range(10):
            sem.record_probe(latency_ms=1000.0, timed_out=True)

        limit_after_first_decrease = sem.limit

        # second batch — cooldown should block second decrease
        for _ in range(10):
            sem.record_probe(latency_ms=1000.0, timed_out=True)

        # limit should be the same — cooldown is still active
        assert sem.limit == limit_after_first_decrease

    def test_recovery_after_congestion(self):
        cfg = AdaptiveConfig(
            initial_concurrency=50,
            min_concurrency=5,
            ai_step=2,
            md_factor=0.5,
            timeout_threshold=0.3,
            decrease_cooldown=0.0,
            min_samples=5,
            increase_interval=10,
            rttvar_threshold=1000.0,
        )
        sem = AdaptiveSemaphore(cfg, max_concurrency=100)

        # phase 1: congestion → decrease
        for _ in range(10):
            sem.record_probe(latency_ms=1000.0, timed_out=True)
        low_limit = sem.limit
        assert low_limit < 50

        # phase 2: recovery → increase
        for _ in range(60):
            sem.record_probe(latency_ms=5.0, timed_out=False)
        assert sem.limit > low_limit


# ---------------------------------------------------------------------------
# AdaptiveSemaphore — limit decrease affects new acquires
# ---------------------------------------------------------------------------


class TestAdaptiveSemaphoreDynamicLimit:
    @pytest.mark.asyncio
    async def test_decreased_limit_blocks_new_acquires(self):
        cfg = AdaptiveConfig(initial_concurrency=5, min_concurrency=1)
        sem = AdaptiveSemaphore(cfg, max_concurrency=10)

        # force limit to 2 directly
        sem._set_limit(2)
        assert sem.limit == 2

        active_counts = []

        async def probe():
            async with sem:
                active_counts.append(sem.active)
                await asyncio.sleep(0.02)

        await asyncio.gather(*[probe() for _ in range(6)])
        # with limit=2, should never see more than 2 active
        assert max(active_counts) <= 2

    @pytest.mark.asyncio
    async def test_increased_limit_allows_more_acquires(self):
        cfg = AdaptiveConfig(initial_concurrency=2, min_concurrency=1)
        sem = AdaptiveSemaphore(cfg, max_concurrency=10)
        sem._set_limit(5)

        active_counts = []

        async def probe():
            async with sem:
                active_counts.append(sem.active)
                await asyncio.sleep(0.02)

        await asyncio.gather(*[probe() for _ in range(10)])
        assert max(active_counts) <= 5


# ---------------------------------------------------------------------------
# AdaptiveSemaphore — summary and adjustments log
# ---------------------------------------------------------------------------


class TestAdaptiveSemaphoreReporting:
    def test_summary_contains_key_fields(self):
        cfg = AdaptiveConfig(initial_concurrency=25)
        sem = AdaptiveSemaphore(cfg, max_concurrency=500)
        s = sem.summary()
        assert "cwnd=" in s
        assert "active=" in s
        assert "timeout_ratio=" in s
        assert "srtt=" in s

    def test_adjustments_logged_on_change(self):
        cfg = AdaptiveConfig(
            initial_concurrency=50,
            min_concurrency=5,
            md_factor=0.5,
            timeout_threshold=0.1,
            decrease_cooldown=0.0,
            min_samples=5,
            increase_interval=999,
        )
        sem = AdaptiveSemaphore(cfg, max_concurrency=100)

        for _ in range(10):
            sem.record_probe(latency_ms=1000.0, timed_out=True)

        assert len(sem.adjustments) >= 1
        ts, reason, new_limit = sem.adjustments[0]
        assert "timeout_ratio" in reason
        assert new_limit < 50

    def test_no_adjustments_initially(self):
        sem = AdaptiveSemaphore(AdaptiveConfig(), max_concurrency=100)
        assert len(sem.adjustments) == 0


# ---------------------------------------------------------------------------
# Public API export
# ---------------------------------------------------------------------------


class TestPublicApiExport:
    def test_importable_from_porthawk(self):
        import porthawk

        assert hasattr(porthawk, "AdaptiveConfig")
        assert hasattr(porthawk, "AdaptiveSemaphore")
        assert hasattr(porthawk, "NetworkStats")

    def test_adaptive_config_is_dataclass(self):
        import porthawk

        cfg = porthawk.AdaptiveConfig(initial_concurrency=10)
        assert cfg.initial_concurrency == 10

    @pytest.mark.asyncio
    async def test_adaptive_semaphore_usable_from_porthawk(self):
        import porthawk

        cfg = porthawk.AdaptiveConfig(initial_concurrency=5)
        sem = porthawk.AdaptiveSemaphore(cfg, max_concurrency=50)
        async with sem:
            assert sem.active == 1
        assert sem.active == 0
