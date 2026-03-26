"""Adaptive scan throttling via AIMD congestion control.

Standard asyncio.Semaphore has a fixed limit. This replaces it with one that
watches RTT variance and timeout ratio, then adjusts concurrency the same way
TCP does: additive increase when the network is happy, multiplicative decrease
when it isn't.

AIMD basics:
  - Additive increase: every N clean probes → cwnd += ai_step
  - Multiplicative decrease: timeout_ratio > threshold → cwnd = cwnd * md_factor
  - Hard floor/ceiling: [min_concurrency, max_concurrency]

RTT smoothing is from RFC 6298 (SRTT/RTTVAR — same math as TCP retransmit timer).
High RTTVAR = jitter = hold steady rather than keep increasing.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass, field

# --- RFC 6298 smoothing constants ------------------------------------------
# alpha = 1/8, beta = 1/4 — these are the standard values, don't change them
# unless you have a very good reason
_SRTT_ALPHA = 0.125
_RTTVAR_BETA = 0.25


@dataclass
class NetworkStats:
    """Rolling window of RTT and timeout observations with EWMA smoothing.

    Tracks two things separately:
      1. Smoothed RTT + variance (RFC 6298 style) for jitter detection
      2. Sliding window timeout ratio for congestion detection

    Using deque with maxlen so old observations naturally fall off.
    """

    window_size: int = 50

    srtt: float | None = None  # smoothed RTT via EWMA
    rttvar: float = 0.0  # RTT variance via EWMA — high = jittery network

    _rtts: deque[float] = field(default_factory=deque, init=False, repr=False)
    _timeouts: deque[bool] = field(default_factory=deque, init=False, repr=False)

    def __post_init__(self) -> None:
        self._rtts = deque(maxlen=self.window_size)
        self._timeouts = deque(maxlen=self.window_size)

    def record(self, latency_ms: float, timed_out: bool) -> None:
        """Record one probe outcome. Call this for every port, open or not."""
        self._timeouts.append(timed_out)

        if timed_out:
            # don't use timeout latency in RTT stats — it's just the timeout value,
            # not an actual network measurement. Would bias SRTT upward and wreck RTTVAR.
            return

        self._rtts.append(latency_ms)

        # RFC 6298 EWMA update — order matters: rttvar uses OLD srtt
        if self.srtt is None:
            # first sample — initialize directly
            self.srtt = latency_ms
            self.rttvar = latency_ms / 2.0
        else:
            self.rttvar = (1.0 - _RTTVAR_BETA) * self.rttvar + _RTTVAR_BETA * abs(
                self.srtt - latency_ms
            )
            self.srtt = (1.0 - _SRTT_ALPHA) * self.srtt + _SRTT_ALPHA * latency_ms

    @property
    def timeout_ratio(self) -> float:
        """Fraction of recent probes that timed out. 0.0 = none, 1.0 = all."""
        if not self._timeouts:
            return 0.0
        return sum(self._timeouts) / len(self._timeouts)

    @property
    def sample_count(self) -> int:
        return len(self._timeouts)

    def reset(self) -> None:
        self._rtts.clear()
        self._timeouts.clear()
        self.srtt = None
        self.rttvar = 0.0


@dataclass
class AdaptiveConfig:
    """Tuning knobs for the AIMD controller.

    Defaults are reasonably conservative for a port scanner on a typical LAN.
    Loosen timeout_threshold if you're scanning through a heavily filtered network
    where lots of FILTERED ports look like congestion (they're not, they're just firewalled).
    """

    initial_concurrency: int = 25
    # ^ start conservative, ramp up — avoids hitting IDS on first burst
    min_concurrency: int = 5
    # ^ floor — we always keep at least this many running
    ai_step: int = 2
    # ^ add this many slots per increase cycle
    md_factor: float = 0.5
    # ^ halve cwnd on congestion, classic TCP behavior
    timeout_threshold: float = 0.30
    # ^ if >30% of recent probes timed out, that's congestion (or aggressive filtering)
    rttvar_threshold: float = 80.0
    # ^ ms — if RTT variance exceeds this, hold steady (don't increase)
    increase_interval: int = 30
    # ^ probe count between additive increases on a stable network
    decrease_cooldown: float = 1.0
    # ^ seconds — don't decrease again this soon after a decrease
    min_samples: int = 10
    # ^ need at least this many observations before trusting the stats
    window_size: int = 50
    # ^ sliding window for timeout ratio — how many probes to remember


class AdaptiveSemaphore:
    """asyncio.Semaphore replacement with AIMD concurrency control.

    Drop-in compatible with asyncio.Semaphore for the __aenter__/__aexit__ interface.
    Caller also calls record_probe() after each network probe to feed back results.

    The concurrency limit adjusts between cfg.min_concurrency and max_concurrency.
    Changes take effect on new acquires — in-flight probes run to completion.

    Usage in a scan loop:
        sem = AdaptiveSemaphore(cfg, max_concurrent=500)
        async with sem:
            state, latency = await _tcp_probe(host, port, timeout)
            sem.record_probe(latency, timed_out=(state == PortState.FILTERED))
    """

    def __init__(self, cfg: AdaptiveConfig, max_concurrency: int = 500) -> None:
        self._cfg = cfg
        self._max = max_concurrency
        self._limit = min(cfg.initial_concurrency, max_concurrency)
        self._active = 0
        self._stats = NetworkStats(window_size=cfg.window_size)
        self._cond: asyncio.Condition | None = None

        # AIMD bookkeeping
        self._last_decrease: float = 0.0
        self._probes_since_increase: int = 0

        # for reporting
        self.adjustments: list[tuple[float, str, int]] = []
        # ^ (timestamp, reason, new_limit)

    def _get_cond(self) -> asyncio.Condition:
        # lazy init — asyncio.Condition must be created from within a running loop in older Pythons
        if self._cond is None:
            self._cond = asyncio.Condition()
        return self._cond

    async def __aenter__(self) -> AdaptiveSemaphore:
        cond = self._get_cond()
        async with cond:
            while self._active >= self._limit:
                await cond.wait()
            self._active += 1
        return self

    async def __aexit__(self, *_: object) -> None:
        cond = self._get_cond()
        async with cond:
            self._active -= 1
            cond.notify_all()

    def record_probe(self, latency_ms: float, timed_out: bool) -> None:
        """Feed network observations back to the controller. Call after every probe.

        This is where the AIMD logic fires. It's synchronous and fast — no awaiting here.
        """
        self._stats.record(latency_ms, timed_out)
        self._probes_since_increase += 1
        self._maybe_adjust()

    def _maybe_adjust(self) -> None:
        """Core AIMD controller. Reads stats, decides whether to change cwnd."""
        cfg = self._cfg
        stats = self._stats

        # wait for enough samples before reacting — early probes are too noisy
        if stats.sample_count < cfg.min_samples:
            return

        timeout_ratio = stats.timeout_ratio
        now = time.monotonic()

        if timeout_ratio > cfg.timeout_threshold:
            # multiplicative decrease — congestion (or aggressive packet filtering)
            # respect cooldown so we don't thrash: decrease → wait → measure → decrease again
            if now - self._last_decrease >= cfg.decrease_cooldown:
                new_limit = max(cfg.min_concurrency, int(self._limit * cfg.md_factor))
                if new_limit < self._limit:
                    self._set_limit(new_limit, reason=f"timeout_ratio={timeout_ratio:.2f}")
                    self._last_decrease = now
                    self._probes_since_increase = 0
            return

        # no congestion path — consider increasing
        rttvar = stats.rttvar if stats.rttvar is not None else 0.0

        if rttvar > cfg.rttvar_threshold:
            # jitter is high — network might be getting busy, hold steady
            # don't reset the probe counter, just wait it out
            return

        # additive increase — network is stable, ramp up
        if self._probes_since_increase >= cfg.increase_interval:
            new_limit = min(self._max, self._limit + cfg.ai_step)
            if new_limit > self._limit:
                self._set_limit(new_limit, reason="stable")
            self._probes_since_increase = 0

    def _set_limit(self, new_limit: int, reason: str = "") -> None:
        """Update cwnd. Takes effect on next acquire — doesn't affect in-flight probes."""
        self._limit = new_limit
        self.adjustments.append((time.monotonic(), reason, new_limit))

    @property
    def limit(self) -> int:
        """Current concurrency limit (cwnd)."""
        return self._limit

    @property
    def active(self) -> int:
        """How many probes currently hold a slot."""
        return self._active

    @property
    def stats(self) -> NetworkStats:
        return self._stats

    def summary(self) -> str:
        """One-line status — handy for debug output or the live UI."""
        srtt = f"{self._stats.srtt:.1f}ms" if self._stats.srtt else "—"
        return (
            f"cwnd={self._limit}/{self._max}"
            f"  active={self._active}"
            f"  timeout_ratio={self._stats.timeout_ratio:.2f}"
            f"  srtt={srtt}"
            f"  rttvar={self._stats.rttvar:.1f}ms"
            f"  adjustments={len(self.adjustments)}"
        )
