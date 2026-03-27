"""Tests for dashboard.py helper functions.

Only the pure data-preparation functions are tested here — no Streamlit,
no browser, no network. The UI rendering itself isn't unit-testable.
"""

from porthawk.dashboard import honeypot_badge, results_to_rows, risk_distribution, service_distribution
from porthawk.scanner import PortState, ScanResult


def _r(
    port: int,
    state: PortState = PortState.OPEN,
    service: str | None = "http",
    risk: str | None = "LOW",
    banner: str | None = None,
    version: str | None = None,
    ttl: int | None = None,
) -> ScanResult:
    return ScanResult(
        host="10.0.0.1",
        port=port,
        protocol="tcp",
        state=state,
        service_name=service,
        risk_level=risk,
        banner=banner,
        service_version=version,
        ttl=ttl,
    )


# ---------------------------------------------------------------------------
# results_to_rows
# ---------------------------------------------------------------------------


class TestResultsToRows:
    def test_open_port_included(self):
        rows = results_to_rows([_r(80)])
        assert len(rows) == 1
        assert rows[0]["Port"] == 80

    def test_closed_port_excluded(self):
        rows = results_to_rows([_r(9999, state=PortState.CLOSED)])
        assert rows == []

    def test_filtered_port_excluded(self):
        rows = results_to_rows([_r(9999, state=PortState.FILTERED)])
        assert rows == []

    def test_risk_emoji_high(self):
        rows = results_to_rows([_r(23, risk="HIGH")])
        assert "🔴" in rows[0]["Risk"]

    def test_risk_emoji_medium(self):
        rows = results_to_rows([_r(21, risk="MEDIUM")])
        assert "🟡" in rows[0]["Risk"]

    def test_risk_emoji_low(self):
        rows = results_to_rows([_r(80, risk="LOW")])
        assert "🟢" in rows[0]["Risk"]

    def test_none_risk_uses_fallback(self):
        rows = results_to_rows([_r(80, risk=None)])
        assert "⚪" in rows[0]["Risk"]

    def test_banner_truncated_at_70_chars(self):
        long_banner = "x" * 100
        rows = results_to_rows([_r(80, banner=long_banner)])
        assert len(rows[0]["Banner"]) <= 70

    def test_no_banner_empty_string(self):
        rows = results_to_rows([_r(80, banner=None)])
        assert rows[0]["Banner"] == ""

    def test_version_present(self):
        rows = results_to_rows([_r(22, version="OpenSSH_8.9p1")])
        assert rows[0]["Version"] == "OpenSSH_8.9p1"

    def test_version_missing_dash(self):
        rows = results_to_rows([_r(80, version=None)])
        assert rows[0]["Version"] == "—"

    def test_multiple_ports(self):
        results = [_r(22), _r(80), _r(443)]
        rows = results_to_rows(results)
        assert len(rows) == 3

    def test_mixed_states(self):
        results = [_r(80), _r(22), _r(9999, state=PortState.CLOSED)]
        rows = results_to_rows(results)
        assert len(rows) == 2  # only open ports


# ---------------------------------------------------------------------------
# risk_distribution
# ---------------------------------------------------------------------------


class TestRiskDistribution:
    def test_single_high(self):
        dist = risk_distribution([_r(23, risk="HIGH")])
        assert dist["HIGH"] == 1

    def test_counts_by_level(self):
        results = [
            _r(23, risk="HIGH"),
            _r(21, risk="HIGH"),
            _r(80, risk="LOW"),
        ]
        dist = risk_distribution(results)
        assert dist["HIGH"] == 2
        assert dist["LOW"] == 1

    def test_none_risk_counted_as_unknown(self):
        dist = risk_distribution([_r(80, risk=None)])
        assert dist["unknown"] == 1

    def test_closed_ports_excluded(self):
        dist = risk_distribution([_r(9999, state=PortState.CLOSED, risk="HIGH")])
        assert dist == {}

    def test_empty_input(self):
        assert risk_distribution([]) == {}


# ---------------------------------------------------------------------------
# service_distribution
# ---------------------------------------------------------------------------


class TestServiceDistribution:
    def test_single_service(self):
        dist = service_distribution([_r(80, service="http")])
        assert dist["http"] == 1

    def test_top_n_limit(self):
        results = [_r(i, service=f"svc{i}") for i in range(1, 21)]
        dist = service_distribution(results, top_n=5)
        assert len(dist) == 5

    def test_counts_same_service(self):
        results = [_r(80, service="http"), _r(8080, service="http")]
        dist = service_distribution(results)
        assert dist["http"] == 2

    def test_none_service_counted_as_unknown(self):
        dist = service_distribution([_r(80, service=None)])
        assert dist["unknown"] == 1

    def test_closed_ports_excluded(self):
        dist = service_distribution([_r(80, state=PortState.CLOSED, service="http")])
        assert dist == {}

    def test_sorted_by_count_descending(self):
        results = [
            _r(80, service="http"),
            _r(8080, service="http"),
            _r(443, service="https"),
        ]
        dist = service_distribution(results)
        keys = list(dist.keys())
        # http (2) should come before https (1)
        assert keys[0] == "http"
        assert keys[1] == "https"

    def test_empty_input(self):
        assert service_distribution([]) == {}


# ---------------------------------------------------------------------------
# honeypot_badge
# ---------------------------------------------------------------------------


class TestHoneypotBadge:
    def test_likely_honeypot_returns_error(self):
        level, text = honeypot_badge(0.85, "LIKELY_HONEYPOT")
        assert level == "error"
        assert "🪤" in text
        assert "0.85" in text

    def test_suspicious_returns_warning(self):
        level, text = honeypot_badge(0.55, "SUSPICIOUS")
        assert level == "warning"
        assert "⚠️" in text
        assert "0.55" in text

    def test_real_returns_success(self):
        level, text = honeypot_badge(0.1, "REAL")
        assert level == "success"
        assert "✅" in text
        assert "0.10" in text

    def test_unknown_verdict_returns_success(self):
        # any verdict that isn't a red flag → treat as real
        level, _ = honeypot_badge(0.0, "UNKNOWN")
        assert level == "success"


# ---------------------------------------------------------------------------
# results_to_rows — TTL field
# ---------------------------------------------------------------------------


class TestResultsToRowsTTL:
    def test_ttl_present(self):
        rows = results_to_rows([_r(80, ttl=64)])
        assert rows[0]["TTL"] == 64

    def test_ttl_missing_dash(self):
        rows = results_to_rows([_r(80, ttl=None)])
        assert rows[0]["TTL"] == "—"
