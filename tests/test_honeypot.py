"""Tests for porthawk/honeypot.py.

Purely unit tests — no network calls, no temp files.
Each check function is tested in isolation where possible.
"""

import pytest

from porthawk.honeypot import (
    HoneypotReport,
    Indicator,
    _check_cowrie_ssh,
    _check_dionaea_ftp,
    _check_ics_ports,
    _check_latency_uniformity,
    _check_port_flood,
    _check_service_diversity,
    _check_ssh_multi_port,
    _check_telnet,
    _confidence,
    _verdict,
    score_honeypot,
)
from porthawk.scanner import PortState, ScanResult


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def make_result(
    port: int,
    state: PortState = PortState.OPEN,
    banner: str | None = None,
    service_name: str | None = None,
    latency_ms: float | None = None,
) -> ScanResult:
    return ScanResult(
        host="1.2.3.4",
        port=port,
        protocol="tcp",
        state=state,
        banner=banner,
        service_name=service_name,
        latency_ms=latency_ms,
    )


# ---------------------------------------------------------------------------
# _verdict
# ---------------------------------------------------------------------------


class TestVerdict:
    def test_below_threshold_is_likely_real(self):
        assert _verdict(0.0) == "LIKELY_REAL"
        assert _verdict(0.24) == "LIKELY_REAL"

    def test_suspicious_range(self):
        assert _verdict(0.25) == "SUSPICIOUS"
        assert _verdict(0.54) == "SUSPICIOUS"

    def test_above_threshold_is_likely_honeypot(self):
        assert _verdict(0.55) == "LIKELY_HONEYPOT"
        assert _verdict(1.0) == "LIKELY_HONEYPOT"


# ---------------------------------------------------------------------------
# _confidence
# ---------------------------------------------------------------------------


class TestConfidence:
    def test_no_indicators_is_low(self):
        assert _confidence([]) == "LOW"

    def test_one_indicator_is_medium(self):
        ind = Indicator(name="x", weight=0.5, description="test")
        assert _confidence([ind]) == "MEDIUM"

    def test_two_indicators_still_medium(self):
        inds = [Indicator(name=f"x{i}", weight=0.5, description="") for i in range(2)]
        assert _confidence(inds) == "MEDIUM"

    def test_three_or_more_is_high(self):
        inds = [Indicator(name=f"x{i}", weight=0.5, description="") for i in range(3)]
        assert _confidence(inds) == "HIGH"


# ---------------------------------------------------------------------------
# score_honeypot — empty / no open ports
# ---------------------------------------------------------------------------


class TestScoreHoneypotEmpty:
    def test_no_results_returns_zero_score(self):
        report = score_honeypot([])
        assert report.score == 0.0
        assert report.verdict == "LIKELY_REAL"
        assert report.open_port_count == 0

    def test_only_closed_ports_returns_zero_score(self):
        results = [
            make_result(22, state=PortState.CLOSED),
            make_result(80, state=PortState.FILTERED),
        ]
        report = score_honeypot(results)
        assert report.score == 0.0

    def test_clean_host_no_indicators(self):
        results = [
            make_result(22, service_name="ssh"),
            make_result(80, service_name="http"),
            make_result(443, service_name="https"),
        ]
        report = score_honeypot(results)
        assert report.score < 0.25
        assert report.verdict == "LIKELY_REAL"
        assert len(report.indicators) == 0


# ---------------------------------------------------------------------------
# _check_cowrie_ssh
# ---------------------------------------------------------------------------


class TestCowrieSsh:
    def test_known_cowrie_banner_fires(self):
        results = [make_result(22, banner="SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2")]
        inds: list[Indicator] = []
        _check_cowrie_ssh(results, inds)
        assert len(inds) == 1
        assert inds[0].name == "cowrie_ssh_banner"
        assert inds[0].weight > 0.5

    def test_banner_with_trailing_whitespace_still_matches(self):
        results = [make_result(22, banner="SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2\r\n")]
        inds: list[Indicator] = []
        _check_cowrie_ssh(results, inds)
        assert len(inds) == 1

    def test_modern_openssh_banner_does_not_fire(self):
        results = [make_result(22, banner="SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3")]
        inds: list[Indicator] = []
        _check_cowrie_ssh(results, inds)
        assert len(inds) == 0

    def test_no_banner_does_not_fire(self):
        results = [make_result(22, banner=None)]
        inds: list[Indicator] = []
        _check_cowrie_ssh(results, inds)
        assert len(inds) == 0

    def test_cowrie_banner_on_non_22_port_does_not_fire(self):
        # We only check port 22 — cowrie on alt ports would need a separate rule
        results = [make_result(2222, banner="SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2")]
        inds: list[Indicator] = []
        _check_cowrie_ssh(results, inds)
        assert len(inds) == 0

    def test_multiple_cowrie_banners_only_appends_once(self):
        # Edge case: if someone put port 22 twice in the list
        results = [
            make_result(22, banner="SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"),
            make_result(22, banner="SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"),
        ]
        inds: list[Indicator] = []
        _check_cowrie_ssh(results, inds)
        assert len(inds) == 1


# ---------------------------------------------------------------------------
# _check_dionaea_ftp
# ---------------------------------------------------------------------------


class TestDionaeaFtp:
    def test_synology_ftp_banner_fires(self):
        results = [make_result(21, banner="220 DiskStation FTP server ready.")]
        inds: list[Indicator] = []
        _check_dionaea_ftp(results, inds)
        assert len(inds) == 1
        assert inds[0].name == "dionaea_ftp_banner"
        assert inds[0].weight > 0.5

    def test_real_ftp_banner_does_not_fire(self):
        results = [make_result(21, banner="220 ProFTPD 1.3.7a Server (ProFTPD)")]
        inds: list[Indicator] = []
        _check_dionaea_ftp(results, inds)
        assert len(inds) == 0

    def test_no_ftp_port_does_not_fire(self):
        results = [make_result(22, banner="220 DiskStation FTP server ready.")]
        inds: list[Indicator] = []
        _check_dionaea_ftp(results, inds)
        assert len(inds) == 0

    def test_partial_match_still_fires(self):
        # Some Dionaea versions strip the trailing period
        results = [make_result(21, banner="220 DiskStation FTP server")]
        inds: list[Indicator] = []
        _check_dionaea_ftp(results, inds)
        assert len(inds) == 1


# ---------------------------------------------------------------------------
# _check_ics_ports
# ---------------------------------------------------------------------------


class TestIcsPorts:
    def test_two_ics_ports_fires_multi(self):
        inds: list[Indicator] = []
        _check_ics_ports({502, 102}, inds)
        assert len(inds) == 1
        assert inds[0].name == "ics_multi_port"
        assert inds[0].weight >= 0.45

    def test_single_ics_port_fires_single(self):
        inds: list[Indicator] = []
        _check_ics_ports({502}, inds)
        assert len(inds) == 1
        assert inds[0].name == "ics_single_port"
        assert inds[0].weight < 0.35

    def test_no_ics_ports_does_not_fire(self):
        inds: list[Indicator] = []
        _check_ics_ports({22, 80, 443}, inds)
        assert len(inds) == 0

    def test_all_ics_ports_still_one_indicator(self):
        inds: list[Indicator] = []
        _check_ics_ports({102, 502, 20000, 44818, 47808}, inds)
        assert len(inds) == 1
        assert inds[0].name == "ics_multi_port"


# ---------------------------------------------------------------------------
# _check_telnet
# ---------------------------------------------------------------------------


class TestTelnet:
    def test_port_23_fires(self):
        inds: list[Indicator] = []
        _check_telnet({23, 22, 80}, inds)
        assert len(inds) == 1
        assert inds[0].name == "telnet_open"

    def test_no_port_23_does_not_fire(self):
        inds: list[Indicator] = []
        _check_telnet({22, 80, 443}, inds)
        assert len(inds) == 0


# ---------------------------------------------------------------------------
# _check_port_flood
# ---------------------------------------------------------------------------


class TestPortFlood:
    def test_fewer_than_20_does_not_fire(self):
        results = [make_result(p) for p in range(1, 21)]
        inds: list[Indicator] = []
        _check_port_flood(results, inds)
        assert len(inds) == 0

    def test_21_ports_fires_high(self):
        results = [make_result(p) for p in range(1, 22)]
        inds: list[Indicator] = []
        _check_port_flood(results, inds)
        assert len(inds) == 1
        assert inds[0].name == "port_flood_high"

    def test_41_ports_fires_extreme(self):
        results = [make_result(p) for p in range(1, 42)]
        inds: list[Indicator] = []
        _check_port_flood(results, inds)
        assert len(inds) == 1
        assert inds[0].name == "port_flood_extreme"

    def test_exactly_20_ports_does_not_fire(self):
        results = [make_result(p) for p in range(1, 21)]
        inds: list[Indicator] = []
        _check_port_flood(results, inds)
        assert len(inds) == 0


# ---------------------------------------------------------------------------
# _check_ssh_multi_port
# ---------------------------------------------------------------------------


class TestSshMultiPort:
    def test_same_banner_on_two_ports_fires(self):
        results = [
            make_result(22, banner="SSH-2.0-OpenSSH_7.4 Debian"),
            make_result(2222, banner="SSH-2.0-OpenSSH_7.4 Debian"),
        ]
        inds: list[Indicator] = []
        _check_ssh_multi_port(results, inds)
        assert len(inds) == 1
        assert inds[0].name == "ssh_multi_port"

    def test_different_ssh_banners_do_not_fire(self):
        results = [
            make_result(22, banner="SSH-2.0-OpenSSH_8.9 Ubuntu"),
            make_result(2222, banner="SSH-2.0-OpenSSH_7.4 Debian"),
        ]
        inds: list[Indicator] = []
        _check_ssh_multi_port(results, inds)
        assert len(inds) == 0

    def test_single_ssh_port_does_not_fire(self):
        results = [make_result(22, banner="SSH-2.0-OpenSSH_8.9 Ubuntu")]
        inds: list[Indicator] = []
        _check_ssh_multi_port(results, inds)
        assert len(inds) == 0

    def test_non_ssh_banners_ignored(self):
        results = [
            make_result(21, banner="220 FTP ready"),
            make_result(80, banner="HTTP/1.1 200 OK"),
        ]
        inds: list[Indicator] = []
        _check_ssh_multi_port(results, inds)
        assert len(inds) == 0


# ---------------------------------------------------------------------------
# _check_service_diversity
# ---------------------------------------------------------------------------


class TestServiceDiversity:
    def test_six_categories_fires(self):
        results = [
            make_result(22, service_name="ssh"),       # remote_access
            make_result(80, service_name="http"),      # web
            make_result(25, service_name="smtp"),      # mail
            make_result(3306, service_name="mysql"),   # database
            make_result(21, service_name="ftp"),       # file
            make_result(502, service_name="modbus"),   # ics
            make_result(53, service_name="dns"),       # infrastructure
        ]
        inds: list[Indicator] = []
        _check_service_diversity(results, inds)
        assert len(inds) == 1
        assert inds[0].name == "service_diversity"

    def test_three_categories_does_not_fire(self):
        results = [
            make_result(22, service_name="ssh"),
            make_result(80, service_name="http"),
            make_result(3306, service_name="mysql"),
        ]
        inds: list[Indicator] = []
        _check_service_diversity(results, inds)
        assert len(inds) == 0

    def test_no_service_names_does_not_fire(self):
        results = [make_result(22), make_result(80)]
        inds: list[Indicator] = []
        _check_service_diversity(results, inds)
        assert len(inds) == 0


# ---------------------------------------------------------------------------
# _check_latency_uniformity
# ---------------------------------------------------------------------------


class TestLatencyUniformity:
    def test_uniform_latency_fires(self):
        # all exactly 1.0ms — CV = 0 → definitely fires
        results = [make_result(p, latency_ms=1.0) for p in range(22, 32)]
        inds: list[Indicator] = []
        _check_latency_uniformity(results, inds)
        assert len(inds) == 1
        assert inds[0].name == "uniform_latency"

    def test_variable_latency_does_not_fire(self):
        # simulate realistic OS latency variance
        latencies = [0.8, 1.2, 2.5, 0.5, 3.1, 1.8, 4.2, 0.9, 2.0, 1.5]
        results = [make_result(22 + i, latency_ms=lat) for i, lat in enumerate(latencies)]
        inds: list[Indicator] = []
        _check_latency_uniformity(results, inds)
        assert len(inds) == 0

    def test_fewer_than_min_samples_does_not_fire(self):
        results = [make_result(p, latency_ms=1.0) for p in range(22, 26)]  # only 4
        inds: list[Indicator] = []
        _check_latency_uniformity(results, inds)
        assert len(inds) == 0

    def test_none_latency_excluded_from_sample(self):
        results = [make_result(p, latency_ms=None) for p in range(22, 32)]
        inds: list[Indicator] = []
        _check_latency_uniformity(results, inds)
        assert len(inds) == 0


# ---------------------------------------------------------------------------
# score_honeypot — integration / score combination
# ---------------------------------------------------------------------------


class TestScoreHoneypotIntegration:
    def test_cowrie_banner_pushes_score_above_suspicious(self):
        results = [make_result(22, banner="SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2")]
        report = score_honeypot(results)
        assert report.score >= 0.55
        assert report.verdict == "LIKELY_HONEYPOT"

    def test_dionaea_ftp_alone_is_likely_honeypot(self):
        results = [make_result(21, banner="220 DiskStation FTP server ready.")]
        report = score_honeypot(results)
        assert report.score >= 0.55
        assert report.verdict == "LIKELY_HONEYPOT"

    def test_multiple_weak_indicators_accumulate(self):
        # telnet + ICS + port flood — none alone triggers LIKELY_HONEYPOT
        # but combined they should
        results = [make_result(p) for p in range(1, 35)]  # 34 open ports
        results.append(make_result(23))  # telnet
        results.append(make_result(502))  # modbus
        results.append(make_result(102))  # S7
        report = score_honeypot(results)
        # 34 ports fires port_flood_high, 502+102 fires ics_multi, 23 fires telnet
        assert report.score >= 0.55
        assert report.verdict == "LIKELY_HONEYPOT"

    def test_score_never_exceeds_1(self):
        # throw everything at it
        results = [make_result(p) for p in range(1, 50)]
        results.append(make_result(23))
        results.append(make_result(502))
        results.append(make_result(102))
        results.append(make_result(21, banner="220 DiskStation FTP server ready."))
        results.append(make_result(22, banner="SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"))
        report = score_honeypot(results)
        assert 0.0 <= report.score <= 1.0

    def test_report_has_correct_open_port_count(self):
        results = [
            make_result(22, state=PortState.OPEN),
            make_result(80, state=PortState.OPEN),
            make_result(443, state=PortState.CLOSED),
            make_result(8080, state=PortState.FILTERED),
        ]
        report = score_honeypot(results)
        assert report.open_port_count == 2

    def test_honeypot_report_str_contains_score(self):
        report = HoneypotReport(
            score=0.75,
            verdict="LIKELY_HONEYPOT",
            confidence="HIGH",
            indicators=[Indicator(name="test", weight=0.75, description="test")],
            open_port_count=5,
        )
        s = str(report)
        assert "0.75" in s
        assert "LIKELY_HONEYPOT" in s
        assert "HIGH" in s


# ---------------------------------------------------------------------------
# score_honeypot — export from porthawk public API
# ---------------------------------------------------------------------------


class TestPublicApiExport:
    def test_score_honeypot_importable_from_porthawk(self):
        import porthawk
        assert hasattr(porthawk, "score_honeypot")
        assert hasattr(porthawk, "HoneypotReport")
        assert hasattr(porthawk, "Indicator")

    def test_score_honeypot_returns_honeypot_report(self):
        import porthawk
        results = [make_result(22)]
        report = porthawk.score_honeypot(results)
        assert isinstance(report, porthawk.HoneypotReport)
