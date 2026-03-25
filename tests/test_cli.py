"""Tests for cli.py — uses typer's test runner, no real network calls + unit tests for helpers.

typer.testing.CliRunner is the right way to test typer apps.
All scanner calls are mocked so tests don't hit the network.

Note: single-command typer apps are invoked directly without a subcommand prefix.
'porthawk -t host --common' not 'porthawk scan -t host --common'.
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from porthawk.cli import _enrich_results, _resolve_port_list, _save_outputs, app
from porthawk.scanner import PortState, ScanResult

runner = CliRunner()


def _fake_scan_result(port: int, state: PortState = PortState.OPEN) -> ScanResult:
    return ScanResult(
        host="192.168.1.1",
        port=port,
        protocol="tcp",
        state=state,
        service_name="http",
        risk_level="LOW",
    )


def _mock_scan_targets(results: list[ScanResult] | None = None):
    """Return an async function that yields fake scan results without touching the network."""
    if results is None:
        results = [_fake_scan_result(80)]

    async def _fake(*args, **kwargs):
        return {"192.168.1.1": results}

    return _fake


# --- Required argument validation ---

class TestRequiredArgs:
    def test_missing_target_exits_with_error(self):
        """typer exits with code 2 when a required option is missing."""
        result = runner.invoke(app, ["--common"])
        assert result.exit_code != 0

    def test_missing_port_spec_exits_with_error(self):
        """Without port spec, cli.py should exit with code 1 (our own error)."""
        with patch("porthawk.cli.asyncio.run", return_value={"192.168.1.1": []}):
            result = runner.invoke(app, ["-t", "192.168.1.1"])
        assert result.exit_code != 0


# --- Port selection flags ---

class TestPortSelection:
    def test_top_ports_flag_invokes_scan(self):
        fake_results = [_fake_scan_result(80)]
        with patch("porthawk.cli._run_scan", new=_mock_scan_targets(fake_results)):
            with patch("porthawk.cli._enrich_results", return_value=fake_results):
                with patch("porthawk.cli.print_terminal"):
                    result = runner.invoke(app, ["-t", "192.168.1.1", "--top-ports", "10"])
        assert result.exit_code == 0

    def test_common_flag_invokes_scan(self):
        fake_results = [_fake_scan_result(80)]
        with patch("porthawk.cli._run_scan", new=_mock_scan_targets(fake_results)):
            with patch("porthawk.cli._enrich_results", return_value=fake_results):
                with patch("porthawk.cli.print_terminal"):
                    result = runner.invoke(app, ["-t", "192.168.1.1", "--common"])
        assert result.exit_code == 0

    def test_full_flag_invokes_scan(self):
        """--full scans all 65535 ports — we mock the actual scan."""
        fake_results = [_fake_scan_result(80)]
        with patch("porthawk.cli._run_scan", new=_mock_scan_targets(fake_results)):
            with patch("porthawk.cli._enrich_results", return_value=fake_results):
                with patch("porthawk.cli.print_terminal"):
                    result = runner.invoke(app, ["-t", "192.168.1.1", "--full"])
        assert result.exit_code == 0

    def test_port_range_flag(self):
        fake_results = [_fake_scan_result(22)]
        with patch("porthawk.cli._run_scan", new=_mock_scan_targets(fake_results)):
            with patch("porthawk.cli._enrich_results", return_value=fake_results):
                with patch("porthawk.cli.print_terminal"):
                    result = runner.invoke(app, ["-t", "192.168.1.1", "-p", "1-100"])
        assert result.exit_code == 0


# --- Timeout and thread options ---

class TestScanOptions:
    def test_timeout_accepts_float(self):
        fake_results = [_fake_scan_result(80)]
        with patch("porthawk.cli._run_scan", new=_mock_scan_targets(fake_results)):
            with patch("porthawk.cli._enrich_results", return_value=fake_results):
                with patch("porthawk.cli.print_terminal"):
                    result = runner.invoke(
                        app,
                        ["-t", "192.168.1.1", "--common", "--timeout", "2.5"],
                    )
        assert result.exit_code == 0

    def test_stealth_mode_overrides_threads(self):
        """--stealth sets threads=1 and timeout=3.0 — verify it doesn't crash."""
        fake_results = [_fake_scan_result(80)]
        with patch("porthawk.cli._run_scan", new=_mock_scan_targets(fake_results)):
            with patch("porthawk.cli._enrich_results", return_value=fake_results):
                with patch("porthawk.cli.print_terminal"):
                    result = runner.invoke(
                        app,
                        ["-t", "192.168.1.1", "--common", "--stealth"],
                    )
        assert result.exit_code == 0

    def test_invalid_top_ports_value_exits_with_error(self):
        result = runner.invoke(app, ["-t", "192.168.1.1", "--top-ports", "0"])
        assert result.exit_code != 0


# --- Version flag ---

class TestVersionFlag:
    def test_version_flag_exits_cleanly(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output or "PortHawk" in result.output


# --- Output format flags ---

class TestOutputFormats:
    def test_json_output_flag_calls_save_json(self, tmp_path):
        fake_results = [_fake_scan_result(80)]
        with patch("porthawk.cli._run_scan", new=_mock_scan_targets(fake_results)):
            with patch("porthawk.cli._enrich_results", return_value=fake_results):
                with patch("porthawk.cli.print_terminal"):
                    with patch("porthawk.cli.save_json", return_value=tmp_path / "out.json") as mock_json:
                        result = runner.invoke(
                            app,
                            ["-t", "192.168.1.1", "--common", "-o", "json"],
                        )
        assert result.exit_code == 0
        mock_json.assert_called_once()

    def test_unknown_output_format_does_not_crash(self):
        """Unknown format should warn but not crash — graceful degradation."""
        fake_results = [_fake_scan_result(80)]
        with patch("porthawk.cli._run_scan", new=_mock_scan_targets(fake_results)):
            with patch("porthawk.cli._enrich_results", return_value=fake_results):
                with patch("porthawk.cli.print_terminal"):
                    result = runner.invoke(
                        app,
                        ["-t", "192.168.1.1", "--common", "-o", "pdf"],
                    )
        assert result.exit_code == 0  # warn, don't crash


# --- _resolve_port_list helper ---

class TestResolvePortList:
    def test_full_returns_65535_ports(self):
        ports = _resolve_port_list(None, None, full=True, common=False)
        assert ports is not None
        assert len(ports) == 65535
        assert 1 in ports
        assert 65535 in ports

    def test_common_returns_100_ports(self):
        ports = _resolve_port_list(None, None, full=False, common=True)
        assert ports is not None
        assert len(ports) == 100

    def test_top_ports_n_returns_n_ports(self):
        ports = _resolve_port_list(None, 25, full=False, common=False)
        assert ports is not None
        assert len(ports) == 25

    def test_port_string_is_parsed(self):
        ports = _resolve_port_list("22,80,443", None, full=False, common=False)
        assert ports == [22, 80, 443]

    def test_none_returns_none(self):
        ports = _resolve_port_list(None, None, full=False, common=False)
        assert ports is None

    def test_full_takes_priority_over_common(self):
        """Priority: --full > --top-ports > --common > -p"""
        ports = _resolve_port_list(None, None, full=True, common=True)
        assert ports is not None
        assert len(ports) == 65535


# --- _enrich_results helper ---

class TestEnrichResults:
    def test_service_name_is_added(self):
        result = _fake_scan_result(80, state=PortState.OPEN)
        result.service_name = None  # reset it
        enriched = _enrich_results([result], host="192.168.1.1", banners=False, os_detect=False, timeout=1.0)
        assert enriched[0].service_name == "http"

    def test_risk_level_is_added(self):
        result = _fake_scan_result(23, state=PortState.OPEN)
        result.risk_level = None
        enriched = _enrich_results([result], host="192.168.1.1", banners=False, os_detect=False, timeout=1.0)
        assert enriched[0].risk_level == "HIGH"

    def test_os_detect_adds_os_guess(self):
        result = _fake_scan_result(80)
        with patch("porthawk.cli.get_ttl_via_ping", return_value=64):
            enriched = _enrich_results([result], host="192.168.1.1", banners=False, os_detect=True, timeout=1.0)
        assert enriched[0].os_guess == "Linux/Unix"
        assert enriched[0].ttl == 64

    def test_os_detect_no_ping_response_skips_os_guess(self):
        result = _fake_scan_result(80)
        with patch("porthawk.cli.get_ttl_via_ping", return_value=None):
            enriched = _enrich_results([result], host="192.168.1.1", banners=False, os_detect=True, timeout=1.0)
        assert enriched[0].os_guess is None

    def test_banners_called_for_open_ports(self):
        open_result = _fake_scan_result(80, state=PortState.OPEN)
        closed_result = _fake_scan_result(9999, state=PortState.CLOSED)

        with patch("porthawk.cli.fingerprint_port", new=AsyncMock(return_value="nginx/1.24")) as mock_fp:
            enriched = _enrich_results(
                [open_result, closed_result],
                host="192.168.1.1",
                banners=True,
                os_detect=False,
                timeout=1.0,
            )

        # fingerprint_port should be called exactly once (only for open port)
        mock_fp.assert_called_once()

    def test_banners_not_grabbed_for_closed_only(self):
        closed_result = _fake_scan_result(9999, state=PortState.CLOSED)

        with patch("porthawk.cli.fingerprint_port", new=AsyncMock(return_value=None)) as mock_fp:
            _enrich_results(
                [closed_result],
                host="192.168.1.1",
                banners=True,
                os_detect=False,
                timeout=1.0,
            )

        mock_fp.assert_not_called()


# --- _save_outputs helper ---

class TestSaveOutputs:
    def test_save_json_called_for_json_format(self, tmp_path):
        from porthawk.reporter import build_report
        report = build_report("192.168.1.1", [_fake_scan_result(80)])

        with patch("porthawk.cli.save_json", return_value=tmp_path / "out.json") as mock_j:
            _save_outputs(report, "json")

        mock_j.assert_called_once()

    def test_save_csv_called_for_csv_format(self, tmp_path):
        from porthawk.reporter import build_report
        report = build_report("192.168.1.1", [_fake_scan_result(80)])

        with patch("porthawk.cli.save_csv", return_value=tmp_path / "out.csv") as mock_c:
            _save_outputs(report, "csv")

        mock_c.assert_called_once()

    def test_save_html_called_for_html_format(self, tmp_path):
        from porthawk.reporter import build_report
        report = build_report("192.168.1.1", [_fake_scan_result(80)])

        with patch("porthawk.cli.save_html", return_value=tmp_path / "out.html") as mock_h:
            _save_outputs(report, "html")

        mock_h.assert_called_once()

    def test_none_output_does_nothing(self, tmp_path):
        from porthawk.reporter import build_report
        report = build_report("192.168.1.1", [])

        with patch("porthawk.cli.save_json") as mock_j:
            _save_outputs(report, None)

        mock_j.assert_not_called()

    def test_multiple_formats_all_called(self, tmp_path):
        from porthawk.reporter import build_report
        report = build_report("192.168.1.1", [_fake_scan_result(80)])

        with patch("porthawk.cli.save_json", return_value=tmp_path / "a.json") as mj:
            with patch("porthawk.cli.save_csv", return_value=tmp_path / "a.csv") as mc:
                with patch("porthawk.cli.save_html", return_value=tmp_path / "a.html") as mh:
                    _save_outputs(report, "json,csv,html")

        mj.assert_called_once()
        mc.assert_called_once()
        mh.assert_called_once()
