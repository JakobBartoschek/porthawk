"""Tests for reporter.py — file output, JSON validity, HTML structure.

Uses tmp_path fixture so no files pollute the working directory.
"""

import csv
import json
from pathlib import Path

import pytest

from porthawk.reporter import (
    ScanReport,
    ScanMetadata,
    build_report,
    print_terminal,
    save_csv,
    save_html,
    save_json,
)
from porthawk.scanner import PortState, ScanResult


def _make_result(
    host: str = "192.168.1.1",
    port: int = 80,
    state: PortState = PortState.OPEN,
    service_name: str = "http",
    risk_level: str = "LOW",
    banner: str | None = None,
) -> ScanResult:
    """Quick factory for ScanResult objects in tests."""
    return ScanResult(
        host=host,
        port=port,
        protocol="tcp",
        state=state,
        service_name=service_name,
        risk_level=risk_level,
        banner=banner,
    )


def _make_report(results: list[ScanResult] | None = None) -> ScanReport:
    """Quick factory for ScanReport objects in tests."""
    if results is None:
        results = [
            _make_result(port=80, state=PortState.OPEN, service_name="http", risk_level="LOW"),
            _make_result(port=23, state=PortState.OPEN, service_name="telnet", risk_level="HIGH"),
            _make_result(port=9999, state=PortState.CLOSED, service_name="unknown", risk_level=None),
        ]
    return build_report(
        target="192.168.1.1",
        results=results,
        protocol="tcp",
        timeout=1.0,
        max_concurrent=500,
    )


# --- build_report ---

class TestBuildReport:
    def test_open_count_is_correct(self):
        results = [
            _make_result(port=80, state=PortState.OPEN),
            _make_result(port=443, state=PortState.OPEN),
            _make_result(port=9999, state=PortState.CLOSED),
        ]
        report = build_report("10.0.0.1", results)
        assert report.metadata.open_ports == 2
        assert report.metadata.total_ports == 3

    def test_target_is_preserved(self):
        report = build_report("scanme.nmap.org", [])
        assert report.metadata.target == "scanme.nmap.org"

    def test_empty_results_valid_report(self):
        report = build_report("192.168.1.1", [])
        assert report.metadata.open_ports == 0
        assert report.metadata.total_ports == 0
        assert report.results == []


# --- open_only filter ---

class TestOpenOnly:
    def test_open_only_filters_correctly(self):
        report = _make_report()
        open_ports = report.open_only()
        assert all(r.state == PortState.OPEN for r in open_ports)
        assert len(open_ports) == 2  # 80 and 23

    def test_empty_results_open_only_is_empty(self):
        report = build_report("192.168.1.1", [])
        assert report.open_only() == []


# --- JSON output ---

class TestSaveJson:
    def test_json_output_is_valid(self, tmp_path: Path):
        report = _make_report()
        out = save_json(report, output_path=tmp_path / "test.json")

        with out.open() as f:
            data = json.load(f)

        assert "metadata" in data
        assert "results" in data

    def test_json_metadata_has_required_keys(self, tmp_path: Path):
        report = _make_report()
        out = save_json(report, output_path=tmp_path / "test.json")

        with out.open() as f:
            data = json.load(f)

        meta = data["metadata"]
        for key in ("target", "scan_time", "total_ports", "open_ports", "protocol"):
            assert key in meta, f"metadata.{key} is missing from JSON output"

    def test_json_empty_results_valid(self, tmp_path: Path):
        report = build_report("192.168.1.1", [])
        out = save_json(report, output_path=tmp_path / "empty.json")

        with out.open() as f:
            data = json.load(f)

        assert data["results"] == []

    def test_json_pretty_printed(self, tmp_path: Path):
        """Output should be indented — one-liner JSON is unreadable."""
        report = _make_report()
        out = save_json(report, output_path=tmp_path / "test.json")
        raw = out.read_text()
        # Pretty-printed JSON has newlines
        assert "\n" in raw


# --- CSV output ---

class TestSaveCsv:
    def test_csv_has_correct_headers(self, tmp_path: Path):
        report = _make_report()
        out = save_csv(report, output_path=tmp_path / "test.csv")

        with out.open(newline="") as f:
            reader = csv.DictReader(f)
            assert reader.fieldnames is not None
            for col in ("host", "port", "protocol", "state", "service_name", "risk_level"):
                assert col in reader.fieldnames

    def test_csv_row_count_matches_results(self, tmp_path: Path):
        results = [_make_result(port=p) for p in [80, 443, 22]]
        report = build_report("10.0.0.1", results)
        out = save_csv(report, output_path=tmp_path / "test.csv")

        with out.open(newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 3

    def test_csv_empty_results(self, tmp_path: Path):
        report = build_report("192.168.1.1", [])
        out = save_csv(report, output_path=tmp_path / "empty.csv")

        with out.open(newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert rows == []


# --- HTML output ---

class TestSaveHtml:
    def test_html_contains_table(self, tmp_path: Path):
        report = _make_report()
        out = save_html(report, output_path=tmp_path / "test.html")
        html = out.read_text(encoding="utf-8")
        assert "<table" in html

    def test_html_contains_target_in_title(self, tmp_path: Path):
        report = _make_report()
        out = save_html(report, output_path=tmp_path / "test.html")
        html = out.read_text(encoding="utf-8")
        assert "192.168.1.1" in html

    def test_html_contains_porthawk_branding(self, tmp_path: Path):
        report = _make_report()
        out = save_html(report, output_path=tmp_path / "test.html")
        html = out.read_text(encoding="utf-8")
        assert "PORTHAWK" in html or "PortHawk" in html

    def test_html_is_valid_enough_to_contain_doctype(self, tmp_path: Path):
        report = _make_report()
        out = save_html(report, output_path=tmp_path / "test.html")
        html = out.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in html

    def test_html_empty_results(self, tmp_path: Path):
        report = build_report("192.168.1.1", [])
        out = save_html(report, output_path=tmp_path / "empty.html")
        html = out.read_text(encoding="utf-8")
        assert "<table" in html  # table should still render, just with no rows


# --- Terminal output ---

class TestPrintTerminal:
    def test_terminal_output_does_not_raise(self, capsys):
        report = _make_report()
        # rich writes to its own Console — capsys won't capture it, but it shouldn't raise
        print_terminal(report, show_closed=False)

    def test_terminal_with_show_closed_does_not_raise(self, capsys):
        report = _make_report()
        print_terminal(report, show_closed=True)

    def test_terminal_empty_results_does_not_raise(self, capsys):
        report = build_report("192.168.1.1", [])
        print_terminal(report)
