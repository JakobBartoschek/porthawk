"""Tests for porthawk/sarif.py — SARIF 2.1.0 output.

All tests use in-memory ScanReport objects. No file I/O except save_sarif() test.
"""

import json
from pathlib import Path

import pytest

from porthawk.reporter import ScanReport, build_report, save_sarif
from porthawk.sarif import _RULES, build_sarif
from porthawk.scanner import PortState, ScanResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _meta():
    """Minimal metadata dict for build_report()."""
    return {
        "target": "192.168.1.1",
        "protocol": "tcp",
        "timeout": 1.0,
        "max_concurrent": 100,
    }


def _result(
    port: int,
    state: PortState = PortState.OPEN,
    risk_level: str | None = "LOW",
    service_name: str | None = "http",
    banner: str | None = None,
    service_version: str | None = None,
    cves: list | None = None,
    protocol: str = "tcp",
) -> ScanResult:
    return ScanResult(
        host="192.168.1.1",
        port=port,
        protocol=protocol,
        state=state,
        risk_level=risk_level,
        service_name=service_name,
        banner=banner,
        service_version=service_version,
        cves=cves or [],
    )


def _report(*results: ScanResult) -> ScanReport:
    return build_report(
        target="192.168.1.1",
        results=list(results),
        protocol="tcp",
        timeout=1.0,
        max_concurrent=100,
    )


# ---------------------------------------------------------------------------
# Structure tests
# ---------------------------------------------------------------------------


def test_sarif_top_level_keys():
    doc = build_sarif(_report())
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert "runs" in doc
    assert len(doc["runs"]) == 1


def test_sarif_tool_driver():
    doc = build_sarif(_report(), version="0.9.0")
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "PortHawk"
    assert driver["version"] == "0.9.0"
    assert "informationUri" in driver


def test_sarif_rules_count():
    doc = build_sarif(_report())
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 4


def test_sarif_rule_ids():
    doc = build_sarif(_report())
    ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert ids == {"PH001", "PH002", "PH003", "PH004"}


def test_sarif_rules_have_security_severity():
    for rule in _RULES:
        assert "security-severity" in rule["properties"]
        score = float(rule["properties"]["security-severity"])
        assert 0.0 < score <= 10.0


def test_sarif_ph001_is_highest_severity():
    scores = {r["id"]: float(r["properties"]["security-severity"]) for r in _RULES}
    assert scores["PH001"] > scores["PH002"] > scores["PH003"] >= scores["PH004"]


# ---------------------------------------------------------------------------
# Empty / no open ports
# ---------------------------------------------------------------------------


def test_empty_report_produces_no_results():
    doc = build_sarif(_report())
    assert doc["runs"][0]["results"] == []


def test_closed_ports_excluded():
    r = _result(22, state=PortState.CLOSED)
    doc = build_sarif(_report(r))
    assert doc["runs"][0]["results"] == []


def test_filtered_ports_excluded():
    r = _result(80, state=PortState.FILTERED)
    doc = build_sarif(_report(r))
    assert doc["runs"][0]["results"] == []


# ---------------------------------------------------------------------------
# Risk level → rule ID mapping
# ---------------------------------------------------------------------------


def test_high_risk_maps_to_ph001_error():
    r = _result(23, risk_level="HIGH", service_name="telnet")
    doc = build_sarif(_report(r))
    finding = doc["runs"][0]["results"][0]
    assert finding["ruleId"] == "PH001"
    assert finding["level"] == "error"


def test_medium_risk_maps_to_ph002_warning():
    r = _result(21, risk_level="MEDIUM", service_name="ftp")
    doc = build_sarif(_report(r))
    finding = doc["runs"][0]["results"][0]
    assert finding["ruleId"] == "PH002"
    assert finding["level"] == "warning"


def test_low_risk_maps_to_ph003_note():
    r = _result(80, risk_level="LOW", service_name="http")
    doc = build_sarif(_report(r))
    finding = doc["runs"][0]["results"][0]
    assert finding["ruleId"] == "PH003"
    assert finding["level"] == "note"


def test_no_risk_maps_to_ph004_note():
    r = _result(9999, risk_level=None, service_name=None)
    doc = build_sarif(_report(r))
    finding = doc["runs"][0]["results"][0]
    assert finding["ruleId"] == "PH004"
    assert finding["level"] == "note"


# ---------------------------------------------------------------------------
# Message content
# ---------------------------------------------------------------------------


def test_message_contains_port_and_host():
    r = _result(443, service_name="https", risk_level="LOW")
    doc = build_sarif(_report(r))
    msg = doc["runs"][0]["results"][0]["message"]["text"]
    assert "443" in msg
    assert "192.168.1.1" in msg


def test_message_contains_service_name():
    r = _result(22, service_name="ssh", risk_level="MEDIUM")
    doc = build_sarif(_report(r))
    msg = doc["runs"][0]["results"][0]["message"]["text"]
    assert "ssh" in msg


def test_message_includes_banner():
    r = _result(22, service_name="ssh", banner="OpenSSH_8.9p1")
    doc = build_sarif(_report(r))
    msg = doc["runs"][0]["results"][0]["message"]["text"]
    assert "OpenSSH_8.9p1" in msg


def test_message_includes_service_version():
    r = _result(22, service_name="ssh", service_version="OpenSSH_9.0")
    doc = build_sarif(_report(r))
    msg = doc["runs"][0]["results"][0]["message"]["text"]
    assert "OpenSSH_9.0" in msg


def test_message_no_banner_no_version_still_valid():
    r = _result(80, service_name="http", banner=None, service_version=None)
    doc = build_sarif(_report(r))
    msg = doc["runs"][0]["results"][0]["message"]["text"]
    assert msg  # non-empty


def test_message_protocol_included():
    r = _result(53, protocol="udp", service_name="dns")
    doc = build_sarif(_report(r))
    msg = doc["runs"][0]["results"][0]["message"]["text"]
    assert "udp" in msg


# ---------------------------------------------------------------------------
# Logical location
# ---------------------------------------------------------------------------


def test_logical_location_name_format():
    r = _result(22, service_name="ssh")
    doc = build_sarif(_report(r))
    loc = doc["runs"][0]["results"][0]["locations"][0]["logicalLocations"][0]
    assert loc["name"] == "192.168.1.1:22/tcp"
    assert loc["decoratedName"] == "ssh"
    assert loc["kind"] == "host"


def test_unknown_service_decorated_name():
    r = _result(9999, service_name=None, risk_level=None)
    doc = build_sarif(_report(r))
    loc = doc["runs"][0]["results"][0]["locations"][0]["logicalLocations"][0]
    assert loc["decoratedName"] == "unknown service"


# ---------------------------------------------------------------------------
# CVE integration
# ---------------------------------------------------------------------------


def test_cves_become_related_locations():
    r = _result(
        22,
        cves=[{"cve_id": "CVE-2023-1234", "score": 7.5}, {"cve_id": "CVE-2022-9876", "score": 5.0}],
    )
    doc = build_sarif(_report(r))
    finding = doc["runs"][0]["results"][0]
    assert "relatedLocations" in finding
    ids = [rl["message"]["text"] for rl in finding["relatedLocations"]]
    assert "CVE-2023-1234" in ids
    assert "CVE-2022-9876" in ids


def test_cves_capped_at_ten():
    cves = [{"cve_id": f"CVE-2023-{i:04d}"} for i in range(15)]
    r = _result(22, cves=cves)
    doc = build_sarif(_report(r))
    related = doc["runs"][0]["results"][0].get("relatedLocations", [])
    assert len(related) <= 10


def test_no_cves_no_related_locations():
    r = _result(80, cves=[])
    doc = build_sarif(_report(r))
    finding = doc["runs"][0]["results"][0]
    assert "relatedLocations" not in finding


def test_cves_without_cve_id_ignored():
    r = _result(80, cves=[{"score": 7.5}])  # no cve_id key
    doc = build_sarif(_report(r))
    finding = doc["runs"][0]["results"][0]
    assert "relatedLocations" not in finding


# ---------------------------------------------------------------------------
# Multiple results
# ---------------------------------------------------------------------------


def test_multiple_open_ports():
    results = [
        _result(22, risk_level="MEDIUM"),
        _result(80, risk_level="LOW"),
        _result(23, risk_level="HIGH"),
    ]
    doc = build_sarif(_report(*results))
    assert len(doc["runs"][0]["results"]) == 3


def test_mixed_states_only_open_included():
    results = [
        _result(22, state=PortState.OPEN, risk_level="LOW"),
        _result(23, state=PortState.CLOSED, risk_level="HIGH"),
        _result(80, state=PortState.FILTERED, risk_level="MEDIUM"),
        _result(443, state=PortState.OPEN, risk_level="LOW"),
    ]
    doc = build_sarif(_report(*results))
    assert len(doc["runs"][0]["results"]) == 2


# ---------------------------------------------------------------------------
# Version embedding
# ---------------------------------------------------------------------------


def test_version_default():
    doc = build_sarif(_report())
    assert doc["runs"][0]["tool"]["driver"]["version"] == "0.0.0"


def test_version_custom():
    doc = build_sarif(_report(), version="1.2.3")
    assert doc["runs"][0]["tool"]["driver"]["version"] == "1.2.3"


# ---------------------------------------------------------------------------
# JSON serialisability
# ---------------------------------------------------------------------------


def test_sarif_is_json_serializable():
    r = _result(22, service_name="ssh", risk_level="HIGH", banner="SSH-2.0-OpenSSH_8.9")
    doc = build_sarif(_report(r))
    serialized = json.dumps(doc)
    assert isinstance(serialized, str)
    roundtrip = json.loads(serialized)
    assert roundtrip["runs"][0]["results"][0]["ruleId"] == "PH001"


# ---------------------------------------------------------------------------
# save_sarif() integration
# ---------------------------------------------------------------------------


def test_save_sarif_creates_file(tmp_path):
    r = _result(80, risk_level="LOW")
    report = _report(r)
    dest = tmp_path / "out.sarif"
    path = save_sarif(report, output_path=dest)
    assert path == dest
    assert dest.exists()


def test_save_sarif_valid_json(tmp_path):
    r = _result(443, risk_level="LOW", service_name="https")
    report = _report(r)
    dest = tmp_path / "out.sarif"
    save_sarif(report, output_path=dest)
    doc = json.loads(dest.read_text())
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"][0]["results"]) == 1


def test_save_sarif_default_path(tmp_path, monkeypatch):
    # redirect the reports dir to tmp_path so we don't litter the project dir
    import porthawk.reporter as rep
    monkeypatch.setattr(rep, "_REPORTS_DIR", tmp_path)
    r = _result(22, risk_level="MEDIUM")
    report = _report(r)
    path = save_sarif(report)
    assert path.suffix == ".sarif"
    assert path.exists()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def test_build_sarif_in_public_api():
    import porthawk
    assert hasattr(porthawk, "build_sarif")
