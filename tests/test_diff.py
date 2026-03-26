"""Tests for porthawk/diff.py — scan diff and load_results.

No network calls, no file I/O except where explicitly testing file loading.
"""

import json
import textwrap
from pathlib import Path

import pytest

from porthawk.diff import PortChange, ScanDiff, compute_diff, load_results, save_diff_json
from porthawk.scanner import PortState, ScanResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _r(
    port: int,
    state: PortState = PortState.OPEN,
    host: str = "10.0.0.1",
    protocol: str = "tcp",
    service_name: str | None = "http",
    service_version: str | None = None,
    risk_level: str | None = "LOW",
) -> ScanResult:
    return ScanResult(
        host=host,
        port=port,
        protocol=protocol,
        state=state,
        service_name=service_name,
        service_version=service_version,
        risk_level=risk_level,
    )


# ---------------------------------------------------------------------------
# compute_diff — new ports
# ---------------------------------------------------------------------------


def test_new_open_port_detected():
    a = [_r(80, state=PortState.OPEN)]
    b = [_r(80, state=PortState.OPEN), _r(443, state=PortState.OPEN)]
    diff = compute_diff(a, b)
    assert len(diff.new_ports) == 1
    assert diff.new_ports[0].port == 443


def test_new_closed_port_not_flagged():
    # a new CLOSED port is not interesting — it just means nmap now knows about it
    a: list[ScanResult] = []
    b = [_r(22, state=PortState.CLOSED)]
    diff = compute_diff(a, b)
    assert diff.new_ports == []


def test_new_filtered_port_not_flagged():
    a: list[ScanResult] = []
    b = [_r(22, state=PortState.FILTERED)]
    diff = compute_diff(a, b)
    assert diff.new_ports == []


def test_new_port_has_correct_after():
    a: list[ScanResult] = []
    b = [_r(8080, risk_level="HIGH")]
    diff = compute_diff(a, b)
    assert diff.new_ports[0].after.port == 8080  # type: ignore[union-attr]
    assert diff.new_ports[0].before is None


# ---------------------------------------------------------------------------
# compute_diff — gone ports
# ---------------------------------------------------------------------------


def test_gone_open_port_detected():
    a = [_r(22, state=PortState.OPEN), _r(80, state=PortState.OPEN)]
    b = [_r(80, state=PortState.OPEN)]
    diff = compute_diff(a, b)
    assert len(diff.gone_ports) == 1
    assert diff.gone_ports[0].port == 22


def test_gone_closed_port_not_flagged():
    # a closed port disappearing from scan B is not interesting
    a = [_r(22, state=PortState.CLOSED)]
    b: list[ScanResult] = []
    diff = compute_diff(a, b)
    assert diff.gone_ports == []


def test_gone_port_has_correct_before():
    a = [_r(3389, state=PortState.OPEN, risk_level="HIGH")]
    b: list[ScanResult] = []
    diff = compute_diff(a, b)
    assert diff.gone_ports[0].before.port == 3389  # type: ignore[union-attr]
    assert diff.gone_ports[0].after is None


# ---------------------------------------------------------------------------
# compute_diff — changed ports
# ---------------------------------------------------------------------------


def test_state_change_detected():
    a = [_r(80, state=PortState.FILTERED)]
    b = [_r(80, state=PortState.OPEN)]
    diff = compute_diff(a, b)
    assert len(diff.changed_ports) == 1
    assert diff.changed_ports[0].change == "changed"


def test_version_change_detected():
    a = [_r(22, service_version="OpenSSH 7.9")]
    b = [_r(22, service_version="OpenSSH 8.9p1")]
    diff = compute_diff(a, b)
    assert len(diff.changed_ports) == 1


def test_service_name_change_detected():
    a = [_r(8080, service_name="http-proxy")]
    b = [_r(8080, service_name="http")]
    diff = compute_diff(a, b)
    assert len(diff.changed_ports) == 1


def test_risk_level_change_detected():
    a = [_r(21, risk_level="MEDIUM")]
    b = [_r(21, risk_level="HIGH")]
    diff = compute_diff(a, b)
    assert len(diff.changed_ports) == 1


def test_changed_has_before_and_after():
    a = [_r(22, service_version="old")]
    b = [_r(22, service_version="new")]
    diff = compute_diff(a, b)
    c = diff.changed_ports[0]
    assert c.before is not None
    assert c.after is not None
    assert c.before.service_version == "old"
    assert c.after.service_version == "new"


# ---------------------------------------------------------------------------
# compute_diff — stable ports (default excluded)
# ---------------------------------------------------------------------------


def test_stable_ports_excluded_by_default():
    a = [_r(80)]
    b = [_r(80)]
    diff = compute_diff(a, b)
    assert diff.stable_ports == []
    assert diff.changes == []


def test_stable_ports_included_when_requested():
    a = [_r(80)]
    b = [_r(80)]
    diff = compute_diff(a, b, include_stable=True)
    assert len(diff.stable_ports) == 1
    assert diff.stable_ports[0].port == 80


# ---------------------------------------------------------------------------
# compute_diff — labels
# ---------------------------------------------------------------------------


def test_labels_preserved():
    diff = compute_diff([], [], label_a="monday.json", label_b="friday.json")
    assert diff.label_a == "monday.json"
    assert diff.label_b == "friday.json"


# ---------------------------------------------------------------------------
# compute_diff — empty inputs
# ---------------------------------------------------------------------------


def test_both_empty():
    diff = compute_diff([], [])
    assert diff.changes == []


def test_a_empty_b_has_open():
    b = [_r(80), _r(443)]
    diff = compute_diff([], b)
    assert len(diff.new_ports) == 2


def test_a_has_open_b_empty():
    a = [_r(22), _r(80)]
    diff = compute_diff(a, [])
    assert len(diff.gone_ports) == 2


# ---------------------------------------------------------------------------
# compute_diff — multi-host
# ---------------------------------------------------------------------------


def test_multi_host_diff():
    a = [
        _r(22, host="10.0.0.1"),
        _r(80, host="10.0.0.2"),
    ]
    b = [
        _r(22, host="10.0.0.1"),
        _r(80, host="10.0.0.2"),
        _r(443, host="10.0.0.2"),  # new
    ]
    diff = compute_diff(a, b)
    assert len(diff.new_ports) == 1
    assert diff.new_ports[0].host == "10.0.0.2"
    assert diff.new_ports[0].port == 443


def test_protocol_is_part_of_key():
    # same port, different protocol — not the same service
    a = [_r(53, protocol="tcp")]
    b = [_r(53, protocol="tcp"), _r(53, protocol="udp")]
    diff = compute_diff(a, b)
    assert len(diff.new_ports) == 1
    assert diff.new_ports[0].protocol == "udp"


# ---------------------------------------------------------------------------
# ScanDiff properties
# ---------------------------------------------------------------------------


def test_has_regressions_true_for_new_high():
    b = [_r(23, risk_level="HIGH")]
    diff = compute_diff([], b)
    assert diff.has_regressions is True


def test_has_regressions_true_for_new_medium():
    b = [_r(21, risk_level="MEDIUM")]
    diff = compute_diff([], b)
    assert diff.has_regressions is True


def test_has_regressions_false_for_new_low():
    b = [_r(80, risk_level="LOW")]
    diff = compute_diff([], b)
    assert diff.has_regressions is False


def test_has_regressions_false_for_no_changes():
    diff = compute_diff([], [])
    assert diff.has_regressions is False


# ---------------------------------------------------------------------------
# PortChange.describe()
# ---------------------------------------------------------------------------


def test_describe_new():
    c = PortChange(
        host="10.0.0.1", port=22, protocol="tcp", change="new",
        before=None, after=_r(22, service_name="ssh", risk_level="MEDIUM"),
    )
    desc = c.describe()
    assert "+" in desc
    assert "22" in desc
    assert "ssh" in desc


def test_describe_gone():
    c = PortChange(
        host="10.0.0.1", port=23, protocol="tcp", change="gone",
        before=_r(23, service_name="telnet", risk_level="HIGH"), after=None,
    )
    desc = c.describe()
    assert "-" in desc
    assert "23" in desc


def test_describe_changed():
    c = PortChange(
        host="10.0.0.1", port=22, protocol="tcp", change="changed",
        before=_r(22, service_version="7.9"),
        after=_r(22, service_version="8.9p1"),
    )
    desc = c.describe()
    assert "~" in desc
    assert "7.9" in desc
    assert "8.9p1" in desc


# ---------------------------------------------------------------------------
# ScanDiff.to_dict()
# ---------------------------------------------------------------------------


def test_to_dict_structure():
    a = [_r(22)]
    b = [_r(22), _r(443)]
    diff = compute_diff(a, b)
    d = diff.to_dict()
    assert "label_a" in d
    assert "label_b" in d
    assert "summary" in d
    assert "changes" in d
    assert d["summary"]["new"] == 1


def test_to_dict_is_json_serializable():
    diff = compute_diff([_r(22)], [_r(22), _r(80)])
    serialized = json.dumps(diff.to_dict())
    assert isinstance(serialized, str)
    roundtrip = json.loads(serialized)
    assert roundtrip["summary"]["new"] == 1


# ---------------------------------------------------------------------------
# save_diff_json()
# ---------------------------------------------------------------------------


def test_save_diff_json(tmp_path):
    diff = compute_diff([_r(22)], [_r(22), _r(80)])
    dest = tmp_path / "diff.json"
    path = save_diff_json(diff, output_path=dest)
    assert path == dest
    assert dest.exists()
    data = json.loads(dest.read_text())
    assert data["summary"]["new"] == 1


# ---------------------------------------------------------------------------
# load_results() — PortHawk JSON
# ---------------------------------------------------------------------------


def _porthawk_json(results: list[ScanResult], tmp_path: Path) -> Path:
    import porthawk
    report = porthawk.build_report(
        target="10.0.0.1", results=results, protocol="tcp",
        timeout=1.0, max_concurrent=100,
    )
    from porthawk.reporter import save_json
    return save_json(report, output_path=tmp_path / "scan.json")


def test_load_porthawk_json(tmp_path):
    original = [_r(22), _r(80)]
    path = _porthawk_json(original, tmp_path)
    loaded = load_results(str(path))
    ports = {r.port for r in loaded}
    assert {22, 80} == ports


def test_load_json_file_not_found():
    with pytest.raises(FileNotFoundError):
        load_results("/nonexistent/scan.json")


def test_load_json_invalid_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("not json", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid JSON"):
        load_results(str(p))


def test_load_json_wrong_structure(tmp_path):
    p = tmp_path / "wrong.json"
    p.write_text('{"metadata": {}}', encoding="utf-8")
    with pytest.raises(ValueError, match="results"):
        load_results(str(p))


# ---------------------------------------------------------------------------
# load_results() — Nmap XML
# ---------------------------------------------------------------------------


def test_load_nmap_xml(tmp_path):
    xml = textwrap.dedent("""\
        <?xml version="1.0"?>
        <nmaprun scanner="nmap" version="7.93">
          <host>
            <status state="up"/>
            <address addr="10.0.0.1" addrtype="ipv4"/>
            <ports>
              <port protocol="tcp" portid="22"><state state="open"/></port>
              <port protocol="tcp" portid="80"><state state="open"/></port>
            </ports>
          </host>
        </nmaprun>
    """)
    p = tmp_path / "scan.xml"
    p.write_text(xml, encoding="utf-8")
    loaded = load_results(str(p))
    assert len(loaded) == 2


# ---------------------------------------------------------------------------
# load_results() — format sniffing (no extension)
# ---------------------------------------------------------------------------


def test_sniff_json_no_extension(tmp_path):
    data = {"results": [{"host": "10.0.0.1", "port": 80, "protocol": "tcp", "state": "open", "cves": []}]}
    p = tmp_path / "scandata"
    p.write_text(json.dumps(data), encoding="utf-8")
    results = load_results(str(p))
    assert results[0].port == 80


def test_sniff_xml_no_extension(tmp_path):
    xml = textwrap.dedent("""\
        <?xml version="1.0"?>
        <nmaprun scanner="nmap" version="7.93">
          <host>
            <status state="up"/>
            <address addr="10.0.0.1" addrtype="ipv4"/>
            <ports><port protocol="tcp" portid="443"><state state="open"/></port></ports>
          </host>
        </nmaprun>
    """)
    p = tmp_path / "scandata"
    p.write_text(xml, encoding="utf-8")
    results = load_results(str(p))
    assert results[0].port == 443


def test_unknown_format_raises(tmp_path):
    p = tmp_path / "scan.csv"
    p.write_text("host,port\n10.0.0.1,80\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Cannot detect format"):
        load_results(str(p))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def test_diff_symbols_in_public_api():
    import porthawk
    assert hasattr(porthawk, "compute_diff")
    assert hasattr(porthawk, "load_results")
    assert hasattr(porthawk, "ScanDiff")
    assert hasattr(porthawk, "PortChange")
