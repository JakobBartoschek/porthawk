"""Tests for porthawk/nmap_import.py — Nmap XML parser.

Uses inline XML strings (no real files). Covers the full surface of
state mapping, service extraction, multi-host runs, and error handling.
"""

import textwrap
from pathlib import Path

import pytest

from porthawk.nmap_import import parse_nmap_xml
from porthawk.scanner import PortState


# ---------------------------------------------------------------------------
# XML fixture helpers
# ---------------------------------------------------------------------------


def _write_xml(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "scan.xml"
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


def _minimal_run(host_block: str) -> str:
    return f"""\
        <?xml version="1.0"?>
        <nmaprun scanner="nmap" version="7.93">
          {host_block}
        </nmaprun>
    """


def _host(ip: str, *port_blocks: str, status: str = "up") -> str:
    ports = "\n    ".join(port_blocks)
    return f"""\
        <host>
          <status state="{status}"/>
          <address addr="{ip}" addrtype="ipv4"/>
          <ports>
            {ports}
          </ports>
        </host>
    """


def _port(portid: int, proto: str = "tcp", state: str = "open",
          name: str | None = None, product: str | None = None,
          version: str | None = None, extrainfo: str | None = None) -> str:
    svc_attrs = ""
    if name:
        svc_attrs += f' name="{name}"'
    if product:
        svc_attrs += f' product="{product}"'
    if version:
        svc_attrs += f' version="{version}"'
    if extrainfo:
        svc_attrs += f' extrainfo="{extrainfo}"'
    svc_elem = f"<service{svc_attrs}/>" if svc_attrs else ""
    return f"""\
        <port protocol="{proto}" portid="{portid}">
          <state state="{state}"/>
          {svc_elem}
        </port>
    """


# ---------------------------------------------------------------------------
# Basic parsing
# ---------------------------------------------------------------------------


def test_parse_single_open_port(tmp_path):
    xml = _minimal_run(_host("192.168.1.1", _port(22, state="open")))
    results = parse_nmap_xml(_write_xml(tmp_path, xml))
    assert len(results) == 1
    assert results[0].port == 22
    assert results[0].host == "192.168.1.1"
    assert results[0].protocol == "tcp"
    assert results[0].state == PortState.OPEN


def test_parse_closed_port(tmp_path):
    xml = _minimal_run(_host("10.0.0.1", _port(23, state="closed")))
    results = parse_nmap_xml(_write_xml(tmp_path, xml))
    assert results[0].state == PortState.CLOSED


def test_parse_filtered_port(tmp_path):
    xml = _minimal_run(_host("10.0.0.1", _port(25, state="filtered")))
    results = parse_nmap_xml(_write_xml(tmp_path, xml))
    assert results[0].state == PortState.FILTERED


def test_parse_open_filtered_maps_to_filtered(tmp_path):
    xml = _minimal_run(_host("10.0.0.1", _port(111, state="open|filtered")))
    results = parse_nmap_xml(_write_xml(tmp_path, xml))
    assert results[0].state == PortState.FILTERED


def test_parse_unfiltered_maps_to_open(tmp_path):
    xml = _minimal_run(_host("10.0.0.1", _port(80, state="unfiltered")))
    results = parse_nmap_xml(_write_xml(tmp_path, xml))
    assert results[0].state == PortState.OPEN


# ---------------------------------------------------------------------------
# Protocol handling
# ---------------------------------------------------------------------------


def test_udp_port_protocol(tmp_path):
    xml = _minimal_run(_host("10.0.0.1", _port(53, proto="udp", state="open")))
    results = parse_nmap_xml(_write_xml(tmp_path, xml))
    assert results[0].protocol == "udp"


def test_unknown_protocol_skipped(tmp_path):
    xml = _minimal_run(_host("10.0.0.1", """
        <port protocol="sctp" portid="9">
          <state state="open"/>
        </port>
    """))
    results = parse_nmap_xml(_write_xml(tmp_path, xml))
    assert results == []


# ---------------------------------------------------------------------------
# Service info extraction
# ---------------------------------------------------------------------------


def test_service_name_extracted(tmp_path):
    xml = _minimal_run(_host("10.0.0.1", _port(22, name="ssh")))
    results = parse_nmap_xml(_write_xml(tmp_path, xml))
    assert results[0].service_name == "ssh"


def test_service_version_combines_product_and_version(tmp_path):
    xml = _minimal_run(_host("10.0.0.1", _port(22, name="ssh", product="OpenSSH", version="8.9p1")))
    results = parse_nmap_xml(_write_xml(tmp_path, xml))
    assert results[0].service_version == "OpenSSH 8.9p1"


def test_banner_includes_extrainfo(tmp_path):
    xml = _minimal_run(_host("10.0.0.1", _port(
        22, name="ssh", product="OpenSSH", version="8.9p1",
        extrainfo="Ubuntu Linux; protocol 2.0"
    )))
    results = parse_nmap_xml(_write_xml(tmp_path, xml))
    assert "Ubuntu Linux" in results[0].banner


def test_service_version_product_only(tmp_path):
    xml = _minimal_run(_host("10.0.0.1", _port(80, name="http", product="nginx")))
    results = parse_nmap_xml(_write_xml(tmp_path, xml))
    assert results[0].service_version == "nginx"


def test_no_service_element(tmp_path):
    xml = _minimal_run(_host("10.0.0.1", _port(9999)))
    results = parse_nmap_xml(_write_xml(tmp_path, xml))
    assert results[0].service_name is None
    assert results[0].service_version is None
    assert results[0].banner is None


# ---------------------------------------------------------------------------
# Multiple ports and hosts
# ---------------------------------------------------------------------------


def test_multiple_ports(tmp_path):
    xml = _minimal_run(_host(
        "192.168.1.1",
        _port(22, state="open"),
        _port(80, state="open"),
        _port(443, state="open"),
        _port(25, state="closed"),
    ))
    results = parse_nmap_xml(_write_xml(tmp_path, xml))
    assert len(results) == 4
    ports = {r.port for r in results}
    assert ports == {22, 80, 443, 25}


def test_multiple_hosts(tmp_path):
    xml = _minimal_run(
        _host("192.168.1.1", _port(22))
        + _host("192.168.1.2", _port(80))
    )
    results = parse_nmap_xml(_write_xml(tmp_path, xml))
    assert len(results) == 2
    hosts = {r.host for r in results}
    assert hosts == {"192.168.1.1", "192.168.1.2"}


def test_empty_run_returns_empty(tmp_path):
    xml = "<?xml version='1.0'?><nmaprun scanner='nmap' version='7.93'/>"
    results = parse_nmap_xml(_write_xml(tmp_path, xml))
    assert results == []


# ---------------------------------------------------------------------------
# Down hosts
# ---------------------------------------------------------------------------


def test_down_host_skipped(tmp_path):
    xml = _minimal_run(_host("10.0.0.1", _port(22), status="down"))
    results = parse_nmap_xml(_write_xml(tmp_path, xml))
    assert results == []


def test_mixed_up_down_hosts(tmp_path):
    xml = _minimal_run(
        _host("192.168.1.1", _port(22), status="up")
        + _host("192.168.1.2", _port(80), status="down")
    )
    results = parse_nmap_xml(_write_xml(tmp_path, xml))
    assert len(results) == 1
    assert results[0].host == "192.168.1.1"


# ---------------------------------------------------------------------------
# Host without <ports>
# ---------------------------------------------------------------------------


def test_host_with_no_ports_element(tmp_path):
    xml = """\
        <?xml version="1.0"?>
        <nmaprun scanner="nmap" version="7.93">
          <host>
            <status state="up"/>
            <address addr="10.0.0.1" addrtype="ipv4"/>
          </host>
        </nmaprun>
    """
    results = parse_nmap_xml(_write_xml(tmp_path, xml))
    assert results == []


# ---------------------------------------------------------------------------
# Address fallback: IPv6, hostname
# ---------------------------------------------------------------------------


def test_ipv6_address_used_when_no_ipv4(tmp_path):
    xml = """\
        <?xml version="1.0"?>
        <nmaprun scanner="nmap" version="7.93">
          <host>
            <status state="up"/>
            <address addr="::1" addrtype="ipv6"/>
            <ports><port protocol="tcp" portid="22"><state state="open"/></port></ports>
          </host>
        </nmaprun>
    """
    results = parse_nmap_xml(_write_xml(tmp_path, xml))
    assert results[0].host == "::1"


def test_ipv4_preferred_over_ipv6(tmp_path):
    xml = """\
        <?xml version="1.0"?>
        <nmaprun scanner="nmap" version="7.93">
          <host>
            <status state="up"/>
            <address addr="::1" addrtype="ipv6"/>
            <address addr="192.168.1.1" addrtype="ipv4"/>
            <ports><port protocol="tcp" portid="22"><state state="open"/></port></ports>
          </host>
        </nmaprun>
    """
    results = parse_nmap_xml(_write_xml(tmp_path, xml))
    assert results[0].host == "192.168.1.1"


def test_hostname_used_as_last_resort(tmp_path):
    xml = """\
        <?xml version="1.0"?>
        <nmaprun scanner="nmap" version="7.93">
          <host>
            <status state="up"/>
            <hostnames><hostname name="myhost.example.com" type="PTR"/></hostnames>
            <ports><port protocol="tcp" portid="80"><state state="open"/></port></ports>
          </host>
        </nmaprun>
    """
    results = parse_nmap_xml(_write_xml(tmp_path, xml))
    assert results[0].host == "myhost.example.com"


# ---------------------------------------------------------------------------
# Port with invalid portid
# ---------------------------------------------------------------------------


def test_invalid_portid_skipped(tmp_path):
    xml = """\
        <?xml version="1.0"?>
        <nmaprun scanner="nmap" version="7.93">
          <host>
            <status state="up"/>
            <address addr="10.0.0.1" addrtype="ipv4"/>
            <ports>
              <port protocol="tcp" portid="not-a-number">
                <state state="open"/>
              </port>
              <port protocol="tcp" portid="22">
                <state state="open"/>
              </port>
            </ports>
          </host>
        </nmaprun>
    """
    results = parse_nmap_xml(_write_xml(tmp_path, xml))
    assert len(results) == 1
    assert results[0].port == 22


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


def test_file_not_found():
    with pytest.raises(FileNotFoundError):
        parse_nmap_xml("/nonexistent/scan.xml")


def test_invalid_xml(tmp_path):
    p = tmp_path / "bad.xml"
    p.write_text("this is not xml at all", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid XML"):
        parse_nmap_xml(p)


def test_wrong_root_element(tmp_path):
    p = tmp_path / "wrong.xml"
    p.write_text("<?xml version='1.0'?><notanmap/>", encoding="utf-8")
    with pytest.raises(ValueError, match="nmaprun"):
        parse_nmap_xml(p)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def test_parse_nmap_xml_in_public_api():
    import porthawk
    assert hasattr(porthawk, "parse_nmap_xml")
