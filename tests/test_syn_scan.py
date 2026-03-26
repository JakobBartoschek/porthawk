"""Tests for porthawk/syn_scan.py.

All network calls are mocked — no root required, no raw sockets.
Tests cover: packet building, checksum math, response parsing, dispatch logic,
privilege checking, and the async scan wrapper.
"""

from __future__ import annotations

import socket
import struct
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from porthawk.exceptions import ScanPermissionError
from porthawk.scanner import PortState, ScanResult
from porthawk.syn_scan import (
    _TCP_RST,
    _TCP_SYN,
    _TCP_SYN_ACK,
    _build_rst_packet,
    _build_syn_packet,
    _get_source_ip,
    _has_raw_socket_privilege,
    _internet_checksum,
    _parse_response,
    _require_privileges,
    _scapy_available,
    _syn_probe,
    _tcp_checksum,
    get_syn_backend,
    syn_scan_host,
)


# ---------------------------------------------------------------------------
# Checksum math
# ---------------------------------------------------------------------------


class TestInternetChecksum:
    def test_known_value_all_zeros(self):
        # checksum of 4 zero bytes — result is 0xFFFF complement = 0xFFFF
        data = b"\x00\x00\x00\x00"
        result = _internet_checksum(data)
        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFF

    def test_odd_length_padded(self):
        # should not crash on odd-length input
        data = b"\x01\x02\x03"
        result = _internet_checksum(data)
        assert 0 <= result <= 0xFFFF

    def test_same_input_gives_same_output(self):
        data = b"\x45\x00\x00\x28\xab\xcd\x00\x00"
        assert _internet_checksum(data) == _internet_checksum(data)

    def test_verify_checksum_roundtrip(self):
        # if we include the checksum itself, the re-computed checksum should be 0
        data = b"\x08\x00"  # simple ICMP type+code
        cksum = _internet_checksum(data + b"\x00\x00")  # placeholder for checksum
        # build with checksum in place
        full = data + struct.pack("!H", cksum)
        # re-compute — result should be 0 (or 0xFFFF depending on convention)
        recomputed = _internet_checksum(full)
        assert recomputed in (0x0000, 0xFFFF)


class TestTcpChecksum:
    def test_returns_int_in_range(self):
        result = _tcp_checksum("192.168.1.1", "192.168.1.2", b"\x00" * 20)
        assert 0 <= result <= 0xFFFF

    def test_different_ips_give_different_checksums(self):
        seg = b"\x00" * 20
        c1 = _tcp_checksum("10.0.0.1", "10.0.0.2", seg)
        c2 = _tcp_checksum("10.0.0.1", "172.16.0.1", seg)
        assert c1 != c2


# ---------------------------------------------------------------------------
# Packet building
# ---------------------------------------------------------------------------


class TestBuildSynPacket:
    def test_packet_length(self):
        pkt = _build_syn_packet("192.168.1.1", "192.168.1.2", 54321, 80, 12345678)
        # IP header (20) + TCP header (20) = 40 bytes
        assert len(pkt) == 40

    def test_ip_version_and_ihl(self):
        pkt = _build_syn_packet("192.168.1.1", "192.168.1.2", 54321, 80, 12345678)
        # first byte: version=4, IHL=5 → 0x45
        assert pkt[0] == 0x45

    def test_ip_protocol_is_tcp(self):
        pkt = _build_syn_packet("192.168.1.1", "192.168.1.2", 54321, 80, 12345678)
        # IP protocol field at offset 9
        assert pkt[9] == socket.IPPROTO_TCP

    def test_dst_ip_encoded_correctly(self):
        pkt = _build_syn_packet("10.0.0.1", "10.0.0.2", 54321, 80, 12345678)
        # dst IP at bytes 16-20 in IP header
        assert pkt[16:20] == socket.inet_aton("10.0.0.2")

    def test_src_ip_encoded_correctly(self):
        pkt = _build_syn_packet("10.0.0.1", "10.0.0.2", 54321, 80, 12345678)
        assert pkt[12:16] == socket.inet_aton("10.0.0.1")

    def test_tcp_dst_port_encoded(self):
        pkt = _build_syn_packet("10.0.0.1", "10.0.0.2", 54321, 443, 12345678)
        # TCP dst port at offset 22-24 (IP header=20, TCP dst port starts at byte 2)
        tcp_dst = struct.unpack("!H", pkt[22:24])[0]
        assert tcp_dst == 443

    def test_tcp_syn_flag_set(self):
        pkt = _build_syn_packet("10.0.0.1", "10.0.0.2", 54321, 80, 12345678)
        # TCP flags at offset 33 (IP=20, TCP flags=13)
        tcp_flags = pkt[33]
        assert tcp_flags & _TCP_SYN
        assert not (tcp_flags & _TCP_RST)
        assert not (tcp_flags & _TCP_SYN_ACK == _TCP_SYN_ACK)

    def test_seq_encoded(self):
        seq = 0xDEADBEEF
        pkt = _build_syn_packet("10.0.0.1", "10.0.0.2", 54321, 80, seq)
        # TCP seq at offset 24-28
        encoded_seq = struct.unpack("!L", pkt[24:28])[0]
        assert encoded_seq == seq


class TestBuildRstPacket:
    def test_packet_length(self):
        pkt = _build_rst_packet("10.0.0.1", "10.0.0.2", 54321, 80, 999)
        assert len(pkt) == 40

    def test_rst_flag_set(self):
        pkt = _build_rst_packet("10.0.0.1", "10.0.0.2", 54321, 80, 999)
        tcp_flags = pkt[33]
        assert tcp_flags & _TCP_RST
        assert not (tcp_flags & _TCP_SYN)


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------


def _make_fake_response(src_ip: str, src_port: int, flags: int) -> bytes:
    """Build a minimal raw IP+TCP packet for testing _parse_response."""
    ip_ihl_ver = 0x45
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ip_ihl_ver, 0, 40, 0, 0, 64,
        socket.IPPROTO_TCP, 0,
        socket.inet_aton(src_ip),
        socket.inet_aton("192.168.1.1"),  # our IP (doesn't matter for parsing)
    )
    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port, 54321, 0, 0,
        (5 << 4), flags, 65535, 0, 0,
    )
    return ip_header + tcp_header


class TestParseResponse:
    def test_syn_ack_from_expected_host(self):
        pkt = _make_fake_response("10.0.0.2", 80, _TCP_SYN_ACK)
        flags = _parse_response(pkt, "10.0.0.2", 80)
        assert flags is not None
        assert flags & _TCP_SYN_ACK == _TCP_SYN_ACK

    def test_rst_from_expected_host(self):
        pkt = _make_fake_response("10.0.0.2", 80, _TCP_RST)
        flags = _parse_response(pkt, "10.0.0.2", 80)
        assert flags is not None
        assert flags & _TCP_RST

    def test_wrong_source_ip_returns_none(self):
        pkt = _make_fake_response("10.0.0.3", 80, _TCP_SYN_ACK)
        flags = _parse_response(pkt, "10.0.0.2", 80)  # looking for 10.0.0.2
        assert flags is None

    def test_wrong_source_port_returns_none(self):
        pkt = _make_fake_response("10.0.0.2", 8080, _TCP_SYN_ACK)
        flags = _parse_response(pkt, "10.0.0.2", 80)  # looking for port 80
        assert flags is None

    def test_too_short_packet_returns_none(self):
        flags = _parse_response(b"\x45\x00\x00", "10.0.0.2", 80)
        assert flags is None


# ---------------------------------------------------------------------------
# Source IP detection
# ---------------------------------------------------------------------------


class TestGetSourceIp:
    def test_returns_valid_ip_string(self):
        # patch socket to avoid actual network call
        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ("192.168.1.100", 0)
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        with patch("porthawk.syn_scan.socket.socket", return_value=mock_sock):
            ip = _get_source_ip("8.8.8.8")

        assert ip == "192.168.1.100"


# ---------------------------------------------------------------------------
# Privilege checking
# ---------------------------------------------------------------------------


class TestPrivilegeCheck:
    @patch("porthawk.syn_scan._has_raw_socket_privilege", return_value=False)
    def test_no_privilege_raises_scan_permission_error(self, mock_priv):
        with pytest.raises(ScanPermissionError):
            _require_privileges()

    @patch("porthawk.syn_scan._has_raw_socket_privilege", return_value=True)
    def test_with_privilege_does_not_raise(self, mock_priv):
        _require_privileges()  # should not raise


# ---------------------------------------------------------------------------
# Scapy availability detection
# ---------------------------------------------------------------------------


class TestScapyAvailable:
    def test_returns_bool(self):
        result = _scapy_available()
        assert isinstance(result, bool)

    def test_false_when_scapy_not_importable(self):
        with patch("importlib.util.find_spec", return_value=None):
            result = _scapy_available()
        assert result is False

    def test_true_when_scapy_importable(self):
        mock_spec = MagicMock()
        with patch("importlib.util.find_spec", return_value=mock_spec):
            result = _scapy_available()
        assert result is True


# ---------------------------------------------------------------------------
# _syn_probe dispatch
# ---------------------------------------------------------------------------


class TestSynProbeDispatch:
    @patch("porthawk.syn_scan._scapy_available", return_value=True)
    @patch("porthawk.syn_scan._syn_probe_scapy", return_value=(PortState.OPEN, 2.5))
    def test_uses_scapy_when_available(self, mock_scapy, mock_avail):
        state, latency = _syn_probe("10.0.0.1", 80, 1.0)
        mock_scapy.assert_called_once_with("10.0.0.1", 80, 1.0)
        assert state == PortState.OPEN

    @patch("porthawk.syn_scan._scapy_available", return_value=False)
    @patch("porthawk.syn_scan._IS_WINDOWS", False)
    @patch("porthawk.syn_scan._syn_probe_raw", return_value=(PortState.CLOSED, 0.8))
    def test_falls_back_to_raw_on_linux(self, mock_raw, mock_avail):
        state, latency = _syn_probe("10.0.0.1", 80, 1.0)
        mock_raw.assert_called_once_with("10.0.0.1", 80, 1.0)
        assert state == PortState.CLOSED

    @patch("porthawk.syn_scan._scapy_available", return_value=False)
    @patch("porthawk.syn_scan._IS_WINDOWS", True)
    def test_raises_on_windows_without_scapy(self, mock_avail):
        with pytest.raises(ScanPermissionError, match="Scapy"):
            _syn_probe("10.0.0.1", 80, 1.0)


# ---------------------------------------------------------------------------
# syn_scan_host — async wrapper
# ---------------------------------------------------------------------------


class TestSynScanHost:
    @pytest.mark.asyncio
    @patch("porthawk.syn_scan._require_privileges")
    @patch("porthawk.syn_scan._syn_probe", return_value=(PortState.OPEN, 1.5))
    async def test_returns_scan_results(self, mock_probe, mock_priv):
        results = await syn_scan_host("10.0.0.1", [80, 443, 22], timeout=1.0)
        assert len(results) == 3
        assert all(isinstance(r, ScanResult) for r in results)
        assert all(r.host == "10.0.0.1" for r in results)
        assert all(r.protocol == "tcp" for r in results)

    @pytest.mark.asyncio
    @patch("porthawk.syn_scan._require_privileges")
    @patch("porthawk.syn_scan._syn_probe", return_value=(PortState.OPEN, 1.5))
    async def test_result_ports_match_input(self, mock_probe, mock_priv):
        ports = [22, 80, 443]
        results = await syn_scan_host("10.0.0.1", ports, timeout=1.0)
        result_ports = sorted(r.port for r in results)
        assert result_ports == sorted(ports)

    @pytest.mark.asyncio
    @patch("porthawk.syn_scan._require_privileges")
    @patch(
        "porthawk.syn_scan._syn_probe",
        side_effect=lambda host, port, timeout: (
            (PortState.OPEN, 1.0) if port == 80
            else (PortState.CLOSED, 0.5) if port == 22
            else (PortState.FILTERED, timeout * 1000)
        ),
    )
    async def test_mixed_states(self, mock_probe, mock_priv):
        results = await syn_scan_host("10.0.0.1", [22, 80, 9999], timeout=0.5)
        by_port = {r.port: r.state for r in results}
        assert by_port[80] == PortState.OPEN
        assert by_port[22] == PortState.CLOSED
        assert by_port[9999] == PortState.FILTERED

    @pytest.mark.asyncio
    async def test_empty_ports_raises(self):
        with pytest.raises(ValueError, match="empty"):
            await syn_scan_host("10.0.0.1", [])

    @pytest.mark.asyncio
    @patch(
        "porthawk.syn_scan._require_privileges",
        side_effect=ScanPermissionError("need root"),
    )
    async def test_permission_error_propagates(self, mock_priv):
        with pytest.raises(ScanPermissionError):
            await syn_scan_host("10.0.0.1", [80])


# ---------------------------------------------------------------------------
# get_syn_backend
# ---------------------------------------------------------------------------


class TestGetSynBackend:
    def test_returns_string(self):
        result = get_syn_backend()
        assert isinstance(result, str)
        assert len(result) > 0

    @patch("porthawk.syn_scan._scapy_available", return_value=False)
    @patch("porthawk.syn_scan._IS_WINDOWS", True)
    def test_windows_without_scapy(self, mock_avail):
        result = get_syn_backend()
        assert "Windows" in result or "unavailable" in result

    @patch("porthawk.syn_scan._scapy_available", return_value=False)
    @patch("porthawk.syn_scan._IS_WINDOWS", False)
    def test_linux_without_scapy(self, mock_avail):
        result = get_syn_backend()
        assert "raw socket" in result

    @patch("porthawk.syn_scan._scapy_available", return_value=True)
    def test_with_scapy(self, mock_avail):
        with patch("importlib.metadata.version", return_value="2.5.0"):
            result = get_syn_backend()
        assert "scapy" in result.lower()


# ---------------------------------------------------------------------------
# Public API export
# ---------------------------------------------------------------------------


class TestPublicApiExport:
    def test_importable_from_porthawk(self):
        import porthawk

        assert hasattr(porthawk, "syn_scan_host")
        assert hasattr(porthawk, "get_syn_backend")

    def test_get_syn_backend_importable(self):
        import porthawk

        result = porthawk.get_syn_backend()
        assert isinstance(result, str)
