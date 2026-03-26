"""Tests for the smart UDP scanner.

All network calls are mocked — no real sockets, no root required.
"""

import asyncio
import struct
from unittest.mock import MagicMock, call, patch

import pytest

from porthawk.scanner import PortState, ScanResult
from porthawk.udp_scan import (
    _DNS_PAYLOAD,
    _IKE_PAYLOAD,
    _MDNS_PAYLOAD,
    _NETBIOS_NAME,
    _NETBIOS_PAYLOAD,
    _NTP_PAYLOAD,
    _SNMP_PAYLOAD,
    _SSDP_PAYLOAD,
    _TFTP_PAYLOAD,
    _UDP_PAYLOADS,
    _UDP_TOP_PORTS,
    _extract_banner,
    _udp_probe_sync,
    _valid_dns,
    _valid_netbios,
    _valid_ntp,
    _valid_snmp,
    _valid_ssdp,
    get_udp_top_ports,
    udp_scan_host,
)


# ---------------------------------------------------------------------------
# Payload structure tests
# ---------------------------------------------------------------------------


class TestDnsPayload:
    def test_transaction_id_is_dead(self):
        assert _DNS_PAYLOAD[:2] == b"\xde\xad"

    def test_recursion_desired_flag_set(self):
        flags = struct.unpack("!H", _DNS_PAYLOAD[2:4])[0]
        assert flags & 0x0100  # RD bit

    def test_qdcount_is_one(self):
        qdcount = struct.unpack("!H", _DNS_PAYLOAD[4:6])[0]
        assert qdcount == 1

    def test_contains_google_com(self):
        assert b"\x06google\x03com\x00" in _DNS_PAYLOAD

    def test_qtype_a_record(self):
        assert _DNS_PAYLOAD[-4:-2] == b"\x00\x01"  # QTYPE A

    def test_qclass_in(self):
        assert _DNS_PAYLOAD[-2:] == b"\x00\x01"  # QCLASS IN


class TestNtpPayload:
    def test_exactly_48_bytes(self):
        assert len(_NTP_PAYLOAD) == 48

    def test_first_byte_is_client_v3(self):
        # 0x1b = 0b00011011 = LI=0, VN=3, Mode=3
        assert _NTP_PAYLOAD[0] == 0x1b

    def test_li_bits_zero(self):
        li = (_NTP_PAYLOAD[0] >> 6) & 0x03
        assert li == 0

    def test_version_is_3(self):
        vn = (_NTP_PAYLOAD[0] >> 3) & 0x07
        assert vn == 3

    def test_mode_is_client(self):
        mode = _NTP_PAYLOAD[0] & 0x07
        assert mode == 3


class TestSnmpPayload:
    def test_starts_with_sequence_tag(self):
        assert _SNMP_PAYLOAD[0] == 0x30

    def test_community_public_present(self):
        assert b"public" in _SNMP_PAYLOAD

    def test_getrequest_pdu_tag(self):
        # 0xa0 = GetRequest-PDU
        assert 0xa0 in _SNMP_PAYLOAD

    def test_sysdescr_oid_present(self):
        # OID 1.3.6.1.2.1.1.1.0 encoded
        assert bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]) in _SNMP_PAYLOAD

    def test_total_length_matches_header(self):
        # second byte is the inner length
        inner_len = _SNMP_PAYLOAD[1]
        assert len(_SNMP_PAYLOAD) == inner_len + 2  # 2 bytes for tag + length


class TestSsdpPayload:
    def test_starts_with_msearch(self):
        assert _SSDP_PAYLOAD.startswith(b"M-SEARCH * HTTP/1.1")

    def test_has_ssdp_discover_man(self):
        assert b"ssdp:discover" in _SSDP_PAYLOAD

    def test_mx_is_1(self):
        assert b"MX: 1" in _SSDP_PAYLOAD

    def test_ends_with_double_crlf(self):
        assert _SSDP_PAYLOAD.endswith(b"\r\n\r\n")


class TestNetbiosPayload:
    def test_netbios_name_is_32_bytes(self):
        assert len(_NETBIOS_NAME) == 32

    def test_starts_with_encoded_asterisk(self):
        # "*" (0x2A) → high nibble 2 + 0x41 = "C", low nibble A + 0x41 = "K"
        assert _NETBIOS_NAME[:2] == b"CK"

    def test_spaces_encoded_as_ca(self):
        # " " (0x20) → "CA"
        assert _NETBIOS_NAME[2:4] == b"CA"

    def test_qtype_is_nbstat(self):
        assert b"\x00\x21" in _NETBIOS_PAYLOAD

    def test_transaction_id_present(self):
        assert _NETBIOS_PAYLOAD[:2] == b"\x82\x28"


class TestMdnsPayload:
    def test_transaction_id_is_zero(self):
        # mDNS RFC 6762: queries MUST use transaction ID 0
        assert _MDNS_PAYLOAD[:2] == b"\x00\x00"

    def test_contains_dns_sd_name(self):
        assert b"_services" in _MDNS_PAYLOAD
        assert b"_dns-sd" in _MDNS_PAYLOAD
        assert b"_udp" in _MDNS_PAYLOAD
        assert b"local" in _MDNS_PAYLOAD

    def test_qtype_ptr(self):
        assert b"\x00\x0c" in _MDNS_PAYLOAD

    def test_qu_bit_set(self):
        # QU bit requests unicast response
        assert b"\x80\x01" in _MDNS_PAYLOAD


class TestTftpPayload:
    def test_opcode_is_rrq(self):
        opcode = struct.unpack("!H", _TFTP_PAYLOAD[:2])[0]
        assert opcode == 1  # RRQ

    def test_filename_is_motd(self):
        assert b"motd\x00" in _TFTP_PAYLOAD

    def test_mode_is_netascii(self):
        assert b"netascii\x00" in _TFTP_PAYLOAD


class TestIkePayload:
    def test_responder_spi_is_zero(self):
        # responder SPI must be 0 for the first message
        assert _IKE_PAYLOAD[8:16] == b"\x00" * 8

    def test_version_is_1_0(self):
        assert _IKE_PAYLOAD[17] == 0x10

    def test_length_field_matches_actual_length(self):
        length = struct.unpack("!I", _IKE_PAYLOAD[24:28])[0]
        assert length == len(_IKE_PAYLOAD)


# ---------------------------------------------------------------------------
# Payload registry
# ---------------------------------------------------------------------------


class TestPayloadRegistry:
    def test_port_53_has_dns_payload(self):
        assert _UDP_PAYLOADS[53] == _DNS_PAYLOAD

    def test_port_123_has_ntp_payload(self):
        assert _UDP_PAYLOADS[123] == _NTP_PAYLOAD

    def test_port_161_has_snmp_payload(self):
        assert _UDP_PAYLOADS[161] == _SNMP_PAYLOAD

    def test_port_1900_has_ssdp_payload(self):
        assert _UDP_PAYLOADS[1900] == _SSDP_PAYLOAD

    def test_port_137_has_netbios_payload(self):
        assert _UDP_PAYLOADS[137] == _NETBIOS_PAYLOAD

    def test_port_5353_has_mdns_payload(self):
        assert _UDP_PAYLOADS[5353] == _MDNS_PAYLOAD

    def test_unknown_port_not_in_registry(self):
        assert 9999 not in _UDP_PAYLOADS


# ---------------------------------------------------------------------------
# Response validators
# ---------------------------------------------------------------------------


class TestValidDns:
    def _dns_response(self, qr=1, extra_flags=0):
        flags = (qr << 15) | extra_flags
        return b"\xde\xad" + struct.pack("!H", flags) + b"\x00" * 8

    def test_valid_response_passes(self):
        assert _valid_dns(self._dns_response(qr=1))

    def test_query_packet_fails(self):
        # QR=0 is a query, not a response
        assert not _valid_dns(self._dns_response(qr=0))

    def test_too_short_fails(self):
        assert not _valid_dns(b"\xde\xad\x80\x00")  # 4 bytes, need 12

    def test_empty_fails(self):
        assert not _valid_dns(b"")


class TestValidNtp:
    def _ntp_response(self, mode=4):
        # first byte: LI=0, VN=4, Mode=mode
        first = (4 << 3) | mode
        return bytes([first]) + b"\x00" * 47

    def test_server_mode_4_passes(self):
        assert _valid_ntp(self._ntp_response(mode=4))

    def test_broadcast_mode_5_passes(self):
        assert _valid_ntp(self._ntp_response(mode=5))

    def test_client_mode_3_fails(self):
        # mode 3 is a client request, not a server response
        assert not _valid_ntp(self._ntp_response(mode=3))

    def test_too_short_fails(self):
        assert not _valid_ntp(b"\x24" + b"\x00" * 10)  # only 11 bytes


class TestValidSnmp:
    def test_sequence_start_passes(self):
        assert _valid_snmp(b"\x30" + b"\x00" * 9)

    def test_wrong_tag_fails(self):
        assert not _valid_snmp(b"\x31" + b"\x00" * 9)

    def test_too_short_fails(self):
        assert not _valid_snmp(b"\x30" * 5)

    def test_empty_fails(self):
        assert not _valid_snmp(b"")


class TestValidSsdp:
    def test_http_1_1_passes(self):
        assert _valid_ssdp(b"HTTP/1.1 200 OK\r\nSERVER: Linux\r\n")

    def test_http_1_0_passes(self):
        assert _valid_ssdp(b"HTTP/1.0 200 OK\r\n")

    def test_non_http_fails(self):
        assert not _valid_ssdp(b"RTSP/1.0 200 OK\r\n")

    def test_empty_fails(self):
        assert not _valid_ssdp(b"")


class TestValidNetbios:
    def _netbios_response(self, response_bit=1):
        flags = response_bit << 15
        return b"\x82\x28" + struct.pack("!H", flags) + b"\x00" * 8

    def test_response_flag_set_passes(self):
        assert _valid_netbios(self._netbios_response(response_bit=1))

    def test_query_flag_fails(self):
        assert not _valid_netbios(self._netbios_response(response_bit=0))

    def test_too_short_fails(self):
        assert not _valid_netbios(b"\x82\x28\x80")


# ---------------------------------------------------------------------------
# Banner extraction
# ---------------------------------------------------------------------------


class TestExtractBanner:
    def test_ntp_banner_shows_stratum(self):
        # NTP response: LI=0, VN=4, Mode=4, Stratum=2, RefID="POOL"
        data = bytes([0x24, 0x02]) + b"\x00" * 10 + b"POOL" + b"\x00" * 32
        banner = _extract_banner(123, data)
        assert banner is not None
        assert "stratum=2" in banner
        assert "POOL" in banner

    def test_snmp_banner_extracts_string(self):
        # SNMP response with a readable sysDescr somewhere in the payload
        payload = b"\x30\x20" + b"\x00" * 5 + b"Linux 5.15.0 SMP" + b"\x00" * 5
        banner = _extract_banner(161, payload)
        assert banner is not None
        assert "Linux" in banner

    def test_ssdp_banner_shows_server(self):
        data = b"HTTP/1.1 200 OK\r\nSERVER: Linux/5.15 UPnP/1.0 MiniUPnP/2.2\r\nUSN: uuid:abc\r\n"
        banner = _extract_banner(1900, data)
        assert banner is not None
        assert "SERVER" in banner or "UPnP" in banner

    def test_dns_returns_dns_string(self):
        # valid DNS response
        data = b"\xde\xad\x80\x00" + b"\x00" * 8
        banner = _extract_banner(53, data)
        assert banner == "DNS"

    def test_netbios_returns_service_name(self):
        data = b"\x82\x28\x80\x00" + b"\x00" * 8
        banner = _extract_banner(137, data)
        assert banner == "NetBIOS Name Service"

    def test_tftp_error_shows_opcode(self):
        # TFTP ERROR packet (opcode=5)
        data = struct.pack("!H", 5) + b"\x00\x01" + b"File not found\x00"
        banner = _extract_banner(69, data)
        assert banner is not None
        assert "ERROR" in banner

    def test_none_for_empty_data(self):
        assert _extract_banner(53, b"") is None

    def test_generic_port_returns_printable_text(self):
        data = b"220 ProFTPD Server ready\r\n"
        banner = _extract_banner(21, data)
        assert banner is not None
        assert "ProFTPD" in banner


# ---------------------------------------------------------------------------
# UDP probe sync — core logic
# ---------------------------------------------------------------------------


class TestUdpProbeSync:
    @patch("porthawk.udp_scan.socket.socket")
    def test_response_returns_open(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.recvfrom.return_value = (b"\x80\x00" + b"\x00" * 10, ("1.2.3.4", 1234))

        state, data = _udp_probe_sync("1.2.3.4", 53, _DNS_PAYLOAD, 1.0, 0)

        assert state == PortState.OPEN
        assert data is not None

    @patch("porthawk.udp_scan.socket.socket")
    def test_timeout_returns_filtered(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.recvfrom.side_effect = TimeoutError("timed out")

        state, data = _udp_probe_sync("1.2.3.4", 161, _SNMP_PAYLOAD, 1.0, 0)

        assert state == PortState.FILTERED
        assert data is None

    @patch("porthawk.udp_scan.socket.socket")
    def test_connection_reset_returns_closed_windows(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.recvfrom.side_effect = ConnectionResetError("ICMP unreachable")

        state, data = _udp_probe_sync("1.2.3.4", 9999, b"", 1.0, 0)

        assert state == PortState.CLOSED

    @patch("porthawk.udp_scan.socket.socket")
    def test_oserror_111_returns_closed_linux(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        err = OSError("Connection refused")
        err.errno = 111
        mock_sock.recvfrom.side_effect = err

        state, data = _udp_probe_sync("1.2.3.4", 9999, b"", 1.0, 0)

        assert state == PortState.CLOSED

    @patch("porthawk.udp_scan.socket.socket")
    def test_oserror_10054_returns_closed_windows(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        err = OSError("WSAECONNRESET")
        err.errno = 10054
        mock_sock.recvfrom.side_effect = err

        state, data = _udp_probe_sync("1.2.3.4", 9999, b"", 1.0, 0)

        assert state == PortState.CLOSED

    @patch("porthawk.udp_scan.socket.socket")
    def test_other_oserror_returns_filtered(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        err = OSError("Network unreachable")
        err.errno = 101
        mock_sock.recvfrom.side_effect = err

        state, data = _udp_probe_sync("1.2.3.4", 53, b"", 1.0, 0)

        assert state == PortState.FILTERED

    @patch("porthawk.udp_scan.socket.socket")
    def test_retry_on_timeout(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        # first attempt: timeout; second attempt: response
        mock_sock.recvfrom.side_effect = [
            TimeoutError("first timeout"),
            (b"\x80\x00" + b"\x00" * 10, ("1.2.3.4", 1234)),
        ]

        state, data = _udp_probe_sync("1.2.3.4", 53, _DNS_PAYLOAD, 1.0, retries=1)

        assert state == PortState.OPEN
        assert mock_sock_cls.call_count == 2  # two socket objects created

    @patch("porthawk.udp_scan.socket.socket")
    def test_all_retries_exhausted_returns_filtered(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.recvfrom.side_effect = TimeoutError("timed out")

        state, data = _udp_probe_sync("1.2.3.4", 53, _DNS_PAYLOAD, 1.0, retries=2)

        assert state == PortState.FILTERED
        assert mock_sock_cls.call_count == 3  # 1 initial + 2 retries

    @patch("porthawk.udp_scan.socket.socket")
    def test_socket_always_closed(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.recvfrom.side_effect = TimeoutError("timed out")

        _udp_probe_sync("1.2.3.4", 53, b"", 1.0, retries=0)

        mock_sock.close.assert_called()

    @patch("porthawk.udp_scan.socket.socket")
    def test_empty_payload_sends_null_byte(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.recvfrom.return_value = (b"response", ("1.2.3.4", 1234))

        _udp_probe_sync("1.2.3.4", 9999, b"", 1.0, 0)

        # empty payload should be replaced with a single null byte
        mock_sock.sendto.assert_called_once_with(b"\x00", ("1.2.3.4", 9999))


# ---------------------------------------------------------------------------
# Async wrapper
# ---------------------------------------------------------------------------


class TestUdpScanHost:
    def test_empty_ports_raises_value_error(self):
        with pytest.raises(ValueError):
            asyncio.run(udp_scan_host("1.2.3.4", []))

    @patch("porthawk.udp_scan._udp_probe_sync")
    def test_returns_list_of_scan_results(self, mock_probe):
        mock_probe.return_value = (PortState.OPEN, b"\x80\x00" + b"\x00" * 10)
        results = asyncio.run(udp_scan_host("1.2.3.4", [53], timeout=0.1, retries=0))
        assert isinstance(results, list)
        assert all(isinstance(r, ScanResult) for r in results)

    @patch("porthawk.udp_scan._udp_probe_sync")
    def test_all_ports_present_in_results(self, mock_probe):
        mock_probe.return_value = (PortState.FILTERED, None)
        ports = [53, 123, 161]
        results = asyncio.run(udp_scan_host("1.2.3.4", ports, timeout=0.1, retries=0))
        result_ports = {r.port for r in results}
        assert result_ports == set(ports)

    @patch("porthawk.udp_scan._udp_probe_sync")
    def test_open_port_has_state_open(self, mock_probe):
        mock_probe.return_value = (PortState.OPEN, b"\x80\x00" + b"\x00" * 10)
        results = asyncio.run(udp_scan_host("1.2.3.4", [53], timeout=0.1, retries=0))
        assert results[0].state == PortState.OPEN

    @patch("porthawk.udp_scan._udp_probe_sync")
    def test_closed_port_has_state_closed(self, mock_probe):
        mock_probe.return_value = (PortState.CLOSED, None)
        results = asyncio.run(udp_scan_host("1.2.3.4", [9999], timeout=0.1, retries=0))
        assert results[0].state == PortState.CLOSED

    @patch("porthawk.udp_scan._udp_probe_sync")
    def test_protocol_is_udp(self, mock_probe):
        mock_probe.return_value = (PortState.OPEN, b"data")
        results = asyncio.run(udp_scan_host("1.2.3.4", [53], timeout=0.1, retries=0))
        assert results[0].protocol == "udp"

    @patch("porthawk.udp_scan._udp_probe_sync")
    def test_open_port_has_banner(self, mock_probe):
        # DNS response with QR bit set
        dns_response = b"\xde\xad\x80\x00" + b"\x00" * 8
        mock_probe.return_value = (PortState.OPEN, dns_response)
        results = asyncio.run(udp_scan_host("1.2.3.4", [53], timeout=0.1, retries=0))
        assert results[0].banner is not None

    @patch("porthawk.udp_scan._udp_probe_sync")
    def test_filtered_port_has_no_banner(self, mock_probe):
        mock_probe.return_value = (PortState.FILTERED, None)
        results = asyncio.run(udp_scan_host("1.2.3.4", [53], timeout=0.1, retries=0))
        assert results[0].banner is None

    @patch("porthawk.udp_scan._udp_probe_sync")
    def test_invalid_response_marked_unvalidated(self, mock_probe):
        # Response on port 53 that doesn't pass DNS validation (QR bit not set)
        invalid_dns = b"\xde\xad\x00\x00" + b"\x00" * 8  # QR=0 means query, not response
        mock_probe.return_value = (PortState.OPEN, invalid_dns)
        results = asyncio.run(udp_scan_host("1.2.3.4", [53], timeout=0.1, retries=0))
        assert results[0].state == PortState.OPEN
        assert "unvalidated" in (results[0].banner or "")


# ---------------------------------------------------------------------------
# Top ports
# ---------------------------------------------------------------------------


class TestTopPorts:
    def test_includes_dns(self):
        assert 53 in _UDP_TOP_PORTS

    def test_includes_snmp(self):
        assert 161 in _UDP_TOP_PORTS

    def test_includes_ntp(self):
        assert 123 in _UDP_TOP_PORTS

    def test_includes_ssdp(self):
        assert 1900 in _UDP_TOP_PORTS

    def test_includes_netbios(self):
        assert 137 in _UDP_TOP_PORTS

    def test_includes_mdns(self):
        assert 5353 in _UDP_TOP_PORTS

    def test_get_top_ports_no_arg_returns_all(self):
        result = get_udp_top_ports()
        assert result == _UDP_TOP_PORTS

    def test_get_top_ports_limits_n(self):
        result = get_udp_top_ports(5)
        assert len(result) == 5

    def test_get_top_ports_returns_new_list(self):
        # modifying the returned list shouldn't affect the original
        result = get_udp_top_ports()
        result.append(99999)
        assert 99999 not in _UDP_TOP_PORTS
