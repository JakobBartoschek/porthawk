"""Tests for scanner.py — all network calls are mocked.

Zero real connections. If a test hits the network, it's wrong.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from porthawk.scanner import (
    PortState,
    ScanResult,
    expand_cidr,
    parse_port_range,
    scan_host,
    scan_tcp_port,
    scan_udp_port,
    _tcp_probe,
    _udp_probe_sync,
)


# --- ScanResult validation ---

class TestScanResultValidation:
    def test_valid_result_creates_cleanly(self):
        r = ScanResult(host="192.168.1.1", port=80, protocol="tcp", state=PortState.OPEN)
        assert r.port == 80
        assert r.state == PortState.OPEN

    def test_port_below_1_raises(self):
        with pytest.raises(Exception):  # pydantic ValidationError
            ScanResult(host="192.168.1.1", port=0, protocol="tcp", state=PortState.OPEN)

    def test_port_above_65535_raises(self):
        with pytest.raises(Exception):
            ScanResult(host="192.168.1.1", port=65536, protocol="tcp", state=PortState.OPEN)

    def test_invalid_protocol_raises(self):
        with pytest.raises(Exception):
            ScanResult(host="192.168.1.1", port=80, protocol="icmp", state=PortState.OPEN)

    def test_optional_fields_default_to_none(self):
        r = ScanResult(host="10.0.0.1", port=22, protocol="tcp", state=PortState.CLOSED)
        assert r.banner is None
        assert r.os_guess is None
        assert r.ttl is None


# --- TCP probe ---

class TestTcpProbe:
    @pytest.mark.asyncio
    async def test_open_port_returns_open_state(self):
        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", new=AsyncMock(return_value=(mock_reader, mock_writer))):
            state, latency = await _tcp_probe("192.168.1.1", 80, timeout=1.0)

        assert state == PortState.OPEN
        assert latency >= 0

    @pytest.mark.asyncio
    async def test_connection_refused_returns_closed(self):
        with patch("asyncio.open_connection", new=AsyncMock(side_effect=ConnectionRefusedError)):
            state, latency = await _tcp_probe("192.168.1.1", 9999, timeout=1.0)

        assert state == PortState.CLOSED

    @pytest.mark.asyncio
    async def test_timeout_returns_filtered(self):
        with patch("asyncio.open_connection", new=AsyncMock(side_effect=asyncio.TimeoutError)):
            state, latency = await _tcp_probe("192.168.1.1", 80, timeout=1.0)

        assert state == PortState.FILTERED

    @pytest.mark.asyncio
    async def test_oserror_returns_closed(self):
        with patch("asyncio.open_connection", new=AsyncMock(side_effect=OSError("Network unreachable"))):
            state, latency = await _tcp_probe("10.255.255.1", 80, timeout=1.0)

        assert state == PortState.CLOSED


# --- scan_tcp_port with semaphore ---

class TestScanTcpPort:
    @pytest.mark.asyncio
    async def test_open_port_returns_correct_scan_result(self):
        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        semaphore = asyncio.Semaphore(10)
        with patch("asyncio.open_connection", new=AsyncMock(return_value=(mock_reader, mock_writer))):
            result = await scan_tcp_port("10.0.0.1", 443, timeout=1.0, semaphore=semaphore)

        assert result.state == PortState.OPEN
        assert result.port == 443
        assert result.host == "10.0.0.1"
        assert result.protocol == "tcp"

    @pytest.mark.asyncio
    async def test_closed_port_returns_closed_state(self):
        semaphore = asyncio.Semaphore(10)
        with patch("asyncio.open_connection", new=AsyncMock(side_effect=ConnectionRefusedError)):
            result = await scan_tcp_port("10.0.0.1", 9999, timeout=1.0, semaphore=semaphore)

        assert result.state == PortState.CLOSED

    @pytest.mark.asyncio
    async def test_filtered_port_returns_filtered_state(self):
        semaphore = asyncio.Semaphore(10)
        with patch("asyncio.open_connection", new=AsyncMock(side_effect=asyncio.TimeoutError)):
            result = await scan_tcp_port("10.0.0.1", 8080, timeout=1.0, semaphore=semaphore)

        assert result.state == PortState.FILTERED


# --- UDP probe ---

class TestUdpProbeSync:
    def test_timeout_returns_filtered(self):
        import socket
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.recvfrom.side_effect = socket.timeout

        with patch("socket.socket", return_value=mock_sock):
            result = _udp_probe_sync("192.168.1.1", 161, timeout=1.0)

        assert result == PortState.FILTERED

    def test_connection_reset_returns_closed(self):
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.recvfrom.side_effect = ConnectionResetError

        with patch("socket.socket", return_value=mock_sock):
            result = _udp_probe_sync("192.168.1.1", 53, timeout=1.0)

        assert result == PortState.CLOSED

    def test_response_received_returns_open(self):
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.recvfrom.return_value = (b"response", ("192.168.1.1", 53))

        with patch("socket.socket", return_value=mock_sock):
            result = _udp_probe_sync("192.168.1.1", 53, timeout=1.0)

        assert result == PortState.OPEN


# --- CIDR expansion ---

class TestExpandCidr:
    def test_single_ip_passes_through(self):
        assert expand_cidr("192.168.1.1") == ["192.168.1.1"]

    def test_cidr_24_expands_to_254_hosts(self):
        hosts = expand_cidr("192.168.1.0/24")
        assert len(hosts) == 254
        assert "192.168.1.1" in hosts
        assert "192.168.1.254" in hosts
        assert "192.168.1.0" not in hosts  # network address excluded
        assert "192.168.1.255" not in hosts  # broadcast excluded

    def test_cidr_32_returns_single_host(self):
        hosts = expand_cidr("10.0.0.5/32")
        assert hosts == ["10.0.0.5"]

    def test_hostname_passes_through(self):
        assert expand_cidr("scanme.nmap.org") == ["scanme.nmap.org"]

    def test_cidr_30_returns_2_hosts(self):
        hosts = expand_cidr("10.0.0.0/30")
        assert len(hosts) == 2
        assert "10.0.0.1" in hosts
        assert "10.0.0.2" in hosts


# --- Port range parsing ---

class TestParsePortRange:
    def test_single_port(self):
        assert parse_port_range("80") == [80]

    def test_range(self):
        assert parse_port_range("1-5") == [1, 2, 3, 4, 5]

    def test_comma_separated(self):
        assert parse_port_range("22,80,443") == [22, 80, 443]

    def test_mixed(self):
        result = parse_port_range("22,80,1000-1003")
        assert result == [22, 80, 1000, 1001, 1002, 1003]

    def test_deduplication(self):
        result = parse_port_range("80,80,80")
        assert result == [80]

    def test_empty_string_raises(self):
        with pytest.raises(ValueError):
            parse_port_range("")

    def test_port_zero_raises(self):
        with pytest.raises(ValueError):
            parse_port_range("0")

    def test_port_above_65535_raises(self):
        with pytest.raises(ValueError):
            parse_port_range("65536")

    def test_invalid_range_lo_greater_than_hi_raises(self):
        with pytest.raises(ValueError):
            parse_port_range("1024-80")

    def test_non_numeric_raises(self):
        with pytest.raises(ValueError):
            parse_port_range("http")

    @pytest.mark.parametrize("spec,expected_len", [
        ("1-100", 100),
        ("1,2,3,4,5", 5),
        ("65535", 1),
    ])
    def test_parametrized_port_counts(self, spec: str, expected_len: int):
        assert len(parse_port_range(spec)) == expected_len


# --- scan_host ---

class TestScanHost:
    @pytest.mark.asyncio
    async def test_empty_port_list_raises(self):
        with pytest.raises(ValueError, match="empty"):
            await scan_host("192.168.1.1", ports=[], show_progress=False)

    @pytest.mark.asyncio
    async def test_scan_host_returns_one_result_per_port(self):
        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", new=AsyncMock(return_value=(mock_reader, mock_writer))):
            results = await scan_host(
                "192.168.1.1",
                ports=[80, 443, 22],
                timeout=1.0,
                max_concurrent=10,
                show_progress=False,
            )

        assert len(results) == 3
        assert all(isinstance(r, ScanResult) for r in results)

    @pytest.mark.asyncio
    async def test_semaphore_limits_concurrency(self):
        """Concurrency limit doesn't affect results — just throughput."""
        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", new=AsyncMock(return_value=(mock_reader, mock_writer))):
            results = await scan_host(
                "10.0.0.1",
                ports=list(range(1, 6)),
                timeout=1.0,
                max_concurrent=2,  # very low — should still work
                show_progress=False,
            )

        assert len(results) == 5

    @pytest.mark.asyncio
    async def test_scan_host_udp_mode(self):
        """scan_host with udp=True should create UDP results."""
        import socket
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.recvfrom.return_value = (b"response", ("10.0.0.1", 53))

        with patch("socket.socket", return_value=mock_sock):
            results = await scan_host(
                "10.0.0.1",
                ports=[53],
                timeout=1.0,
                max_concurrent=10,
                udp=True,
                show_progress=False,
            )

        assert len(results) == 1
        assert results[0].protocol == "udp"


# --- scan_udp_port async wrapper ---

class TestScanUdpPort:
    @pytest.mark.asyncio
    async def test_udp_port_filtered_on_timeout(self):
        """asyncio.TimeoutError in the executor → FILTERED result."""
        semaphore = asyncio.Semaphore(10)
        with patch("porthawk.scanner._udp_probe_sync", side_effect=asyncio.TimeoutError):
            # patch run_in_executor to raise TimeoutError synchronously
            pass
        # Use a side_effect on wait_for instead
        with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError):
            result = await scan_udp_port("10.0.0.1", 161, timeout=1.0, semaphore=semaphore)
        assert result.state == PortState.FILTERED
        assert result.protocol == "udp"

    @pytest.mark.asyncio
    async def test_udp_permission_error_raises(self):
        """PermissionError from raw socket bubbles up with a helpful message.

        Patch _udp_probe_sync directly — patching socket.socket on Windows/ProactorEventLoop
        causes event loop pipe errors that mask the actual PermissionError we're testing.
        """
        semaphore = asyncio.Semaphore(10)
        with patch("porthawk.scanner._udp_probe_sync", side_effect=PermissionError("Operation not permitted")):
            with pytest.raises(PermissionError, match="admin/root"):
                await scan_udp_port("10.0.0.1", 161, timeout=1.0, semaphore=semaphore)


# --- _udp_probe_sync OSError paths ---

class TestUdpProbeSyncOsError:
    def test_oserror_errno_111_returns_closed(self):
        """Linux ICMP port unreachable comes as OSError errno 111."""
        import socket
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        err = OSError()
        err.errno = 111
        mock_sock.recvfrom.side_effect = err

        with patch("socket.socket", return_value=mock_sock):
            result = _udp_probe_sync("192.168.1.1", 80, timeout=1.0)

        assert result == PortState.CLOSED

    def test_oserror_other_errno_returns_filtered(self):
        """Unknown OSError → assume filtered, not closed."""
        import socket
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        err = OSError()
        err.errno = 99  # EADDRNOTAVAIL — not an ICMP unreachable
        mock_sock.recvfrom.side_effect = err

        with patch("socket.socket", return_value=mock_sock):
            result = _udp_probe_sync("192.168.1.1", 80, timeout=1.0)

        assert result == PortState.FILTERED


# --- scan_targets ---

class TestScanTargets:
    @pytest.mark.asyncio
    async def test_scan_targets_returns_results_per_host(self):
        from porthawk.scanner import scan_targets

        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", new=AsyncMock(return_value=(mock_reader, mock_writer))):
            results = await scan_targets(
                targets=["10.0.0.1", "10.0.0.2"],
                ports=[80],
                timeout=1.0,
                max_concurrent=10,
                show_progress=False,
            )

        assert "10.0.0.1" in results
        assert "10.0.0.2" in results
        assert len(results["10.0.0.1"]) == 1
        assert len(results["10.0.0.2"]) == 1
