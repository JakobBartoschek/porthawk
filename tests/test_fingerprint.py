"""Tests for fingerprint.py — no real network connections.

OS detection from TTL is deterministic so no mocking needed there.
Banner grabbing and HTTP grabs get mocked.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from porthawk.fingerprint import (
    extract_ssh_version,
    fingerprint_port,
    grab_banner,
    grab_http_headers,
    guess_os_from_ttl,
    get_ttl_via_ping,
)


# --- TTL-based OS detection ---

class TestGuessOsFromTtl:
    @pytest.mark.parametrize("ttl,expected", [
        (64, "Linux/Unix"),
        (63, "Linux/Unix"),   # 1 hop away from a Linux box
        (57, "Linux/Unix"),   # 7 hops — still under 64
        (1, "Linux/Unix"),    # edge case
        (128, "Windows"),
        (127, "Windows"),     # Windows with one routing hop (hypervisor NAT)
        (125, "Windows"),
        (65, "Windows"),      # anything between 65–128 = Windows
        (255, "Network Device (Cisco/HP)"),
        (200, "Network Device (Cisco/HP)"),
        (129, "Network Device (Cisco/HP)"),
    ])
    def test_ttl_to_os_mapping(self, ttl: int, expected: str):
        assert guess_os_from_ttl(ttl) == expected

    def test_ttl_zero_returns_unknown(self):
        assert guess_os_from_ttl(0) == "Unknown"

    def test_negative_ttl_returns_unknown(self):
        assert guess_os_from_ttl(-1) == "Unknown"


# --- SSH version extraction ---

class TestExtractSshVersion:
    def test_openssh_banner(self):
        banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        assert extract_ssh_version(banner) == "OpenSSH_8.9p1"

    def test_openssh_banner_without_comment(self):
        banner = "SSH-2.0-OpenSSH_9.0"
        assert extract_ssh_version(banner) == "OpenSSH_9.0"

    def test_cisco_ssh_banner(self):
        banner = "SSH-1.99-Cisco-1.25"
        assert extract_ssh_version(banner) == "Cisco-1.25"

    def test_non_ssh_banner_returns_none(self):
        assert extract_ssh_version("220 FTP ready") is None

    def test_empty_string_returns_none(self):
        assert extract_ssh_version("") is None

    def test_none_input_returns_none(self):
        assert extract_ssh_version(None) is None  # type: ignore[arg-type]

    def test_partial_ssh_prefix_returns_none(self):
        # "SSH-" with no protocol version — malformed banner
        assert extract_ssh_version("SSH-") is None


# --- Banner grabbing ---

class TestGrabBanner:
    @pytest.mark.asyncio
    async def test_successful_banner_grab(self):
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"220 FTP server ready\r\n")
        mock_writer = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", new=AsyncMock(return_value=(mock_reader, mock_writer))):
            result = await grab_banner("192.168.1.1", 21, timeout=2.0)

        assert result == "220 FTP server ready"

    @pytest.mark.asyncio
    async def test_connection_refused_returns_none(self):
        with patch("asyncio.open_connection", new=AsyncMock(side_effect=ConnectionRefusedError)):
            result = await grab_banner("192.168.1.1", 9999, timeout=2.0)

        assert result is None

    @pytest.mark.asyncio
    async def test_timeout_returns_none(self):
        with patch("asyncio.open_connection", new=AsyncMock(side_effect=asyncio.TimeoutError)):
            result = await grab_banner("192.168.1.1", 80, timeout=2.0)

        assert result is None

    @pytest.mark.asyncio
    async def test_empty_response_returns_none(self):
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"")
        mock_writer = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", new=AsyncMock(return_value=(mock_reader, mock_writer))):
            result = await grab_banner("192.168.1.1", 80, timeout=2.0)

        assert result is None

    @pytest.mark.asyncio
    async def test_non_utf8_bytes_decode_safely(self):
        """Binary garbage from a custom protocol shouldn't blow up."""
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"\xff\xfe\x00hello\x00")
        mock_writer = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", new=AsyncMock(return_value=(mock_reader, mock_writer))):
            result = await grab_banner("192.168.1.1", 1234, timeout=2.0)

        assert result is not None  # didn't raise


# --- HTTP header grabbing ---

class TestGrabHttpHeaders:
    @pytest.mark.asyncio
    async def test_http_server_header_extracted(self):
        mock_response = MagicMock()
        mock_response.headers = {"server": "nginx/1.24.0", "content-type": "text/html"}
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.head = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await grab_http_headers("192.168.1.1", 80, timeout=2.0)

        assert result is not None
        assert "nginx" in result

    @pytest.mark.asyncio
    async def test_https_port_uses_https_scheme(self):
        """Port 443 should trigger HTTPS even without explicit --ssl flag."""
        mock_response = MagicMock()
        mock_response.headers = {"server": "Apache"}
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.head = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client) as MockClient:
            await grab_http_headers("192.168.1.1", 443, timeout=2.0)
            # The URL passed to head() should start with https
            call_args = mock_client.head.call_args
            assert call_args[0][0].startswith("https://")

    @pytest.mark.asyncio
    async def test_connection_error_returns_none(self):
        mock_client = AsyncMock()
        mock_client.head = AsyncMock(side_effect=Exception("connection error"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await grab_http_headers("192.168.1.1", 80, timeout=2.0)

        assert result is None

    @pytest.mark.asyncio
    async def test_no_interesting_headers_returns_status_code(self):
        mock_response = MagicMock()
        mock_response.headers = {"content-type": "text/html", "date": "Wed, 01 Jan 2025 00:00:00 GMT"}
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.head = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await grab_http_headers("192.168.1.1", 80, timeout=2.0)

        assert result == "HTTP 200"


# --- TTL via ping ---

class TestGetTtlViaPing:
    def test_successful_ping_extracts_ttl(self):
        mock_result = MagicMock()
        mock_result.stdout = "Pinging 192.168.1.1 with 32 bytes of data:\nReply from 192.168.1.1: bytes=32 time=1ms TTL=128"

        with patch("subprocess.run", return_value=mock_result):
            ttl = get_ttl_via_ping("192.168.1.1")

        assert ttl == 128

    def test_ping_failure_returns_none(self):
        import subprocess
        with patch("subprocess.run", side_effect=subprocess.SubprocessError):
            ttl = get_ttl_via_ping("192.168.1.1")

        assert ttl is None

    def test_no_ttl_in_output_returns_none(self):
        mock_result = MagicMock()
        mock_result.stdout = "Request timed out."

        with patch("subprocess.run", return_value=mock_result):
            ttl = get_ttl_via_ping("192.168.1.1")

        assert ttl is None


# --- fingerprint_port (integration of the above) ---

class TestFingerprintPort:
    @pytest.mark.asyncio
    async def test_http_port_uses_http_grabber(self):
        mock_response = MagicMock()
        mock_response.headers = {"server": "nginx"}
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.head = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await fingerprint_port("192.168.1.1", 80, timeout=2.0)

        assert result is not None
        assert "nginx" in result

    @pytest.mark.asyncio
    async def test_ssh_port_returns_ssh_version(self):
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"SSH-2.0-OpenSSH_8.9p1\r\n")
        mock_writer = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", new=AsyncMock(return_value=(mock_reader, mock_writer))):
            result = await fingerprint_port("192.168.1.1", 22, timeout=2.0)

        assert result is not None
        assert "OpenSSH" in result
