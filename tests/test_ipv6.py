"""Tests for IPv6 support across scanner.py, fingerprint.py, and udp_scan.py."""

import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from porthawk.fingerprint import _is_ipv6_address, get_ttl_via_ping, grab_http_headers
from porthawk.scanner import expand_cidr, is_ipv6


# ---------------------------------------------------------------------------
# is_ipv6 / _is_ipv6_address
# ---------------------------------------------------------------------------


class TestIsIpv6:
    def test_ipv6_loopback(self):
        assert is_ipv6("::1") is True

    def test_ipv6_full(self):
        assert is_ipv6("2001:db8::1") is True

    def test_ipv6_full_expanded(self):
        assert is_ipv6("2001:0db8:0000:0000:0000:0000:0000:0001") is True

    def test_ipv4_returns_false(self):
        assert is_ipv6("192.168.1.1") is False

    def test_hostname_returns_false(self):
        assert is_ipv6("scanme.nmap.org") is False

    def test_bracket_notation_returns_true(self):
        # [::1] → strip brackets → ::1 → IPv6
        assert is_ipv6("[::1]") is True

    def test_bracket_full_address(self):
        assert is_ipv6("[2001:db8::1]") is True

    def test_empty_string_returns_false(self):
        assert is_ipv6("") is False

    def test_fingerprint_helper_matches(self):
        # both helpers should agree
        assert _is_ipv6_address("::1") is True
        assert _is_ipv6_address("192.168.1.1") is False


# ---------------------------------------------------------------------------
# expand_cidr — IPv6 support
# ---------------------------------------------------------------------------


class TestExpandCidrIpv6:
    def test_single_ipv6_passthrough(self):
        assert expand_cidr("2001:db8::1") == ["2001:db8::1"]

    def test_ipv6_loopback_passthrough(self):
        assert expand_cidr("::1") == ["::1"]

    def test_ipv6_slash128_is_host(self):
        # /128 = exactly one host
        result = expand_cidr("2001:db8::1/128")
        assert result == ["2001:db8::1"]

    def test_ipv6_cidr_expands(self):
        # /127 has exactly 2 addresses (used for point-to-point links per RFC 6164)
        result = expand_cidr("2001:db8::/127")
        assert len(result) == 2
        assert "2001:db8::1" in result

    def test_bracket_notation_stripped(self):
        # [::1] → expand_cidr → ["::1"]
        result = expand_cidr("[::1]")
        assert result == ["::1"]

    def test_bracket_ipv4_stripped(self):
        # unusual but shouldn't crash
        result = expand_cidr("[192.168.1.1]")
        assert result == ["192.168.1.1"]

    def test_ipv4_still_works(self):
        result = expand_cidr("10.0.0.0/30")
        assert len(result) == 2
        assert "10.0.0.1" in result

    def test_hostname_still_works(self):
        result = expand_cidr("localhost")
        assert result == ["localhost"]


# ---------------------------------------------------------------------------
# UDP socket family
# ---------------------------------------------------------------------------


class TestUdpSocketFamily:
    def test_ipv6_target_uses_af_inet6(self):
        """_udp_probe_sync must use AF_INET6 for IPv6 targets."""
        from porthawk.scanner import _udp_probe_sync

        created_sockets = []

        class FakeSock:
            def __init__(self, family, type_):
                created_sockets.append(family)
                self._family = family

            def settimeout(self, t):
                pass

            def sendto(self, data, addr):
                pass

            def recvfrom(self, n):
                return b"data", ("::1", 0)

            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

        with patch("socket.socket", FakeSock):
            _udp_probe_sync("::1", 53, 0.1)

        assert socket.AF_INET6 in created_sockets

    def test_ipv4_target_uses_af_inet(self):
        from porthawk.scanner import _udp_probe_sync

        created_sockets = []

        class FakeSock:
            def __init__(self, family, type_):
                created_sockets.append(family)

            def settimeout(self, t):
                pass

            def sendto(self, data, addr):
                pass

            def recvfrom(self, n):
                return b"data", ("192.168.1.1", 0)

            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

        with patch("socket.socket", FakeSock):
            _udp_probe_sync("192.168.1.1", 53, 0.1)

        assert socket.AF_INET in created_sockets


# ---------------------------------------------------------------------------
# HTTP URL brackets for IPv6
# ---------------------------------------------------------------------------


class TestHttpUrlIpv6:
    @pytest.mark.asyncio
    async def test_ipv6_host_gets_brackets_in_url(self):
        """grab_http_headers must use [host] notation for IPv6 addresses."""
        captured_urls = []

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_):
                pass

            async def head(self, url, **kwargs):
                captured_urls.append(url)
                resp = MagicMock()
                resp.headers = {"server": "nginx"}
                resp.status_code = 200
                return resp

        with patch("httpx.AsyncClient", return_value=FakeClient()):
            await grab_http_headers("2001:db8::1", 80)

        assert captured_urls, "no URL was requested"
        assert "[2001:db8::1]" in captured_urls[0]

    @pytest.mark.asyncio
    async def test_ipv4_host_no_brackets(self):
        captured_urls = []

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_):
                pass

            async def head(self, url, **kwargs):
                captured_urls.append(url)
                resp = MagicMock()
                resp.headers = {}
                resp.status_code = 200
                return resp

        with patch("httpx.AsyncClient", return_value=FakeClient()):
            await grab_http_headers("192.168.1.1", 80)

        assert captured_urls
        assert "[" not in captured_urls[0]


# ---------------------------------------------------------------------------
# Ping command — IPv6 flag
# ---------------------------------------------------------------------------


class TestPingIpv6:
    def test_ipv6_uses_ping6_on_linux(self):
        """On non-Windows systems, IPv6 targets should use ping6."""
        import sys

        captured_cmds = []

        def fake_run(cmd, **kwargs):
            captured_cmds.append(cmd)
            m = MagicMock()
            m.stdout = b"ttl=64"
            return m

        with patch("sys.platform", "linux"), patch("subprocess.run", fake_run):
            get_ttl_via_ping("::1")

        assert captured_cmds
        assert captured_cmds[0][0] == "ping6"

    def test_ipv4_uses_plain_ping_on_linux(self):
        captured_cmds = []

        def fake_run(cmd, **kwargs):
            captured_cmds.append(cmd)
            m = MagicMock()
            m.stdout = b"ttl=64"
            return m

        with patch("sys.platform", "linux"), patch("subprocess.run", fake_run):
            get_ttl_via_ping("192.168.1.1")

        assert captured_cmds[0][0] == "ping"

    def test_ipv6_uses_dash6_on_windows(self):
        captured_cmds = []

        def fake_run(cmd, **kwargs):
            captured_cmds.append(cmd)
            m = MagicMock()
            m.stdout = b"TTL=64"
            return m

        with patch("sys.platform", "win32"), patch("subprocess.run", fake_run):
            get_ttl_via_ping("::1")

        assert "-6" in captured_cmds[0]

    def test_ipv4_uses_dash4_on_windows(self):
        captured_cmds = []

        def fake_run(cmd, **kwargs):
            captured_cmds.append(cmd)
            m = MagicMock()
            m.stdout = b"TTL=64"
            return m

        with patch("sys.platform", "win32"), patch("subprocess.run", fake_run):
            get_ttl_via_ping("192.168.1.1")

        assert "-4" in captured_cmds[0]
