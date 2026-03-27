"""Tests for porthawk.notify — webhook notification helpers."""

from unittest.mock import MagicMock, patch

from porthawk.notify import (
    _discord_payload,
    _high_risk_ports,
    _slack_payload,
    send_discord,
    send_slack,
)
from porthawk.scanner import PortState, ScanResult


def _r(
    port: int,
    state: PortState = PortState.OPEN,
    risk: str | None = "HIGH",
    service: str | None = "telnet",
    version: str | None = None,
) -> ScanResult:
    return ScanResult(
        host="10.0.0.1",
        port=port,
        protocol="tcp",
        state=state,
        risk_level=risk,
        service_name=service,
        service_version=version,
    )


def _mock_urlopen():
    """Context manager mock for urllib.request.urlopen."""
    m = MagicMock()
    m.__enter__ = lambda s: s
    m.__exit__ = MagicMock(return_value=False)
    m.read = MagicMock(return_value=b"ok")
    return m


# ---------------------------------------------------------------------------
# _high_risk_ports
# ---------------------------------------------------------------------------


class TestHighRiskPorts:
    def test_returns_only_high(self):
        results = [_r(23, risk="HIGH"), _r(80, risk="LOW"), _r(443, risk="MEDIUM")]
        assert [r.port for r in _high_risk_ports(results)] == [23]

    def test_excludes_closed(self):
        assert _high_risk_ports([_r(23, state=PortState.CLOSED, risk="HIGH")]) == []

    def test_excludes_filtered(self):
        assert _high_risk_ports([_r(23, state=PortState.FILTERED, risk="HIGH")]) == []

    def test_empty_input(self):
        assert _high_risk_ports([]) == []

    def test_multiple_high(self):
        results = [_r(23, risk="HIGH"), _r(21, risk="HIGH")]
        assert len(_high_risk_ports(results)) == 2

    def test_none_risk_excluded(self):
        # None is not HIGH — don't alert on unscored ports
        assert _high_risk_ports([_r(80, risk=None)]) == []


# ---------------------------------------------------------------------------
# _slack_payload
# ---------------------------------------------------------------------------


class TestSlackPayload:
    def test_has_blocks_key(self):
        assert "blocks" in _slack_payload("10.0.0.1", [_r(23)])

    def test_header_contains_target(self):
        payload = _slack_payload("10.0.0.1", [_r(23)])
        header_text = payload["blocks"][0]["text"]["text"]
        assert "10.0.0.1" in header_text

    def test_header_contains_count(self):
        payload = _slack_payload("10.0.0.1", [_r(23), _r(21)])
        header_text = payload["blocks"][0]["text"]["text"]
        assert "2" in header_text

    def test_body_contains_port(self):
        payload = _slack_payload("10.0.0.1", [_r(23)])
        body_text = payload["blocks"][1]["text"]["text"]
        assert "23" in body_text

    def test_body_contains_service(self):
        payload = _slack_payload("10.0.0.1", [_r(23, service="telnet")])
        body_text = payload["blocks"][1]["text"]["text"]
        assert "telnet" in body_text

    def test_body_contains_version_when_present(self):
        payload = _slack_payload("10.0.0.1", [_r(22, service="ssh", version="OpenSSH_8.9")])
        body_text = payload["blocks"][1]["text"]["text"]
        assert "OpenSSH_8.9" in body_text

    def test_body_fallback_service_unknown(self):
        payload = _slack_payload("10.0.0.1", [_r(9999, service=None)])
        body_text = payload["blocks"][1]["text"]["text"]
        assert "unknown" in body_text


# ---------------------------------------------------------------------------
# _discord_payload
# ---------------------------------------------------------------------------


class TestDiscordPayload:
    def test_has_embeds_key(self):
        assert "embeds" in _discord_payload("10.0.0.1", [_r(23)])

    def test_color_is_red(self):
        payload = _discord_payload("10.0.0.1", [_r(23)])
        assert payload["embeds"][0]["color"] == 0xEF4444

    def test_title_contains_target(self):
        payload = _discord_payload("10.0.0.1", [_r(23)])
        assert "10.0.0.1" in payload["embeds"][0]["title"]

    def test_title_contains_count(self):
        payload = _discord_payload("10.0.0.1", [_r(23), _r(21)])
        assert "2" in payload["embeds"][0]["title"]

    def test_description_contains_port(self):
        payload = _discord_payload("10.0.0.1", [_r(23)])
        assert "23" in payload["embeds"][0]["description"]

    def test_description_contains_service(self):
        payload = _discord_payload("10.0.0.1", [_r(23, service="telnet")])
        assert "telnet" in payload["embeds"][0]["description"]


# ---------------------------------------------------------------------------
# send_slack
# ---------------------------------------------------------------------------


class TestSendSlack:
    def test_no_high_risk_returns_zero_without_posting(self):
        with patch("urllib.request.urlopen") as mock_open:
            count = send_slack("https://hooks.slack.com/xxx", [_r(80, risk="LOW")], "10.0.0.1")
        assert count == 0
        mock_open.assert_not_called()

    def test_empty_input_returns_zero(self):
        with patch("urllib.request.urlopen") as mock_open:
            count = send_slack("https://hooks.slack.com/xxx", [], "10.0.0.1")
        assert count == 0
        mock_open.assert_not_called()

    def test_posts_on_high_risk(self):
        with patch("urllib.request.urlopen", return_value=_mock_urlopen()) as mock_open:
            count = send_slack("https://hooks.slack.com/xxx", [_r(23)], "10.0.0.1")
        assert count == 1
        mock_open.assert_called_once()

    def test_returns_count_of_high_ports(self):
        with patch("urllib.request.urlopen", return_value=_mock_urlopen()):
            count = send_slack("https://hooks.slack.com/xxx", [_r(23), _r(21)], "10.0.0.1")
        assert count == 2

    def test_only_one_post_even_with_mixed_risk(self):
        results = [_r(23, risk="HIGH"), _r(80, risk="LOW"), _r(443, risk="MEDIUM")]
        with patch("urllib.request.urlopen", return_value=_mock_urlopen()) as mock_open:
            send_slack("https://hooks.slack.com/xxx", results, "10.0.0.1")
        # one POST regardless of how many ports — single alert message
        mock_open.assert_called_once()


# ---------------------------------------------------------------------------
# send_discord
# ---------------------------------------------------------------------------


class TestSendDiscord:
    def test_no_high_risk_returns_zero_without_posting(self):
        with patch("urllib.request.urlopen") as mock_open:
            count = send_discord("https://discord.com/api/webhooks/xxx", [_r(80, risk="LOW")], "10.0.0.1")
        assert count == 0
        mock_open.assert_not_called()

    def test_empty_input_returns_zero(self):
        with patch("urllib.request.urlopen") as mock_open:
            count = send_discord("https://discord.com/api/webhooks/xxx", [], "10.0.0.1")
        assert count == 0
        mock_open.assert_not_called()

    def test_posts_on_high_risk(self):
        with patch("urllib.request.urlopen", return_value=_mock_urlopen()) as mock_open:
            count = send_discord("https://discord.com/api/webhooks/xxx", [_r(23)], "10.0.0.1")
        assert count == 1
        mock_open.assert_called_once()

    def test_returns_count_of_high_ports(self):
        with patch("urllib.request.urlopen", return_value=_mock_urlopen()):
            count = send_discord("https://discord.com/api/webhooks/xxx", [_r(23), _r(21)], "10.0.0.1")
        assert count == 2

    def test_only_one_post_even_with_mixed_risk(self):
        results = [_r(23, risk="HIGH"), _r(80, risk="LOW")]
        with patch("urllib.request.urlopen", return_value=_mock_urlopen()) as mock_open:
            send_discord("https://discord.com/api/webhooks/xxx", results, "10.0.0.1")
        mock_open.assert_called_once()
