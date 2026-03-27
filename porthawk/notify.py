"""Webhook alerts for HIGH-risk findings.

Supports Slack incoming webhooks and Discord webhooks.
Only fires when there are open ports rated HIGH — everything else is noise.
Uses urllib.request so there are zero extra dependencies.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from porthawk.scanner import PortState, ScanResult


def _high_risk_ports(results: list[ScanResult]) -> list[ScanResult]:
    """Open ports with HIGH risk only — nothing else is worth paging someone for."""
    return [r for r in results if r.state == PortState.OPEN and r.risk_level == "HIGH"]


def _post_json(url: str, payload: dict[str, Any]) -> None:
    """POST JSON to a webhook URL. Raises urllib.error.HTTPError on non-2xx."""
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "porthawk"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()


def _slack_payload(target: str, findings: list[ScanResult]) -> dict[str, Any]:
    """Slack Block Kit message — header with count, body with port list."""
    lines = []
    for r in findings:
        svc = r.service_name or "unknown"
        ver = f" ({r.service_version})" if r.service_version else ""
        cve_hint = f" — {len(r.cves)} CVE(s)" if r.cves else ""
        lines.append(f"• *{r.port}/{r.protocol}* {svc}{ver}{cve_hint}")

    return {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"\U0001f534 PortHawk — {len(findings)} HIGH-risk port(s) on {target}",
                },
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": "\n".join(lines)},
            },
        ]
    }


def _discord_payload(target: str, findings: list[ScanResult]) -> dict[str, Any]:
    """Discord embed — red color, port list in description."""
    lines = []
    for r in findings:
        svc = r.service_name or "unknown"
        ver = f" ({r.service_version})" if r.service_version else ""
        cve_hint = f" — {len(r.cves)} CVE(s)" if r.cves else ""
        lines.append(f"\u2022 **{r.port}/{r.protocol}** {svc}{ver}{cve_hint}")

    return {
        "embeds": [
            {
                "title": f"\U0001f534 {len(findings)} HIGH-risk port(s) on {target}",
                "description": "\n".join(lines),
                "color": 0xEF4444,
            }
        ]
    }


def send_slack(webhook_url: str, results: list[ScanResult], target: str) -> int:
    """POST HIGH-risk findings to a Slack incoming webhook.

    Returns number of HIGH-risk ports that were reported (0 = nothing sent).
    Raises urllib.error.HTTPError if Slack rejects the request.
    """
    findings = _high_risk_ports(results)
    if not findings:
        return 0
    _post_json(webhook_url, _slack_payload(target, findings))
    return len(findings)


def send_discord(webhook_url: str, results: list[ScanResult], target: str) -> int:
    """POST HIGH-risk findings to a Discord webhook.

    Returns number of HIGH-risk ports that were reported (0 = nothing sent).
    Raises urllib.error.HTTPError if Discord rejects the request.
    """
    findings = _high_risk_ports(results)
    if not findings:
        return 0
    _post_json(webhook_url, _discord_payload(target, findings))
    return len(findings)
