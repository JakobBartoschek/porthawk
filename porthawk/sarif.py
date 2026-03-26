"""SARIF 2.1.0 output for GitHub Security tab integration.

Maps open ports to SARIF findings by risk level:
  HIGH   → error   (security-severity: 8.5)
  MEDIUM → warning (security-severity: 5.5)
  LOW    → note    (security-severity: 2.0)
  None   → note    (security-severity: 1.0)

Only OPEN ports become findings. Closed/filtered aren't interesting alerts.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from porthawk.reporter import ScanReport

# One rule per risk tier. Results reference these by ruleId.
_RULES: list[dict] = [
    {
        "id": "PH001",
        "name": "HighRiskPortOpen",
        "shortDescription": {"text": "HIGH risk port is open"},
        "fullDescription": {
            "text": (
                "An open port classified as HIGH risk. Services like Telnet, FTP, "
                "rlogin, or default admin panels are attack surface. "
                "Restrict access or remove the service."
            )
        },
        "helpUri": "https://github.com/JakobBartoschek/porthawk#risk-levels",
        "properties": {"security-severity": "8.5"},
    },
    {
        "id": "PH002",
        "name": "MediumRiskPortOpen",
        "shortDescription": {"text": "MEDIUM risk port is open"},
        "fullDescription": {
            "text": (
                "An open port classified as MEDIUM risk. Review whether this "
                "service needs to be publicly reachable and confirm it is current."
            )
        },
        "helpUri": "https://github.com/JakobBartoschek/porthawk#risk-levels",
        "properties": {"security-severity": "5.5"},
    },
    {
        "id": "PH003",
        "name": "LowRiskPortOpen",
        "shortDescription": {"text": "LOW risk port is open"},
        "fullDescription": {
            "text": "An open port classified as LOW risk. Worth auditing periodically."
        },
        "helpUri": "https://github.com/JakobBartoschek/porthawk#risk-levels",
        "properties": {"security-severity": "2.0"},
    },
    {
        "id": "PH004",
        "name": "UnclassifiedPortOpen",
        "shortDescription": {"text": "Open port (no risk classification)"},
        "fullDescription": {
            "text": "An open port with no risk classification in the service database."
        },
        "helpUri": "https://github.com/JakobBartoschek/porthawk",
        "properties": {"security-severity": "1.0"},
    },
]

# risk_level string → (rule_id, sarif_level)
_RISK_TO_RULE: dict[str | None, tuple[str, str]] = {
    "HIGH": ("PH001", "error"),
    "MEDIUM": ("PH002", "warning"),
    "LOW": ("PH003", "note"),
    None: ("PH004", "note"),
}


def build_sarif(report: ScanReport, version: str = "0.0.0") -> dict:
    """Build a SARIF 2.1.0 document from a ScanReport.

    Args:
        report: ScanReport from build_report().
        version: PortHawk version string embedded in the tool metadata.

    Returns:
        SARIF 2.1.0 dict — pass through json.dumps() to write to disk.
    """
    from porthawk.scanner import PortState

    sarif_results: list[dict] = []

    for r in report.results:
        if r.state != PortState.OPEN:
            continue

        rule_id, level = _RISK_TO_RULE.get(r.risk_level, _RISK_TO_RULE[None])
        svc = r.service_name or "unknown service"
        version_note = f" {r.service_version}" if r.service_version else ""
        banner_note = f" — banner: {r.banner}" if r.banner else ""

        msg = (
            f"Port {r.port}/{r.protocol} ({svc}{version_note}) is open on {r.host}{banner_note}. "
            f"Risk: {r.risk_level or 'unclassified'}."
        )

        finding: dict = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": msg},
            "locations": [
                {
                    "logicalLocations": [
                        {
                            "name": f"{r.host}:{r.port}/{r.protocol}",
                            "decoratedName": svc,
                            "kind": "host",
                        }
                    ]
                }
            ],
        }

        # attach CVE IDs as related locations if the scan included CVE lookup
        if r.cves:
            cve_ids = [c.get("cve_id", "") for c in r.cves if c.get("cve_id")][:10]
            if cve_ids:
                finding["relatedLocations"] = [
                    {
                        "id": i + 1,
                        "message": {"text": cve_id},
                        "logicalLocations": [{"name": cve_id, "kind": "vulnerability"}],
                    }
                    for i, cve_id in enumerate(cve_ids)
                ]

        sarif_results.append(finding)

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PortHawk",
                        "version": version,
                        "informationUri": "https://github.com/JakobBartoschek/porthawk",
                        "rules": _RULES,
                    }
                },
                "results": sarif_results,
            }
        ],
    }
