"""CVE lookup via NVD API v2.0.

Queries https://nvd.nist.gov for CVEs related to a service name.
Results are cached in-memory so we don't hammer the API for the same service twice.

NVD rate limits: 5 req/30s without API key, 50 req/30s with one.
Set NVD_API_KEY env var to use your key and skip the inter-request delay.
"""

import asyncio
import os

import httpx
from pydantic import BaseModel

_NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# in-memory cache: service_name → list of CVEInfo
# avoids duplicate API calls when the same service appears on multiple ports
_cache: dict[str, list["CVEInfo"]] = {}

# without an API key the NVD limits you to 5 req/30s — 1s between calls is safe
_REQUEST_DELAY = 0.0 if os.getenv("NVD_API_KEY") else 1.0


class CVEInfo(BaseModel):
    """Single CVE entry from NVD."""

    cve_id: str
    description: str
    cvss_score: float | None = None
    severity: str | None = None  # CRITICAL, HIGH, MEDIUM, LOW
    published: str
    url: str


def _extract_cvss(metrics: dict) -> tuple[float | None, str | None]:
    """Pull the highest-version CVSS score available. v3.1 > v3.0 > v2."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0]["cvssData"]
            return data.get("baseScore"), data.get("baseSeverity")
    entries = metrics.get("cvssMetricV2", [])
    if entries:
        data = entries[0]["cvssData"]
        # v2 severity lives one level up from cvssData
        severity = entries[0].get("baseSeverity")
        return data.get("baseScore"), severity
    return None, None


def _parse_response(data: dict, max_results: int) -> list[CVEInfo]:
    """Turn raw NVD JSON into CVEInfo list, sorted by CVSS score descending."""
    vulns = data.get("vulnerabilities", [])
    parsed: list[CVEInfo] = []

    for item in vulns:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        # grab english description — NVD always has one but belt-and-suspenders
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available.",
        )

        score, severity = _extract_cvss(cve.get("metrics", {}))
        published = cve.get("published", "")[:10]  # trim to YYYY-MM-DD

        parsed.append(
            CVEInfo(
                cve_id=cve_id,
                description=description[:200],  # truncate so terminal doesn't explode
                cvss_score=score,
                severity=severity,
                published=published,
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            )
        )

    # highest CVSS first — most dangerous at the top
    parsed.sort(key=lambda c: c.cvss_score or 0.0, reverse=True)
    return parsed[:max_results]


async def lookup_cves(
    service_name: str,
    *,
    max_results: int = 5,
    api_key: str | None = None,
) -> list[CVEInfo]:
    """Fetch top CVEs for a service name from NVD.

    Returns an empty list on any network/API error — a failed CVE lookup
    should never abort a scan.

    Args:
        service_name: e.g. "redis", "ssh", "mysql"
        max_results: how many CVEs to return (highest CVSS first)
        api_key: NVD API key. Falls back to NVD_API_KEY env var if not set.
    """
    if not service_name:
        return []

    # normalise so "SSH" and "ssh" share a cache entry
    key = service_name.lower().strip()

    if key in _cache:
        return _cache[key]

    resolved_key = api_key or os.getenv("NVD_API_KEY")
    headers = {"apiKey": resolved_key} if resolved_key else {}

    params: dict[str, str | int] = {
        "keywordSearch": key,
        "resultsPerPage": max_results * 2,  # fetch more, filter after sorting
        "noRejected": "",
    }

    try:
        if _REQUEST_DELAY:
            await asyncio.sleep(_REQUEST_DELAY)

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(_NVD_CVE_URL, params=params, headers=headers)
            resp.raise_for_status()
            result = _parse_response(resp.json(), max_results)

    except (httpx.HTTPError, httpx.TimeoutException, KeyError, ValueError):
        # NVD down, rate limited, or malformed response — don't break the scan
        result = []

    _cache[key] = result
    return result


def clear_cache() -> None:
    """Wipe the in-memory CVE cache. Mainly useful in tests."""
    _cache.clear()
