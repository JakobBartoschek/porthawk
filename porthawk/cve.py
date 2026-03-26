"""CVE lookup via NVD API v2.0.

Two-layer cache: in-memory (per process) and on-disk (~/.porthawk/cve_cache.json, 24h TTL).
The disk cache matters because NVD rate-limits you to 5 req/30s without an API key.
Scanning the same network twice in an hour shouldn't cost you 60 API calls.

When service_version is available (e.g., "OpenSSH_8.9p1"), we search NVD with the
specific version string instead of just the service name. "OpenSSH 8.9" returns
actually relevant CVEs. "ssh" returns everything ever published about SSH.

Set NVD_API_KEY env var to raise the limit to 50 req/30s (free at nvd.nist.gov).
"""

import asyncio
import json
import os
import re
import time
from pathlib import Path

import httpx
from pydantic import BaseModel

_NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# in-memory cache: keyword → list of CVEInfo — fastest path, per-process lifetime
_cache: dict[str, list["CVEInfo"]] = {}

# disk cache location — survives between runs, avoids re-hitting NVD rate limits
_CACHE_DIR = Path.home() / ".porthawk"
_DISK_CACHE_FILE = _CACHE_DIR / "cve_cache.json"
_DISK_CACHE_TTL = 86400  # 24 hours — CVE data doesn't change that fast

# without an API key the NVD limits you to 5 req/30s — 1.2s between calls is safe
_REQUEST_DELAY = 0.0 if os.getenv("NVD_API_KEY") else 1.2


class CVEInfo(BaseModel):
    """Single CVE entry from NVD."""

    cve_id: str
    description: str
    cvss_score: float | None = None
    severity: str | None = None  # CRITICAL, HIGH, MEDIUM, LOW
    published: str
    url: str


def _build_keyword(service_name: str, service_version: str | None) -> str:
    """Derive the most specific NVD keyword we can from service name + version.

    The goal: give NVD enough signal to return version-relevant CVEs without
    being so specific that we get zero results. Major.minor is usually the
    right granularity — CVE descriptions rarely reference patch versions.

    Examples:
      "ssh",   "OpenSSH_8.9p1"  -> "OpenSSH 8.9"
      "mysql", "8.0.33"          -> "mysql 8.0"
      "redis", "7.0.11"          -> "redis 7.0"
      "ftp",   "ProFTPD 1.3.6c" -> "ProFTPD 1.3"
      "smtp",  "SMTP/Postfix"    -> "Postfix"
      "pop3",  "POP3/Dovecot"    -> "Dovecot"
      "ssh",   None              -> "ssh"
    """
    if not service_version:
        return service_name.lower()

    # "ProFTPD 1.3.6c" -> "ProFTPD 1.3"
    space_sep = re.match(r"^([A-Za-z][A-Za-z0-9._-]+)\s+(\d+\.\d+)", service_version)
    if space_sep:
        return f"{space_sep.group(1)} {space_sep.group(2)}"

    # "OpenSSH_8.9p1" or "OpenSSH_9.0" -> "OpenSSH 8.9"
    underscore_ver = re.match(r"^([A-Za-z][A-Za-z0-9]+)_(\d+\.\d+)", service_version)
    if underscore_ver:
        return f"{underscore_ver.group(1)} {underscore_ver.group(2)}"

    # "Memcached/1.6.17" or "SMTP/Postfix" -- extract the part after slash
    slash_sep = re.match(r"^[A-Za-z0-9]+/([A-Za-z0-9._-]+)", service_version)
    if slash_sep:
        rest = slash_sep.group(1)
        ver_match = re.match(r"^(\d+\.\d+)", rest)
        if ver_match:
            # "Memcached/1.6.17" -> "memcached 1.6"
            return f"{service_name} {ver_match.group(1)}"
        # "SMTP/Postfix" -> "Postfix"
        return rest

    # bare version "7.0.11" -> combine with service name at major.minor level
    bare_ver = re.match(r"^(\d+\.\d+)", service_version)
    if bare_ver:
        return f"{service_name} {bare_ver.group(1)}"

    return service_name.lower()


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


# --- Disk cache ---


def _load_disk_cache() -> dict[str, dict]:
    """Read the on-disk cache. Returns empty dict if missing or corrupt."""
    try:
        if not _DISK_CACHE_FILE.exists():
            return {}
        with open(_DISK_CACHE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError, ValueError):
        return {}


def _save_disk_cache(disk: dict[str, dict]) -> None:
    """Write cache to disk. Silent on failure — disk cache is best-effort."""
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        with open(_DISK_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(disk, f, indent=2)
    except OSError:
        pass  # read-only fs or permission issue — fall back to in-memory only


def _disk_get(key: str) -> list[CVEInfo] | None:
    """Return cached CVEs from disk if they exist and are within TTL."""
    disk = _load_disk_cache()
    entry = disk.get(key)
    if not entry:
        return None
    if time.time() - entry.get("cached_at", 0) > _DISK_CACHE_TTL:
        return None  # stale — re-fetch from NVD
    try:
        return [CVEInfo(**item) for item in entry.get("data", [])]
    except (ValueError, TypeError, KeyError):
        return None  # corrupt entry — treat as cache miss


def _disk_put(key: str, cves: list[CVEInfo]) -> None:
    """Store CVEs in the persistent cache with the current timestamp."""
    disk = _load_disk_cache()
    disk[key] = {
        "cached_at": time.time(),
        "data": [c.model_dump() for c in cves],
    }
    _save_disk_cache(disk)


# --- Public API ---


async def lookup_cves(
    service_name: str,
    *,
    service_version: str | None = None,
    max_results: int = 5,
    api_key: str | None = None,
) -> list[CVEInfo]:
    """Fetch top CVEs for a service from NVD, using version when available.

    Hit order: in-memory -> disk cache -> NVD API.
    Returns an empty list on any network/API error — a CVE lookup failure
    should never abort a scan.

    Args:
        service_name: e.g. "redis", "ssh", "mysql"
        service_version: from ScanResult.service_version, e.g. "OpenSSH_8.9p1", "7.0.11"
        max_results: how many CVEs to return (highest CVSS first)
        api_key: NVD API key. Falls back to NVD_API_KEY env var if not set.
    """
    if not service_name:
        return []

    keyword = _build_keyword(service_name.lower().strip(), service_version)

    if keyword in _cache:
        return _cache[keyword]

    disk_result = _disk_get(keyword)
    if disk_result is not None:
        _cache[keyword] = disk_result
        return disk_result

    resolved_key = api_key or os.getenv("NVD_API_KEY")
    headers = {"apiKey": resolved_key} if resolved_key else {}

    params: dict[str, str | int] = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results * 2,  # fetch more, filter after sorting by CVSS
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

    _cache[keyword] = result
    _disk_put(keyword, result)
    return result


def clear_cache(*, include_disk: bool = False) -> None:
    """Wipe the in-memory cache. include_disk=True also removes the disk cache file."""
    _cache.clear()
    if include_disk:
        try:
            if _DISK_CACHE_FILE.exists():
                _DISK_CACHE_FILE.unlink()
        except OSError:
            pass
