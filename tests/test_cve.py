from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import porthawk.cve as cve_mod
from porthawk.cve import (
    CVEInfo,
    _build_keyword,
    _extract_cvss,
    _parse_response,
    clear_cache,
    lookup_cves,
)


@pytest.fixture(autouse=True)
def reset_cache(tmp_path, monkeypatch):
    """Each test gets a clean in-memory cache and an isolated disk cache path."""
    monkeypatch.setattr(cve_mod, "_CACHE_DIR", tmp_path)
    monkeypatch.setattr(cve_mod, "_DISK_CACHE_FILE", tmp_path / "cve_cache.json")
    clear_cache()
    yield
    clear_cache()


_SAMPLE_NVD_RESPONSE = {
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2022-0543",
                "descriptions": [
                    {"lang": "en", "value": "Lua sandbox escape in Redis via eval command."}
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}
                    ]
                },
                "published": "2022-02-18T20:15:08.000",
            }
        }
    ],
}


# --- _build_keyword ---


class TestBuildKeyword:
    def test_no_version_returns_service_name(self):
        assert _build_keyword("ssh", None) == "ssh"

    def test_openssh_underscore_version(self):
        assert _build_keyword("ssh", "OpenSSH_8.9p1") == "OpenSSH 8.9"

    def test_openssh_clean_version(self):
        assert _build_keyword("ssh", "OpenSSH_9.0") == "OpenSSH 9.0"

    def test_bare_version_combined_with_service(self):
        # Redis: service_version="7.0.11" -> "redis 7.0"
        assert _build_keyword("redis", "7.0.11") == "redis 7.0"

    def test_bare_version_mysql(self):
        assert _build_keyword("mysql", "8.0.33") == "mysql 8.0"

    def test_name_space_version_proftpd(self):
        assert _build_keyword("ftp", "ProFTPD 1.3.6c") == "ProFTPD 1.3"

    def test_name_space_version_vsftpd(self):
        assert _build_keyword("ftp", "vsftpd 3.0.5") == "vsftpd 3.0"

    def test_slash_name_postfix(self):
        # "SMTP/Postfix" -> just "Postfix" (no version to add)
        assert _build_keyword("smtp", "SMTP/Postfix") == "Postfix"

    def test_slash_name_dovecot(self):
        assert _build_keyword("pop3", "POP3/Dovecot") == "Dovecot"

    def test_slash_version_memcached(self):
        # "Memcached/1.6.17" -> "memcached 1.6"
        assert _build_keyword("memcached", "Memcached/1.6.17") == "memcached 1.6"

    def test_empty_version_falls_back_to_name(self):
        assert _build_keyword("http", "") == "http"

    def test_service_name_lowercased(self):
        assert _build_keyword("SSH", None) == "ssh"


# --- _extract_cvss ---


class TestExtractCvss:
    def test_v31_score(self):
        metrics = {
            "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]
        }
        score, severity = _extract_cvss(metrics)
        assert score == 9.8
        assert severity == "CRITICAL"

    def test_falls_back_to_v2(self):
        metrics = {
            "cvssMetricV2": [{"cvssData": {"baseScore": 7.5}, "baseSeverity": "HIGH"}]
        }
        score, severity = _extract_cvss(metrics)
        assert score == 7.5
        assert severity == "HIGH"

    def test_empty_metrics(self):
        score, severity = _extract_cvss({})
        assert score is None
        assert severity is None


# --- _parse_response ---


class TestParseResponse:
    def test_returns_cve_info(self):
        result = _parse_response(_SAMPLE_NVD_RESPONSE, max_results=5)
        assert len(result) == 1
        cve = result[0]
        assert cve.cve_id == "CVE-2022-0543"
        assert cve.cvss_score == 10.0
        assert cve.severity == "CRITICAL"
        assert cve.published == "2022-02-18"
        assert "CVE-2022-0543" in cve.url

    def test_sorts_by_cvss_descending(self):
        response = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-LOW",
                        "descriptions": [{"lang": "en", "value": "low"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 3.0, "baseSeverity": "LOW"}}
                            ]
                        },
                        "published": "2022-01-01",
                    }
                },
                {
                    "cve": {
                        "id": "CVE-HIGH",
                        "descriptions": [{"lang": "en", "value": "high"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                            ]
                        },
                        "published": "2022-01-02",
                    }
                },
            ]
        }
        result = _parse_response(response, max_results=5)
        assert result[0].cve_id == "CVE-HIGH"
        assert result[1].cve_id == "CVE-LOW"

    def test_respects_max_results(self):
        response = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": f"CVE-2022-000{i}",
                        "descriptions": [{"lang": "en", "value": "desc"}],
                        "metrics": {},
                        "published": "2022-01-01",
                    }
                }
                for i in range(10)
            ]
        }
        result = _parse_response(response, max_results=3)
        assert len(result) == 3


# --- helpers ---


def _mock_client(response_data):
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = response_data

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(return_value=mock_resp)
    return mock_client


# --- lookup_cves ---


@pytest.mark.asyncio
async def test_lookup_cves_returns_results():
    with patch("porthawk.cve.httpx.AsyncClient", return_value=_mock_client(_SAMPLE_NVD_RESPONSE)):
        result = await lookup_cves("redis")

    assert len(result) == 1
    assert result[0].cve_id == "CVE-2022-0543"


@pytest.mark.asyncio
async def test_lookup_cves_with_version_uses_specific_keyword():
    """When version is provided, the NVD query should include the version string."""
    mock_client = _mock_client(_SAMPLE_NVD_RESPONSE)

    with patch("porthawk.cve.httpx.AsyncClient", return_value=mock_client):
        await lookup_cves("ssh", service_version="OpenSSH_8.9p1")

    call_kwargs = mock_client.get.call_args
    params = call_kwargs[1]["params"]
    assert "OpenSSH" in params["keywordSearch"]
    assert "8.9" in params["keywordSearch"]


@pytest.mark.asyncio
async def test_lookup_cves_without_version_uses_service_name():
    """Without version, the NVD query should just use the service name."""
    mock_client = _mock_client(_SAMPLE_NVD_RESPONSE)

    with patch("porthawk.cve.httpx.AsyncClient", return_value=mock_client):
        await lookup_cves("redis")

    call_kwargs = mock_client.get.call_args
    params = call_kwargs[1]["params"]
    assert params["keywordSearch"] == "redis"


@pytest.mark.asyncio
async def test_lookup_cves_uses_in_memory_cache():
    mock_client = _mock_client(_SAMPLE_NVD_RESPONSE)

    with patch("porthawk.cve.httpx.AsyncClient", return_value=mock_client):
        await lookup_cves("redis")
        await lookup_cves("redis")  # second call should hit in-memory cache

    assert mock_client.get.call_count == 1


@pytest.mark.asyncio
async def test_lookup_cves_uses_disk_cache(tmp_path, monkeypatch):
    """Clearing in-memory simulates a new process — disk cache should cover it."""
    monkeypatch.setattr(cve_mod, "_CACHE_DIR", tmp_path)
    monkeypatch.setattr(cve_mod, "_DISK_CACHE_FILE", tmp_path / "cve_cache.json")

    mock_client = _mock_client(_SAMPLE_NVD_RESPONSE)

    with patch("porthawk.cve.httpx.AsyncClient", return_value=mock_client):
        result1 = await lookup_cves("redis")

    # simulate new process: clear in-memory only
    clear_cache()

    with patch("porthawk.cve.httpx.AsyncClient", return_value=mock_client):
        result2 = await lookup_cves("redis")

    # disk cache was used — NVD hit only once across both runs
    assert mock_client.get.call_count == 1
    assert len(result2) == len(result1)
    assert result2[0].cve_id == result1[0].cve_id


@pytest.mark.asyncio
async def test_disk_cache_respects_ttl(monkeypatch):
    """Stale disk cache entries should trigger a fresh NVD fetch."""
    mock_client = _mock_client(_SAMPLE_NVD_RESPONSE)

    with patch("porthawk.cve.httpx.AsyncClient", return_value=mock_client):
        await lookup_cves("redis")

    clear_cache()

    # wind the TTL back so the entry looks expired
    monkeypatch.setattr(cve_mod, "_DISK_CACHE_TTL", -1)

    with patch("porthawk.cve.httpx.AsyncClient", return_value=mock_client):
        await lookup_cves("redis")

    # stale cache forced a second NVD call
    assert mock_client.get.call_count == 2


@pytest.mark.asyncio
async def test_lookup_cves_returns_empty_on_http_error():
    import httpx

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.get = AsyncMock(side_effect=httpx.HTTPError("connection failed"))

    with patch("porthawk.cve.httpx.AsyncClient", return_value=mock_client):
        result = await lookup_cves("ssh")

    assert result == []


@pytest.mark.asyncio
async def test_lookup_cves_empty_service_name():
    result = await lookup_cves("")
    assert result == []


@pytest.mark.asyncio
async def test_different_versions_get_separate_lookups():
    """OpenSSH 8.9 and OpenSSH 9.0 should trigger separate NVD queries."""
    mock_client = _mock_client(_SAMPLE_NVD_RESPONSE)

    with patch("porthawk.cve.httpx.AsyncClient", return_value=mock_client):
        await lookup_cves("ssh", service_version="OpenSSH_8.9p1")
        await lookup_cves("ssh", service_version="OpenSSH_9.0")

    assert mock_client.get.call_count == 2


@pytest.mark.asyncio
async def test_same_version_same_service_cached():
    """Same (service, version) pair on multiple ports = 1 NVD call."""
    mock_client = _mock_client(_SAMPLE_NVD_RESPONSE)

    with patch("porthawk.cve.httpx.AsyncClient", return_value=mock_client):
        await lookup_cves("ssh", service_version="OpenSSH_8.9p1")
        await lookup_cves("ssh", service_version="OpenSSH_8.9p1")

    assert mock_client.get.call_count == 1


def test_cve_info_model():
    cve = CVEInfo(
        cve_id="CVE-2023-1234",
        description="Test vulnerability",
        cvss_score=8.5,
        severity="HIGH",
        published="2023-06-01",
        url="https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
    )
    assert cve.cve_id == "CVE-2023-1234"
    assert cve.cvss_score == 8.5


def test_clear_cache_with_disk(tmp_path, monkeypatch):
    """include_disk=True should remove the cache file."""
    cache_file = tmp_path / "cve_cache.json"
    cache_file.write_text("{}")
    monkeypatch.setattr(cve_mod, "_DISK_CACHE_FILE", cache_file)

    assert cache_file.exists()
    clear_cache(include_disk=True)
    assert not cache_file.exists()
