from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from porthawk.cve import CVEInfo, _extract_cvss, _parse_response, clear_cache, lookup_cves


@pytest.fixture(autouse=True)
def reset_cache():
    """Each test gets a clean cache — otherwise order-dependent failures."""
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


def test_extract_cvss_v31():
    metrics = {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}
    score, severity = _extract_cvss(metrics)
    assert score == 9.8
    assert severity == "CRITICAL"


def test_extract_cvss_falls_back_to_v2():
    metrics = {
        "cvssMetricV2": [{"cvssData": {"baseScore": 7.5}, "baseSeverity": "HIGH"}]
    }
    score, severity = _extract_cvss(metrics)
    assert score == 7.5
    assert severity == "HIGH"


def test_extract_cvss_empty_metrics():
    score, severity = _extract_cvss({})
    assert score is None
    assert severity is None


def test_parse_response_returns_cve_info():
    result = _parse_response(_SAMPLE_NVD_RESPONSE, max_results=5)
    assert len(result) == 1
    cve = result[0]
    assert cve.cve_id == "CVE-2022-0543"
    assert cve.cvss_score == 10.0
    assert cve.severity == "CRITICAL"
    assert cve.published == "2022-02-18"
    assert "redis" in cve.url.lower() or "CVE-2022-0543" in cve.url


def test_parse_response_sorts_by_cvss_descending():
    response = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-LOW",
                    "descriptions": [{"lang": "en", "value": "low"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 3.0, "baseSeverity": "LOW"}}]},
                    "published": "2022-01-01",
                }
            },
            {
                "cve": {
                    "id": "CVE-HIGH",
                    "descriptions": [{"lang": "en", "value": "high"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
                    "published": "2022-01-02",
                }
            },
        ]
    }
    result = _parse_response(response, max_results=5)
    assert result[0].cve_id == "CVE-HIGH"
    assert result[1].cve_id == "CVE-LOW"


def test_parse_response_respects_max_results():
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


@pytest.mark.asyncio
async def test_lookup_cves_returns_results():
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = _SAMPLE_NVD_RESPONSE

    with patch("porthawk.cve.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value = mock_client

        result = await lookup_cves("redis")

    assert len(result) == 1
    assert result[0].cve_id == "CVE-2022-0543"


@pytest.mark.asyncio
async def test_lookup_cves_uses_cache():
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = _SAMPLE_NVD_RESPONSE

    with patch("porthawk.cve.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value = mock_client

        await lookup_cves("redis")
        await lookup_cves("redis")  # second call should hit cache

    assert mock_client.get.call_count == 1


@pytest.mark.asyncio
async def test_lookup_cves_returns_empty_on_http_error():
    with patch("porthawk.cve.httpx.AsyncClient") as mock_client_cls:
        import httpx

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(side_effect=httpx.HTTPError("connection failed"))
        mock_client_cls.return_value = mock_client

        result = await lookup_cves("ssh")

    assert result == []


@pytest.mark.asyncio
async def test_lookup_cves_empty_service_name():
    result = await lookup_cves("")
    assert result == []


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
