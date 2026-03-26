from unittest.mock import AsyncMock, patch

import pytest

import porthawk
from porthawk.api import Scanner, scan
from porthawk.exceptions import InvalidPortSpecError, InvalidTargetError
from porthawk.scanner import PortState, ScanResult


def _make_result(port: int, state: PortState = PortState.OPEN) -> ScanResult:
    return ScanResult(host="127.0.0.1", port=port, protocol="tcp", state=state)


@pytest.mark.asyncio
async def test_scan_returns_list_of_scan_results():
    mock_results = {"127.0.0.1": [_make_result(80)]}
    with patch("porthawk.api.scan_targets", new_callable=AsyncMock, return_value=mock_results):
        results = await scan("127.0.0.1", ports=[80])
    assert len(results) == 1
    assert results[0].port == 80


@pytest.mark.asyncio
async def test_scan_raises_on_bad_port_spec():
    with pytest.raises(InvalidPortSpecError):
        await scan("127.0.0.1", ports="not-valid-!!!")


@pytest.mark.asyncio
async def test_scan_raises_on_empty_target():
    with pytest.raises(InvalidTargetError):
        await scan("")


@pytest.mark.asyncio
async def test_scan_raises_on_whitespace_target():
    with pytest.raises(InvalidTargetError):
        await scan("   ")


@pytest.mark.asyncio
async def test_scan_common_preset_resolves_to_list():
    mock_results: dict = {}
    with patch("porthawk.api.scan_targets", new_callable=AsyncMock, return_value=mock_results):
        results = await scan("127.0.0.1", ports="common")
    assert results == []


@pytest.mark.asyncio
async def test_scan_excludes_closed_by_default():
    mock_results = {
        "127.0.0.1": [
            _make_result(80, PortState.OPEN),
            _make_result(81, PortState.CLOSED),
        ]
    }
    with patch("porthawk.api.scan_targets", new_callable=AsyncMock, return_value=mock_results):
        results = await scan("127.0.0.1", ports=[80, 81])
    assert all(r.state == PortState.OPEN for r in results)


@pytest.mark.asyncio
async def test_scan_include_closed_flag():
    mock_results = {
        "127.0.0.1": [
            _make_result(80, PortState.OPEN),
            _make_result(81, PortState.CLOSED),
        ]
    }
    with patch("porthawk.api.scan_targets", new_callable=AsyncMock, return_value=mock_results):
        results = await scan("127.0.0.1", ports=[80, 81], include_closed=True)
    assert len(results) == 2


@pytest.mark.asyncio
async def test_scan_results_sorted_by_port():
    mock_results = {
        "127.0.0.1": [
            _make_result(443),
            _make_result(22),
            _make_result(80),
        ]
    }
    with patch("porthawk.api.scan_targets", new_callable=AsyncMock, return_value=mock_results):
        results = await scan("127.0.0.1", ports=[22, 80, 443])
    assert [r.port for r in results] == [22, 80, 443]


@pytest.mark.asyncio
async def test_scanner_context_manager():
    mock_results = {"127.0.0.1": [_make_result(443)]}
    with patch("porthawk.api.scan_targets", new_callable=AsyncMock, return_value=mock_results):
        async with Scanner("127.0.0.1") as scanner:
            results = await scanner.scan(ports=[443])
    assert results[0].port == 443


@pytest.mark.asyncio
async def test_scanner_filters_closed_by_default():
    mock_results = {
        "127.0.0.1": [
            _make_result(80, PortState.OPEN),
            _make_result(81, PortState.CLOSED),
        ]
    }
    with patch("porthawk.api.scan_targets", new_callable=AsyncMock, return_value=mock_results):
        async with Scanner("127.0.0.1") as scanner:
            results = await scanner.scan(ports=[80, 81])
    assert all(r.state == PortState.OPEN for r in results)


@pytest.mark.asyncio
async def test_scanner_passes_timeout_to_scan():
    mock_results = {"127.0.0.1": [_make_result(22)]}
    with patch("porthawk.api.scan_targets", new_callable=AsyncMock, return_value=mock_results) as mock_st:
        async with Scanner("127.0.0.1", timeout=5.0) as scanner:
            await scanner.scan(ports=[22])
    _, kwargs = mock_st.call_args
    assert kwargs["timeout"] == 5.0


def test_public_api_exports():
    assert hasattr(porthawk, "scan")
    assert hasattr(porthawk, "Scanner")
    assert hasattr(porthawk, "ScanResult")
    assert hasattr(porthawk, "ScanReport")
    assert hasattr(porthawk, "PortState")
    assert hasattr(porthawk, "build_report")
    assert hasattr(porthawk, "PortHawkError")
    assert hasattr(porthawk, "InvalidTargetError")
    assert hasattr(porthawk, "InvalidPortSpecError")
    assert hasattr(porthawk, "ScanPermissionError")
    assert hasattr(porthawk, "ScanTimeoutError")


def test_version_accessible():
    assert porthawk.__version__ == "0.1.0"
