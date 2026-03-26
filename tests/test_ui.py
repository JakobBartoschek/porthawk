"""Tests for LiveScanUI.

We don't render anything to a real terminal — just verify that on_result()
updates the internal state correctly and that the context manager cleans up.
"""

from unittest.mock import MagicMock, patch

import pytest

from porthawk.scanner import PortState, ScanResult
from porthawk.ui import LiveScanUI, is_interactive


def _result(port: int, state: PortState = PortState.OPEN, service: str = "ssh") -> ScanResult:
    return ScanResult(
        host="127.0.0.1",
        port=port,
        protocol="tcp",
        state=state,
        service_name=service,
        risk_level="MEDIUM",
    )


@pytest.fixture()
def ui_no_render():
    """LiveScanUI with Live display patched out — no terminal needed."""
    with patch("porthawk.ui.Live") as mock_live_cls:
        mock_live = MagicMock()
        mock_live_cls.return_value = mock_live
        yield LiveScanUI("127.0.0.1", total_ports=100, protocol="tcp"), mock_live


def test_open_count_increments_on_open_port(ui_no_render):
    ui, _ = ui_no_render
    assert ui._open_count == 0
    ui.on_result(_result(22, PortState.OPEN))
    ui.on_result(_result(80, PortState.OPEN))
    assert ui._open_count == 2


def test_closed_port_does_not_increment_open_count(ui_no_render):
    ui, _ = ui_no_render
    ui.on_result(_result(23, PortState.CLOSED))
    assert ui._open_count == 0


def test_filtered_port_does_not_increment_open_count(ui_no_render):
    ui, _ = ui_no_render
    ui.on_result(_result(135, PortState.FILTERED))
    assert ui._open_count == 0


def test_scanned_count_increments_for_all_states(ui_no_render):
    ui, _ = ui_no_render
    ui.on_result(_result(22, PortState.OPEN))
    ui.on_result(_result(23, PortState.CLOSED))
    ui.on_result(_result(24, PortState.FILTERED))
    assert ui._scanned == 3


def test_log_entry_added_for_open_port(ui_no_render):
    ui, _ = ui_no_render
    ui.on_result(_result(22, PortState.OPEN))
    # log should have the scan-start entry + the open port entry
    combined = " ".join(ui._log)
    assert "22" in combined


def test_log_does_not_grow_past_maxlen(ui_no_render):
    from porthawk.ui import _LOG_MAXLEN

    ui, _ = ui_no_render
    for port in range(1, _LOG_MAXLEN + 10):
        ui.on_result(_result(port, PortState.OPEN))
    assert len(ui._log) <= _LOG_MAXLEN


def test_results_table_row_added_for_open_port(ui_no_render):
    ui, _ = ui_no_render
    ui.on_result(_result(443, PortState.OPEN, "https"))
    assert ui._results_table.row_count == 1


def test_results_table_not_updated_for_closed_port(ui_no_render):
    ui, _ = ui_no_render
    ui.on_result(_result(9999, PortState.CLOSED))
    assert ui._results_table.row_count == 0


def test_context_manager_starts_and_stops_live(ui_no_render):
    ui, mock_live = ui_no_render
    with ui:
        pass
    mock_live.start.assert_called_once()
    mock_live.stop.assert_called_once()


def test_is_interactive_returns_bool():
    # just confirm it doesn't crash and returns a bool
    result = is_interactive()
    assert isinstance(result, bool)


def test_render_returns_group(ui_no_render):
    from rich.console import Group

    ui, _ = ui_no_render
    rendered = ui._render()
    assert isinstance(rendered, Group)
