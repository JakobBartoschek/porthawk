"""Rich Live UI — the interactive display that runs during a scan.

tqdm stays for non-live mode (pipes, scripts, CI). This kicks in only when
stdout is a real terminal. Falls back gracefully if rich can't render.
"""

import sys
from collections import deque
from datetime import datetime

from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from porthawk.scanner import PortState, ScanResult

# same color scheme as reporter.py — keep them in sync if you change one
_RISK_COLORS: dict[str, str] = {
    "CRITICAL": "bright_red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "INFO": "cyan",
}

# how many log lines to keep visible — more than this and it scrolls off anyway
_LOG_MAXLEN = 10


def is_interactive() -> bool:
    """Return True when stdout is a real terminal, not a pipe or file redirect.

    Checked at call time, not import time — lets tests fake a TTY if needed.
    """
    return sys.stdout.isatty()


class LiveScanUI:
    """Rich Live context manager.

    Shows a progress bar, a live-updating table of open ports, and a timestamped
    event log — all updating in real time as each port result comes in.

    Usage::

        with LiveScanUI(target, total_ports, protocol) as ui:
            results = await scan_host(..., on_result=ui.on_result)
    """

    def __init__(self, target: str, total_ports: int, protocol: str) -> None:
        self.target = target
        self.total_ports = total_ports
        self.protocol = protocol.upper()

        self._open_count = 0
        self._scanned = 0
        self._log: deque[str] = deque(maxlen=_LOG_MAXLEN)

        # separate console so the progress bar doesn't fight with Live
        self._progress = Progress(
            SpinnerColumn(),
            BarColumn(bar_width=45),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=Console(stderr=False, highlight=False),
            transient=False,
        )
        self._task_id = self._progress.add_task("scanning", total=total_ports)

        self._results_table = Table(
            box=box.SIMPLE_HEAVY,
            show_header=True,
            header_style="bold cyan",
            expand=True,
            show_edge=False,
        )
        self._results_table.add_column("Port", style="bold", width=10)
        self._results_table.add_column("State", width=10)
        self._results_table.add_column("Service", width=18)
        self._results_table.add_column("Risk", width=8)
        self._results_table.add_column("Banner / Info", no_wrap=False)

        self._live = Live(
            self._render(),
            refresh_per_second=10,
            transient=False,
        )

    def __enter__(self) -> "LiveScanUI":
        self._add_log(
            f"Scanning [bold cyan]{self.target}[/bold cyan] — "
            f"{self.total_ports} ports ({self.protocol})"
        )
        self._live.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._progress.update(self._task_id, completed=self.total_ports)
        self._add_log(
            f"Done — [bright_green]{self._open_count} open[/bright_green] "
            f"/ {self.total_ports} scanned"
        )
        self._live.update(self._render())
        self._live.refresh()
        self._live.stop()

    def on_result(self, result: ScanResult) -> None:
        """Called for each port the moment it finishes — open, closed, or filtered."""
        self._scanned += 1
        self._progress.update(self._task_id, advance=1)

        if result.state == PortState.OPEN:
            self._open_count += 1
            risk_color = _RISK_COLORS.get(result.risk_level or "INFO", "cyan")

            self._results_table.add_row(
                f"{result.port}/{result.protocol}",
                "[bright_green]open[/bright_green]",
                result.service_name or "unknown",
                f"[{risk_color}]{result.risk_level or '—'}[/{risk_color}]",
                result.banner or "",
            )
            self._add_log(
                f"[bright_green]{result.port}/{result.protocol}[/bright_green]  "
                f"[dim]{result.service_name or 'unknown'}[/dim]"
                + (
                    f"  [{risk_color}]{result.risk_level}[/{risk_color}]"
                    if result.risk_level
                    else ""
                )
            )

        self._live.update(self._render())

    def _add_log(self, message: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self._log.append(f"[dim]{ts}[/dim]  {message}")

    def _render(self) -> Group:
        header = Text(
            f"  PORTHAWK  ·  {self.target}  ·  {self.protocol}  ·  {self._open_count} open",
            style="bold cyan",
            justify="left",
        )
        log_lines = "\n".join(self._log) if self._log else "[dim]waiting...[/dim]"

        return Group(
            Panel(header, style="cyan dim", padding=(0, 1)),
            Panel(self._progress, padding=(0, 1), style="dim"),
            Panel(
                self._results_table,
                title=f"[bold]Open Ports[/bold] ({self._open_count})",
                padding=(0, 0),
            ),
            Panel(
                Text.from_markup(log_lines),
                title="Events",
                padding=(0, 1),
                style="dim",
            ),
        )
