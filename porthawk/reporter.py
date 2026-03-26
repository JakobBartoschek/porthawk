"""Output formatting — terminal, JSON, CSV, HTML, SARIF.

All display logic is here. scanner.py and fingerprint.py produce data,
reporter.py renders it. That boundary is intentional and should stay that way.
"""

import csv
import json
from datetime import datetime
from pathlib import Path

from jinja2 import BaseLoader, Environment
from pydantic import BaseModel
from rich import box
from rich.console import Console
from rich.table import Table

from porthawk.scanner import PortState, ScanResult
from porthawk.service_db import RiskLevel

_REPORTS_DIR = Path("reports")

_RISK_COLORS = {
    RiskLevel.HIGH: "red",
    RiskLevel.MEDIUM: "yellow",
    RiskLevel.LOW: "green",
    RiskLevel.INFO: "cyan",
}

_STATE_COLORS = {
    PortState.OPEN: "bright_green",
    PortState.CLOSED: "white dim",
    PortState.FILTERED: "yellow",
}

# Jinja2 template lives here instead of in a templates/ dir so the package is self-contained.
# If this grows past 150 lines of HTML, extract it.
_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PortHawk Scan Report — {{ metadata.target }}</title>
  <style>
    :root {
      --bg: #0d1117;
      --surface: #161b22;
      --border: #30363d;
      --text: #e6edf3;
      --text-muted: #8b949e;
      --accent: #58a6ff;
      --high: #f85149;
      --medium: #e3b341;
      --low: #3fb950;
      --info: #58a6ff;
      --open: #3fb950;
      --filtered: #e3b341;
      --closed: #8b949e;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Courier New', Courier, monospace;
      background: var(--bg);
      color: var(--text);
      padding: 2rem;
      font-size: 14px;
    }
    header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 1.5rem;
      margin-bottom: 2rem;
    }
    h1 { font-size: 2rem; color: var(--accent); letter-spacing: 2px; }
    h1 span { color: var(--text-muted); font-size: 0.9rem; display: block; margin-top: 0.25rem; }
    .meta-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }
    .meta-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 1rem;
    }
    .meta-card label { color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; }
    .meta-card p { font-size: 1.1rem; margin-top: 0.25rem; }
    table {
      width: 100%;
      border-collapse: collapse;
      background: var(--surface);
      border-radius: 6px;
      overflow: hidden;
    }
    th {
      background: #21262d;
      padding: 0.75rem 1rem;
      text-align: left;
      color: var(--text-muted);
      font-size: 0.75rem;
      text-transform: uppercase;
      cursor: pointer;
      user-select: none;
    }
    th:hover { color: var(--text); }
    td { padding: 0.6rem 1rem; border-top: 1px solid var(--border); }
    tr:hover td { background: #1c2128; }
    .state-open { color: var(--open); font-weight: bold; }
    .state-filtered { color: var(--filtered); }
    .state-closed { color: var(--closed); }
    .risk-HIGH { color: var(--high); font-weight: bold; }
    .risk-MEDIUM { color: var(--medium); }
    .risk-LOW { color: var(--low); }
    .risk-INFO { color: var(--info); }
    .banner { color: var(--text-muted); font-size: 0.85rem; font-style: italic; }
    footer {
      margin-top: 2rem;
      color: var(--text-muted);
      font-size: 0.75rem;
      text-align: center;
    }
  </style>
</head>
<body>
  <header>
    <h1>PORTHAWK <span>Async Port Scanner — Authorized Use Only</span></h1>
  </header>
  <div class="meta-grid">
    <div class="meta-card">
      <label>Target</label>
      <p>{{ metadata.target }}</p>
    </div>
    <div class="meta-card">
      <label>Scan Time</label>
      <p>{{ metadata.scan_time }}</p>
    </div>
    <div class="meta-card">
      <label>Total Ports</label>
      <p>{{ metadata.total_ports }}</p>
    </div>
    <div class="meta-card">
      <label>Open Ports</label>
      <p style="color: var(--open)">{{ metadata.open_ports }}</p>
    </div>
    <div class="meta-card">
      <label>Protocol</label>
      <p>{{ metadata.protocol }}</p>
    </div>
  </div>
  <table id="results">
    <thead>
      <tr>
        <th onclick="sortTable(0)">Port ↕</th>
        <th onclick="sortTable(1)">State ↕</th>
        <th onclick="sortTable(2)">Service ↕</th>
        <th onclick="sortTable(3)">Risk ↕</th>
        <th>Banner / Info</th>
        <th>CVEs</th>
      </tr>
    </thead>
    <tbody>
      {% for r in results %}
      <tr>
        <td>{{ r.port }}/{{ r.protocol }}</td>
        <td class="state-{{ r.state }}">{{ r.state }}</td>
        <td>{{ r.service_name or "unknown" }}</td>
        <td class="risk-{{ r.risk_level or 'INFO' }}">{{ r.risk_level or "—" }}</td>
        <td class="banner">{{ r.banner or "—" }}</td>
        <td>
          {% if r.cves %}
            {% for cve in r.cves %}
              <a href="{{ cve.url }}" target="_blank" style="color: var(--{% if cve.severity == 'CRITICAL' or cve.severity == 'HIGH' %}high{% elif cve.severity == 'MEDIUM' %}medium{% else %}low{% endif %}); display: block; font-size: 0.8rem;">
                {{ cve.cve_id }}{% if cve.cvss_score %} ({{ cve.cvss_score }}){% endif %}
              </a>
            {% endfor %}
          {% else %}
            <span style="color: var(--text-muted)">—</span>
          {% endif %}
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  <footer>
    Generated by PortHawk v{{ metadata.version }} &mdash;
    For authorized penetration testing only &mdash;
    <a href="https://github.com/JakobBartoschek/porthawk" style="color: var(--accent)">github</a>
  </footer>
  <script>
    function sortTable(col) {
      const t = document.getElementById("results");
      const rows = Array.from(t.querySelectorAll("tbody tr"));
      const asc = t.dataset.sortCol === String(col) && t.dataset.sortDir === "asc";
      rows.sort((a, b) => {
        const av = a.cells[col].textContent.trim();
        const bv = b.cells[col].textContent.trim();
        const numA = parseFloat(av), numB = parseFloat(bv);
        if (!isNaN(numA) && !isNaN(numB)) return asc ? numB - numA : numA - numB;
        return asc ? bv.localeCompare(av) : av.localeCompare(bv);
      });
      rows.forEach(r => t.querySelector("tbody").appendChild(r));
      t.dataset.sortCol = col;
      t.dataset.sortDir = asc ? "desc" : "asc";
    }
  </script>
</body>
</html>"""


class ScanMetadata(BaseModel):
    """Everything about the scan that isn't a port result."""

    target: str
    scan_time: str
    total_ports: int
    open_ports: int
    protocol: str
    version: str = "0.1.0"
    timeout: float = 1.0
    max_concurrent: int = 500


class ScanReport(BaseModel):
    """Full scan report — metadata + all results."""

    metadata: ScanMetadata
    results: list[ScanResult]

    def open_only(self) -> list[ScanResult]:
        """Filter to open ports. Caller decides whether to show closed/filtered."""
        return [r for r in self.results if r.state == PortState.OPEN]


def _ensure_reports_dir() -> Path:
    """Create ./reports/ if it doesn't exist. Returns the path."""
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    return _REPORTS_DIR


def _timestamp() -> str:
    """ISO-ish timestamp for filenames. Colons break Windows file paths."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def build_report(
    target: str,
    results: list[ScanResult],
    protocol: str = "tcp",
    timeout: float = 1.0,
    max_concurrent: int = 500,
) -> ScanReport:
    """Assemble results into a ScanReport. Call this once, then pass to any renderer.

    Args:
        target: The scanned host or CIDR range.
        results: All ScanResult objects from scanner.py.
        protocol: 'tcp' or 'udp'.
        timeout: Timeout used during scan.
        max_concurrent: Semaphore value used during scan.

    Returns:
        ScanReport ready for any reporter function.
    """
    open_count = sum(1 for r in results if r.state == PortState.OPEN)
    metadata = ScanMetadata(
        target=target,
        scan_time=datetime.now().isoformat(timespec="seconds"),
        total_ports=len(results),
        open_ports=open_count,
        protocol=protocol,
        timeout=timeout,
        max_concurrent=max_concurrent,
    )
    return ScanReport(metadata=metadata, results=results)


def print_terminal(report: ScanReport, show_closed: bool = False, show_cves: bool = False) -> None:
    """Rich-formatted terminal table. Only shows open ports by default.

    Color coding: red = HIGH risk, yellow = MEDIUM, green = LOW, cyan = INFO.

    Args:
        report: ScanReport from build_report().
        show_closed: Whether to include closed and filtered ports in output.
        show_cves: Whether to add a CVE column (only useful if CVE lookup was run).
    """
    console = Console()
    table = Table(
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold cyan",
        title=f"[bold]{report.metadata.target}[/bold] — {report.metadata.scan_time}",
    )
    table.add_column("Port", style="bold", width=10)
    table.add_column("State", width=10)
    table.add_column("Service", width=18)
    table.add_column("Risk", width=8)
    table.add_column("Banner / Info", no_wrap=False)
    if show_cves:
        table.add_column("Top CVE", no_wrap=False)

    display_results = report.results if show_closed else report.open_only()
    display_results = sorted(display_results, key=lambda r: r.port)

    for result in display_results:
        state_color = _STATE_COLORS.get(result.state, "white")
        risk_color = (
            _RISK_COLORS.get(RiskLevel(result.risk_level), "cyan") if result.risk_level else "cyan"
        )

        row = [
            f"{result.port}/{result.protocol}",
            f"[{state_color}]{result.state}[/{state_color}]",
            result.service_name or "unknown",
            f"[{risk_color}]{result.risk_level or '—'}[/{risk_color}]",
            result.banner or "",
        ]

        if show_cves:
            top_cve = result.cves[0] if result.cves else None
            if top_cve:
                score = top_cve.get("cvss_score") or "?"
                cve_id = top_cve.get("cve_id", "")
                severity = top_cve.get("severity") or ""
                sev_color = (
                    _RISK_COLORS.get(RiskLevel(severity), "cyan")
                    if severity in ("HIGH", "MEDIUM", "LOW")
                    else ("red" if severity == "CRITICAL" else "cyan")
                )
                row.append(f"[{sev_color}]{cve_id} ({score})[/{sev_color}]")
            else:
                row.append("[dim]—[/dim]")

        table.add_row(*row)

    console.print(table)
    console.print(
        f"  [dim]Open: [green]{report.metadata.open_ports}[/green] / "
        f"{report.metadata.total_ports} scanned[/dim]"
    )


def save_json(report: ScanReport, output_path: Path | None = None) -> Path:
    """Dump the full ScanReport as pretty-printed JSON.

    Args:
        report: ScanReport from build_report().
        output_path: Override default path (useful for testing).

    Returns:
        Path where the file was written.
    """
    if output_path is None:
        dest = _ensure_reports_dir() / f"scan_{_timestamp()}.json"
    else:
        dest = output_path

    dest.write_text(
        report.model_dump_json(indent=2),
        encoding="utf-8",
    )
    return dest


def save_csv(report: ScanReport, output_path: Path | None = None) -> Path:
    """Flat CSV — one row per port. Importable into Splunk, Excel, or grep.

    Args:
        report: ScanReport from build_report().
        output_path: Override default path (useful for testing).

    Returns:
        Path where the file was written.
    """
    if output_path is None:
        dest = _ensure_reports_dir() / f"scan_{_timestamp()}.csv"
    else:
        dest = output_path

    fieldnames = [
        "host",
        "port",
        "protocol",
        "state",
        "service_name",
        "risk_level",
        "banner",
        "latency_ms",
        "os_guess",
    ]

    with dest.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in sorted(report.results, key=lambda x: x.port):
            writer.writerow(
                {
                    "host": r.host,
                    "port": r.port,
                    "protocol": r.protocol,
                    "state": r.state,
                    "service_name": r.service_name or "",
                    "risk_level": r.risk_level or "",
                    "banner": r.banner or "",
                    "latency_ms": r.latency_ms or "",
                    "os_guess": r.os_guess or "",
                }
            )

    return dest


def save_sarif(report: ScanReport, output_path: Path | None = None) -> Path:
    """Write a SARIF 2.1.0 file suitable for upload to GitHub Security tab.

    Args:
        report: ScanReport from build_report().
        output_path: Override default path (useful for testing).

    Returns:
        Path where the file was written.
    """
    from porthawk import __version__
    from porthawk.sarif import build_sarif

    if output_path is None:
        dest = _ensure_reports_dir() / f"scan_{_timestamp()}.sarif"
    else:
        dest = output_path

    sarif_doc = build_sarif(report, version=__version__)
    dest.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")
    return dest


def save_html(report: ScanReport, output_path: Path | None = None) -> Path:
    """Render the full report as a self-contained HTML file with sortable table.

    Uses the embedded Jinja2 template — no external template files needed.

    Args:
        report: ScanReport from build_report().
        output_path: Override default path (useful for testing).

    Returns:
        Path where the file was written.
    """
    if output_path is None:
        dest = _ensure_reports_dir() / f"scan_{_timestamp()}.html"
    else:
        dest = output_path

    env = Environment(loader=BaseLoader(), autoescape=True)
    template = env.from_string(_HTML_TEMPLATE)

    # Pass results as dicts so Jinja2 can access .state, .risk_level as strings
    result_dicts = [r.model_dump() for r in sorted(report.results, key=lambda x: x.port)]

    html_content = template.render(
        metadata=report.metadata,
        results=result_dicts,
    )
    dest.write_text(html_content, encoding="utf-8")
    return dest
