"""CLI entry point — parses args, validates input, kicks off the scan.

Thin layer. Business logic belongs in scanner.py and reporter.py.
If this file grows past 200 lines, split it.
"""

import asyncio
from typing import Annotated

import typer
from rich.console import Console

from porthawk import __version__
from porthawk.cve import lookup_cves
from porthawk.fingerprint import fingerprint_port, get_ttl_via_ping, guess_os_from_ttl
from porthawk.honeypot import score_honeypot
from porthawk.predictor import get_sklearn_status, sort_ports
from porthawk.reporter import build_report, print_terminal, save_csv, save_html, save_json
from porthawk.scanner import PortState, expand_cidr, parse_port_range
from porthawk.service_db import get_service, get_top_ports
from porthawk.throttle import AdaptiveConfig
from porthawk.ui import LiveScanUI, is_interactive

app = typer.Typer(
    name="porthawk",
    help="Async port scanner for authorized security testing.",
    no_args_is_help=True,
    add_completion=False,
)

console = Console()
err_console = Console(stderr=True, style="red")

# Ports considered "common" — what you'd scan on first recon pass
_COMMON_PORT_COUNT = 100


def version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold cyan]PortHawk[/bold cyan] v{__version__}")
        raise typer.Exit()


@app.command()
def scan(
    target: Annotated[
        str,
        typer.Option("--target", "-t", help="Target IP, hostname, or CIDR (e.g. 192.168.1.0/24)"),
    ],
    ports: Annotated[
        str | None,
        typer.Option("--ports", "-p", help="Port range: '1-1024', '22,80,443', or 'common'"),
    ] = None,
    top_ports: Annotated[
        int | None, typer.Option("--top-ports", help="Scan top N most common ports")
    ] = None,
    full: Annotated[bool, typer.Option("--full", help="Scan all 65535 ports (slow)")] = False,
    common: Annotated[bool, typer.Option("--common", help="Scan top 100 common ports")] = False,
    stealth: Annotated[
        bool, typer.Option("--stealth", help="Slow scan mode: 1 thread, 3s timeout")
    ] = False,
    udp: Annotated[bool, typer.Option("--udp", help="UDP scan (requires root/admin)")] = False,
    os_detect: Annotated[bool, typer.Option("--os", help="Attempt OS detection via TTL")] = False,
    banners: Annotated[
        bool, typer.Option("--banners", help="Grab service banners from open ports")
    ] = False,
    cve: Annotated[
        bool, typer.Option("--cve", help="Look up CVEs for each open service via NVD API")
    ] = False,
    timeout: Annotated[
        float, typer.Option("--timeout", help="Connection timeout in seconds")
    ] = 1.0,
    threads: Annotated[int, typer.Option("--threads", help="Max concurrent connections")] = 500,
    output: Annotated[
        str | None,
        typer.Option("--output", "-o", help="Output formats: json,csv,html (comma-separated)"),
    ] = None,
    show_closed: Annotated[
        bool,
        typer.Option("--show-closed", help="Show closed and filtered ports in terminal output"),
    ] = False,
    no_live: Annotated[
        bool,
        typer.Option("--no-live", help="Disable live UI — use plain output (for pipes/scripts)"),
    ] = False,
    smart_order: Annotated[
        bool,
        typer.Option(
            "--smart-order",
            help="Reorder ports by predicted open probability before scanning (ML-based, needs scikit-learn)",
        ),
    ] = False,
    honeypot: Annotated[
        bool,
        typer.Option(
            "--honeypot",
            help="Score the target for honeypot likelihood after scanning",
        ),
    ] = False,
    adaptive: Annotated[
        bool,
        typer.Option(
            "--adaptive",
            help="Adaptive concurrency: starts slow, ramps up on stable networks, backs off on congestion",
        ),
    ] = False,
    version: Annotated[
        bool | None, typer.Option("--version", callback=version_callback, is_eager=True)
    ] = None,
) -> None:
    """Scan a target host or network for open ports.

    Examples:
      porthawk -t 192.168.1.1 -p 1-1024 --banners -o json,html
      porthawk -t scanme.nmap.org --common --os
      porthawk -t 10.0.0.0/24 --top-ports 100
      porthawk -t 192.168.1.1 --full --stealth
    """
    # Stealth mode overrides threads and timeout — user probably knows what they're doing
    if stealth:
        threads = 1
        timeout = 3.0
        console.print("[yellow]Stealth mode: 1 thread, 3s timeout[/yellow]")

    port_list = _resolve_port_list(ports, top_ports, full, common)
    if port_list is None:
        err_console.print("Specify ports with -p, --top-ports N, --common, or --full")
        raise typer.Exit(code=1)

    targets = expand_cidr(target)
    protocol = "udp" if udp else "tcp"

    if smart_order:
        # Quick OS ping before the scan — gives the predictor a useful context signal.
        # Especially helpful in stealth mode where port order actually matters.
        os_hint: str | None = None
        if os_detect:
            ttl = get_ttl_via_ping(targets[0], timeout=2.0)
            os_hint = guess_os_from_ttl(ttl) if ttl else None
        port_list = sort_ports(port_list, targets[0], os_hint)
        console.print(
            f"[dim]Smart order active ({get_sklearn_status()}) " f"— first 5: {port_list[:5]}[/dim]"
        )

    console.print(
        f"\n[bold cyan]PortHawk[/bold cyan] — scanning [bold]{target}[/bold] "
        f"({len(targets)} host(s), {len(port_list)} port(s), {protocol.upper()})\n"
    )

    adaptive_cfg = AdaptiveConfig() if adaptive else None

    if adaptive:
        console.print(
            f"[dim]Adaptive mode: starting at {AdaptiveConfig().initial_concurrency} concurrent, "
            f"ramping toward {threads}[/dim]"
        )

    use_live = not no_live and is_interactive()

    try:
        if use_live:
            with LiveScanUI(target, len(port_list) * len(targets), protocol) as ui:
                all_results = asyncio.run(
                    _run_scan(
                        targets,
                        port_list,
                        timeout,
                        threads,
                        udp,
                        on_result=ui.on_result,
                        adaptive_cfg=adaptive_cfg,
                    )
                )
        else:
            all_results = asyncio.run(
                _run_scan(targets, port_list, timeout, threads, udp, adaptive_cfg=adaptive_cfg)
            )
    except PermissionError as exc:
        err_console.print(f"Permission error: {exc}")
        raise typer.Exit(code=1) from exc
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(code=0) from None

    # Flatten all results across all targets for reporting
    flat_results = [r for host_results in all_results.values() for r in host_results]

    # Enrich open ports with service info, banners, OS guess
    flat_results = _enrich_results(
        flat_results, host=targets[0], banners=banners, os_detect=os_detect, timeout=timeout
    )

    if cve:
        console.print("\n[dim]Looking up CVEs via NVD API...[/dim]")
        asyncio.run(_attach_cves(flat_results))

    if honeypot:
        _print_honeypot_report(flat_results)

    report = build_report(
        target=target,
        results=flat_results,
        protocol=protocol,
        timeout=timeout,
        max_concurrent=threads,
    )

    print_terminal(report, show_closed=show_closed, show_cves=cve)
    _save_outputs(report, output)


def _resolve_port_list(
    ports: str | None,
    top_ports: int | None,
    full: bool,
    common: bool,
) -> list[int] | None:
    """Turn CLI port arguments into a concrete list of port numbers.

    Priority: --full > --top-ports > --common > -p
    Returns None if no port spec was given at all.
    """
    if full:
        return list(range(1, 65536))
    if top_ports is not None:
        if top_ports < 1 or top_ports > 65535:
            err_console = Console(stderr=True, style="red")
            err_console.print(f"--top-ports must be between 1 and 65535, got {top_ports}")
            raise typer.Exit(code=1)
        return get_top_ports(top_ports)
    if common:
        return get_top_ports(_COMMON_PORT_COUNT)
    if ports is not None:
        try:
            return parse_port_range(ports)
        except ValueError as exc:
            err_console = Console(stderr=True, style="red")
            err_console.print(f"Invalid port specification: {exc}")
            raise typer.Exit(code=1) from exc
    return None


async def _run_scan(
    targets: list[str],
    port_list: list[int],
    timeout: float,
    threads: int,
    udp: bool,
    on_result=None,
    adaptive_cfg: AdaptiveConfig | None = None,
) -> dict[str, list]:
    """Async wrapper — keeps the asyncio.run() call in main() clean."""
    from porthawk.scanner import scan_targets

    # when on_result is set (live mode), tqdm progress is disabled — the live UI takes over
    return await scan_targets(
        targets=targets,
        ports=port_list,
        timeout=timeout,
        max_concurrent=threads,
        udp=udp,
        show_progress=on_result is None,
        on_result=on_result,
        adaptive_config=adaptive_cfg,
    )


def _enrich_results(
    results: list,
    host: str,
    banners: bool,
    os_detect: bool,
    timeout: float,
) -> list:
    """Add service names, risk levels, banners, and OS guesses to open port results.

    Runs synchronously after the async scan completes — banner grabbing is I/O bound
    but we don't want to complicate the main scan loop with it.
    """
    ttl_value = None
    if os_detect:
        ttl_value = get_ttl_via_ping(host, timeout=2.0)

    enriched = []
    for result in results:
        svc = get_service(result.port, result.protocol)
        result.service_name = svc.service_name
        result.risk_level = svc.risk_level.value if svc.risk_level else None

        if os_detect and ttl_value is not None:
            result.ttl = ttl_value
            result.os_guess = guess_os_from_ttl(ttl_value)

        enriched.append(result)

    # Banner grabbing is sequential on open ports only — doing all ports would be insane
    if banners:
        open_results = [r for r in enriched if r.state == PortState.OPEN]
        if open_results:
            console.print(f"\n[dim]Grabbing banners from {len(open_results)} open port(s)...[/dim]")

            async def _grab_all() -> None:
                for r in open_results:
                    r.banner, r.service_version = await fingerprint_port(
                        r.host, r.port, timeout=timeout
                    )

            asyncio.run(_grab_all())

    return enriched


async def _attach_cves(results: list) -> None:
    """Fetch CVEs for each unique open-port service and attach them to results.

    Deduplicates by (service_name, service_version) — same version on multiple ports
    = 1 API call. Different versions of the same service get separate lookups.
    """
    open_results = [r for r in results if r.state == PortState.OPEN and r.service_name]
    seen: dict[str, list[dict]] = {}

    for r in open_results:
        # version-aware dedup key — "ssh:OpenSSH_8.9p1" and "ssh:OpenSSH_9.0" are different
        dedup_key = f"{r.service_name}:{r.service_version or ''}"
        if dedup_key not in seen:
            cves = await lookup_cves(r.service_name, service_version=r.service_version)
            seen[dedup_key] = [c.model_dump() for c in cves]
        r.cves = seen[dedup_key]


def _save_outputs(report, output: str | None) -> None:
    """Write report files based on the -o flag value."""
    if not output:
        return

    formats = [fmt.strip().lower() for fmt in output.split(",")]
    for fmt in formats:
        if fmt == "json":
            path = save_json(report)
            console.print(f"  [green]JSON:[/green] {path}")
        elif fmt == "csv":
            path = save_csv(report)
            console.print(f"  [green]CSV:[/green]  {path}")
        elif fmt == "html":
            path = save_html(report)
            console.print(f"  [green]HTML:[/green] {path}")
        else:
            console.print(f"  [yellow]Unknown format '{fmt}' — skipped[/yellow]")


def _print_honeypot_report(results: list) -> None:
    """Run the honeypot scorer and print the result to the terminal."""

    hp = score_honeypot(results)

    verdict_color = {
        "LIKELY_REAL": "green",
        "SUSPICIOUS": "yellow",
        "LIKELY_HONEYPOT": "red",
    }.get(hp.verdict, "white")

    console.print(
        f"\n[bold]Honeypot check:[/bold] score=[bold {verdict_color}]{hp.score:.2f}[/bold {verdict_color}]"
        f"  verdict=[bold {verdict_color}]{hp.verdict}[/bold {verdict_color}]"
        f"  confidence={hp.confidence}"
        f"  ({hp.open_port_count} open ports analyzed)"
    )

    if hp.indicators:
        for ind in hp.indicators:
            console.print(
                f"  [{verdict_color}]⚑[/{verdict_color}] [{ind.weight:.2f}] {ind.name}: {ind.description}"
            )
    else:
        console.print("  [dim]No honeypot indicators detected[/dim]")


def main() -> None:
    """Entry point registered in pyproject.toml."""
    app()


if __name__ == "__main__":
    main()
