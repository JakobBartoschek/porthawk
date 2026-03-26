"""Core async scanner — TCP connect and UDP probe logic.

Everything that touches the network lives here.
fingerprint.py and reporter.py both consume ScanResult but never produce it.
"""

import asyncio
import ipaddress
import socket
import time
from collections.abc import Callable
from enum import Enum

from pydantic import BaseModel, field_validator
from tqdm.asyncio import tqdm as async_tqdm


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class ScanResult(BaseModel):
    """One port on one host. All enrichment (banner, OS, service) is optional."""

    host: str
    port: int
    protocol: str  # "tcp" or "udp"
    state: PortState
    banner: str | None = None
    service_name: str | None = None
    risk_level: str | None = None
    os_guess: str | None = None
    ttl: int | None = None
    latency_ms: float | None = None
    cves: list[dict] = []

    @field_validator("port")
    @classmethod
    def port_must_be_valid(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError(f"Port {v} is out of range 1–65535")
        return v

    @field_validator("protocol")
    @classmethod
    def protocol_must_be_tcp_or_udp(cls, v: str) -> str:
        if v not in ("tcp", "udp"):
            raise ValueError(f"Protocol must be 'tcp' or 'udp', got: {v}")
        return v


async def _tcp_probe(host: str, port: int, timeout: float) -> tuple[PortState, float]:
    """Raw TCP connect probe. Returns state + latency in milliseconds.

    asyncio.TimeoutError → FILTERED (firewall silently dropping)
    ConnectionRefusedError → CLOSED (RST received)
    OSError → CLOSED (network unreachable, etc.)
    """
    t_start = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        elapsed_ms = (time.monotonic() - t_start) * 1000
        writer.close()
        await writer.wait_closed()
        return PortState.OPEN, round(elapsed_ms, 2)
    except asyncio.TimeoutError:
        return PortState.FILTERED, round(timeout * 1000, 2)
    except (ConnectionRefusedError, OSError):
        elapsed_ms = (time.monotonic() - t_start) * 1000
        return PortState.CLOSED, round(elapsed_ms, 2)


async def scan_tcp_port(
    host: str,
    port: int,
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> ScanResult:
    """Scan one TCP port. Semaphore keeps us from opening 50k connections at once."""
    async with semaphore:
        state, latency = await _tcp_probe(host, port, timeout)
        return ScanResult(
            host=host,
            port=port,
            protocol="tcp",
            state=state,
            latency_ms=latency,
        )


def _udp_probe_sync(host: str, port: int, timeout: float) -> PortState:
    """Synchronous UDP probe — must run in an executor thread, not the event loop.

    On Linux: ICMP port unreachable triggers OSError errno 111.
    On Windows: ConnectionResetError is the ICMP unreachable equivalent.
    No response after timeout = could be open or firewalled, so FILTERED.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(b"\x00", (host, port))  # empty byte triggers ICMP faster than nothing
            sock.recvfrom(1024)
            return PortState.OPEN
        except TimeoutError:
            return PortState.FILTERED
        except ConnectionResetError:
            # Windows ICMP unreachable shows up as this
            return PortState.CLOSED
        except OSError as exc:
            # Linux ICMP port unreachable: errno 111 (ECONNREFUSED)
            if exc.errno in (111, 10054):
                return PortState.CLOSED
            return PortState.FILTERED


async def scan_udp_port(
    host: str,
    port: int,
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> ScanResult:
    """UDP scan. Requires root on Linux or admin on Windows — raises PermissionError otherwise."""
    async with semaphore:
        loop = asyncio.get_running_loop()
        try:
            state = await asyncio.wait_for(
                loop.run_in_executor(None, _udp_probe_sync, host, port, timeout),
                timeout=timeout + 1.0,
            )
            return ScanResult(host=host, port=port, protocol="udp", state=state)
        except asyncio.TimeoutError:
            return ScanResult(host=host, port=port, protocol="udp", state=PortState.FILTERED)
        except PermissionError as exc:
            raise PermissionError(
                "UDP scanning needs admin/root privileges. "
                "Run as Administrator (Windows) or with sudo (Linux/macOS)."
            ) from exc


def expand_cidr(target: str) -> list[str]:
    """Expand 192.168.1.0/24 into individual host IPs. Single IPs and hostnames pass through.

    strict=False so 192.168.1.5/24 doesn't raise ValueError — it just uses the network.
    """
    try:
        network = ipaddress.ip_network(target, strict=False)
        hosts = list(network.hosts())
        if not hosts:
            # /32 has no "hosts()" — it IS the host
            return [str(network.network_address)]
        return [str(ip) for ip in hosts]
    except ValueError:
        # Not a CIDR block — treat as hostname or bare IP
        return [target]


def parse_port_range(port_spec: str) -> list[int]:
    """Parse '22,80,443', '1-1024', or '22,80,1000-2000' into a sorted port list.

    Raises ValueError for anything that doesn't resolve to valid ports (1–65535).
    """
    if not port_spec or not port_spec.strip():
        raise ValueError("Port specification cannot be empty")

    port_set: set[int] = set()
    for segment in port_spec.split(","):
        segment = segment.strip()
        if not segment:
            continue
        if "-" in segment:
            parts = segment.split("-", 1)
            try:
                lo, hi = int(parts[0]), int(parts[1])
            except ValueError as exc:
                raise ValueError(f"Non-numeric port range: '{segment}'") from exc
            if lo < 1 or hi > 65535 or lo > hi:
                raise ValueError(f"Invalid port range {lo}-{hi}: must be 1–65535 with lo ≤ hi")
            port_set.update(range(lo, hi + 1))
        else:
            try:
                port_num = int(segment)
            except ValueError as exc:
                raise ValueError(f"Non-numeric port: '{segment}'") from exc
            if port_num < 1 or port_num > 65535:
                raise ValueError(f"Port {port_num} is out of range 1–65535")
            port_set.add(port_num)

    if not port_set:
        raise ValueError("Port specification resolved to zero valid ports")

    return sorted(port_set)


async def scan_host(
    host: str,
    ports: list[int],
    timeout: float = 1.0,
    max_concurrent: int = 500,
    udp: bool = False,
    show_progress: bool = True,
    on_result: Callable[[ScanResult], None] | None = None,
) -> list[ScanResult]:
    """Scan all ports on a single host. Filters nothing — returns open, closed, and filtered.

    Caller decides what to display. Don't hide data here.

    on_result: called for each port the instant it finishes — used by LiveScanUI
               to update the display in real time. Disables tqdm when set.
    """
    if not ports:
        raise ValueError("Port list is empty — nothing to scan")

    semaphore = asyncio.Semaphore(max_concurrent)

    if udp:
        tasks = [scan_udp_port(host, p, timeout, semaphore) for p in ports]
    else:
        tasks = [scan_tcp_port(host, p, timeout, semaphore) for p in ports]

    if on_result is not None:
        # stream each result as it lands — as_completed fires in arrival order, not list order
        collected: list[ScanResult] = []
        for coro in asyncio.as_completed(tasks):
            result = await coro
            on_result(result)
            collected.append(result)
        return collected
    elif show_progress:
        results: list[ScanResult] = await async_tqdm.gather(
            *tasks,
            desc=f"  {host}",
        )
        return results
    else:
        return list(await asyncio.gather(*tasks))


async def scan_targets(
    targets: list[str],
    ports: list[int],
    timeout: float = 1.0,
    max_concurrent: int = 500,
    udp: bool = False,
    show_progress: bool = True,
    on_result: Callable[[ScanResult], None] | None = None,
) -> dict[str, list[ScanResult]]:
    """Scan multiple hosts sequentially (parallel host scanning is overkill for v0.1.0).

    Returns {host_ip: [ScanResult, ...]} for all targets.
    """
    all_results: dict[str, list[ScanResult]] = {}
    for target in targets:
        host_results = await scan_host(
            host=target,
            ports=ports,
            timeout=timeout,
            max_concurrent=max_concurrent,
            udp=udp,
            show_progress=show_progress,
            on_result=on_result,
        )
        all_results[target] = host_results
    return all_results
