"""Public programmatic API — wrap the scanner internals behind clean coroutines.

Everything in here is designed for `import porthawk; await porthawk.scan(...)`.
CLI users never touch this file directly.
"""

from __future__ import annotations

from types import TracebackType

from porthawk.exceptions import InvalidPortSpecError, InvalidTargetError
from porthawk.fingerprint import fingerprint_port, get_ttl_via_ping, guess_os_from_ttl
from porthawk.scanner import (
    PortState,
    ScanResult,
    expand_cidr,
    parse_port_range,
    scan_targets,
)
from porthawk.service_db import get_service, get_top_ports

_COMMON_PORT_COUNT = 100


def _resolve_ports(ports: str | list[int]) -> list[int]:
    """Turn a port spec into a concrete list. Raises InvalidPortSpecError on bad input."""
    if isinstance(ports, list):
        return ports
    if ports == "common":
        return get_top_ports(_COMMON_PORT_COUNT)
    if ports == "full":
        return list(range(1, 65536))
    try:
        return parse_port_range(ports)
    except ValueError as exc:
        raise InvalidPortSpecError(str(exc)) from exc


def _validate_target(target: str) -> list[str]:
    """Expand CIDR or validate single host. Raises InvalidTargetError on empty/bad input."""
    if not target or not target.strip():
        raise InvalidTargetError(f"target must not be empty, got {target!r}")
    try:
        return expand_cidr(target)
    except ValueError as exc:
        raise InvalidTargetError(str(exc)) from exc


async def _enrich(
    results: list[ScanResult],
    host: str,
    *,
    banners: bool,
    os_detect: bool,
    timeout: float,
) -> list[ScanResult]:
    """Attach service info, OS guess, and banners. Mirrors cli._enrich_results."""
    ttl_value = get_ttl_via_ping(host, timeout=2.0) if os_detect else None

    for r in results:
        svc = get_service(r.port, r.protocol)
        r.service_name = svc.service_name
        r.risk_level = svc.risk_level.value if svc.risk_level else None
        if ttl_value is not None:
            r.ttl = ttl_value
            r.os_guess = guess_os_from_ttl(ttl_value)

    if banners:
        open_ports = [r for r in results if r.state == PortState.OPEN]
        for r in open_ports:
            r.banner = await fingerprint_port(r.host, r.port, timeout=timeout)

    return results


async def scan(
    target: str,
    *,
    ports: str | list[int] = "common",
    timeout: float = 1.0,
    concurrency: int = 500,
    udp: bool = False,
    banners: bool = False,
    os_detect: bool = False,
    include_closed: bool = False,
) -> list[ScanResult]:
    """Scan a host or CIDR range and return results as a flat list.

    Args:
        target: IP address, hostname, or CIDR (e.g. "192.168.1.0/24").
        ports: Port spec — "common", "full", a range string like "1-1024",
               a comma list like "22,80,443", or a list of ints.
        timeout: Per-port connection timeout in seconds.
        concurrency: Max simultaneous connections (semaphore value).
        udp: Scan UDP instead of TCP. Requires root/admin on most systems.
        banners: Grab service banners from open ports after scan.
        os_detect: Attempt TTL-based OS fingerprinting.
        include_closed: Include closed/filtered ports in the returned list.

    Returns:
        List of ScanResult objects, sorted by port number.

    Raises:
        InvalidTargetError: target is empty or not a valid host/CIDR.
        InvalidPortSpecError: ports string is malformed.
        ScanPermissionError: OS denied the scan (raw socket without root).
    """
    targets = _validate_target(target)
    port_list = _resolve_ports(ports)

    raw = await scan_targets(
        targets=targets,
        ports=port_list,
        timeout=timeout,
        max_concurrent=concurrency,
        udp=udp,
        show_progress=False,
    )

    flat = [r for host_results in raw.values() for r in host_results]
    flat = await _enrich(
        flat, host=targets[0], banners=banners, os_detect=os_detect, timeout=timeout
    )

    if not include_closed:
        flat = [r for r in flat if r.state == PortState.OPEN]

    return sorted(flat, key=lambda r: r.port)


class Scanner:
    """Async context manager for repeated scans against the same target.

    Usage::

        async with Scanner("192.168.1.1", timeout=2.0) as scanner:
            results = await scanner.scan(ports="1-1024", banners=True)

    The context manager doesn't hold a persistent connection — it just
    binds target + options so you don't repeat them on every scan() call.
    """

    def __init__(
        self,
        target: str,
        *,
        timeout: float = 1.0,
        concurrency: int = 500,
        udp: bool = False,
    ) -> None:
        self.target = target
        self.timeout = timeout
        self.concurrency = concurrency
        self.udp = udp

    async def __aenter__(self) -> "Scanner":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        pass  # nothing to close — connections are per-scan, not persistent

    async def scan(
        self,
        ports: str | list[int] = "common",
        *,
        banners: bool = False,
        os_detect: bool = False,
        include_closed: bool = False,
    ) -> list[ScanResult]:
        """Run a scan with the options bound at construction time.

        Args:
            ports: Same as porthawk.scan(ports=...).
            banners: Grab service banners from open ports.
            os_detect: Attempt TTL-based OS fingerprinting.
            include_closed: Include closed/filtered ports in the returned list.

        Returns:
            List of ScanResult objects, sorted by port number.
        """
        return await scan(
            self.target,
            ports=ports,
            timeout=self.timeout,
            concurrency=self.concurrency,
            udp=self.udp,
            banners=banners,
            os_detect=os_detect,
            include_closed=include_closed,
        )
