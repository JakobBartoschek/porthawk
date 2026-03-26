# Public Python API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose a clean `import porthawk` API so the scanner can be used programmatically, not just via CLI.

**Architecture:** `exceptions.py` defines the error hierarchy. `api.py` wraps scanner + enrich logic behind `scan()` and `Scanner`. `__init__.py` re-exports everything that belongs to the public surface.

**Tech Stack:** asyncio, pydantic v2, existing scanner/fingerprint/reporter internals

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `porthawk/exceptions.py` | Create | Custom exception hierarchy rooted at `PortHawkError` |
| `porthawk/api.py` | Create | `scan()` coroutine + `Scanner` async context manager |
| `porthawk/__init__.py` | Modify | Re-export public surface + `__all__` |
| `tests/test_exceptions.py` | Create | Exception hierarchy unit tests |
| `tests/test_api.py` | Create | `scan()` and `Scanner` integration tests (mocked) |
| `docs/api.md` | Create | Public API reference |
| `requirements-dev.txt` | Modify | Add `build` and `twine` |

---

### Task 1: Exception hierarchy

**Files:**
- Create: `porthawk/exceptions.py`
- Create: `tests/test_exceptions.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_exceptions.py
from porthawk.exceptions import (
    InvalidPortSpecError,
    InvalidTargetError,
    PortHawkError,
    ScanPermissionError,
    ScanTimeoutError,
)


def test_all_exceptions_inherit_from_base():
    for cls in (InvalidTargetError, InvalidPortSpecError, ScanPermissionError, ScanTimeoutError):
        assert issubclass(cls, PortHawkError)


def test_base_inherits_from_exception():
    assert issubclass(PortHawkError, Exception)


def test_exceptions_carry_message():
    err = InvalidTargetError("not-a-host")
    assert "not-a-host" in str(err)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_exceptions.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'porthawk.exceptions'`

- [ ] **Step 3: Write minimal implementation**

```python
# porthawk/exceptions.py
"""Custom exceptions — all public errors PortHawk raises inherit from PortHawkError.

Callers can catch PortHawkError to handle any scanner error, or specific
subclasses when they care about the reason.
"""


class PortHawkError(Exception):
    """Base for all PortHawk errors. Catch this if you don't care why it failed."""


class InvalidTargetError(PortHawkError):
    """target string is not a valid IP, hostname, or CIDR."""


class InvalidPortSpecError(PortHawkError):
    """Port spec string is malformed — bad range, out-of-bounds port number, etc."""


class ScanPermissionError(PortHawkError):
    """OS refused the scan — usually raw socket without root, or firewall rule."""


class ScanTimeoutError(PortHawkError):
    """Scan exceeded the configured timeout and was aborted."""
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_exceptions.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add porthawk/exceptions.py tests/test_exceptions.py
git commit -m "feat: add PortHawkError exception hierarchy"
```

---

### Task 2: `scan()` function and `Scanner` class

**Files:**
- Create: `porthawk/api.py`
- Create: `tests/test_api.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_api.py
from unittest.mock import AsyncMock, patch

import pytest

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
async def test_scan_raises_on_bad_target():
    with pytest.raises(InvalidTargetError):
        await scan("")


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
    # default: only open ports
    assert all(r.state == PortState.OPEN for r in results)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_api.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'porthawk.api'`

- [ ] **Step 3: Write the implementation**

```python
# porthawk/api.py
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
    flat = await _enrich(flat, host=targets[0], banners=banners, os_detect=os_detect, timeout=timeout)

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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_api.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add porthawk/api.py tests/test_api.py
git commit -m "feat: add scan() coroutine and Scanner context manager"
```

---

### Task 3: Update `__init__.py` public surface

**Files:**
- Modify: `porthawk/__init__.py`

- [ ] **Step 1: Write the failing test** (add to `tests/test_api.py` or inline check)

```python
# add to tests/test_api.py
import porthawk

def test_public_api_exports():
    assert hasattr(porthawk, "scan")
    assert hasattr(porthawk, "Scanner")
    assert hasattr(porthawk, "ScanResult")
    assert hasattr(porthawk, "PortHawkError")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_api.py::test_public_api_exports -v`
Expected: FAIL — `AttributeError`

- [ ] **Step 3: Write the implementation**

```python
# porthawk/__init__.py
"""PortHawk — async port scanner for authorized security testing.

Scan responsibly. Get written permission first.

Quick start::

    import asyncio
    import porthawk

    results = asyncio.run(porthawk.scan("192.168.1.1", ports="common"))
    for r in results:
        print(r.port, r.service_name, r.risk_level)

Context manager::

    async with porthawk.Scanner("192.168.1.1", timeout=2.0) as scanner:
        results = await scanner.scan(ports="1-1024", banners=True)
"""

from porthawk.api import Scanner, scan
from porthawk.exceptions import (
    InvalidPortSpecError,
    InvalidTargetError,
    PortHawkError,
    ScanPermissionError,
    ScanTimeoutError,
)
from porthawk.reporter import ScanReport, build_report
from porthawk.scanner import PortState, ScanResult

__version__ = "0.1.0"
__author__ = "Jakob Bartoschek"
__license__ = "MIT"

__all__ = [
    # Core API
    "scan",
    "Scanner",
    # Data models
    "ScanResult",
    "ScanReport",
    "PortState",
    # Report builder (for custom rendering)
    "build_report",
    # Exceptions
    "PortHawkError",
    "InvalidTargetError",
    "InvalidPortSpecError",
    "ScanPermissionError",
    "ScanTimeoutError",
]
```

- [ ] **Step 4: Run all tests**

Run: `pytest tests/ -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add porthawk/__init__.py
git commit -m "feat: expose public API surface in __init__.py"
```

---

### Task 4: PyPI readiness + docs

**Files:**
- Modify: `requirements-dev.txt`
- Create: `docs/api.md`

- [ ] **Step 1: Add build tools to requirements-dev.txt**

```
# PyPI publishing
build>=1.0
twine>=5.0
```

- [ ] **Step 2: Verify package builds**

Run: `pip install build && python -m build --wheel`
Expected: `dist/porthawk-0.1.0-py3-none-any.whl` created

- [ ] **Step 3: Write docs/api.md**

See content below.

- [ ] **Step 4: Commit**

```bash
git add requirements-dev.txt docs/api.md
git commit -m "docs: add public API reference and PyPI build tools"
```
