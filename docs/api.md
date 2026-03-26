# PortHawk Python API

PortHawk can be used as a library — no CLI required.

```python
pip install porthawk
```

---

## Quick Start

```python
import asyncio
import porthawk

results = asyncio.run(porthawk.scan("192.168.1.1", ports="common"))
for r in results:
    print(f"{r.port}/{r.protocol}  {r.state}  {r.service_name}  {r.risk_level}")
```

---

## `porthawk.scan()`

```python
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
) -> list[ScanResult]
```

Scan a single host, hostname, or CIDR range.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | `str` | — | IP, hostname, or CIDR e.g. `"10.0.0.0/24"` |
| `ports` | `str \| list[int]` | `"common"` | `"common"`, `"full"`, `"1-1024"`, `"22,80,443"`, or `[22, 80]` |
| `timeout` | `float` | `1.0` | Per-port connection timeout in seconds |
| `concurrency` | `int` | `500` | Max simultaneous connections |
| `udp` | `bool` | `False` | UDP scan — requires root/admin |
| `banners` | `bool` | `False` | Grab service banners from open ports |
| `os_detect` | `bool` | `False` | TTL-based OS fingerprinting |
| `include_closed` | `bool` | `False` | Include closed/filtered ports in results |

**Returns:** `list[ScanResult]` sorted by port number. Only open ports by default.

**Raises:**
- `InvalidTargetError` — empty or malformed target
- `InvalidPortSpecError` — malformed port spec string
- `ScanPermissionError` — OS denied raw socket access

---

## `porthawk.Scanner`

Async context manager for repeated scans against the same target.

```python
async with porthawk.Scanner("192.168.1.1", timeout=2.0, concurrency=200) as scanner:
    web_ports = await scanner.scan(ports="80,443,8080,8443")
    all_ports  = await scanner.scan(ports="1-1024", banners=True)
```

### Constructor

```python
Scanner(
    target: str,
    *,
    timeout: float = 1.0,
    concurrency: int = 500,
    udp: bool = False,
)
```

### `Scanner.scan()`

```python
async def scan(
    ports: str | list[int] = "common",
    *,
    banners: bool = False,
    os_detect: bool = False,
    include_closed: bool = False,
) -> list[ScanResult]
```

Same semantics as `porthawk.scan()` — inherits `target`, `timeout`, `concurrency`, and `udp` from the constructor.

---

## Data Models

### `ScanResult`

```python
class ScanResult(BaseModel):
    host: str
    port: int
    protocol: str           # "tcp" or "udp"
    state: PortState        # OPEN, CLOSED, or FILTERED
    banner: str | None
    service_name: str | None
    risk_level: str | None  # "HIGH", "MEDIUM", "LOW", or "INFO"
    os_guess: str | None
    ttl: int | None
    latency_ms: float | None
```

### `PortState`

```python
class PortState(str, Enum):
    OPEN     = "open"
    CLOSED   = "closed"
    FILTERED = "filtered"
```

---

## Building Reports

```python
import asyncio
import porthawk
from porthawk.reporter import print_terminal, save_html

results = asyncio.run(porthawk.scan("192.168.1.1", ports="common", banners=True))
report  = porthawk.build_report("192.168.1.1", results)

print_terminal(report)
html_path = save_html(report)
print(f"Report: {html_path}")
```

---

## Exceptions

All PortHawk exceptions inherit from `porthawk.PortHawkError`.

```python
try:
    results = await porthawk.scan("192.168.1.1")
except porthawk.InvalidTargetError as e:
    print(f"Bad target: {e}")
except porthawk.ScanPermissionError as e:
    print(f"Need root: {e}")
except porthawk.PortHawkError as e:
    print(f"Scan failed: {e}")
```

| Exception | When raised |
|-----------|-------------|
| `PortHawkError` | Base class — catch-all |
| `InvalidTargetError` | Empty or malformed target string |
| `InvalidPortSpecError` | Malformed port spec (bad range, out-of-bounds) |
| `ScanPermissionError` | OS denied raw socket (UDP without root) |
| `ScanTimeoutError` | Scan aborted due to timeout |

---

## PyPI Publishing

```bash
pip install build twine
python -m build
twine upload dist/*
```
