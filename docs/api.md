# PortHawk Python API

PortHawk can be used as a library — no CLI required.

```bash
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
    cve_lookup: bool = False,
    include_closed: bool = False,
) -> list[ScanResult]
```

Scan a single host, hostname, or CIDR range. Returns only open ports by default.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | `str` | — | IP, hostname, or CIDR e.g. `"10.0.0.0/24"` |
| `ports` | `str \| list[int]` | `"common"` | `"common"` (top 100), `"full"` (all 65535), `"1-1024"`, `"22,80,443"`, or `[22, 80]` |
| `timeout` | `float` | `1.0` | Per-port connection timeout in seconds |
| `concurrency` | `int` | `500` | Max simultaneous connections |
| `udp` | `bool` | `False` | UDP scan — requires root/admin |
| `banners` | `bool` | `False` | Grab service banners and extract version strings from open ports |
| `os_detect` | `bool` | `False` | TTL-based OS fingerprinting via ping |
| `cve_lookup` | `bool` | `False` | Query NVD for CVEs per open service — uses `service_version` when available |
| `include_closed` | `bool` | `False` | Include closed/filtered ports in the returned list |

**Returns:** `list[ScanResult]` sorted by port number.

**Raises:**
- `InvalidTargetError` — empty or malformed target
- `InvalidPortSpecError` — malformed port spec string
- `ScanPermissionError` — OS denied raw socket access (UDP without root)

**Examples:**

```python
# Basic scan
results = asyncio.run(porthawk.scan("192.168.1.1"))

# Version detection + CVE lookup
results = asyncio.run(porthawk.scan(
    "192.168.1.1",
    ports="1-1024",
    banners=True,
    cve_lookup=True,
))

# CIDR sweep, include everything
results = asyncio.run(porthawk.scan(
    "10.0.0.0/24",
    ports="22,80,443,3389,445",
    include_closed=True,
))
```

---

## `porthawk.Scanner`

Async context manager for repeated scans against the same target. Binds target,
timeout, and concurrency once — no need to repeat them on every `scan()` call.

```python
async with porthawk.Scanner("192.168.1.1", timeout=2.0, concurrency=200) as scanner:
    web_ports = await scanner.scan(ports="80,443,8080,8443", banners=True)
    db_ports  = await scanner.scan(ports="3306,5432,6379,27017", cve_lookup=True)
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
    cve_lookup: bool = False,
    include_closed: bool = False,
) -> list[ScanResult]
```

Inherits `target`, `timeout`, `concurrency`, and `udp` from the constructor.

---

## Data Models

### `ScanResult`

```python
class ScanResult(BaseModel):
    host: str
    port: int
    protocol: str            # "tcp" or "udp"
    state: PortState         # OPEN, CLOSED, or FILTERED
    banner: str | None       # human-readable display string (e.g. "SSH OpenSSH_8.9p1")
    service_name: str | None # from service_db, e.g. "ssh", "mysql"
    service_version: str | None  # extracted version string, e.g. "OpenSSH_8.9p1", "8.0.33"
    risk_level: str | None   # "HIGH", "MEDIUM", or "LOW"
    os_guess: str | None     # from TTL: "Linux/Unix", "Windows", "Network Device"
    ttl: int | None          # raw TTL value from ping
    latency_ms: float | None # TCP connect latency in milliseconds
    cves: list[dict]         # list of CVEInfo.model_dump() — empty if --cve not used
```

`service_version` and `banner` are only populated when `banners=True` is passed to `scan()`.
`cves` is only populated when `cve_lookup=True`.

### `PortState`

```python
class PortState(str, Enum):
    OPEN     = "open"
    CLOSED   = "closed"
    FILTERED = "filtered"
```

### `CVEInfo`

```python
class CVEInfo(BaseModel):
    cve_id: str          # e.g. "CVE-2022-0543"
    description: str     # English description, truncated to 200 chars
    cvss_score: float | None  # CVSS base score (v3.1 preferred, falls back to v2)
    severity: str | None      # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    published: str       # publication date as "YYYY-MM-DD"
    url: str             # direct link to nvd.nist.gov/vuln/detail/CVE-...
```

CVEs in `ScanResult.cves` are stored as `dict` (via `CVEInfo.model_dump()`), so no import
needed to read them. Import `CVEInfo` only if you need to validate or reconstruct the model.

---

## Building Reports

```python
import asyncio
import porthawk
from porthawk.reporter import print_terminal, save_html, save_json, save_csv

results = asyncio.run(porthawk.scan(
    "192.168.1.1",
    ports="common",
    banners=True,
    cve_lookup=True,
))

report = porthawk.build_report("192.168.1.1", results)

print_terminal(report, show_cves=True)
html_path = save_html(report)
json_path = save_json(report)
csv_path  = save_csv(report)
```

`build_report()` attaches metadata (scan time, total ports, version) to the results.
`save_*` functions write timestamped files to `reports/` and return the path.

---

## CVE Lookup

CVE lookup uses NVD API v2.0 with a two-layer cache:

1. **In-memory cache** — per process, immediate hits for repeated lookups
2. **Disk cache** — `~/.porthawk/cve_cache.json`, 24h TTL, survives between runs

When `service_version` is populated (from banner grabbing), the lookup uses the specific
version: "OpenSSH 8.9" instead of just "ssh". This returns CVEs that actually match the
running software, not every CVE ever filed against the service name.

```python
from porthawk.cve import lookup_cves, clear_cache

# version-aware lookup — better results than keyword-only
cves = asyncio.run(lookup_cves("ssh", service_version="OpenSSH_8.9p1"))

# clear disk cache if you want fresh results
clear_cache(include_disk=True)
```

**Rate limits:** Without an API key: 5 req/30s. PortHawk adds a 1.2s delay between calls.
Get a free key at `nvd.nist.gov` and set `NVD_API_KEY` to raise the limit to 50 req/30s.

---

## ML Port Prioritization

Reorders the port list by predicted open probability before scanning. Biggest impact in
stealth mode (1 thread, sequential) — with 500 concurrent connections, order barely matters.

```python
from porthawk.predictor import sort_ports, get_sklearn_status

# sort before scanning
ordered = sort_ports([22, 80, 443, 54321, 65000], target="192.168.1.1", os_hint="Linux/Unix")

# check whether sklearn is available
print(get_sklearn_status())
# "sklearn 1.3.2 (logistic regression)" or "sklearn not installed (frequency fallback)"
```

`sort_ports()` uses logistic regression trained on nmap-services frequency data when
`scikit-learn` is installed, falls back to pure frequency-table scoring otherwise.
Install ML dependencies with `pip install porthawk[ml]`.

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

## Honeypot Detection

Score a host for honeypot likelihood based on what was found in the scan.
No network calls — purely analyzes the `ScanResult` list you already have.
Banners improve accuracy significantly; without them you only get port-based checks.

```python
import asyncio
import porthawk

results = asyncio.run(porthawk.scan("10.0.0.1", ports="common", banners=True))
hp = porthawk.score_honeypot(results)

print(f"Score: {hp.score:.2f}  Verdict: {hp.verdict}  Confidence: {hp.confidence}")
for ind in hp.indicators:
    print(f"  [{ind.weight:.2f}] {ind.name}: {ind.description}")
```

### `porthawk.score_honeypot()`

```python
def score_honeypot(results: list[ScanResult]) -> HoneypotReport
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `results` | `list[ScanResult]` | All scan results — closed/filtered ports are ignored automatically |

**Returns:** `HoneypotReport`

### `HoneypotReport`

```python
@dataclass
class HoneypotReport:
    score: float           # 0.0 (probably real) to 1.0 (almost certainly a honeypot)
    verdict: str           # "LIKELY_REAL", "SUSPICIOUS", or "LIKELY_HONEYPOT"
    confidence: str        # "LOW", "MEDIUM", or "HIGH" — based on indicator count
    indicators: list[Indicator]
    open_port_count: int
```

Verdict thresholds: `< 0.25` → LIKELY_REAL, `0.25–0.55` → SUSPICIOUS, `> 0.55` → LIKELY_HONEYPOT

### `Indicator`

```python
@dataclass
class Indicator:
    name: str         # e.g. "cowrie_ssh_banner", "ics_multi_port"
    weight: float     # contribution to the combined score (0.0–1.0)
    description: str  # human-readable explanation
```

Score formula: `1 - product(1 - weight_i)` — multiple weak signals accumulate without any single one maxing the score.

Detected patterns:
- **Cowrie SSH**: exact match against known default banners (EOL Debian/Ubuntu SSH strings)
- **Dionaea FTP**: Synology FTP emulation banner hardcoded in Dionaea's config
- **Conpot ICS**: Modbus (502), S7 (102), BACnet (47808), EtherNet/IP (44818), DNP3 (20000), OPC-UA (4840)
- **T-Pot port flood**: >20 open ports (moderate signal), >40 open ports (strong signal)
- **Telnet open**: port 23 open in 2025 is unusual on real infra
- **SSH multi-port**: same SSH banner appearing on port 22 and an alt port
- **Service diversity**: 6+ different service categories active simultaneously
- **Uniform latency**: latency CV < 0.05 across 5+ ports — suggests software-emulated responses

---

## PyPI Publishing

```bash
pip install build twine
python -m build
twine upload dist/*
```
