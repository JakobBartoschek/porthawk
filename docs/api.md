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

## Adaptive Scan Speed

Pass `adaptive_config` to `scan_host()` or `scan_targets()` to enable AIMD concurrency control.
The semaphore starts at `initial_concurrency` and ramps toward `max_concurrent` as the network proves stable.

```python
import asyncio
import porthawk
from porthawk.throttle import AdaptiveConfig
from porthawk.scanner import scan_host

cfg = AdaptiveConfig(
    initial_concurrency=25,  # start conservative
    min_concurrency=5,
    ai_step=2,               # add 2 slots every 30 clean probes
    md_factor=0.5,           # halve on congestion
    timeout_threshold=0.30,  # >30% timeouts = congestion
    rttvar_threshold=80.0,   # ms — high jitter = hold steady
)

results = asyncio.run(scan_host(
    "192.168.1.1",
    ports=list(range(1, 1025)),
    max_concurrent=500,
    adaptive_config=cfg,
))
```

### `AdaptiveConfig`

```python
@dataclass
class AdaptiveConfig:
    initial_concurrency: int = 25    # starting cwnd
    min_concurrency: int = 5         # floor — never go below this
    ai_step: int = 2                 # slots added per increase cycle
    md_factor: float = 0.5           # multiplicative decrease factor
    timeout_threshold: float = 0.30  # timeout ratio that triggers decrease
    rttvar_threshold: float = 80.0   # ms — RTTVAR above this pauses increases
    increase_interval: int = 30      # probes between increases on stable network
    decrease_cooldown: float = 1.0   # seconds between consecutive decreases
    min_samples: int = 10            # observations needed before AIMD acts
    window_size: int = 50            # sliding window size for timeout ratio
```

### `NetworkStats`

Exposed via `AdaptiveSemaphore.stats` — useful for logging or custom monitoring.

```python
@dataclass
class NetworkStats:
    srtt: float | None    # smoothed RTT (ms), RFC 6298 EWMA
    rttvar: float         # RTT variance (ms), RFC 6298 EWMA

    # methods
    def record(latency_ms: float, timed_out: bool) -> None: ...

    # properties
    timeout_ratio: float  # fraction of window that timed out
    sample_count: int     # total observations in current window
```

AIMD algorithm:
- **Additive increase**: every `increase_interval` probes with no congestion → `cwnd += ai_step`
- **Hold**: RTTVAR > `rttvar_threshold` → pause increases (jitter, not congestion)
- **Multiplicative decrease**: `timeout_ratio > timeout_threshold` → `cwnd = max(min, cwnd * md_factor)`
- Score combination is independent — decrease respects `decrease_cooldown` to prevent thrash

---

## SYN Scan

Half-open TCP scanner — sends SYN, reads SYN-ACK/RST, never completes the handshake.
Requires root/admin. Install Scapy for best results: `pip install porthawk[syn]`.

```python
import asyncio
import porthawk

# requires admin/root
results = asyncio.run(
    porthawk.syn_scan_host("192.168.1.1", [22, 80, 443, 8080], timeout=1.0)
)
for r in results:
    print(f"{r.port}  {r.state}  {r.latency_ms:.1f}ms")

# check what backend will be used before you run
print(porthawk.get_syn_backend())
# → "scapy 2.5.0"  or  "raw socket (Linux)"  or  "unavailable (Windows needs Scapy + Npcap)"
```

### `porthawk.syn_scan_host()`

```python
async def syn_scan_host(
    host: str,
    ports: list[int],
    timeout: float = 1.0,
    max_concurrent: int = 100,
) -> list[ScanResult]
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `host` | `str` | — | Target IP or hostname |
| `ports` | `list[int]` | — | Ports to probe — raises `ValueError` if empty |
| `timeout` | `float` | `1.0` | Per-port wait for SYN-ACK or RST |
| `max_concurrent` | `int` | `100` | Max simultaneous raw socket probes (lower than TCP connect — raw sockets are heavier) |

Raises `ScanPermissionError` if not running as root/admin.

Returns `list[ScanResult]` with `protocol="tcp"` — same structure as regular TCP scan results.

### `porthawk.get_syn_backend()`

```python
def get_syn_backend() -> str
```

Returns a human-readable string describing which SYN scan backend will be used on the current platform, e.g. `"scapy 2.5.0"`, `"raw socket (Linux)"`, or `"unavailable (Windows needs Scapy + Npcap)"`.

Useful for pre-flight checks before starting a scan.

### Backend selection

1. **Scapy** — preferred, cross-platform. Requires `pip install porthawk[syn]` and on Windows: Npcap from npcap.com installed with "WinPcap compatibility mode".
2. **Raw socket** — Linux/macOS only. Kernel-level packet crafting, no extra dependencies beyond root access.
3. **Unavailable** — Windows without Scapy. Raises `ScanPermissionError` with install instructions.

---

## PyPI Publishing

```bash
pip install build twine
python -m build
twine upload dist/*
```
