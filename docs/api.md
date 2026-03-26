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

## Evasion Scan

IDS/IPS evasion techniques for authorized red-team scenarios. Requires root/admin and Scapy for full functionality.

```python
import asyncio
import porthawk

# Full preset — slow & low, looks like Windows, fragments everything
cfg = porthawk.slow_low_config()
cfg.decoys = ["1.2.3.4", "5.6.7.8"]  # optional decoy IPs

results = asyncio.run(
    porthawk.evasion_scan_host("192.168.1.1", [22, 80, 443], config=cfg, max_concurrent=2)
)

# Custom — XMAS scan, 10s jitter, 8-byte fragments
cfg = porthawk.EvasionConfig(
    scan_type="xmas",
    max_delay=10.0,
    jitter_distribution="exponential",
    fragment=True,
    ttl=128,
)
results = asyncio.run(porthawk.evasion_scan_host("192.168.1.1", [80, 443], config=cfg))
```

### `porthawk.evasion_scan_host()`

```python
async def evasion_scan_host(
    host: str,
    ports: list[int],
    config: EvasionConfig | None = None,
    timeout: float = 1.0,
    max_concurrent: int = 10,
) -> list[ScanResult]
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `host` | `str` | — | Target IP or hostname |
| `ports` | `list[int]` | — | Ports to probe — raises `ValueError` if empty |
| `config` | `EvasionConfig \| None` | `None` | Evasion config — `None` uses `EvasionConfig()` defaults (no evasion) |
| `timeout` | `float` | `1.0` | Per-port wait in seconds |
| `max_concurrent` | `int` | `10` | Max simultaneous probes (lower than SYN scan — evasion implies slow) |

### `porthawk.EvasionConfig`

```python
@dataclass
class EvasionConfig:
    scan_type: str = "syn"            # syn, fin, null, xmas, ack, maimon
    min_delay: float = 0.0            # seconds (0 = no delay)
    max_delay: float = 0.0            # seconds
    jitter_distribution: str = "uniform"   # "uniform" or "exponential"
    fragment: bool = False            # split IP payload into fragment_size-byte chunks
    fragment_size: int = 8            # bytes, must be multiple of 8
    decoys: list[str] = []            # fake source IPs (Scapy required)
    ttl: int = 64                     # IP TTL — 128 looks like Windows
    randomize_ip_id: bool = True      # random IP ID defeats passive OS fingerprinting
```

#### Scan type semantics

| Type | TCP Flags | Open | Closed | Notes |
|------|-----------|------|--------|-------|
| `syn` | `0x02` | SYN-ACK | RST | Works everywhere |
| `fin` | `0x01` | No reply | RST | Unreliable on Windows targets |
| `null` | `0x00` | No reply | RST | Unreliable on Windows targets |
| `xmas` | `0x29` | No reply | RST | FIN+PSH+URG, unreliable on Windows |
| `ack` | `0x10` | RST (unfiltered) | No reply (filtered) | Maps firewall rules, not port state |
| `maimon` | `0x11` | No reply | RST | FIN+ACK, works on some BSD stacks |

### `porthawk.slow_low_config()`

```python
def slow_low_config() -> EvasionConfig
```

Returns a red-team preset:
- `min_delay=5.0, max_delay=30.0, jitter_distribution="exponential"` — Poisson-like inter-arrivals
- `fragment=True, fragment_size=8` — 8-byte IP fragments
- `ttl=128` — looks like Windows, confuses passive OS fingerprinting
- Decoys not set — add them explicitly

---

## Passive OS Fingerprinting

Analyzes the SYN-ACK from one probe to infer the target OS without sending unusual packets.
Requires Scapy (`pip install porthawk[syn]`) or root + Linux/macOS for raw sockets.

```python
import porthawk

# Full TCP fingerprint — sends one SYN, reads the SYN-ACK
match = porthawk.passive_os_scan("192.168.1.1")
if match:
    print(f"{match.os_family}  {match.os_detail}")
    print(f"confidence={match.confidence}  score={match.score:.2f}")
    print(f"signals: {', '.join(match.matched_signals[:4])}")
    # e.g. "Windows  Windows 10 / 11 / Server 2019+"
    #      "confidence=HIGH  score=0.91"
    #      "signals: ttl=128 (family 128), window=65535 (exact), df=1, options order match"

# Classify OS from raw packet bytes (e.g. from Scapy capture)
match = porthawk.fingerprint_os(raw_bytes)

# Fallback — no privileges needed, no network access
match = porthawk.ttl_only_os(64)   # → "Linux/Unix", LOW confidence
match = porthawk.ttl_only_os(128)  # → "Windows", LOW confidence
match = porthawk.ttl_only_os(255)  # → "Network Device", LOW confidence
```

### `porthawk.passive_os_scan()`

```python
def passive_os_scan(
    host: str,
    port: int = 80,
    timeout: float = 2.0,
) -> OsMatch | None
```

Sends one SYN to `host:port`, captures the SYN-ACK, and classifies the OS.
Returns `None` if the host doesn't respond or the platform doesn't support raw sockets.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `host` | `str` | — | Target IP or hostname |
| `port` | `int` | `80` | Port to send the SYN to |
| `timeout` | `float` | `2.0` | Wait for SYN-ACK in seconds |

**Platform dispatch:**
1. Scapy available → uses Scapy (cross-platform, sends RST to clean up)
2. Linux/macOS root → raw sockets
3. Windows without Scapy → returns `None`

### `porthawk.fingerprint_os()`

```python
def fingerprint_os(raw_pkt: bytes) -> OsMatch | None
```

Classify OS from raw IP+TCP packet bytes. Useful when you capture packets yourself.
Returns `None` if the packet is too short or malformed.

Two-layer classifier:
1. Rule-based scoring against the signature DB (always runs)
2. KNN in 7D feature space (sklearn if available, pure Python fallback)
3. Blend: 60% rule-based + 40% KNN

### `porthawk.ttl_only_os()`

```python
def ttl_only_os(ttl: int) -> OsMatch
```

Guess OS from TTL alone. No network access required. Always returns `OsMatch` with `confidence="LOW"`.

### `OsFingerprint`

```python
@dataclass
class OsFingerprint:
    ttl: int                     # observed TTL from IP header
    window_size: int             # TCP window size from SYN-ACK
    df_bit: bool                 # IP Don't Fragment bit
    mss: int | None              # TCP MSS option (kind=2)
    wscale: int | None           # TCP Window Scale option (kind=3)
    has_timestamp: bool          # TCP Timestamps present (kind=8)
    has_sack: bool               # SACK Permitted present (kind=4)
    opt_order: tuple[str, ...]   # order of TCP options seen
```

### `OsMatch`

```python
@dataclass
class OsMatch:
    os_family: str          # "Windows", "Linux", "macOS", "FreeBSD", "Network Device", "Unknown"
    os_detail: str          # e.g. "Windows 10 / 11 / Server 2019+", "Linux 5.x"
    confidence: str         # "HIGH" (≥0.70), "MEDIUM" (0.45–0.69), "LOW" (<0.45)
    score: float            # 0.0–1.0 blended classifier score
    matched_signals: list[str]   # which signals contributed most
    method: str             # "tcp_fingerprint+knn", "ttl_only", "tcp_fingerprint+knn(disagreement)"
```

---

## UDP Scanning

TCP scanners skip most UDP services. DNS, NTP, SNMP, NetBIOS, SSDP — all run over UDP. This module sends protocol-specific payloads and validates responses. It also detects closed ports via ICMP unreachable.

```python
import asyncio
import porthawk

# Scan the 20 most common UDP ports
results = asyncio.run(
    porthawk.udp_scan_host("192.168.1.1", ports=porthawk.get_udp_top_ports(), timeout=2.0)
)

# Specific ports with longer timeout for slow networks
results = asyncio.run(
    porthawk.udp_scan_host("192.168.1.1", ports=[53, 123, 161, 1900], timeout=3.0)
)

for r in results:
    print(r.port, r.state, r.banner)
    # 53   OPEN     DNS
    # 123  OPEN     NTP stratum=2 refid=GPS
    # 161  OPEN     SNMP agent
    # 1900 OPEN     Server: UPnP/1.0 Linux/3.x | USN: uuid:...
```

### `porthawk.udp_scan_host()`

```python
async def udp_scan_host(
    host: str,
    ports: list[int],
    timeout: float = 2.0,       # per-probe wait — UDP needs at least 1-2s
    max_concurrent: int = 50,   # cap this low; UDP stacks don't love 500 simultaneous probes
    retries: int = 1,           # one retry catches most packet loss
) -> list[ScanResult]:
```

Returns a flat `list[ScanResult]`, one per port scanned. Port states:

- `OPEN` — got a valid protocol response, or any response that passes basic validation
- `CLOSED` — ICMP "port unreachable" received (Linux: `OSError(errno=111)`, Windows: `ConnectionResetError`)
- `FILTERED` — no response after all retries (firewall, or host just ignores it)

Raises `ValueError` if `ports` is empty.

**Unvalidated responses:** If a response arrives but fails the protocol validator (e.g. a UDP proxy returning garbage), the port is still marked `OPEN` but `r.banner` is prefixed with `"unvalidated:"`. Better a false positive than a false negative.

### Protocol payloads

| Port | Protocol | Payload | Validator |
|------|----------|---------|-----------|
| 53 | DNS | A query for `google.com`, TX ID `0xDEAD` | QR bit set in response |
| 67/68 | DHCP | — | — |
| 69 | TFTP | RRQ for `motd` | Any opcode response |
| 111 | RPCBind | 4 null bytes | Any response |
| 123 | NTP | v3 client request (48 bytes) | Mode field = 4 or 5 |
| 137 | NetBIOS | NBSTAT wildcard query | Response flag 0x8000 set |
| 161 | SNMP | BER GetRequest for `sysDescr.0` | Response starts with `0x30` |
| 500/4500 | IKE | v1 informational (28 bytes) | Any response |
| 1900 | SSDP | M-SEARCH `ssdp:all` | Starts with `HTTP/1.` |
| 5353/5355 | mDNS/LLMNR | PTR query with QU bit | DNS QR bit |

Ports without a payload entry (67, 68, 514, 520, 1194) get an empty datagram. Still useful: ICMP unreachable means definitely closed, no response means filtered.

### `porthawk.get_udp_top_ports()`

```python
def get_udp_top_ports(n: int | None = None) -> list[int]:
```

Returns the top 20 UDP ports (or first `n` if specified): DNS, DHCP, TFTP, RPCBind, NTP, NetBIOS, SNMP, IKE, Syslog, RIP, OpenVPN, SSDP, mDNS, LLMNR, Memcached, Steam/game servers.

These are the ports a TCP scanner would completely miss. Good default for any UDP recon pass.

---

## SARIF Output

SARIF (Static Analysis Results Interchange Format) is what GitHub's Security tab consumes. PortHawk maps open ports to SARIF findings by risk level so they show up as code scanning alerts.

```python
import json
import porthawk

# build a SARIF document from a ScanReport
report = porthawk.build_report(
    target="192.168.1.1",
    results=my_results,
    protocol="tcp",
    timeout=1.0,
    max_concurrent=100,
)

sarif_doc = porthawk.build_sarif(report, version=porthawk.__version__)
with open("results.sarif", "w") as f:
    json.dump(sarif_doc, f, indent=2)
```

Or via CLI — SARIF alongside JSON and HTML in one shot:

```bash
porthawk -t 192.168.1.1 --common -o json,html,sarif
```

### `porthawk.build_sarif()`

```python
def build_sarif(report: ScanReport, version: str = "0.0.0") -> dict:
```

Returns a SARIF 2.1.0 dict. Pass it through `json.dumps()` to write to disk.

**Risk level → SARIF mapping:**

| Risk | Rule ID | SARIF level | security-severity |
|------|---------|-------------|-------------------|
| HIGH | PH001 | error | 8.5 |
| MEDIUM | PH002 | warning | 5.5 |
| LOW | PH003 | note | 2.0 |
| None | PH004 | note | 1.0 |

Only `OPEN` ports become findings. Closed and filtered ports are excluded — they're not security alerts.

CVEs from `--cve` are attached as `relatedLocations` entries. Each CVE ID appears as a named logical location of kind `"vulnerability"`.

### `porthawk.reporter.save_sarif()`

```python
def save_sarif(report: ScanReport, output_path: Path | None = None) -> Path:
```

Writes a SARIF file to `reports/scan_YYYYMMDD_HHMMSS.sarif` (or `output_path` if given). Returns the path.

---

## Nmap Import + Scan Diff

### `porthawk.parse_nmap_xml()`

```python
def parse_nmap_xml(source: str | Path) -> list[ScanResult]:
```

Loads a Nmap `-oX` XML file into a flat list of `ScanResult`. Handles multi-host scans, down hosts, all Nmap port states, and service info extraction.

```python
from porthawk import parse_nmap_xml

results = parse_nmap_xml("nmap_output.xml")
for r in results:
    print(f"{r.host}:{r.port}/{r.protocol} — {r.state}")
```

Raises `FileNotFoundError` if the file doesn't exist, `ValueError` if the XML is malformed.

---

### `porthawk.load_results()`

```python
def load_results(path: str | Path) -> list[ScanResult]:
```

Auto-detects format and loads results. Tries file extension first (`.json` → PortHawk JSON, `.xml` → Nmap XML), then sniffs the first 200 bytes if there's no extension. Raises `ValueError` for unknown formats.

---

### `porthawk.compute_diff()`

```python
def compute_diff(
    results_a: list[ScanResult],
    results_b: list[ScanResult],
    label_a: str = "scan_a",
    label_b: str = "scan_b",
    include_stable: bool = False,
) -> ScanDiff:
```

Compares two scan result lists. Key is `(host, port, protocol)`.

Change types:
- `new` — port is OPEN in B but not in A (potential new exposure)
- `gone` — port was OPEN in A but missing in B (service gone or firewalled)
- `changed` — same port, but state/service_name/service_version/risk_level differs
- `stable` — nothing changed (excluded by default, enable with `include_stable=True`)

```python
from porthawk import load_results, compute_diff

old = load_results("baseline.json")
new = load_results("current.xml")

diff = compute_diff(old, new, label_a="baseline", label_b="current")
print(f"New: {len(diff.new_ports)}, Gone: {len(diff.gone_ports)}, Changed: {len(diff.changed_ports)}")

if diff.has_regressions:
    print("New HIGH or MEDIUM risk ports detected!")

for change in diff.changes:
    print(change.describe())
```

### `ScanDiff` properties

| Property | Type | Description |
|----------|------|-------------|
| `new_ports` | `list[PortChange]` | Ports that appeared as OPEN in B |
| `gone_ports` | `list[PortChange]` | Ports that were OPEN in A and are gone in B |
| `changed_ports` | `list[PortChange]` | Ports present in both scans with different values |
| `stable_ports` | `list[PortChange]` | Ports that didn't change (empty unless `include_stable=True`) |
| `has_regressions` | `bool` | True if any new HIGH or MEDIUM risk ports appeared |

### `PortChange.describe()`

Returns a one-line human-readable summary:
- `+ 10.0.0.1:22/tcp  ssh  [MEDIUM]` — new port
- `- 10.0.0.1:23/tcp  telnet  [HIGH]` — gone port
- `~ 10.0.0.1:22/tcp  ssh  version: 7.9 → 8.9p1` — changed port

### `porthawk.diff.save_diff_json()`

```python
def save_diff_json(diff: ScanDiff, output_path: Path | None = None) -> Path:
```

Writes a `ScanDiff` to JSON. Default path: `reports/diff_YYYYMMDD_HHMMSS.json`.

---

## PyPI Publishing

```bash
pip install build twine
python -m build
twine upload dist/*
```
