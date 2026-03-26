# Changelog

All notable changes to PortHawk are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)

---

## [0.9.0] — 2026-03-27

### GitHub Action + SARIF output

PortHawk can now run as a GitHub Action. Drop it into any workflow, point it at a host, and open ports show up in the GitHub Security tab as code scanning alerts.

**New: `action.yml` — composite GitHub Action**

Other repos use it as:
```yaml
- uses: jakobbartoschek/porthawk@v0.9.0
  with:
    target: ${{ secrets.STAGING_HOST }}
    ports: common
    fail-on-ports: '21,23,3389'
```

Inputs:
- `target` — IP, hostname, or CIDR (required)
- `ports` — `common`, `full`, range like `1-1024`, or list like `22,80,443`
- `scan-mode` — `tcp` (default), `udp`, `syn`, `stealth`
- `timeout` — per-port timeout in seconds
- `threads` — max concurrency
- `output-formats` — `html`, `csv`, or `html,csv` (JSON + SARIF always included)
- `upload-sarif` — upload to GitHub Security tab (default: true, needs `security-events: write`)
- `upload-artifacts` — upload reports as workflow artifacts (default: true)
- `fail-on-ports` — comma-separated ports that fail the workflow if open

Outputs: `open-ports`, `open-count`, `report-path`, `sarif-path`

**New module: `porthawk/sarif.py`**

- `build_sarif(report, version)` — builds a SARIF 2.1.0 document from a `ScanReport`
- Maps risk levels to SARIF severity: HIGH → error (8.5), MEDIUM → warning (5.5), LOW → note (2.0), unclassified → note (1.0)
- Attaches CVE IDs as `relatedLocations` when CVE lookup was run
- Logical locations point to `host:port/protocol` — clean Security tab entries without fake file refs

**Updated: `porthawk/reporter.py`**

- `save_sarif(report, output_path)` — writes SARIF to disk, same pattern as `save_json`/`save_html`

**Updated: CLI**

- `-o sarif` now works alongside `json`, `csv`, `html`
- Action uses `-o json,sarif` by default

**Public API:** `porthawk.build_sarif` added to `__all__`

**34 new tests in `tests/test_sarif.py`** — structure validation, risk→rule mapping, CVE relatedLocations, JSON serialisability, `save_sarif` file output

---

## [0.8.0] — 2026-03-26

### UDP Scanner

TCP scanners miss a lot. DNS, NTP, SNMP, NetBIOS, SSDP — all UDP. This adds a proper UDP scan module that sends protocol-specific payloads and validates responses. Not a simple "send empty bytes, wait for ICMP" — it actually speaks the protocols.

**New module: `porthawk/udp_scan.py`**

- `udp_scan_host(host, ports, timeout, max_concurrent, retries)` — async UDP scanner, returns flat `list[ScanResult]`
- `get_udp_top_ports(n)` — returns the top 20 UDP ports worth scanning on first recon pass

**Protocol-specific payloads (8 protocols):**
- **DNS** (53, 5353, 5355): A record query for google.com, validates QR bit in response
- **NTP** (123): v3 client request (48 bytes), validates mode field (4 or 5)
- **SNMP** (161): BER-encoded GetRequest for `sysDescr.0` (OID 1.3.6.1.2.1.1.1.0), community "public"
- **SSDP** (1900): M-SEARCH `ssdp:all`, validates HTTP/1.1 response header
- **NetBIOS** (137): NBSTAT query for wildcard `"*"`, nibble-encoded per RFC 1001
- **mDNS** (5353, 5355): PTR query for `_services._dns-sd._udp.local`, QU bit set
- **TFTP** (69): RRQ for "motd" — even a "file not found" error proves the service is up
- **IKE** (500, 4500): minimal v1 informational exchange, 28 bytes

**ICMP unreachable detection:**
- Linux: `OSError(errno=111)` on the socket → port is `CLOSED`
- Windows: `ConnectionResetError` → port is `CLOSED`
- No response after retries → `FILTERED` (firewall or host just ignores it)

**Timeout handling:**
- 1 retry by default — UDP is lossy, one miss isn't conclusive
- `asyncio.Semaphore` caps concurrency at 50 by default (UDP stacks get unhappy above that)
- Per-port wait: `timeout * (retries + 1) + 1.0` — outer asyncio timeout prevents hung tasks

**Banner extraction:**
- NTP: stratum, reference ID, version
- SNMP: decodes sysDescr string from BER response
- SSDP: extracts `Server:` and `USN:` headers
- TFTP: translates opcode (ACK, DATA, ERROR) to human string
- DNS/NetBIOS: service name
- Generic: first 40 printable bytes

**Unvalidated responses:**
- If a response arrives but fails the protocol validator, port is still marked `OPEN` but banner is prefixed with `"unvalidated:"` — better than false negatives

**CLI:**
- `--udp` now routes through `udp_scan_host()` instead of the old generic UDP path
- `--udp` without `-p` defaults to `get_udp_top_ports()` (top 20 UDP ports)
- Concurrency capped at 50 for UDP regardless of `--threads`

**Public API:**
- `porthawk.udp_scan_host` — in `__all__`
- `porthawk.get_udp_top_ports` — in `__all__`

**97 new tests in `tests/test_udp_scan.py`** — payload encoding, response validators, banner extraction, probe retry logic, full scan orchestration

---

## [0.7.0] — 2026-03-26

### Passive OS Fingerprinting

- `porthawk.passive_os_scan(host, port, timeout)` — sends one SYN, reads the SYN-ACK, identifies OS
- `porthawk.fingerprint_os(raw_pkt)` — classify OS from any raw IP+TCP packet bytes
- `porthawk.ttl_only_os(ttl)` — lightweight fallback: TTL→OS guess, always returns `OsMatch` with LOW confidence
- `OsFingerprint` dataclass — extracted features: TTL, window size, DF bit, MSS, wscale, has_timestamp, has_sack, opt_order
- `OsMatch` dataclass — result: os_family, os_detail, confidence (HIGH/MEDIUM/LOW), score (0.0–1.0), matched_signals, method

**Signature database (16 entries):**
- Windows: 10/11, 7/8, XP
- Linux: 4.x, 5.x, 6.x, embedded
- Android 8.x–14.x
- macOS: 12–14, 10.x–11.x
- iOS 14–17
- FreeBSD 12–14, OpenBSD 7.x
- Network devices: Cisco IOS, IOS XE, HP JetDirect, Generic RTOS

**Two-layer classifier:**
- Rule-based scoring: TTL family (0.35 weight), window size exact/near (0.22/0.08), DF bit (0.06), TCP option presence (0.15), option order (0.10), wscale (0.07), MSS (0.03)
- KNN in 7-dimensional feature space: [ttl_norm, win_norm, mss_norm, ws_norm, has_ts, has_sack, df_bit]
- Blended score: 60% rule-based + 40% KNN — KNN uses sklearn if available, pure Python fallback otherwise

**Transport dispatch:**
- Scapy: sends SYN, captures SYN-ACK, sends RST to clean up
- Raw sockets: Linux/macOS with root, manual packet construction
- Falls back to `ttl_only_os` on Windows without Scapy

**CLI flag:**
- `--passive-os` — TCP fingerprint OS detection; falls back to TTL ping if raw sockets unavailable

**74 new tests in `tests/test_passive_os.py`** — all mocked, no root required

---

## [0.6.0] — 2026-03-26

### IDS/IPS Evasion Engine

- `porthawk.evasion_scan_host(host, ports, config, timeout, max_concurrent)` — async evasion scanner
- `EvasionConfig` dataclass: scan type, jitter settings, fragmentation, decoys, TTL, IP ID randomization
- `slow_low_config()` — red-team preset: 5–30s exponential jitter, 8-byte IP fragments, TTL=128

**Scan types (TCP flag combinations):**
- `syn` — standard SYN scan (SYN-ACK=OPEN, RST=CLOSED, no reply=FILTERED)
- `fin` — FIN-only (RFC 793: RST=CLOSED, no reply=OPEN — open ports silently discard)
- `null` — no flags set (same semantics as FIN)
- `xmas` — FIN+PSH+URG (0x29, "all the lights on") — same semantics as FIN
- `ack` — ACK-only (maps stateless firewall rules: RST=unfiltered, no reply=filtered)
- `maimon` — FIN+ACK (Uriel Maimon's 1996 trick — works on some BSD stacks)

**Timing jitter:**
- Uniform distribution: random delay in [min_delay, max_delay]
- Exponential distribution: Poisson-like inter-arrivals — statistically indistinguishable from real user traffic
- Pre-probe sleep (before semaphore acquire) means jitter applies regardless of concurrency level

**IP fragmentation:**
- Raw socket path: manual IP fragment headers with correct MF bit and 8-byte-aligned offsets
- Scapy path: `scapy.all.fragment()` for reliable cross-platform fragmentation
- All fragments share the same IP ID (required for target reassembly)
- Splits TCP header across multiple IP fragments — defeats IDS engines that only inspect the first fragment

**Decoy scans (Scapy only):**
- Sends spoofed probe packets from each decoy IP before the real probe
- Target sees scans from multiple hosts simultaneously, obscuring the real scanner
- Irregular spacing between decoys (random 50–300ms) to avoid burst detection

**Packet-level tweaks:**
- `ttl=128` in `slow_low_config()` to look like a Windows host (confuses passive OS fingerprinting)
- `randomize_ip_id=True` — random IP ID defeats some passive fingerprinting

**CLI flags:**
- `--slow-low` — full red-team preset
- `--evasion-type [syn|fin|null|xmas|ack|maimon]` — TCP flag combo
- `--jitter FLOAT` — max random delay in seconds
- `--fragment` — enable IP fragmentation
- `--decoys "IP1,IP2,..."` — comma-separated decoy IPs (Scapy required)
- 78 new tests in `tests/test_evasion.py` — all mocked, no root required

---

## [0.5.0] — 2026-03-26

### SYN Scan (half-open TCP)

- `syn_scan_host(host, ports, timeout, max_concurrent)` — async SYN scanner, returns `list[ScanResult]` identical in structure to regular TCP results
- Half-open handshake: sends SYN, reads SYN-ACK (OPEN) or RST (CLOSED), sends RST to tear down — no full TCP connection established
- Two backends: Scapy (preferred, cross-platform) and raw socket fallback (Linux/macOS only)
- Scapy backend: `IP/TCP` packet with `flags="S"`, uses `sr1()` for single-response capture, sends RST on SYN-ACK via `send()`
- Raw socket backend: hand-crafted IP+TCP headers with RFC 1071 checksum math, `IP_HDRINCL` for full header control, deadline-loop response capture
- `_internet_checksum()`: RFC 1071 one's complement sum with carry folding and odd-byte padding
- `_tcp_checksum()`: pseudo-header method per RFC 793 (src_ip, dst_ip, zero, proto=6, tcp_len)
- `_get_source_ip()`: UDP connect trick — `sock.connect((host, 80)); getsockname()[0]` — routes correctly through VPNs and multiple NICs
- `get_syn_backend()` — returns human-readable string describing active backend and Scapy version if available
- Platform handling: Windows blocks raw TCP sends since XP SP2 — Scapy + Npcap required, clear error with install instructions
- `_has_raw_socket_privilege()`: `IsUserAnAdmin()` on Windows, `os.getuid() == 0` elsewhere
- `_require_privileges()` raises `ScanPermissionError` with OS-specific install instructions
- `--syn` CLI flag — half-open scan with `min(threads, 100)` concurrency cap, prints active backend
- `pip install porthawk[syn]` optional dependency group (scapy>=2.5)
- `porthawk.syn_scan_host`, `porthawk.get_syn_backend` exported from public API
- 41 new tests in `tests/test_syn_scan.py` — all network calls mocked, no root required

---

## [0.4.0] — 2026-03-26

### Adaptive Scan Speed

- `AdaptiveSemaphore` — drops in place of `asyncio.Semaphore`, adjusts concurrency limit at runtime based on observed network conditions
- AIMD control loop: additive increase every N clean probes, multiplicative decrease (×0.5) when timeout ratio exceeds threshold
- RFC 6298 RTT smoothing: SRTT via EWMA (α=0.125), RTTVAR via EWMA (β=0.25) — same math as TCP retransmit timer
- High RTTVAR hold: if jitter exceeds `rttvar_threshold`, increases pause until the network settles
- Decrease cooldown: prevents thrash — minimum gap between consecutive decreases
- `NetworkStats`: sliding window (configurable size) tracking per-probe timeout flag and latency; computes `timeout_ratio` and exposes `srtt`/`rttvar` for monitoring
- `AdaptiveConfig` dataclass: all AIMD tuning knobs with sensible defaults (initial=25, min=5, ai_step=2, md_factor=0.5, timeout_threshold=0.30, rttvar_threshold=80ms)
- `--adaptive` CLI flag: starts at 25 concurrent, ramps toward `--threads` limit (default 500)
- `scan_host()` and `scan_targets()` accept `adaptive_config: AdaptiveConfig | None` — pass `None` (default) to keep existing fixed-concurrency behavior
- `AdaptiveConfig`, `AdaptiveSemaphore`, `NetworkStats` exported from public API
- 35 new tests in `tests/test_throttle.py`

---

## [0.3.0] — 2026-03-26

### Honeypot Detection

- `porthawk.score_honeypot(results)` — returns a `HoneypotReport` with a 0.0–1.0 score and list of triggered indicators
- Cowrie SSH detection: exact banner match against known Cowrie default strings (EOL Debian/Ubuntu SSH versions)
- Dionaea FTP detection: `"220 DiskStation FTP server ready."` banner match — hardcoded in Dionaea's FTP emulator
- Conpot ICS detection: flags hosts with Modbus (502), S7 (102), BACnet (47808), EtherNet/IP (44818), DNP3 (20000), OPC-UA (4840) ports open
- T-Pot port flood detection: >20 open ports = moderate signal, >40 = strong signal
- Telnet (port 23) presence check
- SSH multi-port check: same banner version on port 22 and alternate ports
- Service diversity check: 6+ different service categories simultaneously active
- Latency uniformity check: CV < 0.05 across 5+ ports suggests software emulation
- Score combination via `1 - product(1 - w_i)` — no single indicator maxes the score
- Verdicts: `< 0.25` → LIKELY_REAL, `0.25–0.55` → SUSPICIOUS, `> 0.55` → LIKELY_HONEYPOT
- `--honeypot` CLI flag — runs scorer after scan and prints result with Rich formatting
- `porthawk.HoneypotReport`, `porthawk.Indicator` exported from public API
- 49 new tests in `tests/test_honeypot.py`

---

## [0.2.0] — 2026-03-26

### Service Detection

- Protocol-aware banner grabbing with version extraction for SSH, FTP, SMTP, POP3, IMAP, VNC, MySQL, Redis, Memcached
- Services that speak first (SSH, FTP, MySQL, VNC) are read directly without sending a probe
- Protocol-specific probes for Redis (`PING\r\n`), Memcached (`stats\r\n`), and others
- MySQL version via binary handshake parsing (protocol v10, null-terminated version string at byte 5)
- Redis version via `PING` → `+PONG` confirm, then `INFO server` for exact `redis_version:`
- Named regex version patterns for 8 banner formats — first match wins, clean version string extracted
- `service_version` field on `ScanResult` — structured version string separate from raw banner

### CVE Lookup

- `--cve` flag queries NVD API v2.0 for CVEs per open service, sorted by CVSS score
- Version-aware keyword building: "OpenSSH_8.9p1" → search "OpenSSH 8.9" instead of just "ssh"
- Two-layer cache: in-memory (per process) + disk (`~/.porthawk/cve_cache.json`, 24h TTL)
- Separate lookups per (service, version) pair — different OpenSSH versions on the same network each get their own results
- `NVD_API_KEY` env var support — raises limit from 5 req/30s to 50 req/30s
- CVE column in terminal output and HTML report (clickable NVD links, color-coded by severity)
- `porthawk.scan(..., cve_lookup=True)` and `Scanner.scan(..., cve_lookup=True)` for programmatic use
- `porthawk.CVEInfo` model in the public API

### ML Port Prioritization

- `--smart-order` flag reorders ports by predicted open probability before scanning
- Logistic regression trained on nmap-services frequency data from internet-wide scans
- Context-aware: private IP ranges boost SMB/RDP, Linux TTL hint boosts SSH/databases, Windows hint boosts RDP/SMB
- Falls back to frequency-table scoring if scikit-learn is not installed
- `pip install porthawk[ml]` optional dependency group (scikit-learn + numpy)

### Live Terminal UI

- Rich `Live` display with progress bar, live open-ports table, and timestamped event log
- `--no-live` flag to fall back to tqdm output (for scripts, pipes, CI)
- Auto-disabled when stdout is not a TTY — pipe-safe by default

### Public Python API

- `porthawk.scan()` — async function, returns `list[ScanResult]`
- `porthawk.Scanner` — async context manager for repeated scans against the same target
- `porthawk.build_report()`, `porthawk.reporter.save_html/json/csv()`
- Custom exception hierarchy: `PortHawkError`, `InvalidTargetError`, `InvalidPortSpecError`, `ScanPermissionError`, `ScanTimeoutError`

---

## [0.1.0] — 2026-03-25

### Added

- Async TCP port scanner using `asyncio.open_connection()` with configurable semaphore
- UDP scanning via raw sockets with ICMP unreachable detection (requires root/admin)
- CIDR range expansion — scan `192.168.1.0/24` directly
- Port range parsing — supports `1-1024`, `22,80,443`, and mixed formats
- OS fingerprinting from TTL via `ping` subprocess — Linux/Unix, Windows, Network Device
- Banner grabbing — raw TCP banners for SSH/FTP/SMTP, HTTP header grabbing for web ports
- SSH version extraction from banner strings (e.g. `OpenSSH_8.9p1`)
- Service database with ~200 ports including service names and descriptions
- Risk scoring — HIGH / MEDIUM / LOW per port based on real-world attack surface
- Terminal output using `rich` — color-coded by risk level, sortable
- JSON report with full metadata and all scan results
- CSV report importable into Splunk, Excel, SIEM tools
- Self-contained HTML report with embedded CSS, sortable table, PortHawk branding
- CLI via `typer` with `--common`, `--top-ports N`, `--full`, `--stealth` modes
- `--banners` flag for post-scan banner grabbing on open ports
- `--os` flag for OS detection via TTL
- `--udp` flag for UDP scanning (admin/root required)
- `--stealth` mode — single-threaded, 3s timeout, minimal noise
- Timestamp-based report filenames — no overwriting previous results
- Full test suite with `pytest` — zero real network connections (all mocked)
- GitHub Actions CI pipeline — matrix: Python 3.10, 3.11, 3.12
- MITRE ATT&CK mapping in README (T1046, T1595.001, T1592.004)

### Technical Notes

- Replaced argparse with `typer` for better UX and auto-generated help
- Used `pydantic` BaseModel for ScanResult, ServiceInfo, ScanReport (free JSON serialization)
- Used `httpx` instead of urllib for async-compatible HTTP banner grabbing
- Used `jinja2` templates for HTML report instead of f-strings
- Added `pytest-asyncio` for async test support
