# Changelog

All notable changes to PortHawk are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)

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
