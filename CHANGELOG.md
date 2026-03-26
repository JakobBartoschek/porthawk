# Changelog

All notable changes to PortHawk are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)

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
