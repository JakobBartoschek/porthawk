# Changelog

All notable changes to PortHawk are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)

---

## [Unreleased]

### Added
- CVE lookup via NVD API v2.0 — `--cve` flag attaches top CVEs (sorted by CVSS score) to each open service
- In-memory CVE cache per service name — one API call per unique service, not per open port
- `NVD_API_KEY` env var support — set it to remove inter-request delays (50 req/30s vs 5)
- `porthawk.CVEInfo` model in the public API
- `porthawk.scan(..., cve_lookup=True)` and `Scanner.scan(..., cve_lookup=True)` for programmatic CVE lookups
- CVE column in HTML report — clickable NVD links, color-coded by severity
- CVE column in terminal output when `--cve` is passed — shows top CVE ID + CVSS score
- Public Python API (`porthawk.scan()`, `porthawk.Scanner`) — use PortHawk as a library
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
