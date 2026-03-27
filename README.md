```
██████╗  ██████╗ ██████╗ ████████╗██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗
██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██║  ██║██╔══██╗██║    ██║██║ ██╔╝
██████╔╝██║   ██║██████╔╝   ██║   ███████║███████║██║ █╗ ██║█████╔╝
██╔═══╝ ██║   ██║██╔══██╗   ██║   ██╔══██║██╔══██║██║███╗██║██╔═██╗
██║     ╚██████╔╝██║  ██║   ██║   ██║  ██║██║  ██║╚███╔███╔╝██║  ██╗
╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝

         Async port scanner. Authorized targets only.
```

[![CI](https://github.com/JakobBartoschek/porthawk/actions/workflows/ci.yml/badge.svg)](https://github.com/JakobBartoschek/porthawk/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Authorized Use Only](https://img.shields.io/badge/use-authorized%20targets%20only-red)](DISCLAIMER.md)

PortHawk is an async TCP/UDP port scanner written in pure Python. It scans ports, extracts
service versions from banners, looks up CVEs for what it finds, and outputs results as a
live terminal UI, JSON, CSV, or a self-contained HTML report. No nmap, no external binaries.

---

## Features

- **Web dashboard** — Streamlit UI for non-technical users. Sidebar settings, live scan, Altair charts, PyVis network graph, diff view, one-click report download. No CLI needed. (`pip install porthawk[dashboard]`, then `python start_dashboard.py`)
- **Async TCP scanning** via `asyncio` — 500 concurrent connections by default, configurable
- **UDP scanning** — protocol-specific payloads for DNS, NTP, SNMP, SSDP, NetBIOS, mDNS, IKE, TFTP. Validates responses, extracts banners. ICMP unreachable detection for closed ports. Defaults to top 20 UDP ports.
- **Nmap XML import + diff** — load any Nmap `-oX` output and compare two scans to see what changed: new open ports, gone services, version upgrades. Works with PortHawk JSON too.
- **GitHub Action** — drop `uses: jakobbartoschek/porthawk@v1.0.0` into any workflow. Scan a host, get open ports in the Security tab as SARIF alerts, download reports as artifacts.
- **SARIF output** — `-o sarif` writes a SARIF 2.1.0 file. Open ports become Security tab alerts with risk severity mapped to SARIF levels.
- **OS fingerprinting** from TTL value — Linux/Unix, Windows, Network Device
- **Service detection** — protocol-aware banner grabbing with version extraction for SSH, FTP, SMTP, POP3, IMAP, VNC, MySQL, Redis, Memcached
- **CVE lookup** via NVD API — version-aware: "OpenSSH 8.9" returns relevant CVEs, not just everything tagged "ssh". Two-layer cache (in-memory + disk, 24h TTL) to stay within rate limits
- **ML port prioritization** — logistic regression trained on internet-wide scan frequencies, adjusts for private IP ranges and OS hint (`pip install porthawk[ml]`)
- **Honeypot detection** — scores a host 0.0–1.0 for honeypot likelihood based on banner signatures (Cowrie, Dionaea), ICS port patterns (Conpot), port count (T-Pot), latency uniformity, and more
- **Adaptive scan speed** — AIMD concurrency control: starts conservative, ramps up on stable networks, backs off when timeouts spike. RFC 6298 SRTT/RTTVAR for jitter detection.
- **SYN scan (half-open)** — raw SYN packets without completing the TCP handshake. Uses Scapy when available, falls back to Linux raw sockets. Requires root/admin. (`pip install porthawk[syn]`)
- **IDS/IPS evasion** — "Slow & Low" mode for red-team scenarios: IP fragmentation, exponential timing jitter, decoy source IPs, custom TCP flag combos (FIN, NULL, XMAS, ACK, Maimon)
- **Passive OS fingerprinting** — TCP/IP stack analysis from SYN-ACK responses: TTL, window size, MSS, TCP options, DF bit. Rule-based scoring + KNN classifier, 16-entry signature database (Windows, Linux, macOS, BSD, network devices). >80% OS family accuracy.
- **Service database** — ~200 common ports with names and descriptions
- **Risk scoring** — HIGH / MEDIUM / LOW per open port based on real-world exposure risk
- **Live terminal UI** — progress bar + live-updating open ports table + event log during scan
- **Multi-format output** — Rich terminal table, JSON, CSV, self-contained HTML
- **CIDR support** — scan `192.168.1.0/24` and it expands automatically
- **Stealth mode** — single-threaded, 3s timeout, less noise on the wire
- **Top N ports** — skip the 65535 full scan and focus on what matters
- **Python API** — `await porthawk.scan(...)` for programmatic use

---

## Architecture

```mermaid
flowchart TD
    CLI["cli.py"]
    API["api.py"]
    SCAN["scanner.py"]
    FP["fingerprint.py"]
    PRED["predictor.py"]
    SDB["service_db.py"]
    CVE["cve.py"]
    HP["honeypot.py"]
    TH["throttle.py"]
    SYN["syn_scan.py"]
    EXC["exceptions.py"]
    REP["reporter.py"]
    OUT_JSON["JSON"]
    OUT_CSV["CSV"]
    OUT_HTML["HTML"]
    OUT_TERM["Terminal"]

    CLI --> PRED
    CLI --> SCAN
    CLI --> CVE
    CLI --> HP
    CLI --> TH
    CLI --> SYN
    API --> SCAN
    SCAN --> TH
    API --> CVE
    API --> EXC
    SCAN --> FP
    SCAN --> SDB
    FP --> REP
    SDB --> REP
    CVE --> REP
    HP --> REP
    REP --> OUT_JSON
    REP --> OUT_CSV
    REP --> OUT_HTML
    REP --> OUT_TERM
```

---

## Installation

```bash
pip install porthawk
```

With ML port prioritization (scikit-learn):

```bash
pip install porthawk[ml]
```

With SYN scan support (Scapy):

```bash
pip install porthawk[syn]
```

Or from source:

```bash
git clone https://github.com/JakobBartoschek/porthawk
cd porthawk
pip install .
```

---

## Usage

**Scan top 100 ports on a single host:**
```bash
porthawk -t 192.168.1.1 --common
```

**Service version detection + OS fingerprint:**
```bash
porthawk -t 192.168.1.1 --common --banners --os
```

**CVE lookup — what's actually exploitable on the open ports:**
```bash
porthawk -t 192.168.1.1 --common --banners --cve
```

**Save to JSON and HTML:**
```bash
porthawk -t 192.168.1.1 -p 1-1024 --banners --cve -o json,html
```

**Scan a /24 network, top 50 ports:**
```bash
porthawk -t 192.168.1.0/24 --top-ports 50
```

**Full port scan with custom timeout:**
```bash
porthawk -t scanme.nmap.org --full --timeout 2.0 --threads 200
```

**Stealth mode with ML port ordering — likely-open ports first:**
```bash
porthawk -t 10.0.0.1 --common --stealth --smart-order
```

**Check if the target looks like a honeypot:**
```bash
porthawk -t 10.0.0.1 --common --banners --honeypot
```

**Adaptive scan — ramps up concurrency automatically:**
```bash
porthawk -t 192.168.1.1 -p 1-1024 --adaptive
```

**Half-open SYN scan (requires admin/root + Scapy or Linux):**
```bash
sudo porthawk -t 192.168.1.1 --common --syn
```

**Slow & Low — red-team evasion mode:**
```bash
sudo porthawk -t 192.168.1.1 --common --slow-low
```

**XMAS scan with 5-second jitter:**
```bash
sudo porthawk -t 192.168.1.1 -p 80,443 --evasion-type xmas --jitter 5.0
```

**Decoy scan — hide among fake source IPs:**
```bash
sudo porthawk -t 192.168.1.1 --common --slow-low --decoys "1.2.3.4,5.6.7.8"
```

**Passive OS fingerprinting — TCP stack analysis from SYN-ACK:**
```bash
sudo porthawk -t 192.168.1.1 --common --passive-os
```

**UDP scan — protocol-aware, defaults to top 20 UDP ports:**
```bash
# Top 20 UDP ports with protocol-specific payloads
porthawk -t 192.168.1.1 --udp

# Specific ports only
porthawk -t 192.168.1.1 --udp -p 53,123,161,1900

# Slower networks — bump the timeout
porthawk -t 192.168.1.1 --udp --timeout 3.0
```

**Compare two scans — see what changed between Monday and Friday:**
```bash
# Both PortHawk JSON and Nmap XML work
porthawk diff scan_monday.json scan_friday.json

# Include ports that didn't change (omitted by default — usually just noise)
porthawk diff scan_a.json scan_b.json --show-stable

# Exit with code 1 if any new open ports appear (useful in CI)
porthawk diff baseline.json current.json --exit-on-new

# Only show new ports
porthawk diff baseline.json current.json --only-new

# Save the diff as JSON
porthawk diff scan_a.json nmap_output.xml -o diff_report.json

# Mix formats — compare an old PortHawk scan against a fresh Nmap run
porthawk diff last_month.json nmap -oX current.xml 192.168.1.1; porthawk diff last_month.json current.xml
```

**Load Nmap XML directly (programmatic):**
```python
from porthawk import load_results, compute_diff

old = load_results("baseline.json")      # PortHawk JSON
new = load_results("nmap_output.xml")    # Nmap -oX

diff = compute_diff(old, new, label_a="baseline", label_b="current")
print(f"New open ports: {len(diff.new_ports)}")
for change in diff.new_ports:
    print(change.describe())
```

**Web dashboard — no CLI needed, works on Windows/macOS/Linux:**
```bash
pip install porthawk[dashboard]

# Windows — double-click start_dashboard.bat, or:
python start_dashboard.py

# macOS / Linux:
./start_dashboard.sh
# or: porthawk-dashboard
```

Opens at `http://localhost:8501` in your browser. Enter a target in the sidebar, hit **Start Scan**, results appear in the Results tab. Charts and the network graph fill in automatically. The Diff tab lets you upload two scan files and compare them.

**Disable the live UI (for scripts, pipes, CI):**
```bash
porthawk -t 192.168.1.1 --common --no-live
```

**Set NVD_API_KEY to remove rate limiting (free at nvd.nist.gov):**
```bash
NVD_API_KEY=your-key porthawk -t 192.168.1.1 --common --cve --banners
```

**Example terminal output (with `--banners --cve`):**
```
PortHawk — scanning 192.168.1.1 (1 host, 100 ports, TCP)

  ┏━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃ Port      ┃ State    ┃ Service    ┃ Risk     ┃ Banner             ┃ Top CVE                  ┃
  ┡━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━┩
  │ 22/tcp    │ open     │ ssh        │ MEDIUM   │ SSH OpenSSH_8.9p1  │ CVE-2023-38408 (9.8)     │
  │ 80/tcp    │ open     │ http       │ LOW      │ server: nginx/1.24 │ CVE-2023-44487 (7.5)     │
  │ 443/tcp   │ open     │ https      │ LOW      │ HTTP 200           │ —                        │
  │ 3306/tcp  │ open     │ mysql      │ MEDIUM   │ MySQL 8.0.33       │ CVE-2023-22005 (4.9)     │
  │ 6379/tcp  │ open     │ redis      │ HIGH     │ Redis 7.0.11       │ CVE-2022-0543 (10.0)     │
  └───────────┴──────────┴────────────┴──────────┴────────────────────┴──────────────────────────┘
  Open: 5 / 100 scanned
```

---

## Python API

PortHawk works as a library. No CLI required.

```python
import asyncio
import porthawk

# Full scan with banners and CVE lookup
results = asyncio.run(porthawk.scan(
    "192.168.1.1",
    ports="common",
    banners=True,
    cve_lookup=True,
))

for r in results:
    version = r.service_version or "unknown version"
    top_cve = r.cves[0]["cve_id"] if r.cves else "—"
    print(f"{r.port}/{r.protocol}  {r.service_name}  {version}  {top_cve}")
```

```python
# Context manager — same target, multiple scans
async with porthawk.Scanner("192.168.1.1", timeout=2.0) as scanner:
    web   = await scanner.scan(ports="80,443,8080,8443", banners=True)
    infra = await scanner.scan(ports="22,3306,5432,6379", cve_lookup=True)
```

```python
# Build a report and export
report    = porthawk.build_report("192.168.1.1", results)
html_path = porthawk.reporter.save_html(report)
```

```python
# Check if a host looks like a honeypot
hp = porthawk.score_honeypot(results)
print(f"{hp.verdict}  score={hp.score:.2f}  confidence={hp.confidence}")
for ind in hp.indicators:
    print(f"  [{ind.weight:.2f}] {ind.name}: {ind.description}")
```

```python
# Half-open SYN scan (requires root/admin)
results = asyncio.run(porthawk.syn_scan_host("192.168.1.1", [22, 80, 443], timeout=1.0))
print(porthawk.get_syn_backend())  # e.g. "scapy 2.5.0" or "raw socket (Linux)"
```

```python
# Slow & Low evasion scan — red-team preset (requires root/admin)
cfg = porthawk.slow_low_config()
cfg.decoys = ["1.2.3.4", "5.6.7.8"]  # optional: add decoy IPs

results = asyncio.run(
    porthawk.evasion_scan_host("192.168.1.1", [22, 80, 443], config=cfg, max_concurrent=2)
)

# custom config — XMAS scan with 10s max jitter and IP fragmentation
cfg = porthawk.EvasionConfig(scan_type="xmas", max_delay=10.0, fragment=True)
results = asyncio.run(porthawk.evasion_scan_host("192.168.1.1", [80, 443], config=cfg))
```

```python
# Passive OS fingerprinting — analyze one SYN-ACK response (requires root/admin or Scapy)
match = porthawk.passive_os_scan("192.168.1.1")
if match:
    print(f"{match.os_family}  {match.os_detail}  confidence={match.confidence}")
    # e.g. "Windows  Windows 10 / 11 / Server 2019+  confidence=HIGH"

# Classify OS from raw packet bytes (e.g. from your own capture)
raw_pkt = bytes(...)  # raw IP+TCP bytes
match = porthawk.fingerprint_os(raw_pkt)

# TTL-only fallback — no privileges needed, always LOW confidence
match = porthawk.ttl_only_os(64)  # → "Linux/Unix"
```

```python
# UDP scan — protocol-specific payloads, ICMP unreachable detection
results = asyncio.run(
    porthawk.udp_scan_host("192.168.1.1", ports=[53, 123, 161, 1900], timeout=2.0)
)
for r in results:
    print(r.port, r.state, r.banner)
    # e.g. 53 OPEN "DNS"
    # e.g. 123 OPEN "NTP stratum=2 refid=GPS"

# Default top 20 UDP ports (DNS, NTP, SNMP, NetBIOS, SSDP, IKE, mDNS, ...)
ports = porthawk.get_udp_top_ports()
results = asyncio.run(porthawk.udp_scan_host("192.168.1.1", ports=ports))
```

Full API reference: [`docs/api.md`](docs/api.md)

---

## GitHub Action

Run PortHawk in any GitHub Actions workflow. Open ports appear in the **Security tab** as code scanning alerts.

```yaml
# .github/workflows/port-scan.yml
name: Port Scan

on:
  schedule:
    - cron: '0 6 * * 1'   # every Monday at 06:00
  workflow_dispatch:

permissions:
  security-events: write   # needed for SARIF upload

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan staging server
        uses: jakobbartoschek/porthawk@v0.9.0
        with:
          target: ${{ secrets.STAGING_HOST }}
          ports: common
          fail-on-ports: '21,23,3389'   # fail if FTP, Telnet, or RDP is open

      - name: Scan with UDP
        uses: jakobbartoschek/porthawk@v0.9.0
        with:
          target: ${{ secrets.STAGING_HOST }}
          scan-mode: udp
          timeout: '2.0'
          output-formats: html
```

The action uploads scan reports as workflow artifacts and pushes a SARIF file to the Security tab automatically. No extra steps needed.

**Inputs:**

| Input | Default | Description |
|-------|---------|-------------|
| `target` | — | IP, hostname, or CIDR (required) |
| `ports` | `common` | `common`, `full`, range, or list |
| `scan-mode` | `tcp` | `tcp`, `udp`, `syn`, `stealth` |
| `timeout` | `1.0` | Per-port timeout in seconds |
| `threads` | `100` | Max concurrent connections |
| `output-formats` | — | `html`, `csv`, or `html,csv` |
| `upload-sarif` | `true` | Push to GitHub Security tab |
| `upload-artifacts` | `true` | Upload reports as artifacts |
| `fail-on-ports` | — | Ports that fail the workflow if open |

**Outputs:** `open-ports`, `open-count`, `report-path`, `sarif-path`

---

## Example Output (JSON)

```json
{
  "metadata": {
    "target": "192.168.1.1",
    "scan_time": "2026-03-26T14:30:00",
    "total_ports": 100,
    "open_ports": 5,
    "protocol": "tcp",
    "version": "0.9.0",
    "timeout": 1.0,
    "max_concurrent": 500
  },
  "results": [
    {
      "host": "192.168.1.1",
      "port": 22,
      "protocol": "tcp",
      "state": "open",
      "banner": "SSH OpenSSH_8.9p1",
      "service_name": "ssh",
      "service_version": "OpenSSH_8.9p1",
      "risk_level": "MEDIUM",
      "os_guess": "Linux/Unix",
      "ttl": 64,
      "latency_ms": 0.8,
      "cves": [
        {
          "cve_id": "CVE-2023-38408",
          "cvss_score": 9.8,
          "severity": "CRITICAL",
          "description": "Remote code execution in ssh-agent...",
          "published": "2023-07-19",
          "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-38408"
        }
      ]
    }
  ]
}
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | TCP/UDP port scanning to identify open services |
| Active Scanning: Scanning IP Blocks | [T1595.001](https://attack.mitre.org/techniques/T1595/001/) | CIDR range scanning across IP blocks |
| Gather Victim Host Info: Client Configurations | [T1592.004](https://attack.mitre.org/techniques/T1592/004/) | OS fingerprinting via TTL, banner-based version detection |

---

## Testing

```bash
# Install test dependencies
pip install -r requirements-dev.txt

# Run tests with coverage
pytest tests/ --cov=porthawk --cov-report=term-missing

# Run a specific test file
pytest tests/test_scanner.py -v

# Run with short output
pytest tests/ --tb=short
```

Coverage target: **>90%** on all modules.
All network calls are mocked — tests run without any real connections.

---

## Roadmap

- [x] CVE lookup via NVD API per detected service/version
- [x] Version-aware service detection (SSH, FTP, MySQL, Redis, ...)
- [x] ML port prioritization via logistic regression
- [x] Persistent CVE disk cache with TTL
- [x] Honeypot detection — score-based detection for Cowrie, Dionaea, Conpot, T-Pot
- [x] Adaptive scan speed — AIMD concurrency control with RFC 6298 RTT smoothing
- [x] SYN scan — half-open TCP via Scapy or raw sockets
- [x] IDS/IPS evasion — Slow & Low mode: IP fragmentation, jitter, decoys, custom TCP flags
- [x] Passive OS fingerprinting — TCP stack analysis from SYN-ACK, rule-based + KNN classifier
- [x] UDP scanning — protocol-specific payloads, ICMP unreachable detection, 8 protocols
- [x] GitHub Action — `uses: jakobbartoschek/porthawk@v1.0.0`, SARIF to Security tab, artifact upload
- [x] Nmap XML import and diff/compare mode — `porthawk diff a.json b.xml`, new/gone/changed detection
- [x] Web dashboard — Streamlit, `pip install porthawk[dashboard]`, one-click launchers for all platforms
- [ ] Slack and Discord webhook alerts for HIGH-risk open ports
- [ ] IPv6 support

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions, branch naming,
code style, and how to write a good PR.

---

## Legal

PortHawk is for **authorized penetration testing only**.
You must have written permission from the target owner before scanning.
Unauthorized port scanning may violate the CFAA (USA), Computer Misuse Act (UK),
§202a StGB (Germany), and equivalent laws in your jurisdiction.

See [DISCLAIMER.md](DISCLAIMER.md) for the full legal disclaimer.

---

## License

MIT License — see [LICENSE](LICENSE) file.
