# PortHawk Usage Examples

Practical examples for common scenarios. All examples assume `porthawk` is installed
and you have authorization to scan the target.

---

## 1. Quick Recon on a Single Host

**Scenario:** You've got a target IP in a pentest scope. First pass, top 100 ports.

```bash
porthawk -t 192.168.1.100 --common
```

What happens:
- Scans the top 100 most commonly targeted ports
- Live UI shows open ports as they're found
- Shows service names and risk levels in terminal
- No files written (add `-o json` if you want to save)

Expected output:
```
PortHawk — scanning 192.168.1.100 (1 host, 100 ports, TCP)

  Port       State     Service     Risk     Banner
  22/tcp     open      ssh         MEDIUM
  80/tcp     open      http        LOW
  3306/tcp   open      mysql       MEDIUM

  Open: 3 / 100 scanned
```

---

## 2. Service Version Detection

**Scenario:** You found open ports. Now you want to know what software is actually running.

```bash
porthawk -t 192.168.1.100 --common --banners
```

What happens:
- Runs port scan first
- After scan, connects to each open port with protocol-specific probes
- SSH: reads banner directly, extracts version
- MySQL/Redis: binary handshake or protocol exchange to get exact version
- HTTP: HEAD request, grabs Server and X-Powered-By headers

Expected output:
```
  22/tcp     open    ssh      MEDIUM   SSH OpenSSH_8.9p1
  80/tcp     open    http     LOW      server: nginx/1.24.0
  3306/tcp   open    mysql    MEDIUM   MySQL 8.0.33
  6379/tcp   open    redis    HIGH     Redis 7.0.11
```

Supported protocols: SSH, FTP, SMTP, POP3, IMAP, VNC, MySQL, Redis, Memcached, HTTP/HTTPS.

---

## 3. OS Fingerprinting

**Scenario:** You want to know if this is a Windows or Linux box before going further.

```bash
porthawk -t 192.168.1.100 --common --os
```

Works by pinging the target and reading the TTL value from the response:
- TTL ≤ 64: Linux/Unix
- TTL ≤ 128: Windows
- TTL ≤ 255: Network Device (Cisco/HP)

This is a rough heuristic — VPNs and routing hops will shift the value. Don't trust it blindly.

---

## 4. CVE Lookup — What's Actually Exploitable

**Scenario:** You have a list of open services. You want to know which ones have known CVEs.

```bash
porthawk -t 192.168.1.100 --common --banners --cve
```

What happens:
- Scans ports, grabs banners, extracts service versions
- Queries NVD API for CVEs per service — using the specific version when available
  ("OpenSSH 8.9" returns relevant CVEs, not everything ever filed against "ssh")
- Shows top CVE per service in terminal, sorted by CVSS score

Expected output:
```
  22/tcp    open   ssh     MEDIUM   SSH OpenSSH_8.9p1   CVE-2023-38408 (9.8)
  6379/tcp  open   redis   HIGH     Redis 7.0.11         CVE-2022-0543 (10.0)
```

The CVE column shows the highest-CVSS match. Full list is in JSON/HTML output.

**Rate limits:** NVD allows 5 requests/30s without an API key. Get a free key at
`nvd.nist.gov` and set the env var to raise the limit:

```bash
NVD_API_KEY=your-key porthawk -t 192.168.1.100 --common --banners --cve
```

CVE results are cached to `~/.porthawk/cve_cache.json` for 24 hours — repeated scans
on the same day don't hit the API again.

---

## 5. Save Results for Later Analysis

**Scenario:** Reporting time. You need JSON for the ticket and HTML for the client.

```bash
porthawk -t 10.0.0.50 -p 1-1024 --banners --cve -o json,html
```

What gets written:
- `reports/scan_20260326_143000.json` — full results with CVEs, versions, metadata
- `reports/scan_20260326_143000.html` — self-contained, sortable table, clickable CVE links

The HTML file has no external dependencies — safe to send to a client directly.

---

## 6. Network-Wide Sweep

**Scenario:** Internal network assessment. Scan the whole /24 for common ports.

```bash
porthawk -t 192.168.1.0/24 --top-ports 50
```

What happens:
- Expands the /24 to 254 hosts
- Scans top 50 ports on each host sequentially
- Progress bar per host

Tip: Add `-o csv` here — a flat CSV per-port is much easier to analyze in Excel
or grep than terminal output for 254 hosts.

---

## 7. Full Port Scan (All 65535)

**Scenario:** Deep dive on a specific host where you have time.

```bash
porthawk -t 10.0.0.1 --full --timeout 2.0 --threads 300
```

Expected time: 2–5 minutes depending on the network.

`--threads 300` is lower than default 500 to avoid overwhelming the target or triggering
IDS. Adjust based on scope and target sensitivity.

---

## 8. Stealth Scan with ML Port Ordering

**Scenario:** IDS/IPS in scope. You want to go slow, and see results on likely-open ports first.

```bash
porthawk -t 10.0.0.1 --common --stealth --smart-order
```

`--stealth` sets 1 thread and 3s timeout — one port at a time, much less noisy.

`--smart-order` reorders the port list by predicted open probability before scanning.
Logistic regression trained on nmap-services frequency data — 80/443/22 come before 54321.
Also adjusts for target context: private IPs get SMB/RDP higher, Linux TTL hint boosts SSH.

Requires `pip install porthawk[ml]`. Falls back to frequency-table sorting without sklearn.

Note: port ordering only matters in stealth mode or with very low concurrency. With 500
concurrent connections, all ports start scanning nearly simultaneously anyway.

---

## 9. UDP Scan for Common Protocols

**Scenario:** Looking for SNMP, DNS, TFTP, NTP.

```bash
# Requires admin (Windows) or root/sudo (Linux/macOS)
sudo porthawk -t 192.168.1.1 -p 53,67,69,123,161,162 --udp
```

UDP scanning is unreliable by nature. A port showing as "filtered" might actually be open —
firewalls silently drop UDP packets, so PortHawk can't tell the difference between
"open and ignoring you" and "firewall blocking."

---

## 10. Disable Live UI (for Scripts and CI)

**Scenario:** Running PortHawk in a shell script, pipe, or CI pipeline.

```bash
porthawk -t 192.168.1.1 --common --no-live -o json
```

`--no-live` disables the Rich Live display and falls back to tqdm progress bars.
The live UI is also auto-disabled when stdout is not a TTY (piped output, CI runners).

---

## 11. CTF Lab Environment

**Scenario:** Hack The Box, TryHackMe, or a local lab VM.

```bash
# Quick initial scan
porthawk -t 10.10.10.5 --common --banners

# Something unusual on a high port? Go deeper
porthawk -t 10.10.10.5 -p 1-65535 --timeout 2.0 -o json
```

CTF tip: `--common` covers the top 100 ports. Unusual CTF services often run on ports
like 4444, 8888, or 5000 — all included in the top 100 list.

---

## 12. VPS Hardening Check

**Scenario:** You just spun up a VPS and want to make sure you didn't expose anything stupid.

```bash
# Run from outside your VPS — scan your own public IP
porthawk -t YOUR.PUBLIC.IP --common --banners -o html
```

What you're looking for: anything open on HIGH risk ports that shouldn't be public.
Common mistakes: Redis on 6379 (no auth), MongoDB on 27017, Jupyter on 8888, dev servers on 5000.

---

## Python API — Quick Recipes

```python
import asyncio, porthawk

# Scan + CVE in one call
results = asyncio.run(porthawk.scan("192.168.1.1", ports="common", banners=True, cve_lookup=True))
for r in results:
    top_cve = r.cves[0]["cve_id"] if r.cves else "—"
    print(f"{r.port:5}  {r.service_name:<12}  {r.service_version or '?':<20}  {top_cve}")
```

```python
# Save HTML report programmatically
from porthawk.reporter import save_html
report = porthawk.build_report("192.168.1.1", results)
path = save_html(report)
print(f"Report: {path}")
```

```python
# Filter only HIGH-risk ports
high_risk = [r for r in results if r.risk_level == "HIGH"]
```

---

## Common Error Messages

### `PermissionError: UDP scanning needs admin/root privileges`

Run as Administrator on Windows (`runas /user:Administrator cmd`) or
with sudo on Linux (`sudo porthawk ...`).

### `ValueError: Invalid port range 1024-80: must be 1–65535 with lo ≤ hi`

Port range must be low-to-high. Use `80-1024` not `1024-80`.

### `ValueError: Port specification cannot be empty`

Specify ports with `-p 1-1024`, `--common`, `--top-ports 50`, or `--full`.

### `KeyboardInterrupt` during scan

Not an error — Ctrl+C stops the scan cleanly. Results up to that point are lost
unless you specified `-o` before the interrupt.

### `OSError: [Errno 11001] getaddrinfo failed` (Windows) / `socket.gaierror`

Hostname doesn't resolve. Check the target is correct, or use an IP directly.
