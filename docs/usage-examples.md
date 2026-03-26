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

**Scenario:** Looking for DNS, NTP, SNMP, NetBIOS, SSDP — services a TCP scanner won't find.

```bash
# Scan top 20 UDP ports with protocol-specific payloads (no -p needed)
porthawk -t 192.168.1.1 --udp

# Specific ports only
porthawk -t 192.168.1.1 --udp -p 53,123,161,1900

# Slow network or cross-internet target — give it more time
porthawk -t 192.168.1.1 --udp --timeout 3.0
```

Unlike a basic "send empty bytes, wait for ICMP" scanner, this sends real protocol payloads:
DNS queries, NTP client requests, SNMP GetRequests, SSDP M-SEARCHes. A lot of services ignore
empty datagrams but will respond to a proper request.

UDP state breakdown:
- **OPEN** — got a response that validates against the expected protocol
- **CLOSED** — ICMP port-unreachable received (definitively no service on that port)
- **FILTERED** — no response after retries (firewall, or the host ignores unknown senders)

`"unvalidated:"` in the banner means a response arrived but didn't match the protocol format.
Still probably open — check manually.

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

## 13. Adaptive Scan Speed

**Scenario:** You want maximum speed without triggering IDS or overloading the target network.

```bash
porthawk -t 192.168.1.1 -p 1-1024 --adaptive
```

What `--adaptive` does:
- Starts at 25 concurrent connections (instead of 500)
- After every 30 clean probes, adds 2 more concurrent slots
- If more than 30% of recent probes time out → halves the concurrency immediately
- If RTT variance is high (jitter > 80ms) → pauses increases but doesn't decrease
- Never drops below 5 concurrent, never exceeds `--threads` limit

This is AIMD — the same algorithm TCP uses for congestion control. Additive increase,
multiplicative decrease. It found the right rate for your connection and adjusted.

Combine with other flags:

```bash
# Adaptive + banners — good for slow scans where you don't want to kill the network
porthawk -t 192.168.1.1 --common --banners --adaptive

# Adaptive with a higher ceiling
porthawk -t 192.168.1.1 -p 1-10000 --adaptive --threads 300
```

**When to use it:**
- Scanning through a VPN where the throughput varies
- Scanning a real target in an engagement where you can't afford IDS triggers
- Networks where you don't know the capacity upfront

**When NOT to use it:**
- Local subnet scans (just use `--threads 500`, the network can handle it)
- Stealth mode (fixed 1 thread — adaptive doesn't help there)

Programmatic use:

```python
import asyncio
from porthawk.scanner import scan_host
from porthawk.throttle import AdaptiveConfig

cfg = AdaptiveConfig(
    initial_concurrency=20,
    timeout_threshold=0.25,  # back off faster — careful mode
)

results = asyncio.run(scan_host(
    "10.0.0.1",
    ports=list(range(1, 65536)),
    max_concurrent=200,
    adaptive_config=cfg,
))
```

---

## 14. Honeypot Check Before You Do Anything Stupid

**Scenario:** You found a host in scope that has telnet open, Redis exposed, and FTP. Something feels off.

```bash
porthawk -t 10.0.0.50 --common --banners --honeypot
```

What happens:
- Scans ports, grabs banners
- Runs the honeypot scorer against the results
- Prints a score (0.0–1.0), a verdict, and which indicators fired

Expected output if it's suspicious:
```
Honeypot check: score=0.72  verdict=LIKELY_HONEYPOT  confidence=HIGH  (7 open ports analyzed)
  ⚑ [0.60] cowrie_ssh_banner: SSH banner matches known Cowrie default: 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2'
  ⚑ [0.25] telnet_open: Telnet (port 23) is open — rare on real hosts, common on honeypots
```

The scorer checks for:
- **Cowrie** SSH banners — specific EOL Debian/Ubuntu strings Cowrie ships as defaults
- **Dionaea** FTP — `"220 DiskStation FTP server ready."` is literally hardcoded in Dionaea
- **Conpot** ICS ports — Modbus (502), S7 (102), BACnet (47808), DNP3 (20000) etc.
- **T-Pot** port flood — >20 open ports is unusual, >40 is a big flag
- Telnet open (port 23)
- Same SSH banner responding on multiple ports
- Suspiciously uniform latency across ports (software-emulated responses)

Score is not binary. SUSPICIOUS (0.25–0.55) means "proceed carefully but don't abort."
LIKELY_HONEYPOT (>0.55) means stop and verify with your scope owner before continuing.

Programmatic use:

```python
import asyncio, porthawk

results = asyncio.run(porthawk.scan("10.0.0.50", ports="common", banners=True))
hp = porthawk.score_honeypot(results)

if hp.verdict == "LIKELY_HONEYPOT":
    print(f"Stop. Score {hp.score:.2f} — this looks like a honeypot.")
    for ind in hp.indicators:
        print(f"  {ind.name}: {ind.description}")
```

---

## 15. SYN Scan — Half-Open TCP

Sends a SYN, reads the response, never completes the handshake. Leaves less noise
in server logs than a full connect scan. Requires root/admin and either Scapy or Linux raw sockets.

```bash
# install Scapy first (or rely on Linux raw sockets)
pip install porthawk[syn]

# run as root/Administrator
sudo porthawk -t 192.168.1.1 --common --syn
```

Output shows the backend being used:

```
SYN scan backend: scapy 2.5.0
```

Check what backend you'll get before scanning:

```python
import porthawk
print(porthawk.get_syn_backend())
# scapy 2.5.0        → cross-platform, Scapy installed
# raw socket (Linux) → no Scapy, but running on Linux as root
# unavailable (Windows needs Scapy + Npcap)  → install Npcap first
```

Programmatic SYN scan:

```python
import asyncio
import porthawk

# must be root/admin
results = asyncio.run(
    porthawk.syn_scan_host("192.168.1.1", [22, 80, 443, 3306], timeout=1.0)
)
open_ports = [r for r in results if r.state.value == "open"]
print(f"{len(open_ports)} open ports")
```

On Windows without Scapy: `ScanPermissionError` with instructions to install Npcap
from npcap.com and run `pip install porthawk[syn]`.

---

## 16. Slow & Low — Evasion Scan

Red-team mode. All the evasion techniques combined. Requires root/admin and Scapy.

```bash
pip install porthawk[syn]

# Full preset — randomized timing, IP fragments, TTL=128
sudo porthawk -t 192.168.1.1 --common --slow-low

# XMAS scan with 10s max jitter
sudo porthawk -t 192.168.1.1 -p 80,443 --evasion-type xmas --jitter 10.0

# Fragment packets + decoys
sudo porthawk -t 192.168.1.1 --common --fragment --decoys "1.2.3.4,5.6.7.8"

# Everything at once
sudo porthawk -t 192.168.1.1 --common --slow-low --evasion-type fin --decoys "1.2.3.4,5.6.7.8"
```

Programmatic evasion:

```python
import asyncio
import porthawk

# slow & low preset — ready to go
cfg = porthawk.slow_low_config()
cfg.decoys = ["1.2.3.4", "5.6.7.8"]

results = asyncio.run(
    porthawk.evasion_scan_host("192.168.1.1", [22, 80, 443, 3306], config=cfg, max_concurrent=2)
)

# XMAS scan — RST=CLOSED, no reply=OPEN (unreliable against Windows)
cfg = porthawk.EvasionConfig(
    scan_type="xmas",
    max_delay=5.0,
    jitter_distribution="exponential",
    fragment=True,
)
results = asyncio.run(porthawk.evasion_scan_host("192.168.1.1", [80, 443], config=cfg))

# ACK scan — maps firewall rules, not port state
cfg = porthawk.EvasionConfig(scan_type="ack")
results = asyncio.run(porthawk.evasion_scan_host("192.168.1.1", range(1, 1025), config=cfg))
# OPEN = unfiltered (RST received), FILTERED = stateful firewall dropped it
```

**Why each technique works:**
- **Fragmented packets** — many IDS engines only inspect the first fragment. Split the TCP header into 8-byte chunks and signature-based IDS misses the port/flag check entirely.
- **Exponential jitter** — inter-arrival times follow a Poisson distribution. Looks like real user traffic hitting a service, defeats threshold-based "N connections in T seconds" rules.
- **Decoys** — target sees scans from multiple source IPs simultaneously. Analyst has to figure out which one is real. Doesn't bypass host-based firewalls, but obscures source in network logs.
- **TTL=128** — passive OS fingerprinting (p0f, Zeek) will misidentify you as Windows. Breaks correlation with other scan data from the same session.
- **FIN/NULL/XMAS** — some older IDS only alert on SYN packets. These bypass those rules. Unreliable against Windows targets (sends RST for both open and closed ports, ignoring RFC 793).

---

## 17. Passive OS Fingerprinting

**Scenario:** You want to know what OS a host is running without sending unusual packets.
One SYN — the SYN-ACK response tells you the OS from its TCP stack defaults.

```bash
# Requires root/admin or Scapy
sudo porthawk -t 192.168.1.1 --common --passive-os

# Combine with a full scan for context
sudo porthawk -t 192.168.1.1 --common --banners --passive-os
```

Expected output (with `--passive-os`):
```
PortHawk — scanning 192.168.1.1 (1 host, 100 ports, TCP)

Running passive OS fingerprinting (sends one SYN)...

Passive OS fingerprint: Windows — Windows 10 / 11 / Server 2019+
  confidence=HIGH  score=0.91  method=tcp_fingerprint+knn
  signals: ttl=128 (family 128), window=65535 (exact), df=1, options order match
```

Programmatic use:

```python
import porthawk

# Full TCP stack fingerprint — sends one SYN, reads SYN-ACK
match = porthawk.passive_os_scan("192.168.1.1")
if match:
    print(f"OS: {match.os_family} — {match.os_detail}")
    print(f"confidence={match.confidence}  score={match.score:.2f}")
    # Windows — Windows 10 / 11 / Server 2019+
    # confidence=HIGH  score=0.91

# Classify from raw bytes (e.g. from your own packet capture)
match = porthawk.fingerprint_os(raw_ip_tcp_bytes)

# TTL-only — no root needed, low confidence
match = porthawk.ttl_only_os(64)
print(match.os_family)   # "Linux/Unix"
print(match.confidence)  # "LOW"
```

**What it reads from the SYN-ACK:**
- **TTL** — 64=Linux, 128=Windows, 255=Cisco/OpenBSD
- **Window size** — Windows sends 65535, Linux 4.x sends 29200
- **TCP option order** — Windows: MSS,NOP,WS,NOP,NOP,SACK — Linux: MSS,SACK,TS,NOP,WS
- **Window scale** — Windows=8, Linux=7, macOS=6
- **Timestamps** — Linux/macOS include them, Windows doesn't by default
- **DF bit** — almost everyone sets it; network devices often don't

Confidence thresholds: `≥0.70` → HIGH, `0.45–0.69` → MEDIUM, `<0.45` → LOW

---

## 18. UDP Scan — Python API

**Scenario:** You want to integrate UDP scanning into your own tooling.

```python
import asyncio
import porthawk

# Scan the 20 most useful UDP ports
ports = porthawk.get_udp_top_ports()
results = asyncio.run(
    porthawk.udp_scan_host("192.168.1.1", ports=ports, timeout=2.0)
)

# Print open ports with their banners
for r in results:
    if r.state.name == "OPEN":
        print(f"  UDP/{r.port:5d}  {r.banner or '?'}")
# e.g.:
#   UDP/   53  DNS
#   UDP/  123  NTP stratum=2 refid=GPS
#   UDP/  161  SNMP agent
#   UDP/ 1900  Server: UPnP/1.0 Linux | USN: uuid:abc...

# Scan specific ports, more retries for unreliable links
results = asyncio.run(
    porthawk.udp_scan_host(
        "192.168.1.1",
        ports=[53, 123, 161, 500],
        timeout=3.0,
        retries=2,
        max_concurrent=20,
    )
)

# Mix TCP and UDP — combine results into one report
tcp_results = asyncio.run(porthawk.scan("192.168.1.1", ports="common"))
udp_results = asyncio.run(
    porthawk.udp_scan_host("192.168.1.1", ports=porthawk.get_udp_top_ports())
)
all_results = tcp_results + udp_results
```

Port states returned by `udp_scan_host`:
- `PortState.OPEN` — protocol response received and validated
- `PortState.CLOSED` — ICMP port unreachable received
- `PortState.FILTERED` — no response after all retries

---

## Common Error Messages

### `ValueError: Invalid port range 1024-80: must be 1–65535 with lo ≤ hi`

Port range must be low-to-high. Use `80-1024` not `1024-80`.

### `ValueError: Port specification cannot be empty`

Specify ports with `-p 1-1024`, `--common`, `--top-ports 50`, or `--full`.

### `KeyboardInterrupt` during scan

Not an error — Ctrl+C stops the scan cleanly. Results up to that point are lost
unless you specified `-o` before the interrupt.

### `OSError: [Errno 11001] getaddrinfo failed` (Windows) / `socket.gaierror`

Hostname doesn't resolve. Check the target is correct, or use an IP directly.
