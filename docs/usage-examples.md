# PortHawk Usage Examples

Practical examples for common scenarios. All examples assume `porthawk` is installed
and you have authorization to scan the target.

---

## 1. Quick Recon on a Single Host

**Scenario:** You've got a target IP in a pentest scope. First pass, top 100 ports.

```bash
porthawk scan -t 192.168.1.100 --common
```

**What happens:**
- Scans the top 100 most commonly targeted ports
- Shows open ports in terminal with service names and risk levels
- No files written (use `-o json` if you want to save)

**Expected output:**
```
PortHawk — scanning 192.168.1.100 (1 host, 100 ports, TCP)

  192.168.1.100 100%|████████| 100/100 [00:01<00:00]

  Port       State     Service             Risk     Banner / Info
  22/tcp     open      ssh                 MEDIUM
  80/tcp     open      http                LOW
  3306/tcp   open      mysql               MEDIUM

  Open: 3 / 100 scanned
```

---

## 2. Banner Grabbing + OS Detection

**Scenario:** You found open ports. Now you want software versions and OS hints.

```bash
porthawk scan -t 192.168.1.100 --common --banners --os
```

**What happens:**
- Runs port scan first
- After scan completes, grabs banners from open ports (SSH version, HTTP headers, etc.)
- Pings the host and guesses OS from TTL
- Adds `os_guess` and `banner` columns to the output

**Expected output (snippet):**
```
  22/tcp     open      ssh       MEDIUM   SSH OpenSSH_8.9p1
  80/tcp     open      http      LOW      server: nginx/1.24.0
  OS guess: Linux/Unix (TTL=64)
```

---

## 3. Save Results for Later Analysis

**Scenario:** Reporting time. You need JSON for the ticket and HTML for the client.

```bash
porthawk scan -t 10.0.0.50 -p 1-1024 --banners -o json,html
```

**What happens:**
- Scans ports 1–1024
- Grabs banners from open ports
- Saves `reports/scan_20260325_143000.json` and `reports/scan_20260325_143000.html`
- HTML file is self-contained — send it to the client directly

---

## 4. Network-Wide Sweep

**Scenario:** Internal network assessment. Scan the whole /24 for common ports.

```bash
porthawk scan -t 192.168.1.0/24 --top-ports 50
```

**What happens:**
- Expands the /24 to 254 hosts
- Scans top 50 ports on each host sequentially
- Progress bar per host

**Tip:** Add `-o csv` here — a flat CSV per-port is much easier to analyze in Excel
or grep than the terminal output for 254 hosts.

---

## 5. Full Port Scan (All 65535)

**Scenario:** Deep dive on a specific host where you have time.

```bash
porthawk scan -t 10.0.0.1 --full --timeout 2.0 --threads 300
```

**Expected time:** 2–5 minutes depending on the network.
**Why --threads 300:** Lower than default 500 to avoid overwhelming the target or
triggering IDS. Adjust based on scope and target sensitivity.

---

## 6. Stealth Scan — Slow and Quiet

**Scenario:** IDS/IPS in scope. You want to go slow and be less obvious.

```bash
porthawk scan -t 10.0.0.1 --common --stealth
```

**What stealth mode does:**
- Single thread (max_concurrent=1)
- 3 second timeout per port
- Much slower, much less noisy on the wire

PortHawk's stealth mode is about reducing connection rate, not about SYN packet manipulation.
For actual SYN stealth scanning, you need nmap -sS (requires raw socket + root).

---

## 7. UDP Scan for Common Protocols

**Scenario:** Looking for SNMP, DNS, TFTP, NTP.

```bash
# Requires admin (Windows) or root/sudo (Linux/macOS)
sudo porthawk scan -t 192.168.1.1 -p 53,67,69,123,161,162 --udp
```

**Important:** UDP scanning is unreliable by nature. A port showing as "filtered" might
actually be open — firewalls silently drop UDP packets, so PortHawk can't tell the difference
between "open and ignoring you" and "firewall blocking."

---

## 8. CTF Lab Environment

**Scenario:** Hack The Box, TryHackMe, or your own lab VM.

```bash
# Quick initial scan
porthawk scan -t 10.10.10.5 --common --banners

# If something weird is found, go deeper
porthawk scan -t 10.10.10.5 -p 1-65535 --timeout 2.0 -o json
```

**CTF tip:** The `--common` scan covers the ports in the top 100 list. Unusual CTF services
often run on ports like 4444, 8888, or 5000 — all included.

---

## 9. Web App Port Discovery

**Scenario:** Looking for web services on non-standard ports.

```bash
porthawk scan -t app.example.com -p 80,443,8080,8443,8000,8888,3000,5000,9000 --banners
```

**Expected banner info:**
```
  80/tcp    open   http        LOW    server: Apache/2.4.54
  8080/tcp  open   http-proxy  MEDIUM server: Tomcat/10.1
  8888/tcp  open   http-alt    MEDIUM server: Jupyter/6.5.4  ← bad news if public
```

---

## 10. VPS Hardening Check

**Scenario:** You just spun up a VPS and want to make sure you didn't expose anything stupid.

```bash
# Run this from outside your VPS — scan your own public IP
porthawk scan -t YOUR.PUBLIC.IP --common --banners -o html
```

**What you're looking for:** Anything open on HIGH risk ports that shouldn't be public.
Common mistakes: Redis on 6379, MongoDB on 27017, Jupyter on 8888, dev servers on 5000.

---

## Common Error Messages

### `PermissionError: UDP scanning needs admin/root privileges`

**Fix:** Run as Administrator on Windows (`runas /user:Administrator cmd`) or
with sudo on Linux (`sudo porthawk scan ...`).

### `ValueError: Invalid port range 1024-80: must be 1–65535 with lo ≤ hi`

**Fix:** Port range must be low-to-high. Use `80-1024` not `1024-80`.

### `ValueError: Port specification cannot be empty`

**Fix:** Specify ports with `-p 1-1024`, `--common`, `--top-ports 50`, or `--full`.

### `KeyboardInterrupt` during scan

**Fix:** Not an error — Ctrl+C stops the scan cleanly. Results up to that point are lost
(they're in memory, not written to disk unless you specified `-o`).

### `OSError: [Errno 11001] getaddrinfo failed` (Windows) / `socket.gaierror`

**Fix:** Hostname doesn't resolve. Check the target is correct, or use an IP directly.
