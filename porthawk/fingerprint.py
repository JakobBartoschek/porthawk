"""Service fingerprinting — banner grabbing, HTTP header sniffing, SSH version extraction.

None of this is definitive. TTL lies when there are VPNs. Banners get faked.
But it's way better than just showing an open port number.
"""

import asyncio
import re
import subprocess
import sys

import httpx

# TTL thresholds for OS guessing.
# Initial TTL values: Linux/Unix=64, Windows=128, Cisco=255.
# Each routing hop subtracts 1, so we use ranges not exact values.
# A TTL of 57 from a Linux box 7 hops away still lands under 64.
_TTL_LINUX_THRESHOLD = 64
_TTL_WINDOWS_THRESHOLD = 128
_TTL_CISCO_THRESHOLD = 255

# Ports where we try HTTP header grabbing instead of raw banner
_HTTP_PORTS = frozenset({80, 443, 8080, 8443, 8000, 8888, 9200})

# SSH banner prefix — if a service starts with this, it's SSH
_SSH_BANNER_PREFIX = "SSH-"

# Ports that speak first — no probe needed, just read what arrives
_LISTEN_FIRST_PORTS = frozenset({21, 22, 23, 25, 110, 143, 3306, 5432, 5900})

# For everything else, send a protocol-specific probe before reading
# \r\n as fallback still works for most text-based services
_PROTOCOL_PROBES: dict[int, bytes] = {
    6379: b"PING\r\n",  # Redis — +PONG tells us it's alive
    11211: b"stats\r\n",  # Memcached — returns STAT version X.Y.Z
    27017: b"",  # MongoDB — sends a banner anyway on newer versions
}

# Version extraction patterns — tried in order, first match wins.
# Named groups make the template substitution readable without positional index juggling.
_VERSION_PATTERNS: list[tuple[re.Pattern, str]] = [
    # SSH-2.0-OpenSSH_8.9p1 Ubuntu → "OpenSSH_8.9p1"
    (re.compile(r"^SSH-\d+\.\d+-(?P<ver>\S+)"), "{ver}"),
    # 220 ProFTPD 1.3.6c Server (Ubuntu) → "ProFTPD 1.3.6c"
    (
        re.compile(r"^220[- ].*?(?P<sw>ProFTPD|vsftpd|Pure-FTPd|FileZilla)[/ ]?(?P<ver>\S*)", re.I),
        "{sw} {ver}",
    ),
    # 220 mail.example.com ESMTP Postfix → "Postfix"
    (re.compile(r"^220[- ].*?ESMTP (?P<ver>\S+)", re.I), "SMTP/{ver}"),
    # +OK Dovecot ready. → "Dovecot"
    (re.compile(r"^\+OK (?P<ver>\S+)", re.I), "POP3/{ver}"),
    # * OK Dovecot ready. → "Dovecot"
    (re.compile(r"^\* OK (?P<ver>\S+)", re.I), "IMAP/{ver}"),
    # RFB 003.008 → "VNC RFB/003.008"
    (re.compile(r"^RFB (?P<ver>\d+\.\d+)"), "VNC/RFB-{ver}"),
    # STAT version 1.6.17 (from Memcached)
    (re.compile(r"STAT version (?P<ver>\S+)", re.I), "Memcached/{ver}"),
    # +PONG (Redis without version — _grab_redis handles the full version)
    (re.compile(r"^\+PONG"), "Redis"),
]


def extract_version(banner: str) -> str | None:
    """Try every pattern against the banner and return the first version string found.

    Returns None if no pattern matches — caller should just show the raw banner.
    """
    for pattern, template in _VERSION_PATTERNS:
        m = pattern.search(banner)
        if m:
            try:
                return template.format(**m.groupdict()).strip()
            except KeyError:
                continue
    return None


def guess_os_from_ttl(ttl: int) -> str:
    """Rough OS classification from TTL value.

    edge case: Windows TTL is sometimes 127 due to a single routing hop (hypervisor NAT).
    We still classify it as Windows because the threshold is 128, not exactly 128.
    This function is intentionally coarse — don't trust it blindly.
    """
    if ttl <= 0:
        return "Unknown"
    if ttl <= _TTL_LINUX_THRESHOLD:
        return "Linux/Unix"
    if ttl <= _TTL_WINDOWS_THRESHOLD:
        return "Windows"
    if ttl <= _TTL_CISCO_THRESHOLD:
        return "Network Device (Cisco/HP)"
    return "Unknown"


def get_ttl_via_ping(host: str, timeout: float = 2.0) -> int | None:
    """Ping the host once and pull the TTL from the output.

    Uses subprocess because asyncio doesn't expose the IP TTL from TCP connections.
    Falls back to None on any error — caller handles missing TTL gracefully.
    """
    if sys.platform == "win32":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), host]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2.0)
        ttl_match = re.search(r"ttl=(\d+)", proc.stdout, re.IGNORECASE)
        return int(ttl_match.group(1)) if ttl_match else None
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError, FileNotFoundError):
        return None


async def grab_banner(host: str, port: int, timeout: float = 2.0) -> str | None:
    """Connect and grab a service banner using protocol-aware probing.

    Services that speak first (SSH, FTP, MySQL, VNC...) get read immediately.
    Services that need a kick (Redis, Memcached) get the right probe bytes.
    Generic fallback sends \\r\\n — enough for most text-based protocols.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        try:
            if port not in _LISTEN_FIRST_PORTS:
                probe = _PROTOCOL_PROBES.get(port, b"\r\n")
                writer.write(probe)
                await writer.drain()

            raw = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            decoded = raw.decode("utf-8", errors="ignore").strip()
            return decoded if decoded else None
        finally:
            writer.close()
            await writer.wait_closed()
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def grab_http_headers(host: str, port: int, timeout: float = 2.0) -> str | None:
    """HEAD request to pull Server, X-Powered-By, and other noisy headers.

    verify=False because self-signed certs on internal hosts are basically the rule, not exception.
    We only grab headers we actually care about for fingerprinting.
    """
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}/"
    fingerprint_headers = {"server", "x-powered-by", "x-aspnet-version", "via", "x-generator"}

    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
            resp = await client.head(url, follow_redirects=True)
            interesting = {
                k.lower(): v for k, v in resp.headers.items() if k.lower() in fingerprint_headers
            }
            if interesting:
                return " | ".join(f"{k}: {v}" for k, v in interesting.items())
            return f"HTTP {resp.status_code}"
    except Exception:  # noqa: BLE001 — httpx throws many specific exceptions, we want all
        return None


async def _grab_mysql_version(host: str, port: int, timeout: float) -> str | None:
    """Read the MySQL handshake packet and extract the server version.

    MySQL 5+ sends protocol_version=10 followed by a null-terminated version string.
    The raw bytes at offset 5 are the version — e.g. b"8.0.33-community\\x00".
    This breaks on MySQL 3.x (protocol_version=9) but nobody should run that anymore.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        try:
            raw = await asyncio.wait_for(reader.read(128), timeout=timeout)
            # byte 4 = protocol version, must be 10 for MySQL 5+
            if len(raw) < 6 or raw[4] != 10:
                return None
            null_pos = raw.find(b"\x00", 5)
            if null_pos == -1:
                return None
            return raw[5:null_pos].decode("ascii", errors="ignore")
        finally:
            writer.close()
            await writer.wait_closed()
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def _grab_redis_version(host: str, port: int, timeout: float) -> str | None:
    """PING → +PONG confirms Redis, then INFO server gives us the actual version.

    Two-step because +PONG alone only tells us it's Redis, not which version.
    If INFO fails for any reason we still return "Redis" — partial info beats nothing.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        try:
            writer.write(b"PING\r\n")
            await writer.drain()
            pong = await asyncio.wait_for(reader.read(64), timeout=timeout)
            if not pong.startswith(b"+PONG"):
                return None  # something responded but it's not Redis

            writer.write(b"INFO server\r\n")
            await writer.drain()
            info = await asyncio.wait_for(reader.read(2048), timeout=timeout)
            version_match = re.search(rb"redis_version:(\S+)", info)
            return version_match.group(1).decode() if version_match else "Redis"
        finally:
            writer.close()
            await writer.wait_closed()
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


def extract_ssh_version(banner: str) -> str | None:
    """Pull the SSH software version out of a banner string.

    SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6 → OpenSSH_8.9p1
    SSH-1.99-Cisco-1.25 → Cisco-1.25
    """
    if not banner or not banner.startswith(_SSH_BANNER_PREFIX):
        return None
    parts = banner.split("-", 2)
    if len(parts) < 3:
        return None
    # strip trailing comment — everything after the first space is optional
    return parts[2].split(" ", 1)[0]


async def fingerprint_port(
    host: str,
    port: int,
    timeout: float = 2.0,
    grab_http: bool = True,
) -> tuple[str | None, str | None]:
    """Best-effort fingerprint of an open port.

    Returns (banner, service_version) — both can be None.
    banner is the human-readable display string.
    service_version is just the version component for structured use.

    Dispatch order: HTTP ports → MySQL → Redis → generic banner.
    """
    if grab_http and port in _HTTP_PORTS:
        http_info = await grab_http_headers(host, port, timeout)
        return http_info, None

    if port == 3306:
        version = await _grab_mysql_version(host, port, timeout)
        if version:
            return f"MySQL {version}", version
        return None, None

    if port == 6379:
        version = await _grab_redis_version(host, port, timeout)
        if version and version != "Redis":
            return f"Redis {version}", version
        return ("Redis", None) if version else (None, None)

    raw_banner = await grab_banner(host, port, timeout)
    if not raw_banner:
        return None, None

    service_version = extract_version(raw_banner)

    # for SSH, clean up the full banner into something readable
    ssh_ver = extract_ssh_version(raw_banner)
    if ssh_ver:
        return f"SSH {ssh_ver}", ssh_ver

    first_line = raw_banner.split("\n")[0].strip()
    return (first_line if first_line else None), service_version
