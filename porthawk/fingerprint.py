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
_HTTP_PORTS = frozenset({80, 443, 8080, 8443, 8000, 8888})

# SSH banner prefix — if a service starts with this, it's SSH
_SSH_BANNER_PREFIX = "SSH-"


def guess_os_from_ttl(ttl: int) -> str:
    """Rough OS classification from TTL value.

    edge case: Windows TTL is sometimes 127 due to a single routing hop (hypervisor NAT).
    We still classify it as Windows because the threshold is 128, not exactly 128.
    This function is intentionally coarse — don't trust it blindly.

    Args:
        ttl: IP TTL value from ping response.

    Returns:
        Human-readable OS guess string, or 'Unknown' if TTL doesn't fit known ranges.
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

    Args:
        host: Hostname or IP to ping.
        timeout: Seconds to wait for ping response.

    Returns:
        Integer TTL value, or None if ping failed or TTL not found in output.
    """
    if sys.platform == "win32":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), host]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 2.0,
        )
        ttl_match = re.search(r"ttl=(\d+)", proc.stdout, re.IGNORECASE)
        if ttl_match:
            return int(ttl_match.group(1))
        return None
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError, FileNotFoundError):
        return None


async def grab_banner(host: str, port: int, timeout: float = 2.0) -> str | None:
    """Connect and wait for a spontaneous banner (SSH, FTP, SMTP send one immediately).

    Sends a single null byte if the service doesn't speak first — enough to wake
    some services like SMTP that expect a EHLO but respond to anything.

    Args:
        host: Target hostname or IP.
        port: Target port number.
        timeout: Per-operation timeout in seconds.

    Returns:
        Decoded banner string, or None if connection failed or no data received.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        try:
            # Some services (HTTP) won't send a banner until you speak.
            # Send a minimal probe and hope for the best.
            writer.write(b"\r\n")
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

    Args:
        host: Target hostname or IP.
        port: Target port (80, 443, 8080, etc.).
        timeout: Request timeout in seconds.

    Returns:
        Formatted header string like "server: nginx | x-powered-by: PHP/8.1", or None.
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


def extract_ssh_version(banner: str) -> str | None:
    """Pull the SSH software version out of a banner string.

    SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6 → OpenSSH_8.9p1
    SSH-1.99-Cisco-1.25 → Cisco-1.25

    Args:
        banner: Raw banner string from grab_banner().

    Returns:
        Software version component, or None if banner isn't an SSH banner.
    """
    if not banner or not banner.startswith(_SSH_BANNER_PREFIX):
        return None
    # Format: SSH-<protoversion>-<softwareversion>[ <comment>]
    parts = banner.split("-", 2)
    if len(parts) < 3:
        return None
    # Strip trailing whitespace and comment
    software_and_comment = parts[2].split(" ", 1)
    return software_and_comment[0]


async def fingerprint_port(
    host: str,
    port: int,
    timeout: float = 2.0,
    grab_http: bool = True,
) -> str | None:
    """Best-effort fingerprint of an open port. Tries HTTP first, then raw banner.

    For security tooling, the caller is responsible for deciding whether to fingerprint.
    We don't fingerprint closed or filtered ports — that would be pointless.

    Args:
        host: Target hostname or IP.
        port: Open port to fingerprint.
        timeout: Per-operation timeout in seconds.
        grab_http: Whether to attempt HTTP header grabbing on web ports.

    Returns:
        Human-readable fingerprint string, or None if nothing useful was found.
    """
    if grab_http and port in _HTTP_PORTS:
        http_banner = await grab_http_headers(host, port, timeout)
        if http_banner:
            return http_banner

    raw_banner = await grab_banner(host, port, timeout)
    if not raw_banner:
        return None

    # SSH version extraction — cleaner than the raw banner
    ssh_version = extract_ssh_version(raw_banner)
    if ssh_version:
        return f"SSH {ssh_version}"

    # Return first line of banner — multi-line banners are noise for the table
    first_line = raw_banner.split("\n")[0].strip()
    return first_line if first_line else None
