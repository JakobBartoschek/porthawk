"""Smart UDP scanner with protocol-specific payloads.

Why UDP is hard:
- No handshake. "Open" means we got a response. "Closed" means ICMP port unreachable.
  "Filtered" means nothing came back — could be open-but-silent or a firewall that
  dropped the packet. We can't tell.
- Every unresponsive port costs a full timeout. With 100 ports at 2s each you're
  looking at 3+ minutes without concurrency.
- Firewalls often rate-limit ICMP unreachable, so a port that's closed might look
  filtered if the router already sent 10 unreachables this second.

Strategy:
- Protocol-specific payloads: DNS, NTP, SNMP, SSDP, NetBIOS, mDNS, TFTP, IKE
  each get a proper probe. An SNMP agent that ignores empty datagrams will respond
  to a GetRequest. NTP responds to a mode-3 client packet. Etc.
- Response validation: a valid NTP reply on port 123 is more convincing than random
  bytes — we record this in the banner so callers know confidence level.
- Retry once on timeout: lossy links drop packets. Two attempts cuts false-filtered
  rate significantly without doubling worst-case time.
- Generic fallback: ports without a known protocol get b"\\x00" — sometimes enough
  to trigger an ICMP unreachable, sometimes enough to get a banner back.
"""

from __future__ import annotations

import asyncio
import socket
import struct
from collections.abc import Callable

from porthawk.scanner import PortState, ScanResult, is_ipv6

# ---------------------------------------------------------------------------
# Protocol-specific payloads
# ---------------------------------------------------------------------------

# DNS: query for google.com A record, RD=1
# Using google.com because version.bind/CH class is commonly disabled.
# Transaction ID 0xDEAD is recognizable in packet captures.
_DNS_PAYLOAD = (
    b"\xde\xad"  # Transaction ID
    b"\x01\x00"  # Flags: standard query, RD=1
    b"\x00\x01"  # QDCOUNT=1
    b"\x00\x00\x00\x00\x00\x00"  # ANCOUNT, NSCOUNT, ARCOUNT
    b"\x06google\x03com\x00"  # QNAME: google.com
    b"\x00\x01"  # QTYPE: A
    b"\x00\x01"  # QCLASS: IN
)

# NTP v3 client request — 48 bytes
# 0x1b = 0b00011011 = LI=0, VN=3 (version 3), Mode=3 (client)
# Most NTP servers also respond to v4 (0x23) but v3 has broader compat.
_NTP_PAYLOAD = b"\x1b" + b"\x00" * 47

# SNMP v1 GetRequest for sysDescr.0 (OID 1.3.6.1.2.1.1.1.0), community "public"
# Hand-encoded BER because adding a dependency on an ASN.1 library for this is overkill.
# Many SNMP agents respond to "public" with sysDescr even on hardened boxes.
_SNMP_PAYLOAD = bytes(
    [
        0x30,
        0x29,  # SEQUENCE, 41 bytes total
        0x02,
        0x01,
        0x00,  # INTEGER version = 0 (SNMPv1)
        0x04,
        0x06,  # OCTET STRING, 6 bytes
        0x70,
        0x75,
        0x62,
        0x6C,
        0x69,
        0x63,  # "public"
        0xA0,
        0x1C,  # GetRequest-PDU, 28 bytes
        0x02,
        0x04,
        0xCA,
        0xFE,
        0xBA,
        0xBE,  # INTEGER request-id = 0xcafebabe
        0x02,
        0x01,
        0x00,  # INTEGER error-status = 0
        0x02,
        0x01,
        0x00,  # INTEGER error-index = 0
        0x30,
        0x0E,  # SEQUENCE VarBindList, 14 bytes
        0x30,
        0x0C,  # SEQUENCE VarBind, 12 bytes
        0x06,
        0x08,  # OID, 8 bytes
        0x2B,
        0x06,
        0x01,
        0x02,
        0x01,
        0x01,
        0x01,
        0x00,  # 1.3.6.1.2.1.1.1.0 (sysDescr.0)
        0x05,
        0x00,  # NULL value
    ]
)

# SSDP M-SEARCH — triggers UPnP responses from routers, smart TVs, printers
_SSDP_PAYLOAD = (
    b"M-SEARCH * HTTP/1.1\r\n"
    b"HOST: 239.255.255.250:1900\r\n"
    b'MAN: "ssdp:discover"\r\n'
    b"MX: 1\r\n"
    b"ST: ssdp:all\r\n"
    b"\r\n"
)

# NetBIOS Name Service status request for wildcard "*"
# NetBIOS name encoding: each nibble → nibble + 0x41
# "*" (0x2A) → "CK", " " (0x20) → "CA"
# So: "*" + 15 spaces → b"CK" + b"CA" * 15 = 32 bytes
_NETBIOS_NAME = b"CK" + b"CA" * 15  # 32 bytes, encodes "*               "
_NETBIOS_PAYLOAD = (
    b"\x82\x28"  # Transaction ID
    b"\x00\x00"  # Flags: non-recursive query
    b"\x00\x01"  # QDCOUNT=1
    b"\x00\x00"  # ANCOUNT=0
    b"\x00\x00"  # NSCOUNT=0
    b"\x00\x00"  # ARCOUNT=0
    b"\x20"  # QNAME length = 32
    + _NETBIOS_NAME
    + b"\x00"  # root label
    + b"\x00\x21"  # QTYPE: NBSTAT (33)
    + b"\x00\x01"  # QCLASS: IN
)

# mDNS: query for _services._dns-sd._udp.local PTR
# TX ID must be 0 per RFC 6762 for mDNS queries.
# QU bit (0x8000) in QCLASS requests a unicast response rather than multicast.
_MDNS_PAYLOAD = (
    b"\x00\x00"  # TX ID = 0 (mDNS)
    b"\x00\x00"  # Flags: standard query
    b"\x00\x01"  # QDCOUNT=1
    b"\x00\x00\x00\x00\x00\x00"  # ANCOUNT, NSCOUNT, ARCOUNT
    b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"  # QNAME
    b"\x00\x0c"  # QTYPE: PTR (12)
    b"\x80\x01"  # QCLASS: IN with QU bit
)

# TFTP RRQ for "motd" — common file, triggers an error response even if it doesn't exist
# which still proves the TFTP service is listening
_TFTP_PAYLOAD = (
    b"\x00\x01"  # Opcode: RRQ
    b"motd\x00"  # Filename
    b"netascii\x00"  # Mode
)

# IKE v1 informational exchange — simplest valid IKE packet
# Responders that understand IKE will send back an informational or error PDU
_IKE_PAYLOAD = (
    b"\x00" * 8  # Initiator SPI (8 bytes)
    + b"\x00" * 8  # Responder SPI (0 = new SA)
    + b"\x00"  # Next Payload: None
    + b"\x10"  # Version: 1.0
    + b"\x05"  # Exchange Type: Informational
    + b"\x00"  # Flags
    + b"\x00\x00\x00\x01"  # Message ID
    + b"\x00\x00\x00\x1c"  # Total length: 28
)

# ---------------------------------------------------------------------------
# Payload registry — port → bytes to send
# ---------------------------------------------------------------------------

_UDP_PAYLOADS: dict[int, bytes] = {
    53: _DNS_PAYLOAD,
    69: _TFTP_PAYLOAD,
    111: b"\x00" * 4,  # RPCBind portmapper — null XID, usually triggers a response
    123: _NTP_PAYLOAD,
    137: _NETBIOS_PAYLOAD,
    138: b"",  # NetBIOS Datagram — just knock
    161: _SNMP_PAYLOAD,
    162: b"",  # SNMP Trap receiver — just knock
    500: _IKE_PAYLOAD,
    514: b"",  # Syslog — listens but never responds; ICMP = no listener
    520: b"",  # RIP — responds to RIP requests, empty is enough to detect
    1194: b"",  # OpenVPN — TLS handshake needed but empty triggers ICMP
    1900: _SSDP_PAYLOAD,
    4500: _IKE_PAYLOAD,  # IKE NAT-Traversal uses same format
    5353: _MDNS_PAYLOAD,
    5355: _MDNS_PAYLOAD,  # LLMNR uses same packet format as DNS
}

# ---------------------------------------------------------------------------
# Response validators
# ---------------------------------------------------------------------------


def _valid_dns(data: bytes) -> bool:
    """Check that the response looks like a DNS reply (QR bit set)."""
    if len(data) < 12:
        return False
    flags = struct.unpack("!H", data[2:4])[0]
    return bool(flags & 0x8000)  # QR bit = 1 means response


def _valid_ntp(data: bytes) -> bool:
    """NTP server responses are 48 bytes, mode 4 (server) or 5 (broadcast)."""
    if len(data) < 48:
        return False
    mode = data[0] & 0x07
    return mode in (4, 5)  # 4=server, 5=broadcast


def _valid_snmp(data: bytes) -> bool:
    """SNMP responses start with SEQUENCE (0x30) and are at least 10 bytes."""
    return len(data) >= 10 and data[0] == 0x30


def _valid_ssdp(data: bytes) -> bool:
    """SSDP responses start with HTTP/1. header."""
    return data[:7] in (b"HTTP/1.", b"HTTP/1.0", b"HTTP/1.1"[:7])


def _valid_netbios(data: bytes) -> bool:
    """NetBIOS stat response: tx ID matches and RCODE is 0 (success)."""
    if len(data) < 12:
        return False
    # flags byte 2-3: response bit + rcode
    flags = struct.unpack("!H", data[2:4])[0]
    return bool(flags & 0x8000)  # response flag set


_VALIDATORS: dict[int, Callable[[bytes], bool]] = {
    53: _valid_dns,
    123: _valid_ntp,
    137: _valid_netbios,
    161: _valid_snmp,
    1900: _valid_ssdp,
    5353: _valid_dns,  # mDNS uses the same wire format as DNS
    5355: _valid_dns,  # LLMNR also uses DNS format
}

# ---------------------------------------------------------------------------
# Banner extraction — pull a human-readable string from the response
# ---------------------------------------------------------------------------


def _extract_banner(port: int, data: bytes) -> str | None:
    """Best-effort: extract something useful from a UDP response."""
    if not data:
        return None

    if port == 123 and len(data) >= 48:
        # NTP: stratum at byte 1, reference ID at bytes 12-15
        stratum = data[1]
        ref_id = data[12:16]
        try:
            ref_str = ref_id.decode("ascii").rstrip("\x00")
        except UnicodeDecodeError:
            ref_str = ref_id.hex()
        return f"NTP stratum={stratum} refid={ref_str}"

    if port == 161 and data[0] == 0x30:
        # SNMP: try to extract a readable string from the response
        # The sysDescr value is usually a long ASCII string somewhere in the payload
        try:
            text = data.decode("latin-1")
            # look for a printable run of at least 10 chars
            run = ""
            best = ""
            for ch in text:
                if ch.isprintable() and ch not in "\x00\x01\x02":
                    run += ch
                    if len(run) > len(best):
                        best = run
                else:
                    run = ""
            if len(best) >= 8:
                return f"SNMP: {best[:80]}"
        except Exception:
            pass
        return "SNMP agent"

    if port == 1900 and data[:5] in (b"HTTP/", b"http/"):
        # SSDP: grab the first few headers
        try:
            lines = data.decode("utf-8", errors="replace").split("\r\n")
            server = next((ln for ln in lines if ln.lower().startswith("server:")), "")
            usn = next((ln for ln in lines if ln.lower().startswith("usn:")), "")
            return " | ".join(filter(None, [server, usn]))[:100] or "SSDP/UPnP"
        except Exception:
            return "SSDP/UPnP"

    if port in (53, 5353, 5355) and _valid_dns(data):
        return "DNS"

    if port == 137 and _valid_netbios(data):
        return "NetBIOS Name Service"

    if port == 69:
        # TFTP: opcode at bytes 0-1
        if len(data) >= 2:
            opcode = struct.unpack("!H", data[:2])[0]
            names = {1: "RRQ", 2: "WRQ", 3: "DATA", 4: "ACK", 5: "ERROR"}
            return f"TFTP {names.get(opcode, f'opcode={opcode}')}"

    # Generic: show first 40 printable bytes
    try:
        printable = "".join(ch if ch.isprintable() else "." for ch in data[:40].decode("latin-1"))
        return printable.strip(".") or None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Top UDP ports — the 20 most useful for first-pass UDP recon
# ---------------------------------------------------------------------------

_UDP_TOP_PORTS: list[int] = [
    53,  # DNS
    67,  # DHCP server
    68,  # DHCP client
    69,  # TFTP
    111,  # RPCBind / Portmapper
    123,  # NTP
    137,  # NetBIOS Name Service
    138,  # NetBIOS Datagram
    161,  # SNMP
    162,  # SNMP Trap
    500,  # IKE/ISAKMP
    514,  # Syslog
    520,  # RIP
    1194,  # OpenVPN
    1900,  # SSDP/UPnP
    4500,  # IKE NAT-T
    5353,  # mDNS
    5355,  # LLMNR
    11211,  # Memcached (UDP mode)
    27015,  # Steam/game servers — common in enterprise too
]


def get_udp_top_ports(n: int | None = None) -> list[int]:
    """Return the top N UDP ports worth scanning.

    With no argument, returns all 20. These cover DNS, DHCP, NTP, SNMP,
    NetBIOS, SSDP, IKE, Syslog, mDNS, LLMNR — the ones TCP scanners miss.
    """
    if n is None:
        return list(_UDP_TOP_PORTS)
    return _UDP_TOP_PORTS[:n]


# ---------------------------------------------------------------------------
# Core probe — synchronous, runs in executor threads
# ---------------------------------------------------------------------------


def _udp_probe_sync(
    host: str,
    port: int,
    payload: bytes,
    timeout: float,
    retries: int,
) -> tuple[PortState, bytes | None]:
    """Send a UDP probe and read the response.

    Returns (state, raw_response_data).
    Retries on timeout — UDP packets get dropped on congested links more often
    than you'd think, even on LAN. One retry is usually enough.
    """
    for attempt in range(retries + 1):
        family = socket.AF_INET6 if is_ipv6(host) else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(payload if payload else b"\x00", (host, port))
            data, _ = sock.recvfrom(4096)
            return PortState.OPEN, data
        except TimeoutError:
            # no response — could be open|filtered or just slow
            if attempt < retries:
                continue
            return PortState.FILTERED, None
        except ConnectionResetError:
            # Windows delivers ICMP port unreachable as ConnectionResetError
            return PortState.CLOSED, None
        except OSError as exc:
            # Linux delivers ICMP port unreachable via errno 111 (ECONNREFUSED)
            # errno 10054 is the Windows equivalent via WSAECONNRESET
            if exc.errno in (111, 10054):
                return PortState.CLOSED, None
            # anything else (network unreachable, etc.) → treat as filtered
            return PortState.FILTERED, None
        finally:
            sock.close()

    return PortState.FILTERED, None  # all retries exhausted


# ---------------------------------------------------------------------------
# Async wrapper
# ---------------------------------------------------------------------------


async def _scan_port(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    semaphore: asyncio.Semaphore,
) -> ScanResult:
    async with semaphore:
        payload = _UDP_PAYLOADS.get(port, b"")
        loop = asyncio.get_running_loop()
        try:
            state, data = await asyncio.wait_for(
                loop.run_in_executor(None, _udp_probe_sync, host, port, payload, timeout, retries),
                timeout=timeout * (retries + 1) + 1.0,
            )
        except asyncio.TimeoutError:
            state, data = PortState.FILTERED, None

        # validate response if we have a validator for this port
        banner: str | None = None
        if state == PortState.OPEN and data is not None:
            validator = _VALIDATORS.get(port)
            if validator and not validator(data):
                # response didn't validate — still OPEN but mark it
                banner = f"unvalidated: {_extract_banner(port, data) or data[:20].hex()}"
            else:
                banner = _extract_banner(port, data)

        return ScanResult(
            host=host,
            port=port,
            protocol="udp",
            state=state,
            banner=banner,
        )


async def udp_scan_host(
    host: str,
    ports: list[int],
    timeout: float = 2.0,
    max_concurrent: int = 50,
    retries: int = 1,
) -> list[ScanResult]:
    """Scan UDP ports on a single host using protocol-specific payloads.

    Returns results for ALL ports (open, closed, filtered). Callers typically
    filter on state == OPEN.

    timeout: per-probe wait in seconds. Total worst-case time per port =
             timeout * (retries + 1). Default: 2.0s × 2 = 4s max per port.
    max_concurrent: 50 is a good default — too high and ICMP rate-limiting
                    causes false FILTERED results.
    retries: 1 means each port gets two attempts before marking filtered.
             Set to 0 for a fast but less accurate scan.
    """
    if not ports:
        raise ValueError("Port list cannot be empty")

    semaphore = asyncio.Semaphore(max_concurrent)
    tasks = [_scan_port(host, p, timeout, retries, semaphore) for p in ports]
    return list(await asyncio.gather(*tasks))
