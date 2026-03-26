"""SYN scan via raw packet crafting.

Half-open TCP scan: send SYN, watch for SYN-ACK (open) or RST (closed),
then immediately send RST to tear down without completing the handshake.

Why half-open matters:
  - Older stateful firewalls that only log completed connections miss it
  - Some IDS thresholds are tuned for full connections, not half-open
  - Faster than connect scan — skips the full FIN/RST teardown
  - This is what nmap -sS does

Two implementation paths (selected at runtime):
  1. Scapy (preferred): cross-platform with libpcap/Npcap
     Install: pip install porthawk[syn]
  2. Raw sockets (Linux-only fallback): needs CAP_NET_RAW or root, no extra deps

Platform notes:
  - Windows: raw TCP sends are blocked since XP SP2 by design. Scapy + Npcap
    is the only option. Install Npcap from npcap.com, then pip install porthawk[syn]
  - macOS: Scapy works with root. Raw socket fallback also works but the kernel
    may send RST before our sniffer reads the SYN-ACK on some versions.
  - Linux: both paths work. Raw socket path needs root or CAP_NET_RAW.
    The kernel sends RST for incoming SYN-ACKs because it has no socket for
    that connection — that's fine, it just means the target gets a clean teardown.

Requires root/admin regardless. ScanPermissionError raised otherwise.
"""

from __future__ import annotations

import asyncio
import os
import random
import socket
import struct
import sys
import time

from porthawk.exceptions import ScanPermissionError
from porthawk.scanner import PortState, ScanResult

# --------------------------------------------------------------------------
# privilege check
# --------------------------------------------------------------------------

# On Linux/macOS, os.getuid() == 0 means root.
# On Windows, we check the well-known Admin SID via ctypes.
# Either way, we surface a clear message rather than cryptic PermissionError.

_IS_WINDOWS = sys.platform == "win32"
_IS_LINUX = sys.platform.startswith("linux")
_IS_MACOS = sys.platform == "darwin"


def _has_raw_socket_privilege() -> bool:
    """Check if we can open raw sockets without actually opening one."""
    if _IS_WINDOWS:
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    else:
        return os.getuid() == 0  # type: ignore[attr-defined]


def _require_privileges() -> None:
    """Raise ScanPermissionError if we can't do raw socket operations."""
    if not _has_raw_socket_privilege():
        if _IS_WINDOWS:
            raise ScanPermissionError(
                "SYN scan needs Administrator privileges on Windows. "
                "Run your terminal as Administrator and install Npcap from npcap.com, "
                "then: pip install porthawk[syn]"
            )
        else:
            raise ScanPermissionError(
                "SYN scan needs root or CAP_NET_RAW. "
                "Try: sudo porthawk -t <target> --syn  "
                "or:  setcap cap_net_raw=ep $(which python3)"
            )


# --------------------------------------------------------------------------
# Scapy path — preferred when available
# --------------------------------------------------------------------------


def _scapy_available() -> bool:
    try:
        import importlib.util

        return importlib.util.find_spec("scapy") is not None
    except Exception:
        return False


def _syn_probe_scapy(host: str, port: int, timeout: float) -> tuple[PortState, float]:
    """SYN probe via Scapy. Works on all platforms with libpcap/Npcap.

    The flow:
      1. Send SYN with random source port and seq number
      2. sr1() receives the first reply — SYN-ACK (open), RST (closed), or timeout
      3. If SYN-ACK: immediately send RST — half-open, no full handshake
      4. If no reply: FILTERED (firewall dropped it silently)
    """
    # scapy is guarded by _scapy_available() before calling this
    from scapy.all import IP, TCP, conf, send, sr1

    conf.verb = 0  # scapy logs are noisy, suppress them

    src_port = random.randint(1024, 65000)
    seq = random.randint(0, 2**32 - 1)

    t_start = time.monotonic()
    pkt = IP(dst=host) / TCP(sport=src_port, dport=port, flags="S", seq=seq)
    resp = sr1(pkt, timeout=timeout, verbose=0)
    latency_ms = round((time.monotonic() - t_start) * 1000, 2)

    if resp is None:
        return PortState.FILTERED, round(timeout * 1000, 2)

    if not resp.haslayer(TCP):
        return PortState.FILTERED, latency_ms

    tcp_flags = resp[TCP].flags
    if tcp_flags & 0x12:  # SYN-ACK (SYN=0x02, ACK=0x10)
        # send RST to cleanly tear down — some targets log half-open connections
        # that never get a RST, which is fine for evasion but messy for repeated scans
        rst = IP(dst=host) / TCP(
            sport=src_port,
            dport=port,
            flags="R",
            seq=resp[TCP].ack,
        )
        send(rst, verbose=0)
        return PortState.OPEN, latency_ms

    if tcp_flags & 0x04:  # RST
        return PortState.CLOSED, latency_ms

    return PortState.FILTERED, latency_ms


# --------------------------------------------------------------------------
# Raw socket path — Linux/macOS fallback (no scapy required)
# --------------------------------------------------------------------------

# TCP flag bitmasks
_TCP_SYN = 0x02
_TCP_ACK = 0x10
_TCP_RST = 0x04
_TCP_SYN_ACK = _TCP_SYN | _TCP_ACK

# IPv4 constants
_IP_PROTO_TCP = socket.IPPROTO_TCP
_IP_HEADER_LEN = 20
_TCP_HEADER_LEN = 20


def _internet_checksum(data: bytes) -> int:
    """Standard internet checksum (RFC 1071). Used for both IP and TCP headers.

    Works on arbitrary byte sequences. Adds 16-bit words, folds the carry,
    returns the one's complement.
    """
    if len(data) % 2 != 0:
        data += b"\x00"

    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word

    # fold carry bits
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return ~total & 0xFFFF


def _tcp_checksum(src_ip: str, dst_ip: str, tcp_segment: bytes) -> int:
    """TCP checksum needs a pseudo-header (RFC 793 section 3.1).

    Pseudo-header = src_ip + dst_ip + zero + protocol + tcp_length.
    The real checksum covers pseudo-header + TCP header + data.
    """
    pseudo = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,
        _IP_PROTO_TCP,
        len(tcp_segment),
    )
    return _internet_checksum(pseudo + tcp_segment)


def _get_source_ip(dst_host: str) -> str:
    """Figure out which local IP we'd use to reach this host.

    Opens a UDP socket (no packets actually sent) and reads the bound address.
    Handles VPNs and multiple NICs correctly because the kernel picks the right route.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((dst_host, 80))
        return s.getsockname()[0]


def _build_syn_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
) -> bytes:
    """Build a raw IPv4 + TCP SYN packet from scratch.

    IP header: 20 bytes, no options.
    TCP header: 20 bytes, no options.
    SYN flag only — no ACK, no PSH, no FIN.

    Checksums: IP checksum is left at 0 (kernel fills it with IP_HDRINCL=True).
    TCP checksum is calculated manually — kernel does NOT fill it for raw sockets.
    """
    # --- IP header ---
    ip_ver_ihl = (4 << 4) | 5  # version 4, IHL=5 (20 bytes, no options)
    ip_tos = 0
    ip_total_len = _IP_HEADER_LEN + _TCP_HEADER_LEN
    ip_id = random.randint(0, 0xFFFF)
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = _IP_PROTO_TCP
    ip_checksum = 0  # kernel fills this when IP_HDRINCL is used — leave at 0

    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ip_ver_ihl,
        ip_tos,
        ip_total_len,
        ip_id,
        ip_frag_off,
        ip_ttl,
        ip_proto,
        ip_checksum,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )

    # --- TCP header (first pass — checksum=0 placeholder) ---
    tcp_doff_flags = 5 << 4  # data offset = 5 (20 bytes), reserved = 0
    tcp_flags = _TCP_SYN
    tcp_window = 65535  # advertise max window — we're not a real TCP stack
    tcp_urg_ptr = 0

    tcp_header_no_cksum = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        seq,
        0,  # ack_seq = 0 (SYN has no ACK)
        tcp_doff_flags,
        tcp_flags,
        tcp_window,
        0,  # checksum placeholder
        tcp_urg_ptr,
    )

    # --- calculate real TCP checksum ---
    cksum = _tcp_checksum(src_ip, dst_ip, tcp_header_no_cksum)

    # --- TCP header (second pass — with real checksum) ---
    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        seq,
        0,
        tcp_doff_flags,
        tcp_flags,
        tcp_window,
        cksum,
        tcp_urg_ptr,
    )

    return ip_header + tcp_header


def _parse_response(raw_pkt: bytes, expected_src_ip: str, expected_src_port: int) -> int | None:
    """Parse a raw IP packet and extract TCP flags if it's the response we want.

    Returns TCP flags byte if this packet is from (expected_src_ip, expected_src_port),
    None if it's unrelated traffic.
    """
    if len(raw_pkt) < _IP_HEADER_LEN + _TCP_HEADER_LEN:
        return None

    # IP header: parse IHL to find where TCP starts
    ip_ihl = (raw_pkt[0] & 0x0F) * 4
    ip_src = socket.inet_ntoa(raw_pkt[12:16])

    if ip_src != expected_src_ip:
        return None

    # TCP header starts at ip_ihl
    if len(raw_pkt) < ip_ihl + _TCP_HEADER_LEN:
        return None

    tcp_src_port = struct.unpack("!H", raw_pkt[ip_ihl : ip_ihl + 2])[0]
    if tcp_src_port != expected_src_port:
        return None

    tcp_flags = raw_pkt[ip_ihl + 13]  # flags byte: offset 13 in TCP header
    return tcp_flags


def _build_rst_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    ack_seq: int,
) -> bytes:
    """Build an RST packet to cleanly terminate the half-open connection."""
    ip_ver_ihl = (4 << 4) | 5
    ip_total_len = _IP_HEADER_LEN + _TCP_HEADER_LEN
    ip_id = random.randint(0, 0xFFFF)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ip_ver_ihl,
        0,
        ip_total_len,
        ip_id,
        0,
        64,
        _IP_PROTO_TCP,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )

    tcp_header_no_cksum = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        ack_seq,
        0,
        (5 << 4),
        _TCP_RST,
        65535,
        0,
        0,
    )
    cksum = _tcp_checksum(src_ip, dst_ip, tcp_header_no_cksum)
    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        ack_seq,
        0,
        (5 << 4),
        _TCP_RST,
        65535,
        cksum,
        0,
    )

    return ip_header + tcp_header


def _syn_probe_raw(host: str, port: int, timeout: float) -> tuple[PortState, float]:
    """SYN probe via raw sockets. Linux/macOS only — Windows blocks raw TCP sends.

    Steps:
      1. Open send socket (SOCK_RAW + IPPROTO_RAW + IP_HDRINCL)
      2. Open receive socket (SOCK_RAW + IPPROTO_TCP) to sniff responses
      3. Send SYN packet we built manually
      4. Wait up to `timeout` seconds for a response
      5. Parse flags: SYN-ACK → open + send RST, RST → closed, nothing → filtered
    """
    if _IS_WINDOWS:
        raise ScanPermissionError(
            "Raw socket SYN scan is not supported on Windows without Scapy + Npcap. "
            "Install with: pip install porthawk[syn]  (and install Npcap from npcap.com)"
        )

    src_ip = _get_source_ip(host)
    src_port = random.randint(1024, 65000)
    seq = random.randint(0, 2**32 - 1)

    syn_pkt = _build_syn_packet(src_ip, host, src_port, port, seq)

    try:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except PermissionError as exc:
        raise ScanPermissionError(
            "Raw socket needs root or CAP_NET_RAW. "
            "Try: sudo porthawk ... --syn  or  setcap cap_net_raw=ep $(which python3)"
        ) from exc

    try:
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        recv_sock.settimeout(timeout)

        t_start = time.monotonic()
        send_sock.sendto(syn_pkt, (host, 0))

        deadline = t_start + timeout
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            recv_sock.settimeout(remaining)
            try:
                raw_pkt, _ = recv_sock.recvfrom(4096)
            except TimeoutError:
                break

            flags = _parse_response(raw_pkt, host, port)
            if flags is None:
                continue

            latency_ms = round((time.monotonic() - t_start) * 1000, 2)

            if flags & _TCP_SYN_ACK == _TCP_SYN_ACK:
                # extract ack_seq from the response to build a correct RST
                ip_ihl = (raw_pkt[0] & 0x0F) * 4
                ack_num = struct.unpack("!L", raw_pkt[ip_ihl + 8 : ip_ihl + 12])[0]
                rst_pkt = _build_rst_packet(src_ip, host, src_port, port, ack_num)
                try:
                    send_sock.sendto(rst_pkt, (host, 0))
                except OSError:
                    pass  # kernel might have already sent RST — that's fine
                return PortState.OPEN, latency_ms

            if flags & _TCP_RST:
                return PortState.CLOSED, latency_ms

    finally:
        send_sock.close()
        recv_sock.close()

    return PortState.FILTERED, round(timeout * 1000, 2)


# --------------------------------------------------------------------------
# dispatch — pick the right implementation at runtime
# --------------------------------------------------------------------------


def _syn_probe(host: str, port: int, timeout: float) -> tuple[PortState, float]:
    """Pick Scapy or raw socket path based on what's available."""
    if _scapy_available():
        return _syn_probe_scapy(host, port, timeout)
    if _IS_WINDOWS:
        raise ScanPermissionError(
            "SYN scan on Windows requires Scapy + Npcap. "
            "Install Npcap from npcap.com, then: pip install porthawk[syn]"
        )
    return _syn_probe_raw(host, port, timeout)


# --------------------------------------------------------------------------
# public API
# --------------------------------------------------------------------------


def get_syn_backend() -> str:
    """Report which backend will be used for SYN scanning."""
    if _scapy_available():
        import importlib.metadata

        try:
            ver = importlib.metadata.version("scapy")
            return f"scapy {ver}"
        except Exception:
            return "scapy (version unknown)"
    if _IS_WINDOWS:
        return "unavailable (Windows needs Scapy + Npcap)"
    return f"raw sockets ({sys.platform})"


async def syn_scan_host(
    host: str,
    ports: list[int],
    timeout: float = 1.0,
    max_concurrent: int = 100,
) -> list[ScanResult]:
    """Half-open SYN scan on a single host.

    Requires root/admin. Raises ScanPermissionError otherwise.

    Uses a thread pool because raw socket I/O is blocking and doesn't integrate
    cleanly with asyncio's event loop. Same pattern as UDP scan.

    Args:
        host: target IP or hostname
        ports: list of port numbers to scan
        timeout: per-port probe timeout in seconds
        max_concurrent: max simultaneous probes (default lower than TCP connect
                        scan — raw socket ops are heavier)

    Returns:
        list[ScanResult] with protocol="tcp", same structure as regular scan results
    """
    if not ports:
        raise ValueError("Port list is empty — nothing to scan")

    _require_privileges()

    semaphore = asyncio.Semaphore(max_concurrent)
    loop = asyncio.get_running_loop()

    async def _probe_one(port: int) -> ScanResult:
        async with semaphore:
            state, latency = await loop.run_in_executor(None, _syn_probe, host, port, timeout)
            return ScanResult(
                host=host,
                port=port,
                protocol="tcp",
                state=state,
                latency_ms=latency,
            )

    return list(await asyncio.gather(*[_probe_one(p) for p in ports]))
