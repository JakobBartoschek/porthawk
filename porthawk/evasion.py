"""IDS/IPS evasion techniques for authorized red-team scanning.

Slow & Low: fragment packets, add random timing jitter, send decoy probes,
use non-standard TCP flag combinations to avoid signature-based detection.

All of this requires root/admin and Scapy for full functionality.
Raw socket fallback handles fragmentation and timing on Linux/macOS.
Decoy scans need Scapy — IP spoofing via raw sockets is unreliable without libpcap.

Authorized use only. Get written permission before scanning anything.
"""

from __future__ import annotations

import asyncio
import random
import socket
import struct
import time
from dataclasses import dataclass, field

from porthawk.exceptions import ScanPermissionError
from porthawk.scanner import PortState, ScanResult
from porthawk.syn_scan import (
    _IP_HEADER_LEN,
    _IP_PROTO_TCP,
    _IS_WINDOWS,
    _TCP_HEADER_LEN,
    _TCP_RST,
    _TCP_SYN,
    _TCP_SYN_ACK,
    _get_source_ip,
    _has_raw_socket_privilege,
    _parse_response,
    _scapy_available,
    _tcp_checksum,
)

# additional TCP flags not needed in the SYN-only syn_scan.py
_TCP_FIN = 0x01
_TCP_PSH = 0x08
_TCP_URG = 0x20
_TCP_ACK = 0x10

# scan type → TCP flag bitmask
_SCAN_FLAGS: dict[str, int] = {
    "syn": _TCP_SYN,
    "fin": _TCP_FIN,
    "null": 0x00,
    "xmas": _TCP_FIN | _TCP_PSH | _TCP_URG,  # 0x29 — all the lights on
    "ack": _TCP_ACK,
    "maimon": _TCP_FIN | _TCP_ACK,  # Uriel Maimon's 1996 trick — works on some BSD stacks
}

VALID_SCAN_TYPES = list(_SCAN_FLAGS.keys())


@dataclass
class EvasionConfig:
    """Tuning knobs for IDS/IPS evasion.

    All defaults are conservative (no evasion). Enable features explicitly
    or use slow_low_config() for a ready-made red-team preset.
    """

    scan_type: str = "syn"

    # timing jitter — random pause BEFORE each probe is sent
    min_delay: float = 0.0  # seconds (0 = no delay)
    max_delay: float = 0.0  # seconds
    jitter_distribution: str = "uniform"  # "uniform" or "exponential"

    # IP fragmentation — splits the IP payload into small chunks
    fragment: bool = False
    fragment_size: int = 8  # bytes per fragment, must be a multiple of 8

    # decoy IPs (Scapy required — IP spoofing needs libpcap)
    decoys: list[str] = field(default_factory=list)

    # packet-level tweaks
    ttl: int = 64  # IP TTL — set to 128 to look like Windows
    randomize_ip_id: bool = True  # random IP ID field defeats some passive OS fingerprinting

    def __post_init__(self) -> None:
        if self.scan_type not in _SCAN_FLAGS:
            raise ValueError(
                f"Unknown scan type '{self.scan_type}'. " f"Valid: {', '.join(VALID_SCAN_TYPES)}"
            )
        if self.fragment_size < 8 or self.fragment_size % 8 != 0:
            raise ValueError(
                f"fragment_size must be a positive multiple of 8, got {self.fragment_size}"
            )
        if self.min_delay < 0 or self.max_delay < 0:
            raise ValueError("Delay values must be non-negative")
        if self.max_delay > 0 and self.min_delay > self.max_delay:
            raise ValueError(f"min_delay ({self.min_delay}) > max_delay ({self.max_delay})")
        if self.jitter_distribution not in ("uniform", "exponential"):
            raise ValueError(
                f"Unknown distribution '{self.jitter_distribution}'. "
                "Use 'uniform' or 'exponential'"
            )


def slow_low_config() -> EvasionConfig:
    """Red-team preset — prioritizes stealth over speed.

    - 5–30s random gaps between probes (exponential distribution)
    - IP fragmentation with minimum 8-byte fragments
    - TTL=128 to look like a Windows host (confuses passive OS fingerprinting on the target)
    - Decoys not included — add them explicitly since they require context

        cfg = slow_low_config()
        cfg.decoys = ["1.2.3.4", "5.6.7.8"]  # mix real-looking IPs into the traffic
    """
    return EvasionConfig(
        scan_type="syn",
        min_delay=5.0,
        max_delay=30.0,
        jitter_distribution="exponential",
        fragment=True,
        fragment_size=8,
        ttl=128,
        randomize_ip_id=True,
    )


def _next_delay(config: EvasionConfig) -> float:
    """Compute the next inter-probe delay based on the configured distribution.

    Exponential distribution gives Poisson-like inter-arrival times — looks like
    real user traffic hitting a service rather than a systematic scan.
    """
    if config.max_delay == 0.0 and config.min_delay == 0.0:
        return 0.0

    if config.max_delay == 0.0:
        return config.min_delay

    span = config.max_delay - config.min_delay

    if config.jitter_distribution == "exponential":
        # exponential centered at the midpoint — clamp to [min, max]
        mean = config.min_delay + span * 0.5
        sample = random.expovariate(1.0 / mean) if mean > 0 else 0.0
        return max(config.min_delay, min(config.max_delay, sample))

    # uniform
    return random.uniform(config.min_delay, config.max_delay)


def _build_probe_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    flags: int,
    ttl: int = 64,
    randomize_ip_id: bool = True,
) -> bytes:
    """Build a raw IPv4 + TCP probe packet with arbitrary TCP flags.

    Same structure as _build_syn_packet in syn_scan.py but parameterized
    for all TCP flag combinations and TTL control.
    """
    ip_ver_ihl = (4 << 4) | 5
    ip_id = random.randint(0, 0xFFFF) if randomize_ip_id else 0x4142

    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        ip_ver_ihl,
        0,
        _IP_HEADER_LEN + _TCP_HEADER_LEN,
        ip_id,
        0,
        ttl,
        _IP_PROTO_TCP,
        0,  # checksum=0, kernel fills it with IP_HDRINCL
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )

    tcp_no_cksum = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        seq,
        0,
        (5 << 4),
        flags,
        65535,
        0,
        0,
    )
    cksum = _tcp_checksum(src_ip, dst_ip, tcp_no_cksum)
    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        seq,
        0,
        (5 << 4),
        flags,
        65535,
        cksum,
        0,
    )

    return ip_header + tcp_header


def _fragment_raw(packet: bytes, frag_size: int) -> list[bytes]:
    """Split an IP packet into fragments of frag_size bytes of payload.

    frag_size must be a multiple of 8 (IP fragment offset is in 8-byte units).
    Each fragment gets its own IP header. The original IP ID is preserved across
    all fragments — the target needs it to reassemble.

    The point: many IDS engines only inspect the FIRST fragment (which contains
    the start of the TCP header, including destination port). Split the TCP header
    into small enough chunks and some IDS engines can't reassemble and miss the
    port/flag checks entirely. Works best against older IDS without full fragment
    reassembly.
    """
    ip_ihl = (packet[0] & 0x0F) * 4
    ip_header = packet[:ip_ihl]
    payload = packet[ip_ihl:]

    # pull the fields we need to reuse — ID must be same across all fragments
    ip_id = struct.unpack("!H", ip_header[4:6])[0]
    ip_ver_ihl = ip_header[0]
    ip_tos = ip_header[1]
    ip_ttl = ip_header[8]
    ip_proto = ip_header[9]
    src_addr = ip_header[12:16]
    dst_addr = ip_header[16:20]

    fragments: list[bytes] = []
    offset = 0
    total = len(payload)

    while offset < total:
        chunk = payload[offset : offset + frag_size]
        is_last = (offset + frag_size) >= total

        # fragment offset field: bits 12-0 = offset in 8-byte units
        # MF flag: bit 13 (0x2000) — set on all fragments except the last
        frag_off_word = (0 if is_last else 0x2000) | (offset // 8)

        new_ip = struct.pack(
            "!BBHHHBBH4s4s",
            ip_ver_ihl,
            ip_tos,
            ip_ihl + len(chunk),
            ip_id,
            frag_off_word,
            ip_ttl,
            ip_proto,
            0,  # kernel recalculates checksum
            src_addr,
            dst_addr,
        )

        fragments.append(new_ip + chunk)
        offset += frag_size

    return fragments


def _state_from_flags(
    resp_flags: int | None, scan_type: str, timeout: float
) -> tuple[PortState, float]:
    """Map TCP flags in a response to PortState based on scan type semantics.

    SYN scan (RFC-compliant + Windows):
        SYN-ACK → OPEN, RST → CLOSED, no reply → FILTERED

    FIN / NULL / XMAS / Maimon (RFC 793 §3.9 — not always followed):
        RST → CLOSED
        No reply → OPEN (RFC says open ports silently discard these)
        NOTE: Windows sends RST for open AND closed — FIN/NULL/XMAS unreliable against Windows targets

    ACK scan — maps stateless firewall rules, not port state:
        RST → UNFILTERED (packet reached the host, we report OPEN for ScanResult compat)
        No reply → FILTERED
    """
    timed_out = round(timeout * 1000, 2)

    if scan_type == "syn":
        if resp_flags is None:
            return PortState.FILTERED, timed_out
        if resp_flags & _TCP_SYN_ACK == _TCP_SYN_ACK:
            return PortState.OPEN, 0.0
        if resp_flags & _TCP_RST:
            return PortState.CLOSED, 0.0
        return PortState.FILTERED, 0.0

    elif scan_type in ("fin", "null", "xmas", "maimon"):
        if resp_flags is None:
            # no RST = port is not actively rejecting = likely open
            return PortState.OPEN, timed_out
        if resp_flags & _TCP_RST:
            return PortState.CLOSED, 0.0
        return PortState.OPEN, 0.0

    elif scan_type == "ack":
        if resp_flags is None:
            return PortState.FILTERED, timed_out
        if resp_flags & _TCP_RST:
            # RST = packet reached the host, no stateful firewall in the way
            return PortState.OPEN, 0.0  # OPEN here means "unfiltered"
        return PortState.FILTERED, 0.0

    return PortState.FILTERED, timed_out


def _evasion_probe_scapy(
    host: str, port: int, config: EvasionConfig, timeout: float
) -> tuple[PortState, float]:
    """Evasion probe via Scapy — handles decoys, fragmentation, and custom flags.

    Decoy flow:
        1. Send spoofed probes from each decoy IP — target sees scans from multiple hosts
        2. Short random pause between decoys (burst = obvious)
        3. Send real probe and wait for response

    For fragmentation, Scapy's fragment() reassembles on our end too, so sr1()
    gets the complete response. The target gets the fragmented probe.
    """
    from scapy.all import IP, TCP, conf, fragment, send, sr1

    conf.verb = 0

    flags_int = _SCAN_FLAGS[config.scan_type]
    src_port = random.randint(1024, 65000)
    seq = random.randint(0, 2**32 - 1)

    # send decoys before the real probe — IDS sees multiple "scanners"
    for decoy_ip in config.decoys:
        decoy = IP(src=decoy_ip, dst=host, ttl=config.ttl) / TCP(
            sport=random.randint(1024, 65000),
            dport=port,
            flags=flags_int,
            seq=random.randint(0, 2**32 - 1),
        )
        if config.fragment:
            for frag in fragment(decoy, fragsize=config.fragment_size):
                send(frag, verbose=0)
        else:
            send(decoy, verbose=0)
        # irregular spacing between decoys — burst timing is a detection signature
        time.sleep(random.uniform(0.05, 0.3))

    probe = IP(dst=host, ttl=config.ttl) / TCP(sport=src_port, dport=port, flags=flags_int, seq=seq)

    t_start = time.monotonic()

    if config.fragment:
        frags = fragment(probe, fragsize=config.fragment_size)
        for frag in frags[:-1]:
            send(frag, verbose=0)
        # only the last fragment triggers sr1() — response comes after target reassembles
        resp = sr1(frags[-1], timeout=timeout, verbose=0)
    else:
        resp = sr1(probe, timeout=timeout, verbose=0)

    latency_ms = round((time.monotonic() - t_start) * 1000, 2)

    if resp is None or not resp.haslayer(TCP):
        state, _ = _state_from_flags(None, config.scan_type, timeout)
        return state, round(timeout * 1000, 2)

    resp_flags = int(resp[TCP].flags)

    # SYN-ACK → send RST to clean up the half-open connection
    if config.scan_type == "syn" and resp_flags & 0x12 == 0x12:
        rst = IP(dst=host) / TCP(sport=src_port, dport=port, flags="R", seq=resp[TCP].ack)
        send(rst, verbose=0)

    state, partial = _state_from_flags(resp_flags, config.scan_type, timeout)
    return state, latency_ms


def _build_rst_cleanup(
    src_ip: str, dst_ip: str, src_port: int, dst_port: int, ack_seq: int
) -> bytes:
    """Minimal RST for SYN scan cleanup in raw socket mode."""
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | 5,
        0,
        _IP_HEADER_LEN + _TCP_HEADER_LEN,
        random.randint(0, 0xFFFF),
        0,
        64,
        _IP_PROTO_TCP,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    tcp_no_cksum = struct.pack(
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
    cksum = _tcp_checksum(src_ip, dst_ip, tcp_no_cksum)
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


def _evasion_probe_raw(
    host: str, port: int, config: EvasionConfig, timeout: float
) -> tuple[PortState, float]:
    """Evasion probe via raw sockets — Linux/macOS only.

    Supports custom TCP flags, fragmentation, and TTL manipulation.
    Decoys not supported here — IP spoofing without libpcap is too unreliable.
    """
    if _IS_WINDOWS:
        raise ScanPermissionError(
            "Raw socket evasion scan is not supported on Windows without Scapy + Npcap. "
            "Install: pip install porthawk[syn]  and Npcap from npcap.com"
        )

    if config.decoys:
        raise ScanPermissionError(
            "Decoy scans require Scapy for reliable IP spoofing. "
            "Install: pip install porthawk[syn]"
        )

    src_ip = _get_source_ip(host)
    src_port = random.randint(1024, 65000)
    seq = random.randint(0, 2**32 - 1)
    flags_int = _SCAN_FLAGS[config.scan_type]

    probe = _build_probe_packet(
        src_ip,
        host,
        src_port,
        port,
        seq,
        flags_int,
        ttl=config.ttl,
        randomize_ip_id=config.randomize_ip_id,
    )

    try:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except PermissionError as exc:
        raise ScanPermissionError(
            "Raw socket needs root or CAP_NET_RAW. " "Try: sudo porthawk ... --slow-low"
        ) from exc

    try:
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        recv_sock.settimeout(timeout)

        t_start = time.monotonic()

        if config.fragment:
            for frag in _fragment_raw(probe, config.fragment_size):
                send_sock.sendto(frag, (host, 0))
        else:
            send_sock.sendto(probe, (host, 0))

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

            resp_flags = _parse_response(raw_pkt, host, port)
            if resp_flags is None:
                continue

            latency_ms = round((time.monotonic() - t_start) * 1000, 2)
            state, _ = _state_from_flags(resp_flags, config.scan_type, timeout)

            if config.scan_type == "syn" and resp_flags & _TCP_SYN_ACK == _TCP_SYN_ACK:
                ip_ihl = (raw_pkt[0] & 0x0F) * 4
                ack_num = struct.unpack("!L", raw_pkt[ip_ihl + 8 : ip_ihl + 12])[0]
                rst = _build_rst_cleanup(src_ip, host, src_port, port, ack_num)
                try:
                    send_sock.sendto(rst, (host, 0))
                except OSError:
                    pass  # kernel probably already sent RST — that's fine

            return state, latency_ms

    finally:
        send_sock.close()
        recv_sock.close()

    state, _ = _state_from_flags(None, config.scan_type, timeout)
    return state, round(timeout * 1000, 2)


def _evasion_probe(
    host: str, port: int, config: EvasionConfig, timeout: float
) -> tuple[PortState, float]:
    """Dispatch to Scapy or raw socket backend."""
    if _scapy_available():
        return _evasion_probe_scapy(host, port, config, timeout)
    if not _IS_WINDOWS:
        return _evasion_probe_raw(host, port, config, timeout)
    raise ScanPermissionError(
        "Evasion scan on Windows requires Scapy + Npcap. "
        "Install: pip install porthawk[syn]  and Npcap from npcap.com"
    )


async def evasion_scan_host(
    host: str,
    ports: list[int],
    config: EvasionConfig | None = None,
    timeout: float = 1.0,
    max_concurrent: int = 10,
) -> list[ScanResult]:
    """Async evasion scanner — probes with IDS/IPS evasion techniques.

    Each probe gets a random pre-sleep based on the config's jitter settings.
    With max_concurrent=1 and high jitter, you get truly serialized slow-and-low behavior.
    With max_concurrent=10 and exponential jitter, probes overlap but have randomized timing.

    The exponential jitter gives Poisson-like inter-arrivals — statistically indistinguishable
    from real users hitting a service, which defeats threshold-based IDS rules.
    """
    if not ports:
        raise ValueError("Port list is empty — nothing to scan")

    if config is None:
        config = EvasionConfig()

    if not _has_raw_socket_privilege():
        if _IS_WINDOWS:
            raise ScanPermissionError(
                "Evasion scan needs Administrator privileges on Windows. "
                "Run as Administrator and install Npcap from npcap.com, "
                "then: pip install porthawk[syn]"
            )
        else:
            raise ScanPermissionError(
                "Evasion scan needs root or CAP_NET_RAW. "
                "Try: sudo porthawk -t <target> --slow-low"
            )

    semaphore = asyncio.Semaphore(max_concurrent)
    loop = asyncio.get_running_loop()

    async def _probe_one(port: int) -> ScanResult:
        # jitter BEFORE acquiring — randomizes the actual send time regardless of concurrency
        delay = _next_delay(config)
        if delay > 0:
            await asyncio.sleep(delay)
        async with semaphore:
            state, latency = await loop.run_in_executor(
                None, _evasion_probe, host, port, config, timeout
            )
        return ScanResult(
            host=host,
            port=port,
            protocol="tcp",
            state=state,
            latency_ms=latency,
        )

    tasks = [asyncio.create_task(_probe_one(p)) for p in ports]
    return await asyncio.gather(*tasks)
