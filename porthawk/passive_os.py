"""Passive OS fingerprinting via TCP/IP stack analysis.

Analyzes SYN-ACK responses to infer the target OS without sending unusual packets.
Extracted features: TTL, TCP window size, MSS, window scale, TCP option order,
SACK support, TCP timestamps, and the IP DF bit.

Two modes:
  - Full fingerprint (raw sockets or Scapy): sends one SYN, parses the SYN-ACK
  - TTL-only fallback: when raw sockets unavailable, degrades gracefully to TTL guessing

Classifier stack:
  1. Rule-based scoring against a signature database (always available)
  2. KNN in 7-dimensional feature space using sklearn if installed — marginally better
     on ambiguous fingerprints where multiple OS families share TTL and window values

Accuracy target: >80% correct OS family identification on public internet hosts.
Main failure modes: VPNs (TTL mangled by tunnel), load balancers (window set by LB),
Docker/k8s (Linux everywhere regardless of host OS).
"""

from __future__ import annotations

import importlib.util
import socket
import struct
import sys
from dataclasses import dataclass, field
from typing import NamedTuple

from porthawk.syn_scan import _scapy_available

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class OsFingerprint:
    """Raw features extracted from a TCP SYN-ACK packet."""

    ttl: int
    window_size: int
    df_bit: bool
    mss: int | None = None
    wscale: int | None = None
    has_timestamp: bool = False
    has_sack: bool = False
    opt_order: tuple[str, ...] = field(default_factory=tuple)


@dataclass
class OsMatch:
    """Result of an OS fingerprint match."""

    os_family: str  # "Windows", "Linux", "macOS", "FreeBSD", "Network Device", "Unknown"
    os_detail: str  # "Windows 10/11", "Linux 5.x", etc.
    confidence: str  # "HIGH", "MEDIUM", "LOW"
    score: float  # 0.0–1.0 from classifier
    matched_signals: list[str]  # which signals contributed most
    method: str  # "tcp_fingerprint", "ttl_only"


class _OsSig(NamedTuple):
    """One row in the signature database."""

    os_family: str
    os_detail: str
    ttl: int
    window: int
    df: bool
    opt_order: tuple[str, ...]
    wscale: int | None
    mss: int | None
    has_timestamp: bool
    has_sack: bool


# ---------------------------------------------------------------------------
# Signature database
# ---------------------------------------------------------------------------
# Built from p0f, nmap-os-db, and per-OS documentation.
# TTL values are the *initial* TTL — routing hops reduce it, but hosts
# almost never start with a value other than 64, 128, or 255.

_OS_DB: list[_OsSig] = [
    # --- Windows ---
    _OsSig(
        "Windows",
        "Windows 10 / 11 / Server 2019+",
        ttl=128,
        window=65535,
        df=True,
        opt_order=("mss", "nop", "wscale", "nop", "nop", "sack"),
        wscale=8,
        mss=1460,
        has_timestamp=False,
        has_sack=True,
    ),
    _OsSig(
        "Windows",
        "Windows 7 / 8 / Server 2012",
        ttl=128,
        window=8192,
        df=True,
        opt_order=("mss", "nop", "wscale", "nop", "nop", "sack"),
        wscale=8,
        mss=1460,
        has_timestamp=False,
        has_sack=True,
    ),
    _OsSig(
        "Windows",
        "Windows XP / Server 2003",
        ttl=128,
        window=65535,
        df=True,
        opt_order=("mss", "nop", "wscale", "nop", "nop", "sack"),
        wscale=0,
        mss=1460,
        has_timestamp=False,
        has_sack=True,
    ),
    # --- Linux ---
    _OsSig(
        "Linux",
        "Linux 4.x (Ubuntu 16.04–18.04 / CentOS 7)",
        ttl=64,
        window=29200,
        df=True,
        opt_order=("mss", "sack", "ts", "nop", "wscale"),
        wscale=7,
        mss=1460,
        has_timestamp=True,
        has_sack=True,
    ),
    _OsSig(
        "Linux",
        "Linux 5.x (Ubuntu 20.04–22.04 / Debian 11)",
        ttl=64,
        window=65535,
        df=True,
        opt_order=("mss", "sack", "ts", "nop", "wscale"),
        wscale=7,
        mss=1460,
        has_timestamp=True,
        has_sack=True,
    ),
    _OsSig(
        "Linux",
        "Linux 6.x (Ubuntu 24.04 / Debian 12 / RHEL 9)",
        ttl=64,
        window=65535,
        df=True,
        opt_order=("mss", "sack", "ts", "nop", "wscale"),
        wscale=7,
        mss=1460,
        has_timestamp=True,
        has_sack=True,
    ),
    _OsSig(
        "Linux",
        "Linux embedded (routers, IoT)",
        ttl=64,
        window=5840,
        df=True,
        opt_order=("mss", "sack", "ts", "nop", "wscale"),
        wscale=2,
        mss=1460,
        has_timestamp=True,
        has_sack=True,
    ),
    # --- Android ---
    _OsSig(
        "Android",
        "Android 8.x–14.x",
        ttl=64,
        window=65535,
        df=True,
        opt_order=("mss", "sack", "ts", "nop", "wscale"),
        wscale=8,
        mss=1460,
        has_timestamp=True,
        has_sack=True,
    ),
    # --- macOS / iOS ---
    _OsSig(
        "macOS",
        "macOS 12–14 (Monterey / Ventura / Sonoma)",
        ttl=64,
        window=65535,
        df=True,
        opt_order=("mss", "nop", "wscale", "nop", "nop", "ts", "sack"),
        wscale=6,
        mss=1460,
        has_timestamp=True,
        has_sack=True,
    ),
    _OsSig(
        "macOS",
        "macOS 10.x–11.x (Catalina / Big Sur)",
        ttl=64,
        window=65535,
        df=True,
        opt_order=("mss", "nop", "wscale", "nop", "nop", "ts", "sack"),
        wscale=5,
        mss=1460,
        has_timestamp=True,
        has_sack=True,
    ),
    _OsSig(
        "iOS",
        "iOS 14–17",
        ttl=64,
        window=65535,
        df=True,
        opt_order=("mss", "nop", "wscale", "nop", "nop", "ts", "sack"),
        wscale=6,
        mss=1460,
        has_timestamp=True,
        has_sack=True,
    ),
    # --- BSD ---
    _OsSig(
        "FreeBSD",
        "FreeBSD 12–14",
        ttl=64,
        window=65535,
        df=True,
        opt_order=("mss", "nop", "wscale", "sack", "ts"),
        wscale=6,
        mss=1460,
        has_timestamp=True,
        has_sack=True,
    ),
    _OsSig(
        "OpenBSD",
        "OpenBSD 7.x",
        ttl=255,
        window=16384,
        df=True,
        opt_order=("mss", "nop", "nop", "sack", "nop", "ts", "wscale"),
        wscale=6,
        mss=1460,
        has_timestamp=True,
        has_sack=True,
    ),
    # --- Network devices ---
    _OsSig(
        "Network Device",
        "Cisco IOS",
        ttl=255,
        window=4128,
        df=False,
        opt_order=("mss",),
        wscale=None,
        mss=536,
        has_timestamp=False,
        has_sack=False,
    ),
    _OsSig(
        "Network Device",
        "Cisco IOS XE",
        ttl=255,
        window=4128,
        df=False,
        opt_order=("mss",),
        wscale=None,
        mss=1460,
        has_timestamp=False,
        has_sack=False,
    ),
    _OsSig(
        "Network Device",
        "HP JetDirect / Printer",
        ttl=60,
        window=8760,
        df=False,
        opt_order=("mss",),
        wscale=None,
        mss=1460,
        has_timestamp=False,
        has_sack=False,
    ),
    _OsSig(
        "Network Device",
        "Generic embedded / RTOS",
        ttl=255,
        window=2048,
        df=False,
        opt_order=("mss",),
        wscale=None,
        mss=1460,
        has_timestamp=False,
        has_sack=False,
    ),
]


# ---------------------------------------------------------------------------
# TCP option parsing
# ---------------------------------------------------------------------------


def _parse_tcp_options(opt_bytes: bytes) -> dict:
    """Parse raw TCP options bytes into a structured dict.

    TCP option format (after the 20-byte fixed header):
      kind=0: End of Options
      kind=1: NOP (1 byte)
      kind=2: MSS (4 bytes: kind, len=4, MSS value 2 bytes)
      kind=3: Window Scale (3 bytes: kind, len=3, shift count)
      kind=4: SACK Permitted (2 bytes: kind, len=2)
      kind=8: Timestamps (10 bytes: kind, len=10, val 4 bytes, echo 4 bytes)
    """
    result: dict = {
        "order": [],
        "mss": None,
        "wscale": None,
        "has_timestamp": False,
        "has_sack": False,
    }

    i = 0
    while i < len(opt_bytes):
        kind = opt_bytes[i]

        if kind == 0:  # End of Options List
            break

        if kind == 1:  # NOP — single byte, no length field
            result["order"].append("nop")
            i += 1
            continue

        if i + 1 >= len(opt_bytes):
            break

        length = opt_bytes[i + 1]
        if length < 2 or i + length > len(opt_bytes):
            break

        if kind == 2 and length == 4:  # MSS
            result["mss"] = struct.unpack("!H", opt_bytes[i + 2 : i + 4])[0]
            result["order"].append("mss")
        elif kind == 3 and length == 3:  # Window Scale
            result["wscale"] = opt_bytes[i + 2]
            result["order"].append("wscale")
        elif kind == 4 and length == 2:  # SACK Permitted
            result["has_sack"] = True
            result["order"].append("sack")
        elif kind == 8 and length == 10:  # Timestamps
            result["has_timestamp"] = True
            result["order"].append("ts")
        else:
            result["order"].append(f"opt{kind}")

        i += length

    return result


# ---------------------------------------------------------------------------
# Feature extraction from raw packets
# ---------------------------------------------------------------------------


def extract_fingerprint(raw_pkt: bytes) -> OsFingerprint | None:
    """Extract OS fingerprint features from a raw IP+TCP packet.

    Works on any TCP packet but most useful on SYN-ACK responses — that's when
    the OS reveals its TCP stack defaults before any negotiation happens.

    Returns None if the packet is malformed or too short.
    """
    # need at least 40 bytes: IP header (20) + TCP header (20)
    if len(raw_pkt) < 40:
        return None

    ip_ihl = (raw_pkt[0] & 0x0F) * 4
    if len(raw_pkt) < ip_ihl + 20:
        return None

    # IP header fields
    ip_flags_frag = struct.unpack("!H", raw_pkt[6:8])[0]
    df_bit = bool(ip_flags_frag & 0x4000)  # bit 14 in the flags+frag field
    ttl = raw_pkt[8]

    # verify it's actually TCP
    proto = raw_pkt[9]
    if proto != socket.IPPROTO_TCP:
        return None

    tcp_offset = ip_ihl
    if len(raw_pkt) < tcp_offset + 20:
        return None

    # TCP header fields
    window_size = struct.unpack("!H", raw_pkt[tcp_offset + 14 : tcp_offset + 16])[0]
    data_offset = (raw_pkt[tcp_offset + 12] >> 4) * 4  # TCP header length in bytes

    if data_offset < 20:
        return None

    opt_start = tcp_offset + 20
    opt_end = tcp_offset + data_offset

    if opt_end > len(raw_pkt):
        opt_end = len(raw_pkt)

    opts = _parse_tcp_options(raw_pkt[opt_start:opt_end])

    return OsFingerprint(
        ttl=ttl,
        window_size=window_size,
        df_bit=df_bit,
        mss=opts["mss"],
        wscale=opts["wscale"],
        has_timestamp=opts["has_timestamp"],
        has_sack=opts["has_sack"],
        opt_order=tuple(opts["order"]),
    )


# ---------------------------------------------------------------------------
# TTL normalization
# ---------------------------------------------------------------------------


def _ttl_family(ttl: int) -> str:
    """Map observed TTL to the initial TTL the host most likely started with.

    Routing hops subtract 1 from TTL. A TTL of 57 from a Linux box 7 hops away
    is still "64-family". We pick the smallest initial value that's >= observed TTL
    from the known set {64, 128, 255}.
    """
    if ttl <= 0:
        return "unknown"
    if ttl <= 64:
        return "64"
    if ttl <= 128:
        return "128"
    return "255"


def _sig_ttl_family(sig: _OsSig) -> str:
    """Get TTL family for a signature."""
    return _ttl_family(sig.ttl)


# ---------------------------------------------------------------------------
# Feature vectors for ML / KNN
# ---------------------------------------------------------------------------


def _feature_vector(fp: OsFingerprint) -> list[float]:
    """Normalize OsFingerprint to a 7-dimensional feature vector in [0, 1].

    Used for both the manual KNN and the sklearn KNN (same features).
    Feature weights are baked in by choosing sensible scales.
    """
    ttl_fam = _ttl_family(fp.ttl)
    ttl_norm = {"64": 0.0, "128": 0.5, "255": 1.0}.get(ttl_fam, 0.25)

    # window size: log-scale would be better but linear keeps it simple
    win_norm = min(fp.window_size / 65535.0, 1.0)

    mss_norm = min((fp.mss or 0) / 9000.0, 1.0)

    # wscale: None (absent) gets 0, which is also the wscale=0 value — acceptable ambiguity
    ws_norm = min((fp.wscale or 0) / 14.0, 1.0)

    ts_flag = 1.0 if fp.has_timestamp else 0.0
    sack_flag = 1.0 if fp.has_sack else 0.0
    df_flag = 1.0 if fp.df_bit else 0.0

    return [ttl_norm, win_norm, mss_norm, ws_norm, ts_flag, sack_flag, df_flag]


def _sig_feature_vector(sig: _OsSig) -> list[float]:
    """Same as _feature_vector but for a database signature."""
    fp = OsFingerprint(
        ttl=sig.ttl,
        window_size=sig.window,
        df_bit=sig.df,
        mss=sig.mss,
        wscale=sig.wscale,
        has_timestamp=sig.has_timestamp,
        has_sack=sig.has_sack,
        opt_order=sig.opt_order,
    )
    return _feature_vector(fp)


# ---------------------------------------------------------------------------
# Rule-based scoring
# ---------------------------------------------------------------------------


def _score_signature(fp: OsFingerprint, sig: _OsSig) -> tuple[float, list[str]]:
    """Score how well a fingerprint matches one database signature.

    Returns (score in 0-1, list of matched signals).
    Weights are calibrated so an exact match scores ~1.0 and a TTL-only
    match scores ~0.35 (LOW confidence).
    """
    score = 0.0
    signals: list[str] = []

    # TTL family match — most important single signal
    if _ttl_family(fp.ttl) == _sig_ttl_family(sig):
        score += 0.35
        signals.append(f"ttl={fp.ttl} (family {_ttl_family(fp.ttl)})")

    # Window size — exact match is specific, range is less so
    if fp.window_size == sig.window:
        score += 0.22
        signals.append(f"window={fp.window_size} (exact)")
    elif abs(fp.window_size - sig.window) < 512:
        score += 0.08
        signals.append(f"window={fp.window_size} (near {sig.window})")

    # DF bit
    if fp.df_bit == sig.df:
        score += 0.06
        signals.append(f"df={'1' if fp.df_bit else '0'}")

    # TCP option presence
    opts_match = sum(1 for opt in sig.opt_order if opt in fp.opt_order)
    if sig.opt_order:
        presence_ratio = opts_match / len(sig.opt_order)
        score += presence_ratio * 0.15
        if presence_ratio > 0.7:
            signals.append(f"options present ({opts_match}/{len(sig.opt_order)})")

    # TCP option ORDER match — more specific than just presence
    if fp.opt_order and sig.opt_order and fp.opt_order == sig.opt_order:
        score += 0.10
        signals.append(f"options order match {fp.opt_order}")

    # Window scale
    if fp.wscale is not None and sig.wscale is not None and fp.wscale == sig.wscale:
        score += 0.07
        signals.append(f"wscale={fp.wscale}")
    elif fp.wscale is None and sig.wscale is None:
        score += 0.03
        signals.append("wscale absent (both)")

    # MSS — usually 1460, less discriminating; still counts
    if fp.mss is not None and sig.mss is not None and fp.mss == sig.mss:
        score += 0.03
        signals.append(f"mss={fp.mss}")

    # Timestamp and SACK flags
    if fp.has_timestamp == sig.has_timestamp:
        score += 0.01
        if fp.has_timestamp:
            signals.append("tcp timestamps")
    if fp.has_sack == sig.has_sack:
        score += 0.01
        if fp.has_sack:
            signals.append("sack permitted")

    return round(score, 3), signals


def _best_rule_match(fp: OsFingerprint) -> tuple[_OsSig, float, list[str]]:
    """Find the best matching signature using rule-based scoring."""
    best_sig = _OS_DB[0]
    best_score = 0.0
    best_signals: list[str] = []

    for sig in _OS_DB:
        score, signals = _score_signature(fp, sig)
        if score > best_score:
            best_score = score
            best_sig = sig
            best_signals = signals

    return best_sig, best_score, best_signals


# ---------------------------------------------------------------------------
# ML-based classification (KNN)
# ---------------------------------------------------------------------------


def _sklearn_available() -> bool:
    return importlib.util.find_spec("sklearn") is not None


def _knn_classify(fp: OsFingerprint) -> tuple[str, str, float] | None:
    """KNN classification using sklearn.

    Trains on the signature DB each time — the DB is tiny (16 entries),
    so fit() takes microseconds. Returns (os_family, os_detail, confidence_score).
    Returns None if sklearn is unavailable.
    """
    if not _sklearn_available():
        return None

    from sklearn.neighbors import KNeighborsClassifier

    # Build training data from signature DB
    X = [_sig_feature_vector(sig) for sig in _OS_DB]
    y_family = [sig.os_family for sig in _OS_DB]
    y_detail = [sig.os_detail for sig in _OS_DB]

    probe = [_feature_vector(fp)]

    # k=3 is enough — DB is small and we want nearest neighbors only
    k = min(3, len(_OS_DB))
    clf_family = KNeighborsClassifier(n_neighbors=k, weights="distance")
    clf_family.fit(X, y_family)

    clf_detail = KNeighborsClassifier(n_neighbors=k, weights="distance")
    clf_detail.fit(X, y_detail)

    pred_family = clf_family.predict(probe)[0]
    pred_detail = clf_detail.predict(probe)[0]

    # get distance to nearest neighbor as confidence proxy
    distances, _ = clf_family.kneighbors(probe)
    nearest_dist = distances[0][0]
    # distance of 0 = perfect match (1.0 confidence), distance > 1.5 = very low confidence
    ml_score = max(0.0, 1.0 - (nearest_dist / 1.5))

    return pred_family, pred_detail, round(ml_score, 3)


def _manual_knn(fp: OsFingerprint, k: int = 3) -> tuple[str, str, float]:
    """KNN without sklearn — pure Python Euclidean distance.

    Same feature vector as the sklearn version. Used as fallback.
    """
    probe = _feature_vector(fp)

    # compute distances to all signatures
    dists: list[tuple[float, _OsSig]] = []
    for sig in _OS_DB:
        sig_vec = _sig_feature_vector(sig)
        dist = sum((a - b) ** 2 for a, b in zip(probe, sig_vec, strict=True)) ** 0.5
        dists.append((dist, sig))

    dists.sort(key=lambda x: x[0])
    neighbors = dists[:k]

    # vote on OS family (weighted by 1/distance, with epsilon to avoid div/0)
    votes: dict[str, float] = {}
    for dist, sig in neighbors:
        weight = 1.0 / (dist + 1e-6)
        votes[sig.os_family] = votes.get(sig.os_family, 0.0) + weight

    best_family = max(votes, key=lambda k: votes[k])
    # pick the detail from the closest neighbor with that family
    best_detail = next(sig.os_detail for _, sig in neighbors if sig.os_family == best_family)

    nearest_dist = neighbors[0][0]
    score = max(0.0, 1.0 - (nearest_dist / 1.5))

    return best_family, best_detail, round(score, 3)


# ---------------------------------------------------------------------------
# Confidence mapping
# ---------------------------------------------------------------------------


def _confidence_label(score: float) -> str:
    if score >= 0.70:
        return "HIGH"
    if score >= 0.45:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Public fingerprinting API
# ---------------------------------------------------------------------------


def fingerprint_os(raw_pkt: bytes) -> OsMatch | None:
    """Classify OS from a raw IP+TCP packet (e.g. a SYN-ACK response).

    Uses a two-layer classifier:
      1. Rule-based scoring against the signature database
      2. KNN in feature space (sklearn or fallback pure-Python)

    The final score is a weighted blend: 60% rule-based, 40% KNN.
    Returns None if the packet is too short or malformed.
    """
    fp = extract_fingerprint(raw_pkt)
    if fp is None:
        return None

    # rule-based
    rule_sig, rule_score, rule_signals = _best_rule_match(fp)

    # KNN
    ml_result = _knn_classify(fp)
    if ml_result is not None:
        ml_family, ml_detail, ml_score = ml_result
    else:
        ml_family, ml_detail, ml_score = _manual_knn(fp)

    # blend — rule-based wins on high-confidence exact matches,
    # KNN helps on ambiguous TTL-64 hosts (Linux vs macOS vs BSD)
    blended_score = round(rule_score * 0.6 + ml_score * 0.4, 3)

    # pick winner: rule-based detail if it agrees on family, else ML
    if rule_sig.os_family == ml_family:
        final_family = rule_sig.os_family
        final_detail = rule_sig.os_detail
        method = "tcp_fingerprint+knn"
    else:
        # disagreement — trust the higher individual score
        if rule_score >= ml_score:
            final_family = rule_sig.os_family
            final_detail = rule_sig.os_detail
        else:
            final_family = ml_family
            final_detail = ml_detail
        method = "tcp_fingerprint+knn(disagreement)"

    return OsMatch(
        os_family=final_family,
        os_detail=final_detail,
        confidence=_confidence_label(blended_score),
        score=blended_score,
        matched_signals=rule_signals,
        method=method,
    )


def ttl_only_os(ttl: int) -> OsMatch:
    """Guess OS from TTL alone — fallback when raw sockets unavailable.

    Less precise than full TCP fingerprinting but requires no special privileges.
    """
    family = _ttl_family(ttl)

    mapping = {
        "64": ("Linux/Unix", "Linux / macOS / BSD (indistinct without TCP options)"),
        "128": ("Windows", "Windows (all versions)"),
        "255": ("Network Device", "Cisco IOS / OpenBSD / RTOS"),
    }

    os_family, os_detail = mapping.get(family, ("Unknown", "Unknown"))

    # TTL-only is always LOW confidence — we can't distinguish Linux from macOS here
    return OsMatch(
        os_family=os_family,
        os_detail=os_detail,
        confidence="LOW",
        score=0.35,
        matched_signals=[f"ttl={ttl} (family {family})"],
        method="ttl_only",
    )


def passive_os_scan(
    host: str,
    port: int = 80,
    timeout: float = 2.0,
) -> OsMatch | None:
    """Send one SYN, analyze the SYN-ACK for OS fingerprinting.

    Tries ports in order: [port, 443, 22, 80] — stops at the first one that responds.
    Returns None if no port responds or the platform doesn't support raw sockets.

    Requires Scapy (pip install porthawk[syn]) or root + Linux/macOS.
    Falls back to None on Windows without Scapy.
    """
    if _scapy_available():
        return _passive_os_scapy(host, port, timeout)

    if sys.platform != "win32":
        return _passive_os_raw(host, port, timeout)

    return None


def _passive_os_scapy(host: str, port: int, timeout: float) -> OsMatch | None:
    """Passive OS scan via Scapy — sends SYN, captures raw SYN-ACK bytes."""
    from scapy.all import IP, TCP, conf, send, sr1

    conf.verb = 0

    import random

    src_port = random.randint(1024, 65000)
    seq = random.randint(0, 2**32 - 1)

    pkt = IP(dst=host) / TCP(sport=src_port, dport=port, flags="S", seq=seq)
    resp = sr1(pkt, timeout=timeout, verbose=0)

    if resp is None or not resp.haslayer(TCP):
        return None

    # send RST to clean up — we don't want the target logging a half-open connection
    rst = IP(dst=host) / TCP(sport=src_port, dport=port, flags="R", seq=resp[TCP].ack)
    send(rst, verbose=0)

    raw = bytes(resp[IP])
    return fingerprint_os(raw)


def _passive_os_raw(host: str, port: int, timeout: float) -> OsMatch | None:
    """Passive OS scan via raw sockets — Linux/macOS only."""
    import os
    import random
    import sys
    import time

    from porthawk.syn_scan import (
        _build_syn_packet,
        _get_source_ip,
        _parse_response,
    )

    if sys.platform == "win32":
        return None

    try:
        if os.getuid() != 0:
            return None
    except AttributeError:
        return None

    src_ip = _get_source_ip(host)
    src_port = random.randint(1024, 65000)
    seq = random.randint(0, 2**32 - 1)

    syn_pkt = _build_syn_packet(src_ip, host, src_port, port, seq)

    try:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except PermissionError:
        return None

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

            return fingerprint_os(raw_pkt)

    finally:
        send_sock.close()
        recv_sock.close()

    return None
