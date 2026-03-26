"""Honeypot detection — score a set of scan results and flag likely fakes.

This is heuristic, not forensic. You'll get false positives on weird hardened servers
and false negatives against well-configured honeypots. The score is a signal, not a verdict.

Supported honeypot profiles:
  - Cowrie: SSH honeypot, tends to use EOL Debian/Ubuntu banners
  - Dionaea: malware catcher, emulates FTP with a dead-giveaway Synology banner
  - Conpot: ICS/SCADA honeypot, opens Modbus/S7/BACnet/DNP3 ports
  - T-Pot: multi-honeypot stack — runs 20-50 fake services simultaneously
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field

from porthawk.scanner import PortState, ScanResult

# --- indicator weight table -----------------------------------------------
# Each weight is the confidence contribution if the indicator fires.
# Combined via 1 - product(1 - w_i) so no single indicator maxes the score.
#
# Calibration notes:
#   0.60 → seen this exact pattern in Cowrie/Dionaea source, very specific
#   0.45 → strong signal but plausible on real ICS gear
#   0.25 → weak signal — worth logging but don't cry wolf

_W_COWRIE_BANNER = 0.60  # exact match to known Cowrie SSH banner defaults
_W_DIONAEA_FTP = 0.65  # "220 DiskStation FTP server ready." is hardcoded in Dionaea
_W_ICS_SINGLE = 0.25  # one ICS port could just be real OT equipment
_W_ICS_MULTI = 0.50  # two or more ICS ports on the same host is sus
_W_TELNET_OPEN = 0.25  # telnet in 2024 — real or bait?
_W_PORT_FLOOD_20 = 0.30  # >20 open ports suggests T-Pot or similar multi-service stack
_W_PORT_FLOOD_40 = 0.50  # >40 open ports — almost certainly a honeypot farm
_W_UNIFORM_LATENCY = 0.35  # suspiciously uniform latency across ports
_W_SSH_MULTI_PORT = 0.30  # same SSH version banner on ports 22 AND alt port (e.g. 2222)
_W_SERVICE_DIVERSITY = 0.25  # running >6 completely different service categories at once

# ICS/SCADA port numbers — these showing up on an internet-facing host is unusual
_ICS_PORTS = frozenset(
    {
        102,  # S7 (Siemens) — Conpot classic
        502,  # Modbus TCP
        20000,  # DNP3
        44818,  # EtherNet/IP
        47808,  # BACnet/IP
        4840,  # OPC-UA
        9600,  # OMRON FINS
    }
)

# Cowrie's default SSH banner list — these haven't changed much across versions.
# Cowrie pulls from a static list in cowrie/ssh/userauth.py.
# EOL Debian/Ubuntu banners are the giveaway — real admins patch these away.
_COWRIE_SSH_BANNERS = {
    "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",  # Debian 7 (Wheezy), EOL 2018
    "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2",  # popular Cowrie default circa 2022
    "SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.1",  # Ubuntu 12.04, EOL 2017
    "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.8",  # Ubuntu 14.04, EOL 2019
    "SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u4",  # Debian 8 (Jessie), EOL 2020
    "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7",  # Debian 9 (Stretch), EOL 2022
}

# Dionaea FTP module literally ships with this banner in its config/ftp.yaml
_DIONAEA_FTP_BANNERS = {
    "220 DiskStation FTP server ready.",
    "220 DiskStation FTP",
}

# Minimum ports needed to compute latency variance
_MIN_LATENCY_SAMPLES = 5

# CV below this → latency is too uniform to be a real OS TCP stack
_UNIFORM_LATENCY_CV_THRESHOLD = 0.05

# Service categories used for diversity check
# Catching a host running SSH + FTP + SMTP + MySQL + Redis + Telnet + ICS all at once
_SERVICE_CATEGORIES = {
    "remote_access": {"ssh", "telnet", "rdp", "vnc"},
    "web": {"http", "https", "http-alt", "https-alt"},
    "mail": {"smtp", "pop3", "imap", "smtps", "imaps", "pop3s"},
    "database": {"mysql", "postgresql", "mssql", "oracle", "redis", "mongodb", "memcached"},
    "file": {"ftp", "ftps", "sftp", "smb", "nfs"},
    "ics": {"modbus", "s7", "bacnet", "dnp3", "ethernet-ip", "opcua"},
    "infrastructure": {"dns", "ntp", "snmp", "dhcp", "ldap", "kerberos"},
}


@dataclass
class Indicator:
    """A single fired detection indicator."""

    name: str
    weight: float  # 0.0–1.0 contribution to final score
    description: str


@dataclass
class HoneypotReport:
    """Result of scoring a host's scan results for honeypot likelihood.

    score:   0.0 (probably real) → 1.0 (almost certainly honeypot)
    verdict: human-readable label for the score bucket
    """

    score: float
    verdict: str  # LIKELY_REAL | SUSPICIOUS | LIKELY_HONEYPOT
    confidence: str  # LOW | MEDIUM | HIGH — based on how many indicators fired
    indicators: list[Indicator] = field(default_factory=list)
    open_port_count: int = 0

    def __str__(self) -> str:
        lines = [
            f"Honeypot score: {self.score:.2f} [{self.verdict}] (confidence: {self.confidence})",
            f"Open ports analyzed: {self.open_port_count}",
        ]
        if self.indicators:
            lines.append("Triggered indicators:")
            for ind in self.indicators:
                lines.append(f"  [{ind.weight:.2f}] {ind.name}: {ind.description}")
        return "\n".join(lines)


def score_honeypot(results: list[ScanResult]) -> HoneypotReport:
    """Analyze a host's scan results and return a honeypot likelihood score.

    Does not make any network calls — purely analyzes what scan() already found.
    Call this after a full scan with banners=True for best results.
    Without banners, you lose the SSH/FTP banner checks but port-based heuristics still work.

    Args:
        results: list of ScanResult from porthawk.scan() — all states, not just open

    Returns:
        HoneypotReport with score, verdict, and list of triggered indicators
    """
    open_results = [r for r in results if r.state == PortState.OPEN]

    if not open_results:
        # nothing open — can't score what we can't see
        return HoneypotReport(
            score=0.0,
            verdict="LIKELY_REAL",
            confidence="LOW",
            indicators=[],
            open_port_count=0,
        )

    indicators: list[Indicator] = []
    open_ports = {r.port for r in open_results}

    # --- banner-based checks (require --banners) ----------------------------

    _check_cowrie_ssh(open_results, indicators)
    _check_dionaea_ftp(open_results, indicators)

    # --- port-based checks --------------------------------------------------

    _check_ics_ports(open_ports, indicators)
    _check_telnet(open_ports, indicators)
    _check_port_flood(open_results, indicators)
    _check_ssh_multi_port(open_results, indicators)
    _check_service_diversity(open_results, indicators)

    # --- timing-based checks (require latency_ms populated) -----------------

    _check_latency_uniformity(open_results, indicators)

    # combine scores: 1 - product(1 - w_i)
    # additive independence model — each indicator contributes without dominating
    if not indicators:
        score = 0.0
    else:
        score = 1.0 - math.prod(1.0 - ind.weight for ind in indicators)

    score = round(min(score, 1.0), 4)
    verdict = _verdict(score)
    confidence = _confidence(indicators)

    return HoneypotReport(
        score=score,
        verdict=verdict,
        confidence=confidence,
        indicators=indicators,
        open_port_count=len(open_results),
    )


# --- individual check functions -------------------------------------------
# Each function appends to indicators if the check fires.
# Intentionally small and testable in isolation.


def _check_cowrie_ssh(results: list[ScanResult], indicators: list[Indicator]) -> None:
    """Look for Cowrie's default SSH banners — specific enough to be damning."""
    for r in results:
        if r.port == 22 and r.banner:
            # strip surrounding whitespace — some grabbers add trailing \r\n
            banner = r.banner.strip()
            if banner in _COWRIE_SSH_BANNERS:
                indicators.append(
                    Indicator(
                        name="cowrie_ssh_banner",
                        weight=_W_COWRIE_BANNER,
                        description=f"SSH banner matches known Cowrie default: '{banner}'",
                    )
                )
                return  # no point appending this twice


def _check_dionaea_ftp(results: list[ScanResult], indicators: list[Indicator]) -> None:
    """Dionaea FTP emulation — ships with a hardcoded Synology banner that's a dead giveaway."""
    for r in results:
        if r.port == 21 and r.banner:
            banner = r.banner.strip()
            for known in _DIONAEA_FTP_BANNERS:
                if banner.startswith(known[:20]):  # prefix match — some versions truncate
                    indicators.append(
                        Indicator(
                            name="dionaea_ftp_banner",
                            weight=_W_DIONAEA_FTP,
                            description=f"FTP banner matches Dionaea's hardcoded Synology emulation: '{banner}'",
                        )
                    )
                    return


def _check_ics_ports(open_ports: set[int], indicators: list[Indicator]) -> None:
    """ICS/SCADA ports open on what might be an internet-facing host.

    One ICS port could be legitimate OT equipment. Two or more on the same host
    is the Conpot signature — it emulates multiple ICS protocols simultaneously.
    """
    matched = open_ports & _ICS_PORTS
    if len(matched) >= 2:
        indicators.append(
            Indicator(
                name="ics_multi_port",
                weight=_W_ICS_MULTI,
                description=f"Multiple ICS/SCADA ports open: {sorted(matched)} — Conpot pattern",
            )
        )
    elif len(matched) == 1:
        (port,) = matched
        indicators.append(
            Indicator(
                name="ics_single_port",
                weight=_W_ICS_SINGLE,
                description=f"ICS/SCADA port {port} open — could be Conpot or real OT equipment",
            )
        )


def _check_telnet(open_ports: set[int], indicators: list[Indicator]) -> None:
    """Telnet is effectively dead in production but honeypots keep emulating it.

    Most CTF/research honeypots enable telnet because it's trivially emulated.
    """
    if 23 in open_ports:
        indicators.append(
            Indicator(
                name="telnet_open",
                weight=_W_TELNET_OPEN,
                description="Telnet (port 23) is open — rare on real hosts, common on honeypots",
            )
        )


def _check_port_flood(results: list[ScanResult], indicators: list[Indicator]) -> None:
    """T-Pot and similar stacks run many fake services simultaneously.

    A real server with >40 open ports isn't impossible, but it's unusual enough
    that it's worth flagging. T-Pot can easily have 50+ ports answering.
    """
    n = len(results)
    if n > 40:
        indicators.append(
            Indicator(
                name="port_flood_extreme",
                weight=_W_PORT_FLOOD_40,
                description=f"{n} open ports — very high, T-Pot or similar multi-honeypot stack",
            )
        )
    elif n > 20:
        indicators.append(
            Indicator(
                name="port_flood_high",
                weight=_W_PORT_FLOOD_20,
                description=f"{n} open ports — unusually high, could be a multi-service honeypot",
            )
        )


def _check_ssh_multi_port(results: list[ScanResult], indicators: list[Indicator]) -> None:
    """SSH answering on both port 22 and an alternate port with the same banner.

    Some honeypots (Cowrie configs, custom setups) listen on 22 AND 2222/22222/etc.
    Finding the same SSH version string on multiple ports is suspicious.
    """
    ssh_banners: dict[str, list[int]] = {}
    for r in results:
        if r.banner and r.banner.startswith("SSH-"):
            banner = r.banner.strip()
            ssh_banners.setdefault(banner, []).append(r.port)

    for banner, ports in ssh_banners.items():
        if len(ports) >= 2:
            indicators.append(
                Indicator(
                    name="ssh_multi_port",
                    weight=_W_SSH_MULTI_PORT,
                    description=f"Same SSH banner on {len(ports)} ports {sorted(ports)}: '{banner[:40]}'",
                )
            )
            break  # one flag is enough


def _check_service_diversity(results: list[ScanResult], indicators: list[Indicator]) -> None:
    """Too many different service types on one host.

    A real server might have web + SSH + database. Running all 7 service categories
    (remote access, web, mail, database, file, ICS, infrastructure) at once is a honeypot tell.
    """
    service_names = {r.service_name for r in results if r.service_name}
    if not service_names:
        return

    matched_categories = 0
    for category_services in _SERVICE_CATEGORIES.values():
        if service_names & category_services:
            matched_categories += 1

    if matched_categories >= 6:
        indicators.append(
            Indicator(
                name="service_diversity",
                weight=_W_SERVICE_DIVERSITY,
                description=f"{matched_categories} different service categories open — unusually diverse",
            )
        )


def _check_latency_uniformity(results: list[ScanResult], indicators: list[Indicator]) -> None:
    """Honeypots running in software respond to all ports from the same event loop.

    Real OS TCP stacks have measurable variance per port (routing decisions, socket overhead).
    A CV below 0.05 across many ports suggests all responses are coming from the same process.

    Only fires if we have enough samples with latency data — needs --banners or at minimum
    the raw TCP connect latency from the scanner.
    """
    latencies = [r.latency_ms for r in results if r.latency_ms is not None and r.latency_ms > 0]

    if len(latencies) < _MIN_LATENCY_SAMPLES:
        return

    mean = statistics.mean(latencies)
    if mean <= 0:
        return

    stdev = statistics.stdev(latencies)
    cv = stdev / mean  # coefficient of variation

    if cv < _UNIFORM_LATENCY_CV_THRESHOLD:
        indicators.append(
            Indicator(
                name="uniform_latency",
                weight=_W_UNIFORM_LATENCY,
                description=(
                    f"Latency CV={cv:.4f} across {len(latencies)} ports — "
                    f"suspiciously uniform (mean={mean:.1f}ms, stdev={stdev:.2f}ms)"
                ),
            )
        )


# --- helpers ---------------------------------------------------------------


def _verdict(score: float) -> str:
    if score >= 0.55:
        return "LIKELY_HONEYPOT"
    if score >= 0.25:
        return "SUSPICIOUS"
    return "LIKELY_REAL"


def _confidence(indicators: list[Indicator]) -> str:
    """Confidence reflects how many independent signals fired, not how high the score is.

    One strong indicator (e.g. Cowrie banner) → MEDIUM.
    Three or more → HIGH.
    """
    n = len(indicators)
    if n >= 3:
        return "HIGH"
    if n >= 1:
        return "MEDIUM"
    return "LOW"
