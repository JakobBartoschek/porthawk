"""PortHawk — async port scanner for authorized security testing.

Scan responsibly. Get written permission first.

Quick start::

    import asyncio
    import porthawk

    results = asyncio.run(porthawk.scan("192.168.1.1", ports="common"))
    for r in results:
        print(r.port, r.service_name, r.risk_level)

Context manager::

    async with porthawk.Scanner("192.168.1.1", timeout=2.0) as scanner:
        results = await scanner.scan(ports="1-1024", banners=True)
"""

from porthawk.api import Scanner, scan
from porthawk.cve import CVEInfo
from porthawk.evasion import EvasionConfig, evasion_scan_host, slow_low_config
from porthawk.exceptions import (
    InvalidPortSpecError,
    InvalidTargetError,
    PortHawkError,
    ScanPermissionError,
    ScanTimeoutError,
)
from porthawk.honeypot import HoneypotReport, Indicator, score_honeypot
from porthawk.passive_os import OsFingerprint, OsMatch, fingerprint_os, passive_os_scan, ttl_only_os
from porthawk.reporter import ScanReport, build_report
from porthawk.scanner import PortState, ScanResult
from porthawk.syn_scan import get_syn_backend, syn_scan_host
from porthawk.throttle import AdaptiveConfig, AdaptiveSemaphore, NetworkStats

__version__ = "0.7.0"
__author__ = "Jakob Bartoschek"
__license__ = "MIT"

__all__ = [
    # Core API
    "scan",
    "Scanner",
    # Data models
    "ScanResult",
    "ScanReport",
    "PortState",
    # Report builder (for custom rendering)
    "build_report",
    # CVE lookup
    "CVEInfo",
    # Honeypot detection
    "score_honeypot",
    "HoneypotReport",
    "Indicator",
    # SYN scan
    "syn_scan_host",
    "get_syn_backend",
    # Evasion
    "evasion_scan_host",
    "EvasionConfig",
    "slow_low_config",
    # Passive OS fingerprinting
    "fingerprint_os",
    "passive_os_scan",
    "ttl_only_os",
    "OsMatch",
    "OsFingerprint",
    # Adaptive throttling
    "AdaptiveConfig",
    "AdaptiveSemaphore",
    "NetworkStats",
    # Exceptions
    "PortHawkError",
    "InvalidTargetError",
    "InvalidPortSpecError",
    "ScanPermissionError",
    "ScanTimeoutError",
]
