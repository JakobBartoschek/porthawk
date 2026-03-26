"""Custom exceptions — all public errors PortHawk raises inherit from PortHawkError.

Callers can catch PortHawkError to handle any scanner error, or specific
subclasses when they care about the reason.
"""


class PortHawkError(Exception):
    """Base for all PortHawk errors. Catch this if you don't care why it failed."""


class InvalidTargetError(PortHawkError):
    """target string is not a valid IP, hostname, or CIDR."""


class InvalidPortSpecError(PortHawkError):
    """Port spec string is malformed — bad range, out-of-bounds port number, etc."""


class ScanPermissionError(PortHawkError):
    """OS refused the scan — usually raw socket without root, or firewall rule."""


class ScanTimeoutError(PortHawkError):
    """Scan exceeded the configured timeout and was aborted."""
