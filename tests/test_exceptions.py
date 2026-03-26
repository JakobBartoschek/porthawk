from porthawk.exceptions import (
    InvalidPortSpecError,
    InvalidTargetError,
    PortHawkError,
    ScanPermissionError,
    ScanTimeoutError,
)


def test_all_exceptions_inherit_from_base():
    for cls in (InvalidTargetError, InvalidPortSpecError, ScanPermissionError, ScanTimeoutError):
        assert issubclass(cls, PortHawkError)


def test_base_inherits_from_exception():
    assert issubclass(PortHawkError, Exception)


def test_exceptions_carry_message():
    err = InvalidTargetError("not-a-host")
    assert "not-a-host" in str(err)


def test_invalid_port_spec_error_message():
    err = InvalidPortSpecError("port 99999 out of range")
    assert "99999" in str(err)


def test_scan_permission_error():
    err = ScanPermissionError("raw socket requires root")
    assert isinstance(err, PortHawkError)


def test_scan_timeout_error():
    err = ScanTimeoutError("scan timed out after 30s")
    assert isinstance(err, PortHawkError)
