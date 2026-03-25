"""Tests for service_db.py — pure data, no mocking needed.

If these tests fail, someone changed the service database or risk levels.
Both are intentional decisions that need to be reconsidered carefully.
"""

import pytest

from porthawk.service_db import (
    RiskLevel,
    ServiceInfo,
    get_service,
    get_top_ports,
)


class TestGetService:
    def test_port_80_is_http_low_risk(self):
        svc = get_service(80)
        assert svc.service_name == "http"
        assert svc.risk_level == RiskLevel.LOW

    def test_port_23_is_telnet_high_risk(self):
        svc = get_service(23)
        assert svc.service_name == "telnet"
        assert svc.risk_level == RiskLevel.HIGH

    def test_port_22_is_ssh_medium_risk(self):
        svc = get_service(22)
        assert svc.service_name == "ssh"
        assert svc.risk_level == RiskLevel.MEDIUM

    def test_port_443_is_https_low_risk(self):
        svc = get_service(443)
        assert svc.service_name == "https"
        assert svc.risk_level == RiskLevel.LOW

    def test_port_445_is_smb_high_risk(self):
        """SMB is always HIGH — EternalBlue, WannaCry, etc."""
        svc = get_service(445)
        assert svc.risk_level == RiskLevel.HIGH

    def test_port_3389_is_rdp_high_risk(self):
        """RDP is the ransomware crew's favorite entry point."""
        svc = get_service(3389)
        assert svc.risk_level == RiskLevel.HIGH

    def test_port_6379_is_redis_high_risk(self):
        """Redis with no auth + SLAVEOF = RCE. HIGH risk."""
        svc = get_service(6379)
        assert svc.service_name == "redis"
        assert svc.risk_level == RiskLevel.HIGH

    def test_port_27017_is_mongodb_high_risk(self):
        svc = get_service(27017)
        assert svc.service_name == "mongodb"
        assert svc.risk_level == RiskLevel.HIGH

    def test_port_3306_is_mysql_medium_risk(self):
        svc = get_service(3306)
        assert svc.service_name == "mysql"
        assert svc.risk_level == RiskLevel.MEDIUM

    def test_unknown_port_returns_unknown_service(self):
        svc = get_service(65534)  # not in database
        assert svc.service_name == "unknown"
        assert svc.risk_level is None

    def test_out_of_range_port_returns_unknown(self):
        """We don't validate port range here — service_db is just a lookup."""
        svc = get_service(99999)
        assert svc.service_name == "unknown"

    def test_protocol_is_preserved(self):
        svc = get_service(53, protocol="udp")
        assert svc.protocol == "udp"

    def test_result_is_service_info_instance(self):
        svc = get_service(80)
        assert isinstance(svc, ServiceInfo)

    def test_description_is_not_empty_for_known_ports(self):
        for port in [21, 22, 23, 25, 80, 443]:
            svc = get_service(port)
            assert svc.description, f"Port {port} has no description"

    @pytest.mark.parametrize("port,expected_name", [
        (21, "ftp"),
        (22, "ssh"),
        (25, "smtp"),
        (53, "dns"),
        (80, "http"),
        (110, "pop3"),
        (143, "imap"),
        (443, "https"),
        (3306, "mysql"),
        (5432, "postgresql"),
    ])
    def test_common_ports_have_correct_names(self, port: int, expected_name: str):
        assert get_service(port).service_name == expected_name


class TestGetTopPorts:
    def test_top_10_returns_10_ports(self):
        assert len(get_top_ports(10)) == 10

    def test_top_100_returns_100_ports(self):
        assert len(get_top_ports(100)) == 100

    def test_top_1_returns_1_port(self):
        assert len(get_top_ports(1)) == 1

    def test_all_ports_in_valid_range(self):
        ports = get_top_ports(100)
        for p in ports:
            assert 1 <= p <= 65535, f"Port {p} is out of valid range"

    def test_no_duplicates_in_top_ports(self):
        ports = get_top_ports(100)
        assert len(ports) == len(set(ports))

    def test_port_80_in_top_10(self):
        """HTTP should be in the top 10 for any reasonable ordering."""
        assert 80 in get_top_ports(10)

    def test_port_443_in_top_20(self):
        assert 443 in get_top_ports(20)

    def test_large_n_does_not_crash(self):
        """Asking for more ports than exist should just return what we have."""
        ports = get_top_ports(10000)
        assert len(ports) <= 65535
        assert len(ports) > 0
