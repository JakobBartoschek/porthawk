"""Tests for the port predictor / scan order optimizer.

We don't test that the ML model achieves specific accuracy — that's brittle.
We test the contract: common ports come before obscure ones, context shifts rankings,
and the fallback without sklearn behaves consistently.
"""

from unittest.mock import patch

import pytest

import porthawk.predictor as pred
from porthawk.predictor import _frequency_score, _is_private_ip, sort_ports


# --- IP range detection ---


class TestIsPrivateIp:
    def test_rfc1918_10_block(self):
        assert _is_private_ip("10.0.0.1") is True

    def test_rfc1918_172_block(self):
        assert _is_private_ip("172.16.5.10") is True

    def test_rfc1918_192_block(self):
        assert _is_private_ip("192.168.1.100") is True

    def test_loopback(self):
        assert _is_private_ip("127.0.0.1") is True

    def test_public_ip(self):
        assert _is_private_ip("8.8.8.8") is False

    def test_public_ip_2(self):
        assert _is_private_ip("1.1.1.1") is False

    def test_hostname_treated_as_public(self):
        # hostnames can't be resolved here — default to public (conservative)
        assert _is_private_ip("scanme.nmap.org") is False


# --- Frequency-based fallback scoring ---


class TestFrequencyScore:
    def test_known_port_scores_higher_than_unknown(self):
        http_score = _frequency_score(80, False, False, False)
        random_score = _frequency_score(54321, False, False, False)
        assert http_score > random_score

    def test_private_windows_boost(self):
        rdp_private = _frequency_score(3389, True, False, False)
        rdp_public = _frequency_score(3389, False, False, False)
        assert rdp_private > rdp_public

    def test_windows_os_hint_boosts_smb(self):
        smb_win = _frequency_score(445, True, True, False)
        smb_unknown = _frequency_score(445, True, False, False)
        assert smb_win > smb_unknown

    def test_linux_os_hint_boosts_ssh(self):
        ssh_linux = _frequency_score(22, True, False, True)
        ssh_unknown = _frequency_score(22, True, False, False)
        assert ssh_linux > ssh_unknown


# --- sort_ports: behavioral contracts ---


class TestSortPorts:
    def test_empty_list_returns_empty(self):
        assert sort_ports([], "192.168.1.1") == []

    def test_single_port_returns_unchanged(self):
        assert sort_ports([80], "192.168.1.1") == [80]

    def test_common_ports_before_obscure_ones(self):
        """22, 80, 443, 8080 should all outrank 54321."""
        ports = [54321, 22, 80, 443, 8080, 65534]
        result = sort_ports(ports, "8.8.8.8")
        assert result.index(22) < result.index(54321)
        assert result.index(80) < result.index(65534)
        assert result.index(443) < result.index(65534)

    def test_rdp_ranks_higher_on_private_target(self):
        """3389 should rank better on 192.168.x.x than on 8.8.8.8."""
        ports = [3389, 9999, 54321]
        public_order = sort_ports(ports, "8.8.8.8")
        private_order = sort_ports(ports, "192.168.1.1")
        # RDP index should be equal or smaller (i.e. higher ranked) on private
        assert private_order.index(3389) <= public_order.index(3389)

    def test_windows_hint_boosts_smb_over_ssh(self):
        """On a Windows target, 445 should outrank 22."""
        ports = [22, 445, 8080]
        result = sort_ports(ports, "192.168.1.50", os_hint="Windows")
        assert result.index(445) < result.index(22)

    def test_linux_hint_boosts_ssh_over_rdp(self):
        """On a Linux target, 22 should outrank 3389."""
        ports = [22, 3389, 8080]
        result = sort_ports(ports, "192.168.1.50", os_hint="Linux/Unix")
        assert result.index(22) < result.index(3389)

    def test_all_ports_preserved(self):
        """sort_ports must not drop or add any port."""
        ports = [22, 80, 443, 8080, 3306, 54321, 65534]
        result = sort_ports(ports, "10.0.0.1", os_hint="Linux/Unix")
        assert sorted(result) == sorted(ports)

    def test_no_duplicates(self):
        ports = [22, 80, 443, 3389, 445, 9999]
        result = sort_ports(ports, "192.168.1.1", os_hint="Windows")
        assert len(result) == len(set(result))

    def test_no_os_hint_still_works(self):
        ports = [22, 80, 54321]
        result = sort_ports(ports, "192.168.1.1", os_hint=None)
        assert set(result) == {22, 80, 54321}
        assert result[0] in {22, 80}  # either common port should lead


# --- Fallback without sklearn ---


class TestFallbackWithoutSklearn:
    def test_sort_ports_without_sklearn(self, monkeypatch):
        """Fallback path must return a valid sorted list."""
        monkeypatch.setattr(pred, "_model_cache", None)
        monkeypatch.setattr(pred, "_get_model", lambda: None)

        result = sort_ports([443, 22, 65535, 80, 3389], "192.168.1.1", os_hint="Windows")
        assert set(result) == {443, 22, 65535, 80, 3389}
        # 65535 should be last (no frequency entry, lowest score)
        assert result[-1] == 65535

    def test_fallback_common_port_still_wins(self, monkeypatch):
        monkeypatch.setattr(pred, "_model_cache", None)
        monkeypatch.setattr(pred, "_get_model", lambda: None)

        ports = [80, 54321, 65000]
        result = sort_ports(ports, "8.8.8.8")
        assert result[0] == 80


# --- sklearn status string ---


def test_get_sklearn_status_returns_string():
    from porthawk.predictor import get_sklearn_status

    status = get_sklearn_status()
    assert isinstance(status, str)
    assert len(status) > 0


# --- Feature vector shape ---


def test_featurize_returns_10_features():
    from porthawk.predictor import _featurize

    features = _featurize(80, True, False, True)
    assert len(features) == 10


def test_featurize_values_are_floats():
    from porthawk.predictor import _featurize

    features = _featurize(22, False, True, False)
    assert all(isinstance(f, float) for f in features)


# --- Training data shape sanity check ---


def test_training_data_has_matching_lengths():
    from porthawk.predictor import _build_training_data

    X, y = _build_training_data()
    assert len(X) == len(y)
    assert len(X) > 100  # should have a decent number of samples
    assert all(len(row) == 10 for row in X)
    assert all(label in (0, 1) for label in y)
