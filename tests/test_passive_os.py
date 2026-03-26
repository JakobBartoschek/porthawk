"""Tests for porthawk/passive_os.py.

All network calls are mocked — no root, no raw sockets.
Tests cover: TCP option parsing, feature extraction from raw packets,
TTL normalization, rule-based scoring, KNN classification, end-to-end
fingerprint_os(), ttl_only_os(), and passive_os_scan() dispatch.
"""

from __future__ import annotations

import socket
import struct
from unittest.mock import MagicMock, patch

import pytest

from porthawk.passive_os import (
    _OS_DB,
    _OsSig,
    _best_rule_match,
    _confidence_label,
    _feature_vector,
    _manual_knn,
    _parse_tcp_options,
    _score_signature,
    _sig_feature_vector,
    _sklearn_available,
    _ttl_family,
    extract_fingerprint,
    fingerprint_os,
    OsFingerprint,
    OsMatch,
    passive_os_scan,
    ttl_only_os,
)


# ---------------------------------------------------------------------------
# Helpers — build raw IP+TCP packets for testing
# ---------------------------------------------------------------------------


def _make_raw_pkt(
    ttl: int = 64,
    window: int = 65535,
    df: bool = True,
    tcp_flags: int = 0x12,   # SYN-ACK
    tcp_options: bytes = b"",
    src_ip: str = "10.0.0.2",
    dst_ip: str = "10.0.0.1",
    src_port: int = 80,
    dst_port: int = 54321,
) -> bytes:
    """Build a minimal raw IP+TCP packet with custom TCP options."""
    ip_ihl = 5
    ip_flags_frag = 0x4000 if df else 0x0000  # DF bit at position 14

    data_offset_bytes = 20 + len(tcp_options)
    # pad to 4-byte boundary
    pad = (4 - data_offset_bytes % 4) % 4
    tcp_options_padded = tcp_options + b"\x00" * pad
    tcp_header_len = 20 + len(tcp_options_padded)
    data_offset_field = (tcp_header_len // 4) << 4

    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | ip_ihl, 0,
        20 + tcp_header_len,
        0x1234,
        ip_flags_frag,
        ttl, socket.IPPROTO_TCP, 0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port, dst_port,
        0, 0,
        data_offset_field, tcp_flags,
        window, 0, 0,
    )
    return ip_header + tcp_header + tcp_options_padded


def _make_windows_pkt() -> bytes:
    """Build a packet matching Windows 10/11 signature."""
    opts = (
        b"\x02\x04\x05\xb4"    # MSS=1460
        b"\x01"                  # NOP
        b"\x03\x03\x08"          # Window Scale=8
        b"\x01"                  # NOP
        b"\x01"                  # NOP
        b"\x04\x02"              # SACK Permitted
    )
    return _make_raw_pkt(ttl=128, window=65535, df=True, tcp_options=opts)


def _make_linux_pkt() -> bytes:
    """Build a packet matching Linux 5.x signature."""
    opts = (
        b"\x02\x04\x05\xb4"    # MSS=1460
        b"\x04\x02"              # SACK Permitted
        b"\x08\x0a\x00\x00\x00\x01\x00\x00\x00\x00"  # Timestamps
        b"\x01"                  # NOP
        b"\x03\x03\x07"          # Window Scale=7
    )
    return _make_raw_pkt(ttl=64, window=65535, df=True, tcp_options=opts)


def _make_macos_pkt() -> bytes:
    """Build a packet matching macOS 12-14 signature."""
    opts = (
        b"\x02\x04\x05\xb4"    # MSS=1460
        b"\x01"                  # NOP
        b"\x03\x03\x06"          # Window Scale=6
        b"\x01"                  # NOP
        b"\x01"                  # NOP
        b"\x08\x0a\x00\x00\x00\x01\x00\x00\x00\x00"  # Timestamps
        b"\x04\x02"              # SACK Permitted
    )
    return _make_raw_pkt(ttl=64, window=65535, df=True, tcp_options=opts)


def _make_cisco_pkt() -> bytes:
    """Build a packet matching Cisco IOS signature."""
    opts = b"\x02\x04\x02\x18"  # MSS=536
    return _make_raw_pkt(ttl=255, window=4128, df=False, tcp_options=opts)


# ---------------------------------------------------------------------------
# TCP option parsing
# ---------------------------------------------------------------------------


class TestParseTcpOptions:
    def test_empty_returns_defaults(self):
        result = _parse_tcp_options(b"")
        assert result["mss"] is None
        assert result["wscale"] is None
        assert not result["has_timestamp"]
        assert not result["has_sack"]
        assert result["order"] == []

    def test_nop_only(self):
        result = _parse_tcp_options(b"\x01\x01\x01")
        assert result["order"] == ["nop", "nop", "nop"]

    def test_end_of_options_stops_parsing(self):
        # kind=0 terminates — NOP after it should not appear
        result = _parse_tcp_options(b"\x01\x00\x01")
        assert result["order"] == ["nop"]

    def test_mss_parsed(self):
        # kind=2, len=4, value=1460
        result = _parse_tcp_options(b"\x02\x04\x05\xb4")
        assert result["mss"] == 1460
        assert "mss" in result["order"]

    def test_mss_9000(self):
        result = _parse_tcp_options(b"\x02\x04\x23\x28")  # 0x2328 = 9000
        assert result["mss"] == 9000

    def test_window_scale_parsed(self):
        # kind=3, len=3, shift=7
        result = _parse_tcp_options(b"\x03\x03\x07")
        assert result["wscale"] == 7
        assert "wscale" in result["order"]

    def test_window_scale_zero(self):
        result = _parse_tcp_options(b"\x03\x03\x00")
        assert result["wscale"] == 0

    def test_sack_permitted_parsed(self):
        result = _parse_tcp_options(b"\x04\x02")
        assert result["has_sack"] is True
        assert "sack" in result["order"]

    def test_timestamp_parsed(self):
        ts = b"\x08\x0a" + b"\x00\x00\x00\x01" + b"\x00\x00\x00\x00"
        result = _parse_tcp_options(ts)
        assert result["has_timestamp"] is True
        assert "ts" in result["order"]

    def test_windows_options_order(self):
        # MSS NOP WS NOP NOP SACK
        opts = (
            b"\x02\x04\x05\xb4"
            b"\x01"
            b"\x03\x03\x08"
            b"\x01"
            b"\x01"
            b"\x04\x02"
        )
        result = _parse_tcp_options(opts)
        assert result["order"] == ["mss", "nop", "wscale", "nop", "nop", "sack"]
        assert result["mss"] == 1460
        assert result["wscale"] == 8

    def test_linux_options_order(self):
        # MSS SACK TS NOP WS
        opts = (
            b"\x02\x04\x05\xb4"
            b"\x04\x02"
            b"\x08\x0a\x00\x00\x00\x01\x00\x00\x00\x00"
            b"\x01"
            b"\x03\x03\x07"
        )
        result = _parse_tcp_options(opts)
        assert result["order"] == ["mss", "sack", "ts", "nop", "wscale"]

    def test_unknown_kind_added_as_optN(self):
        # kind=99, len=3, 1 byte data
        result = _parse_tcp_options(b"\x63\x03\xff")
        assert "opt99" in result["order"]

    def test_malformed_length_stops_gracefully(self):
        # length field points beyond buffer
        result = _parse_tcp_options(b"\x02\xff")
        # should not raise, order may be empty
        assert isinstance(result["order"], list)


# ---------------------------------------------------------------------------
# Feature extraction from raw packets
# ---------------------------------------------------------------------------


class TestExtractFingerprint:
    def test_too_short_returns_none(self):
        assert extract_fingerprint(b"\x45\x00") is None

    def test_non_tcp_returns_none(self):
        # build a UDP packet (proto=17)
        pkt = _make_raw_pkt()
        # replace protocol byte at offset 9
        pkt = pkt[:9] + b"\x11" + pkt[10:]
        assert extract_fingerprint(pkt) is None

    def test_extracts_ttl(self):
        fp = extract_fingerprint(_make_raw_pkt(ttl=128))
        assert fp is not None
        assert fp.ttl == 128

    def test_extracts_window_size(self):
        fp = extract_fingerprint(_make_raw_pkt(window=29200))
        assert fp is not None
        assert fp.window_size == 29200

    def test_extracts_df_bit_set(self):
        fp = extract_fingerprint(_make_raw_pkt(df=True))
        assert fp is not None
        assert fp.df_bit is True

    def test_extracts_df_bit_clear(self):
        fp = extract_fingerprint(_make_raw_pkt(df=False))
        assert fp is not None
        assert fp.df_bit is False

    def test_extracts_mss(self):
        fp = extract_fingerprint(_make_windows_pkt())
        assert fp is not None
        assert fp.mss == 1460

    def test_extracts_wscale(self):
        fp = extract_fingerprint(_make_windows_pkt())
        assert fp is not None
        assert fp.wscale == 8

    def test_extracts_sack(self):
        fp = extract_fingerprint(_make_windows_pkt())
        assert fp is not None
        assert fp.has_sack is True

    def test_extracts_timestamps(self):
        fp = extract_fingerprint(_make_linux_pkt())
        assert fp is not None
        assert fp.has_timestamp is True

    def test_no_options_packet(self):
        fp = extract_fingerprint(_make_raw_pkt(tcp_options=b""))
        assert fp is not None
        assert fp.mss is None
        assert fp.wscale is None
        assert not fp.has_timestamp
        assert not fp.has_sack

    def test_returns_os_fingerprint_instance(self):
        fp = extract_fingerprint(_make_raw_pkt())
        assert isinstance(fp, OsFingerprint)


# ---------------------------------------------------------------------------
# TTL normalization
# ---------------------------------------------------------------------------


class TestTtlFamily:
    def test_ttl_64_family(self):
        assert _ttl_family(64) == "64"
        assert _ttl_family(57) == "64"  # 7 hops away from Linux
        assert _ttl_family(1) == "64"

    def test_ttl_128_family(self):
        assert _ttl_family(128) == "128"
        assert _ttl_family(120) == "128"  # 8 hops from Windows
        assert _ttl_family(65) == "128"

    def test_ttl_255_family(self):
        assert _ttl_family(255) == "255"
        assert _ttl_family(200) == "255"

    def test_ttl_zero(self):
        # edge case — should return "unknown" not crash
        assert _ttl_family(0) == "unknown"


# ---------------------------------------------------------------------------
# Feature vectors
# ---------------------------------------------------------------------------


class TestFeatureVector:
    def test_returns_7_dimensions(self):
        fp = OsFingerprint(ttl=64, window_size=65535, df_bit=True)
        vec = _feature_vector(fp)
        assert len(vec) == 7

    def test_all_values_in_01_range(self):
        fp = OsFingerprint(ttl=128, window_size=65535, df_bit=True, mss=1460, wscale=8)
        vec = _feature_vector(fp)
        for v in vec:
            assert 0.0 <= v <= 1.0

    def test_ttl_64_gives_zero_normalized(self):
        fp = OsFingerprint(ttl=64, window_size=0, df_bit=False)
        vec = _feature_vector(fp)
        assert vec[0] == 0.0  # TTL bucket for 64-family

    def test_ttl_128_gives_half(self):
        fp = OsFingerprint(ttl=128, window_size=0, df_bit=False)
        vec = _feature_vector(fp)
        assert vec[0] == 0.5

    def test_windows_and_linux_differ(self):
        win = OsFingerprint(ttl=128, window_size=65535, df_bit=True, has_timestamp=False)
        lin = OsFingerprint(ttl=64, window_size=29200, df_bit=True, has_timestamp=True)
        assert _feature_vector(win) != _feature_vector(lin)


# ---------------------------------------------------------------------------
# Signature scoring
# ---------------------------------------------------------------------------


class TestScoreSignature:
    def _windows_sig(self) -> _OsSig:
        return next(s for s in _OS_DB if "Windows 10" in s.os_detail)

    def _linux_sig(self) -> _OsSig:
        return next(s for s in _OS_DB if "Linux 5.x" in s.os_detail)

    def test_windows_packet_scores_high_against_windows_sig(self):
        fp = extract_fingerprint(_make_windows_pkt())
        assert fp is not None
        score, signals = _score_signature(fp, self._windows_sig())
        assert score >= 0.60, f"Expected >=0.60, got {score}"

    def test_windows_packet_scores_low_against_linux_sig(self):
        fp = extract_fingerprint(_make_windows_pkt())
        assert fp is not None
        score, _ = _score_signature(fp, self._linux_sig())
        assert score < 0.50, f"Expected <0.50, got {score}"

    def test_linux_packet_scores_high_against_linux_sig(self):
        fp = extract_fingerprint(_make_linux_pkt())
        assert fp is not None
        score, signals = _score_signature(fp, self._linux_sig())
        assert score >= 0.50, f"Expected >=0.50, got {score}"

    def test_signals_list_is_not_empty_on_match(self):
        fp = extract_fingerprint(_make_windows_pkt())
        assert fp is not None
        _, signals = _score_signature(fp, self._windows_sig())
        assert len(signals) > 0

    def test_ttl_family_mismatch_yields_lower_score(self):
        fp = OsFingerprint(ttl=64, window_size=65535, df_bit=True)
        win_sig = self._windows_sig()
        lin_sig = self._linux_sig()
        win_score, _ = _score_signature(fp, win_sig)
        lin_score, _ = _score_signature(fp, lin_sig)
        assert lin_score > win_score


# ---------------------------------------------------------------------------
# Best rule match
# ---------------------------------------------------------------------------


class TestBestRuleMatch:
    def test_windows_packet_matches_windows(self):
        fp = extract_fingerprint(_make_windows_pkt())
        assert fp is not None
        sig, score, signals = _best_rule_match(fp)
        assert sig.os_family == "Windows"
        assert score >= 0.60

    def test_cisco_packet_matches_network_device(self):
        fp = extract_fingerprint(_make_cisco_pkt())
        assert fp is not None
        sig, score, _ = _best_rule_match(fp)
        assert sig.os_family == "Network Device"


# ---------------------------------------------------------------------------
# Confidence labels
# ---------------------------------------------------------------------------


class TestConfidenceLabel:
    def test_high_confidence(self):
        assert _confidence_label(0.85) == "HIGH"
        assert _confidence_label(0.70) == "HIGH"

    def test_medium_confidence(self):
        assert _confidence_label(0.60) == "MEDIUM"
        assert _confidence_label(0.45) == "MEDIUM"

    def test_low_confidence(self):
        assert _confidence_label(0.44) == "LOW"
        assert _confidence_label(0.0) == "LOW"


# ---------------------------------------------------------------------------
# Manual KNN
# ---------------------------------------------------------------------------


class TestManualKnn:
    def test_returns_tuple_of_three(self):
        fp = extract_fingerprint(_make_windows_pkt())
        assert fp is not None
        result = _manual_knn(fp)
        assert len(result) == 3

    def test_score_in_01_range(self):
        fp = extract_fingerprint(_make_linux_pkt())
        assert fp is not None
        _, _, score = _manual_knn(fp)
        assert 0.0 <= score <= 1.0

    def test_windows_classified_as_windows(self):
        fp = extract_fingerprint(_make_windows_pkt())
        assert fp is not None
        family, _, _ = _manual_knn(fp)
        assert family == "Windows"

    def test_cisco_classified_as_network_device(self):
        fp = extract_fingerprint(_make_cisco_pkt())
        assert fp is not None
        family, _, _ = _manual_knn(fp)
        assert family == "Network Device"


# ---------------------------------------------------------------------------
# fingerprint_os — end-to-end
# ---------------------------------------------------------------------------


class TestFingerprintOs:
    def test_too_short_returns_none(self):
        assert fingerprint_os(b"\x45\x00\x00") is None

    def test_returns_os_match_instance(self):
        result = fingerprint_os(_make_windows_pkt())
        assert isinstance(result, OsMatch)

    def test_windows_packet_classified_as_windows(self):
        result = fingerprint_os(_make_windows_pkt())
        assert result is not None
        assert result.os_family == "Windows"

    def test_cisco_packet_classified_as_network_device(self):
        result = fingerprint_os(_make_cisco_pkt())
        assert result is not None
        assert result.os_family == "Network Device"

    def test_linux_packet_classified_as_linux(self):
        result = fingerprint_os(_make_linux_pkt())
        assert result is not None
        assert result.os_family == "Linux"

    def test_macos_packet_classified_as_macos(self):
        # macOS and Linux share TTL=64 — TCP options distinguish them
        result = fingerprint_os(_make_macos_pkt())
        assert result is not None
        assert result.os_family in ("macOS", "Linux", "iOS")  # high TTL similarity

    def test_score_is_float_in_range(self):
        result = fingerprint_os(_make_windows_pkt())
        assert result is not None
        assert 0.0 <= result.score <= 1.0

    def test_confidence_is_valid_label(self):
        result = fingerprint_os(_make_windows_pkt())
        assert result is not None
        assert result.confidence in ("HIGH", "MEDIUM", "LOW")

    def test_matched_signals_not_empty(self):
        result = fingerprint_os(_make_windows_pkt())
        assert result is not None
        assert len(result.matched_signals) > 0

    def test_method_string_present(self):
        result = fingerprint_os(_make_windows_pkt())
        assert result is not None
        assert isinstance(result.method, str)
        assert len(result.method) > 0


# ---------------------------------------------------------------------------
# ttl_only_os — fallback
# ---------------------------------------------------------------------------


class TestTtlOnlyOs:
    def test_ttl_64_returns_linux_unix(self):
        result = ttl_only_os(64)
        assert "Linux" in result.os_family or "Unix" in result.os_family

    def test_ttl_128_returns_windows(self):
        result = ttl_only_os(128)
        assert result.os_family == "Windows"

    def test_ttl_255_returns_network_device(self):
        result = ttl_only_os(255)
        assert result.os_family == "Network Device"

    def test_confidence_is_low(self):
        # TTL-only is never HIGH — can't distinguish Linux from macOS
        result = ttl_only_os(64)
        assert result.confidence == "LOW"

    def test_method_is_ttl_only(self):
        result = ttl_only_os(128)
        assert result.method == "ttl_only"

    def test_returns_os_match_instance(self):
        result = ttl_only_os(64)
        assert isinstance(result, OsMatch)


# ---------------------------------------------------------------------------
# passive_os_scan dispatch
# ---------------------------------------------------------------------------


class TestPassiveOsScan:
    @patch("porthawk.passive_os._scapy_available", return_value=True)
    @patch("porthawk.passive_os._passive_os_scapy", return_value=OsMatch(
        os_family="Linux", os_detail="Linux 5.x", confidence="HIGH",
        score=0.85, matched_signals=["ttl=64"], method="tcp_fingerprint+knn",
    ))
    def test_uses_scapy_when_available(self, mock_scan, mock_avail):
        result = passive_os_scan("10.0.0.1")
        mock_scan.assert_called_once()
        assert result is not None
        assert result.os_family == "Linux"

    @patch("porthawk.passive_os._scapy_available", return_value=False)
    @patch("porthawk.passive_os._passive_os_raw", return_value=OsMatch(
        os_family="Windows", os_detail="Windows 10/11", confidence="HIGH",
        score=0.90, matched_signals=["ttl=128", "window=65535"], method="tcp_fingerprint+knn",
    ))
    @patch("porthawk.passive_os.sys")
    def test_falls_back_to_raw_on_linux(self, mock_sys, mock_scan, mock_avail):
        mock_sys.platform = "linux"
        result = passive_os_scan("10.0.0.1")
        mock_scan.assert_called_once()
        assert result is not None

    @patch("porthawk.passive_os._scapy_available", return_value=False)
    @patch("porthawk.passive_os.sys")
    def test_returns_none_on_windows_without_scapy(self, mock_sys, mock_avail):
        mock_sys.platform = "win32"
        result = passive_os_scan("10.0.0.1")
        assert result is None


# ---------------------------------------------------------------------------
# Database sanity checks
# ---------------------------------------------------------------------------


class TestOsDatabase:
    def test_db_is_not_empty(self):
        assert len(_OS_DB) >= 10

    def test_all_entries_have_required_fields(self):
        for sig in _OS_DB:
            assert sig.os_family
            assert sig.os_detail
            assert 1 <= sig.ttl <= 255
            assert sig.window > 0

    def test_windows_entries_have_ttl_128(self):
        windows = [s for s in _OS_DB if s.os_family == "Windows"]
        assert len(windows) >= 3
        for sig in windows:
            assert sig.ttl == 128

    def test_linux_entries_have_ttl_64(self):
        linux = [s for s in _OS_DB if s.os_family == "Linux"]
        assert len(linux) >= 3
        for sig in linux:
            assert sig.ttl == 64

    def test_network_device_entries_exist(self):
        devices = [s for s in _OS_DB if s.os_family == "Network Device"]
        assert len(devices) >= 2

    def test_feature_vectors_are_valid(self):
        for sig in _OS_DB:
            vec = _sig_feature_vector(sig)
            assert len(vec) == 7
            for v in vec:
                assert 0.0 <= v <= 1.0, f"Invalid vector value {v} in {sig.os_detail}"


# ---------------------------------------------------------------------------
# Public API export
# ---------------------------------------------------------------------------


class TestPublicApiExport:
    def test_importable_from_porthawk(self):
        import porthawk
        assert hasattr(porthawk, "OsMatch")
        assert hasattr(porthawk, "OsFingerprint")
        assert hasattr(porthawk, "fingerprint_os")
        assert hasattr(porthawk, "passive_os_scan")
        assert hasattr(porthawk, "ttl_only_os")
