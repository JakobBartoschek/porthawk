"""Tests for porthawk/evasion.py.

All network calls are mocked — no root required, no raw sockets.
Tests cover: config validation, timing math, packet building, fragmentation,
state determination per scan type, probe dispatch, and the async wrapper.
"""

from __future__ import annotations

import struct
import socket
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from porthawk.exceptions import ScanPermissionError
from porthawk.scanner import PortState, ScanResult
from porthawk.evasion import (
    _TCP_FIN,
    _TCP_PSH,
    _TCP_URG,
    _TCP_ACK,
    _SCAN_FLAGS,
    VALID_SCAN_TYPES,
    EvasionConfig,
    _next_delay,
    _build_probe_packet,
    _fragment_raw,
    _state_from_flags,
    _evasion_probe,
    evasion_scan_host,
    slow_low_config,
)
from porthawk.syn_scan import _TCP_SYN, _TCP_RST, _TCP_SYN_ACK


# ---------------------------------------------------------------------------
# EvasionConfig validation
# ---------------------------------------------------------------------------


class TestEvasionConfigValidation:
    def test_default_config_is_valid(self):
        cfg = EvasionConfig()
        assert cfg.scan_type == "syn"
        assert cfg.min_delay == 0.0
        assert cfg.max_delay == 0.0
        assert not cfg.fragment

    def test_invalid_scan_type_raises(self):
        with pytest.raises(ValueError, match="Unknown scan type"):
            EvasionConfig(scan_type="stealth")

    def test_all_valid_scan_types_accepted(self):
        for st in VALID_SCAN_TYPES:
            cfg = EvasionConfig(scan_type=st)
            assert cfg.scan_type == st

    def test_fragment_size_not_multiple_of_8_raises(self):
        with pytest.raises(ValueError, match="multiple of 8"):
            EvasionConfig(fragment_size=7)

    def test_fragment_size_zero_raises(self):
        with pytest.raises(ValueError, match="multiple of 8"):
            EvasionConfig(fragment_size=0)

    def test_fragment_size_16_is_valid(self):
        cfg = EvasionConfig(fragment_size=16)
        assert cfg.fragment_size == 16

    def test_negative_min_delay_raises(self):
        with pytest.raises(ValueError, match="non-negative"):
            EvasionConfig(min_delay=-1.0)

    def test_negative_max_delay_raises(self):
        with pytest.raises(ValueError, match="non-negative"):
            EvasionConfig(max_delay=-1.0)

    def test_min_greater_than_max_raises(self):
        with pytest.raises(ValueError, match="min_delay"):
            EvasionConfig(min_delay=10.0, max_delay=1.0)

    def test_unknown_distribution_raises(self):
        with pytest.raises(ValueError, match="Unknown distribution"):
            EvasionConfig(jitter_distribution="gaussian")

    def test_exponential_distribution_accepted(self):
        cfg = EvasionConfig(jitter_distribution="exponential")
        assert cfg.jitter_distribution == "exponential"

    def test_decoys_empty_by_default(self):
        cfg = EvasionConfig()
        assert cfg.decoys == []

    def test_decoys_list_stored(self):
        cfg = EvasionConfig(decoys=["1.2.3.4", "5.6.7.8"])
        assert len(cfg.decoys) == 2


# ---------------------------------------------------------------------------
# slow_low_config preset
# ---------------------------------------------------------------------------


class TestSlowLowConfig:
    def test_returns_evasion_config(self):
        cfg = slow_low_config()
        assert isinstance(cfg, EvasionConfig)

    def test_has_delay(self):
        cfg = slow_low_config()
        assert cfg.min_delay >= 1.0
        assert cfg.max_delay >= cfg.min_delay

    def test_exponential_distribution(self):
        cfg = slow_low_config()
        assert cfg.jitter_distribution == "exponential"

    def test_fragmentation_enabled(self):
        cfg = slow_low_config()
        assert cfg.fragment is True
        assert cfg.fragment_size == 8

    def test_ttl_looks_like_windows(self):
        cfg = slow_low_config()
        # TTL=128 is the Windows default — messes with passive OS fingerprinting
        assert cfg.ttl == 128

    def test_no_decoys_by_default(self):
        cfg = slow_low_config()
        assert cfg.decoys == []


# ---------------------------------------------------------------------------
# Timing: _next_delay
# ---------------------------------------------------------------------------


class TestNextDelay:
    def test_zero_delay_returns_zero(self):
        cfg = EvasionConfig(min_delay=0.0, max_delay=0.0)
        assert _next_delay(cfg) == 0.0

    def test_uniform_stays_in_range(self):
        cfg = EvasionConfig(min_delay=1.0, max_delay=5.0)
        for _ in range(50):
            d = _next_delay(cfg)
            assert 1.0 <= d <= 5.0

    def test_exponential_stays_in_range(self):
        cfg = EvasionConfig(min_delay=1.0, max_delay=10.0, jitter_distribution="exponential")
        for _ in range(50):
            d = _next_delay(cfg)
            assert 1.0 <= d <= 10.0

    def test_uniform_varies(self):
        cfg = EvasionConfig(min_delay=0.0, max_delay=100.0)
        results = {_next_delay(cfg) for _ in range(20)}
        # should not all be the same value
        assert len(results) > 1

    def test_fixed_min_delay_with_no_max(self):
        cfg = EvasionConfig(min_delay=2.5, max_delay=0.0)
        assert _next_delay(cfg) == 2.5


# ---------------------------------------------------------------------------
# Packet building: _build_probe_packet
# ---------------------------------------------------------------------------


class TestBuildProbePacket:
    def test_packet_length(self):
        pkt = _build_probe_packet("10.0.0.1", "10.0.0.2", 54321, 80, 12345, _TCP_SYN)
        assert len(pkt) == 40

    def test_ip_version_ihl(self):
        pkt = _build_probe_packet("10.0.0.1", "10.0.0.2", 54321, 80, 0, 0)
        assert pkt[0] == 0x45

    def test_correct_ttl_in_packet(self):
        pkt = _build_probe_packet("10.0.0.1", "10.0.0.2", 54321, 80, 0, 0, ttl=128)
        assert pkt[8] == 128

    def test_default_ttl_64(self):
        pkt = _build_probe_packet("10.0.0.1", "10.0.0.2", 54321, 80, 0, 0)
        assert pkt[8] == 64

    def test_dst_ip_encoded(self):
        pkt = _build_probe_packet("10.0.0.1", "10.0.0.2", 54321, 80, 0, 0)
        assert pkt[16:20] == socket.inet_aton("10.0.0.2")

    def test_src_ip_encoded(self):
        pkt = _build_probe_packet("10.0.0.1", "10.0.0.2", 54321, 80, 0, 0)
        assert pkt[12:16] == socket.inet_aton("10.0.0.1")

    def test_flags_syn(self):
        pkt = _build_probe_packet("10.0.0.1", "10.0.0.2", 54321, 80, 0, _TCP_SYN)
        assert pkt[33] == _TCP_SYN

    def test_flags_null(self):
        pkt = _build_probe_packet("10.0.0.1", "10.0.0.2", 54321, 80, 0, 0x00)
        assert pkt[33] == 0x00

    def test_flags_xmas(self):
        xmas = _TCP_FIN | _TCP_PSH | _TCP_URG
        pkt = _build_probe_packet("10.0.0.1", "10.0.0.2", 54321, 80, 0, xmas)
        assert pkt[33] == xmas

    def test_flags_fin(self):
        pkt = _build_probe_packet("10.0.0.1", "10.0.0.2", 54321, 80, 0, _TCP_FIN)
        assert pkt[33] == _TCP_FIN

    def test_seq_encoded(self):
        seq = 0xDEADBEEF
        pkt = _build_probe_packet("10.0.0.1", "10.0.0.2", 54321, 80, seq, _TCP_SYN)
        encoded = struct.unpack("!L", pkt[24:28])[0]
        assert encoded == seq


# ---------------------------------------------------------------------------
# Fragmentation: _fragment_raw
# ---------------------------------------------------------------------------


class TestFragmentRaw:
    def _make_test_packet(self) -> bytes:
        """Build a minimal 40-byte IP+TCP packet for fragmentation tests."""
        return _build_probe_packet("10.0.0.1", "10.0.0.2", 54321, 80, 12345, _TCP_SYN)

    def test_single_fragment_when_packet_fits(self):
        pkt = self._make_test_packet()
        # frag_size=32 — TCP header is 20 bytes, fits in one fragment
        frags = _fragment_raw(pkt, 32)
        assert len(frags) == 1

    def test_three_fragments_for_8_byte_frags(self):
        pkt = self._make_test_packet()  # 20 bytes TCP
        # 20 bytes payload, 8 bytes per fragment: ceil(20/8) = 3 fragments
        frags = _fragment_raw(pkt, 8)
        assert len(frags) == 3

    def test_mf_set_on_non_last_fragments(self):
        pkt = self._make_test_packet()
        frags = _fragment_raw(pkt, 8)
        for frag in frags[:-1]:
            frag_off_word = struct.unpack("!H", frag[6:8])[0]
            mf = (frag_off_word >> 13) & 1
            assert mf == 1, "MF bit must be set on non-last fragments"

    def test_mf_clear_on_last_fragment(self):
        pkt = self._make_test_packet()
        frags = _fragment_raw(pkt, 8)
        last = frags[-1]
        frag_off_word = struct.unpack("!H", last[6:8])[0]
        mf = (frag_off_word >> 13) & 1
        assert mf == 0, "MF bit must be clear on last fragment"

    def test_fragment_offsets_are_correct(self):
        pkt = self._make_test_packet()
        frags = _fragment_raw(pkt, 8)
        for i, frag in enumerate(frags):
            frag_off_word = struct.unpack("!H", frag[6:8])[0]
            offset_units = frag_off_word & 0x1FFF  # lower 13 bits
            assert offset_units == i, f"Fragment {i}: expected offset {i}, got {offset_units}"

    def test_all_fragments_have_same_ip_id(self):
        pkt = self._make_test_packet()
        frags = _fragment_raw(pkt, 8)
        ids = {struct.unpack("!H", f[4:6])[0] for f in frags}
        assert len(ids) == 1, "All fragments must share the same IP ID for reassembly"

    def test_all_fragments_have_correct_ip_header_size(self):
        pkt = self._make_test_packet()
        frags = _fragment_raw(pkt, 8)
        for frag in frags:
            ip_ihl = (frag[0] & 0x0F) * 4
            assert ip_ihl == 20

    def test_payload_reassembles_correctly(self):
        pkt = self._make_test_packet()
        frags = _fragment_raw(pkt, 8)
        # collect all payload bytes in order
        reassembled = b""
        for frag in frags:
            ip_ihl = (frag[0] & 0x0F) * 4
            reassembled += frag[ip_ihl:]
        original_payload = pkt[20:]  # skip IP header
        assert reassembled == original_payload


# ---------------------------------------------------------------------------
# State determination: _state_from_flags
# ---------------------------------------------------------------------------


class TestStateFromFlags:
    # --- SYN scan ---
    def test_syn_syn_ack_is_open(self):
        state, _ = _state_from_flags(_TCP_SYN_ACK, "syn", 1.0)
        assert state == PortState.OPEN

    def test_syn_rst_is_closed(self):
        state, _ = _state_from_flags(_TCP_RST, "syn", 1.0)
        assert state == PortState.CLOSED

    def test_syn_no_response_is_filtered(self):
        state, _ = _state_from_flags(None, "syn", 1.0)
        assert state == PortState.FILTERED

    # --- FIN scan ---
    def test_fin_rst_is_closed(self):
        state, _ = _state_from_flags(_TCP_RST, "fin", 1.0)
        assert state == PortState.CLOSED

    def test_fin_no_response_is_open(self):
        # RFC 793: open port silently discards FIN without SYN
        state, _ = _state_from_flags(None, "fin", 1.0)
        assert state == PortState.OPEN

    # --- NULL scan ---
    def test_null_rst_is_closed(self):
        state, _ = _state_from_flags(_TCP_RST, "null", 1.0)
        assert state == PortState.CLOSED

    def test_null_no_response_is_open(self):
        state, _ = _state_from_flags(None, "null", 1.0)
        assert state == PortState.OPEN

    # --- XMAS scan ---
    def test_xmas_rst_is_closed(self):
        state, _ = _state_from_flags(_TCP_RST, "xmas", 1.0)
        assert state == PortState.CLOSED

    def test_xmas_no_response_is_open(self):
        state, _ = _state_from_flags(None, "xmas", 1.0)
        assert state == PortState.OPEN

    # --- ACK scan ---
    def test_ack_rst_means_unfiltered(self):
        # RST = packet reached host = no stateful firewall = OPEN (semantic: unfiltered)
        state, _ = _state_from_flags(_TCP_RST, "ack", 1.0)
        assert state == PortState.OPEN

    def test_ack_no_response_is_filtered(self):
        state, _ = _state_from_flags(None, "ack", 1.0)
        assert state == PortState.FILTERED

    # --- Maimon ---
    def test_maimon_rst_is_closed(self):
        state, _ = _state_from_flags(_TCP_RST, "maimon", 1.0)
        assert state == PortState.CLOSED

    def test_maimon_no_response_is_open(self):
        state, _ = _state_from_flags(None, "maimon", 1.0)
        assert state == PortState.OPEN

    # --- latency propagation ---
    def test_timeout_latency_is_timeout_times_1000(self):
        _, latency = _state_from_flags(None, "syn", 1.5)
        assert latency == 1500.0

    def test_response_latency_is_zero_placeholder(self):
        # caller fills in actual latency — _state_from_flags returns 0.0
        _, latency = _state_from_flags(_TCP_RST, "syn", 1.0)
        assert latency == 0.0


# ---------------------------------------------------------------------------
# Probe dispatch: _evasion_probe
# ---------------------------------------------------------------------------


class TestEvasionProbeDispatch:
    @patch("porthawk.evasion._scapy_available", return_value=True)
    @patch("porthawk.evasion._evasion_probe_scapy", return_value=(PortState.OPEN, 1.5))
    def test_uses_scapy_when_available(self, mock_scapy, mock_avail):
        cfg = EvasionConfig()
        state, latency = _evasion_probe("10.0.0.1", 80, cfg, 1.0)
        mock_scapy.assert_called_once_with("10.0.0.1", 80, cfg, 1.0)
        assert state == PortState.OPEN

    @patch("porthawk.evasion._scapy_available", return_value=False)
    @patch("porthawk.evasion._IS_WINDOWS", False)
    @patch("porthawk.evasion._evasion_probe_raw", return_value=(PortState.CLOSED, 0.8))
    def test_falls_back_to_raw_on_linux(self, mock_raw, mock_avail):
        cfg = EvasionConfig()
        state, _ = _evasion_probe("10.0.0.1", 80, cfg, 1.0)
        mock_raw.assert_called_once()
        assert state == PortState.CLOSED

    @patch("porthawk.evasion._scapy_available", return_value=False)
    @patch("porthawk.evasion._IS_WINDOWS", True)
    def test_raises_on_windows_without_scapy(self, mock_avail):
        with pytest.raises(ScanPermissionError, match="Scapy"):
            _evasion_probe("10.0.0.1", 80, EvasionConfig(), 1.0)


# ---------------------------------------------------------------------------
# XMAS scan flags constant
# ---------------------------------------------------------------------------


class TestScanFlagConstants:
    def test_xmas_has_fin_psh_urg(self):
        xmas = _SCAN_FLAGS["xmas"]
        assert xmas & _TCP_FIN
        assert xmas & _TCP_PSH
        assert xmas & _TCP_URG

    def test_null_is_zero(self):
        assert _SCAN_FLAGS["null"] == 0x00

    def test_fin_is_fin_only(self):
        assert _SCAN_FLAGS["fin"] == _TCP_FIN
        assert not (_SCAN_FLAGS["fin"] & _TCP_PSH)
        assert not (_SCAN_FLAGS["fin"] & _TCP_URG)

    def test_ack_is_ack_only(self):
        assert _SCAN_FLAGS["ack"] == _TCP_ACK
        assert not (_SCAN_FLAGS["ack"] & _TCP_SYN)

    def test_maimon_is_fin_ack(self):
        assert _SCAN_FLAGS["maimon"] == (_TCP_FIN | _TCP_ACK)


# ---------------------------------------------------------------------------
# evasion_scan_host — async wrapper
# ---------------------------------------------------------------------------


class TestEvasionScanHost:
    @pytest.mark.asyncio
    async def test_empty_ports_raises_value_error(self):
        with pytest.raises(ValueError, match="empty"):
            await evasion_scan_host("10.0.0.1", [])

    @pytest.mark.asyncio
    @patch("porthawk.evasion._has_raw_socket_privilege", return_value=False)
    @patch("porthawk.evasion._IS_WINDOWS", False)
    async def test_no_privilege_raises_scan_permission_error(self, mock_priv):
        with pytest.raises(ScanPermissionError):
            await evasion_scan_host("10.0.0.1", [80])

    @pytest.mark.asyncio
    @patch("porthawk.evasion._has_raw_socket_privilege", return_value=True)
    @patch("porthawk.evasion._evasion_probe", return_value=(PortState.OPEN, 1.5))
    async def test_returns_scan_results(self, mock_probe, mock_priv):
        results = await evasion_scan_host("10.0.0.1", [80, 443, 22], timeout=1.0)
        assert len(results) == 3
        assert all(isinstance(r, ScanResult) for r in results)
        assert all(r.host == "10.0.0.1" for r in results)
        assert all(r.protocol == "tcp" for r in results)

    @pytest.mark.asyncio
    @patch("porthawk.evasion._has_raw_socket_privilege", return_value=True)
    @patch("porthawk.evasion._evasion_probe", return_value=(PortState.OPEN, 1.5))
    async def test_result_ports_match_input(self, mock_probe, mock_priv):
        ports = [22, 80, 443]
        results = await evasion_scan_host("10.0.0.1", ports, timeout=1.0)
        result_ports = sorted(r.port for r in results)
        assert result_ports == sorted(ports)

    @pytest.mark.asyncio
    @patch("porthawk.evasion._has_raw_socket_privilege", return_value=True)
    @patch(
        "porthawk.evasion._evasion_probe",
        side_effect=lambda host, port, config, timeout: (
            (PortState.OPEN, 1.0) if port == 80
            else (PortState.CLOSED, 0.5) if port == 22
            else (PortState.FILTERED, timeout * 1000)
        ),
    )
    async def test_mixed_states_per_port(self, mock_probe, mock_priv):
        results = await evasion_scan_host("10.0.0.1", [22, 80, 9999], timeout=0.5)
        by_port = {r.port: r.state for r in results}
        assert by_port[80] == PortState.OPEN
        assert by_port[22] == PortState.CLOSED
        assert by_port[9999] == PortState.FILTERED

    @pytest.mark.asyncio
    @patch("porthawk.evasion._has_raw_socket_privilege", return_value=True)
    @patch("porthawk.evasion._evasion_probe", return_value=(PortState.OPEN, 1.0))
    @patch("porthawk.evasion._next_delay", return_value=0.0)
    async def test_no_delay_when_config_has_no_jitter(self, mock_delay, mock_probe, mock_priv):
        cfg = EvasionConfig(min_delay=0.0, max_delay=0.0)
        results = await evasion_scan_host("10.0.0.1", [80], config=cfg)
        assert len(results) == 1

    @pytest.mark.asyncio
    @patch("porthawk.evasion._has_raw_socket_privilege", return_value=True)
    @patch("porthawk.evasion._evasion_probe", return_value=(PortState.OPEN, 1.0))
    async def test_custom_scan_type_passed_to_probe(self, mock_probe, mock_priv):
        cfg = EvasionConfig(scan_type="xmas")
        await evasion_scan_host("10.0.0.1", [80], config=cfg)
        # probe was called with the config we passed
        call_args = mock_probe.call_args
        assert call_args[0][2].scan_type == "xmas"

    @pytest.mark.asyncio
    @patch("porthawk.evasion._has_raw_socket_privilege", return_value=True)
    @patch("porthawk.evasion._evasion_probe", return_value=(PortState.OPEN, 1.0))
    async def test_none_config_uses_defaults(self, mock_probe, mock_priv):
        results = await evasion_scan_host("10.0.0.1", [80], config=None)
        assert len(results) == 1
        call_args = mock_probe.call_args
        assert call_args[0][2].scan_type == "syn"

    @pytest.mark.asyncio
    @patch("porthawk.evasion._has_raw_socket_privilege", return_value=False)
    @patch("porthawk.evasion._IS_WINDOWS", True)
    async def test_windows_privilege_error_mentions_npcap(self, mock_priv):
        with pytest.raises(ScanPermissionError, match="Npcap"):
            await evasion_scan_host("10.0.0.1", [80])


# ---------------------------------------------------------------------------
# Public API export
# ---------------------------------------------------------------------------


class TestPublicApiExport:
    def test_evasion_scan_host_importable(self):
        import porthawk
        assert hasattr(porthawk, "evasion_scan_host")

    def test_evasion_config_importable(self):
        import porthawk
        assert hasattr(porthawk, "EvasionConfig")

    def test_slow_low_config_importable(self):
        import porthawk
        assert hasattr(porthawk, "slow_low_config")
