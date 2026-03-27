"""Streamlit web dashboard — every PortHawk feature, no CLI required.

Run: streamlit run porthawk/dashboard.py
Or:  python start_dashboard.py  /  porthawk-dashboard
"""

from __future__ import annotations

import asyncio
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import streamlit as st

st.set_page_config(
    page_title="PortHawk",
    page_icon="🦅",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        "About": "PortHawk — async port scanner. https://github.com/JakobBartoschek/porthawk"
    },
)

import porthawk  # noqa: E402
from porthawk.reporter import build_report, save_csv, save_html, save_json, save_sarif  # noqa: E402
from porthawk.scanner import PortState, ScanResult  # noqa: E402

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RISK_COLORS = {"HIGH": "#ef4444", "MEDIUM": "#f59e0b", "LOW": "#22c55e"}
RISK_EMOJI = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}

SCAN_MODES: dict[str, str] = {
    "TCP": "Standard async TCP connect. Fast, works without root.",
    "UDP": "UDP scan with protocol payloads (DNS, NTP, SNMP, …). Top 20 UDP ports by default.",
    "Stealth": "Slow TCP: 1 thread, 3 s timeout. Leaves less noise.",
    "SYN (root)": "Half-open SYN scan. Needs root/admin + Scapy or Linux raw sockets.",
    "Evasion (root)": "IDS evasion: randomized timing, fragmentation, custom TCP flags. Needs root/admin.",
}

EVASION_TYPES = ["syn", "fin", "null", "xmas", "ack", "maimon"]

# ---------------------------------------------------------------------------
# Pure helpers — no Streamlit, fully testable
# ---------------------------------------------------------------------------


def results_to_rows(
    results: list[ScanResult], include_closed: bool = False
) -> list[dict[str, Any]]:
    """Convert ScanResults to plain dicts for st.dataframe."""
    rows = []
    for r in results:
        if r.state != PortState.OPEN and not include_closed:
            continue
        risk = r.risk_level or "—"
        rows.append(
            {
                "Port": r.port,
                "Proto": r.protocol,
                "Service": r.service_name or "—",
                "Risk": f"{RISK_EMOJI.get(risk, '⚪')} {risk}",
                "Version": r.service_version or "—",
                "Banner": (r.banner or "")[:70],
                "OS": r.os_guess or "—",
                "TTL": r.ttl if r.ttl else "—",
                "CVEs": len(r.cves),
                "Latency": f"{r.latency_ms:.1f} ms" if r.latency_ms else "—",
            }
        )
    return rows


def risk_distribution(results: list[ScanResult]) -> dict[str, int]:
    """Count open ports per risk level."""
    counts: dict[str, int] = {}
    for r in results:
        if r.state == PortState.OPEN:
            key = r.risk_level or "unknown"
            counts[key] = counts.get(key, 0) + 1
    return counts


def service_distribution(results: list[ScanResult], top_n: int = 10) -> dict[str, int]:
    """Count open ports per service name, top N by frequency."""
    counts: dict[str, int] = {}
    for r in results:
        if r.state == PortState.OPEN:
            key = r.service_name or "unknown"
            counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1])[:top_n])


def honeypot_badge(score: float, verdict: str) -> tuple[str, str]:
    """(streamlit color level, display text) for a honeypot result."""
    if verdict == "LIKELY_HONEYPOT":
        return "error", f"🪤 {score:.2f} — likely honeypot"
    if verdict == "SUSPICIOUS":
        return "warning", f"⚠️ {score:.2f} — suspicious"
    return "success", f"✅ {score:.2f} — likely real"


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------


def _init_state() -> None:
    defaults: dict[str, Any] = {
        "scan_running": False,
        "scan_results": None,
        "scan_error": None,
        "scan_target": "",
        "scan_start": 0.0,
        "report": None,
        "honeypot_report": None,
        "passive_os_result": None,
        "dash_timeout": 1.0,
        "dash_threads": 500,
        "dash_include_closed": False,
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val


_init_state()

# ---------------------------------------------------------------------------
# Scan options
# ---------------------------------------------------------------------------


@dataclass
class ScanOptions:
    ports: str | list[int]
    scan_mode: str  # "TCP" | "UDP" | "Stealth" | "SYN (root)" | "Evasion (root)"
    timeout: float
    threads: int
    banners: bool
    os_detect: bool
    cve_lookup: bool
    include_closed: bool
    smart_order: bool
    adaptive: bool
    honeypot: bool
    passive_os: bool
    evasion_type: str = "syn"
    jitter: float = 0.0
    fragment: bool = False
    decoys: str = ""
    slack_webhook: str = ""
    discord_webhook: str = ""


# ---------------------------------------------------------------------------
# Async scan execution — mirrors cli.py logic
# ---------------------------------------------------------------------------


async def _run_scan_async(
    targets: list[str],
    port_list: list[int],
    opts: ScanOptions,
) -> list[ScanResult]:
    """Route to the right scan backend based on scan_mode."""
    if opts.scan_mode == "SYN (root)":
        from porthawk.syn_scan import syn_scan_host

        results: list[ScanResult] = []
        for host in targets:
            results.extend(
                await syn_scan_host(
                    host, port_list, timeout=opts.timeout, max_concurrent=min(opts.threads, 100)
                )
            )
        return results

    if opts.scan_mode == "Evasion (root)":
        from porthawk.evasion import evasion_scan_host, slow_low_config

        cfg = slow_low_config()
        cfg.scan_type = opts.evasion_type
        if opts.jitter > 0:
            cfg.max_delay = opts.jitter
            cfg.min_delay = 0.0
        cfg.fragment = opts.fragment
        if opts.decoys:
            cfg.decoys = [d.strip() for d in opts.decoys.split(",") if d.strip()]
        results = []
        for host in targets:
            results.extend(
                await evasion_scan_host(
                    host,
                    port_list,
                    config=cfg,
                    timeout=opts.timeout,
                    max_concurrent=min(opts.threads, 20),
                )
            )
        return results

    if opts.scan_mode == "UDP":
        from porthawk.udp_scan import get_udp_top_ports, udp_scan_host

        ports = port_list if port_list else get_udp_top_ports()
        results = []
        for host in targets:
            results.extend(
                await udp_scan_host(
                    host, ports, timeout=opts.timeout, max_concurrent=min(opts.threads, 50)
                )
            )
        return results

    # TCP or Stealth
    from porthawk.scanner import scan_targets
    from porthawk.throttle import AdaptiveConfig

    timeout = 3.0 if opts.scan_mode == "Stealth" else opts.timeout
    threads = 1 if opts.scan_mode == "Stealth" else opts.threads
    adaptive_cfg = AdaptiveConfig() if opts.adaptive else None

    all_dicts = await scan_targets(
        targets=targets,
        ports=port_list,
        timeout=timeout,
        max_concurrent=threads,
        udp=False,
        show_progress=False,
        adaptive_config=adaptive_cfg,
    )
    return [r for host_results in all_dicts.values() for r in host_results]


def _enrich_results(
    results: list[ScanResult],
    targets: list[str],
    opts: ScanOptions,
) -> list[ScanResult]:
    """Add service names, risk, OS guess, banners. Mirrors cli._enrich_results."""
    from porthawk.fingerprint import get_ttl_via_ping, guess_os_from_ttl
    from porthawk.service_db import get_service

    ttl_value = None
    if opts.os_detect:
        ttl_value = get_ttl_via_ping(targets[0], timeout=2.0)

    for r in results:
        svc = get_service(r.port, r.protocol)
        r.service_name = svc.service_name
        r.risk_level = svc.risk_level.value if svc.risk_level else None
        if opts.os_detect and ttl_value is not None:
            r.ttl = ttl_value
            r.os_guess = guess_os_from_ttl(ttl_value)

    if opts.banners:
        open_results = [r for r in results if r.state == PortState.OPEN]
        if open_results:
            from porthawk.fingerprint import fingerprint_port

            async def _grab() -> None:
                for r in open_results:
                    r.banner, r.service_version = await fingerprint_port(
                        r.host, r.port, timeout=opts.timeout
                    )

            asyncio.run(_grab())

    return results


async def _attach_cves(results: list[ScanResult]) -> None:
    """CVE lookup — deduplicates by (service, version)."""
    from porthawk.cve import lookup_cves

    open_results = [r for r in results if r.state == PortState.OPEN and r.service_name]
    seen: dict[str, list[dict[str, Any]]] = {}
    for r in open_results:
        key = f"{r.service_name}:{r.service_version or ''}"
        if key not in seen:
            cves = await lookup_cves(r.service_name or "", service_version=r.service_version)
            seen[key] = [c.model_dump() for c in cves]
        r.cves = seen[key]


# ---------------------------------------------------------------------------
# Webhook helpers
# ---------------------------------------------------------------------------


def _fire_webhooks(results: list[ScanResult], target: str, opts: ScanOptions) -> None:
    """Send Slack/Discord alerts for HIGH-risk ports. Silently ignores network errors."""
    import urllib.error

    from porthawk.notify import send_discord, send_slack

    if opts.slack_webhook:
        try:
            send_slack(opts.slack_webhook, results, target)
        except (urllib.error.HTTPError, urllib.error.URLError, OSError):
            pass  # don't crash the scan thread over a webhook hiccup

    if opts.discord_webhook:
        try:
            send_discord(opts.discord_webhook, results, target)
        except (urllib.error.HTTPError, urllib.error.URLError, OSError):
            pass


# ---------------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------------


def _scan_worker(target: str, opts: ScanOptions) -> None:
    """Runs in a daemon thread. Writes into session_state when done."""
    try:
        from porthawk.scanner import expand_cidr, parse_port_range
        from porthawk.service_db import get_top_ports

        targets = expand_cidr(target)

        # resolve port list from opts
        if isinstance(opts.ports, list):
            port_list = opts.ports
        elif opts.ports == "common":
            port_list = get_top_ports(100)
        elif opts.ports == "full":
            port_list = list(range(1, 65536))
        else:
            port_list = parse_port_range(str(opts.ports))

        # smart order — ML port frequency reordering
        if opts.smart_order:
            try:
                from porthawk.predictor import sort_ports

                port_list = sort_ports(port_list, targets[0], None)
            except ImportError:
                pass  # scikit-learn not installed, just continue

        results = asyncio.run(_run_scan_async(targets, port_list, opts))
        results = _enrich_results(results, targets, opts)

        if opts.cve_lookup:
            asyncio.run(_attach_cves(results))

        honeypot_report = None
        if opts.honeypot:
            from porthawk.honeypot import score_honeypot

            honeypot_report = score_honeypot(results)

        passive_os_result = None
        if opts.passive_os:
            from porthawk.passive_os import passive_os_scan, ttl_only_os

            passive_os_result = passive_os_scan(targets[0])
            if passive_os_result is None:
                # raw sockets unavailable — TTL fallback
                from porthawk.fingerprint import get_ttl_via_ping

                ttl = get_ttl_via_ping(targets[0], timeout=2.0)
                if ttl:
                    passive_os_result = ttl_only_os(ttl)

        protocol = "udp" if opts.scan_mode == "UDP" else "tcp"
        effective_timeout = 3.0 if opts.scan_mode == "Stealth" else opts.timeout
        effective_threads = 1 if opts.scan_mode == "Stealth" else opts.threads

        report = build_report(
            target,
            results,
            protocol=protocol,
            timeout=effective_timeout,
            max_concurrent=effective_threads,
        )

        # fire webhooks before writing session state so errors don't silence the alert
        _fire_webhooks(results, target, opts)

        st.session_state["scan_results"] = results
        st.session_state["honeypot_report"] = honeypot_report
        st.session_state["passive_os_result"] = passive_os_result
        st.session_state["report"] = report
        st.session_state["scan_error"] = None

    except Exception as exc:
        st.session_state["scan_results"] = []
        st.session_state["scan_error"] = str(exc)
        st.session_state["honeypot_report"] = None
        st.session_state["passive_os_result"] = None
    finally:
        st.session_state["scan_running"] = False


def _start_scan(target: str, opts: ScanOptions) -> None:
    st.session_state.update(
        {
            "scan_running": True,
            "scan_results": None,
            "scan_error": None,
            "scan_target": target,
            "scan_start": time.time(),
            "report": None,
            "honeypot_report": None,
            "passive_os_result": None,
        }
    )
    threading.Thread(target=_scan_worker, args=(target, opts), daemon=True).start()


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------


def render_sidebar() -> tuple[str, ScanOptions, bool]:
    with st.sidebar:
        st.markdown("# 🦅 PortHawk")
        st.caption(f"v{porthawk.__version__}")
        st.markdown("---")

        # quick-scan preset — one click fills in sensible fast defaults
        if st.button(
            "⚡ Quick Scan preset",
            use_container_width=True,
            help="Common ports, 0.5 s timeout, no enrichment — results in ~3 s",
        ):
            st.session_state["dash_timeout"] = 0.5
            st.session_state["dash_threads"] = 300
            st.rerun()

        st.markdown("---")

        # target
        st.subheader("Target")
        target = st.text_input(
            "IP / Hostname / CIDR",
            placeholder="192.168.1.1  ·  10.0.0.0/24  ·  2001:db8::1  ·  fe80::/64",
        )

        # ports
        st.subheader("Ports")
        port_mode = st.radio(
            "Range",
            ["Common (100)", "Top 1000", "Full (65535)", "Custom"],
            index=0,  # always default to common — fast for remote hosts
        )
        ports: str | list[int]
        if port_mode == "Common (100)":
            ports = "common"
        elif port_mode == "Top 1000":
            from porthawk.service_db import get_top_ports

            ports = get_top_ports(1000)
        elif port_mode == "Full (65535)":
            ports = "full"
        else:
            raw = st.text_input("Ports", placeholder="22,80,443  or  1-1024")
            ports = raw if raw else "common"

        # scan mode
        st.subheader("Scan mode")
        scan_mode = st.radio("Mode", list(SCAN_MODES.keys()))
        st.caption(SCAN_MODES.get(scan_mode, ""))

        # evasion sub-options — only visible in evasion mode
        evasion_type, jitter, fragment, decoys = "syn", 0.0, False, ""
        if scan_mode == "Evasion (root)":
            with st.expander("Evasion settings", expanded=True):
                evasion_type = st.selectbox("TCP flag type", EVASION_TYPES)
                jitter = st.slider(
                    "Jitter (s)",
                    0.0,
                    30.0,
                    2.0,
                    0.5,
                    help="Max random delay between probes",
                )
                fragment = st.checkbox(
                    "Fragment packets",
                    help="Split packets into 8-byte chunks — confuses some IDS",
                )
                decoys = st.text_input(
                    "Decoy IPs",
                    placeholder="1.2.3.4,5.6.7.8",
                    help="Comma-separated fake source IPs (Scapy only)",
                )

        # enrichment options — preset forces all off for speed
        st.subheader("Enrichment")
        c1, c2 = st.columns(2)
        with c1:
            banners = st.checkbox(
                "Banners", value=False, help="Grab service banners and extract versions"
            )
            os_detect = st.checkbox("OS (TTL)", value=False, help="Guess OS from TTL ping response")
            passive_os = st.checkbox(
                "Passive OS",
                value=False,
                help="TCP stack fingerprinting via SYN-ACK (needs root or Scapy)",
            )
        with c2:
            cve_lookup = st.checkbox(
                "CVE lookup", value=False, help="NVD API lookup per open service"
            )
            honeypot = st.checkbox(
                "Honeypot check",
                value=False,
                help="Score the target for honeypot likelihood after scan",
            )
            include_closed = st.checkbox(
                "Show closed",
                key="dash_include_closed",
                help="Include closed/filtered ports in results",
            )

        # advanced settings — preset forces safe fast defaults
        with st.expander("Advanced"):
            smart_order = st.checkbox(
                "Smart port order",
                value=False,
                help="ML-based port prioritization — scans likely-open ports first (needs scikit-learn)",
            )
            adaptive = st.checkbox(
                "Adaptive speed",
                value=False,
                help="AIMD concurrency control: starts conservative, ramps up on stable networks",
            )
            timeout = st.slider("Timeout per port (s)", 0.1, 10.0, 1.0, 0.1, key="dash_timeout")
            threads = st.slider("Concurrency", 10, 1000, 500, 10, key="dash_threads")

        with st.expander("Notifications"):
            slack_webhook = st.text_input(
                "Slack webhook URL",
                placeholder="https://hooks.slack.com/services/…",
                help="Paste a Slack incoming webhook URL. An alert fires if HIGH-risk ports are found.",
                type="password",
            )
            discord_webhook = st.text_input(
                "Discord webhook URL",
                placeholder="https://discord.com/api/webhooks/…",
                help="Paste a Discord webhook URL. An alert fires if HIGH-risk ports are found.",
                type="password",
            )

        st.markdown("---")
        start = st.button(
            "🚀 Start Scan",
            disabled=bool(st.session_state["scan_running"]) or not bool(target),
            use_container_width=True,
            type="primary",
        )

    return (
        target,
        ScanOptions(
            ports=ports,
            scan_mode=scan_mode,
            timeout=timeout,
            threads=threads,
            banners=banners,
            os_detect=os_detect,
            cve_lookup=cve_lookup,
            include_closed=include_closed,
            smart_order=smart_order,
            adaptive=adaptive,
            honeypot=honeypot,
            passive_os=passive_os,
            evasion_type=evasion_type,
            jitter=jitter,
            fragment=fragment,
            decoys=decoys,
            slack_webhook=slack_webhook,
            discord_webhook=discord_webhook,
        ),
        start,
    )


# ---------------------------------------------------------------------------
# Results tab
# ---------------------------------------------------------------------------


def render_results_tab(results: list[ScanResult]) -> None:
    open_ports = [r for r in results if r.state == PortState.OPEN]
    closed_ports = [r for r in results if r.state != PortState.OPEN]

    # passive OS result — shown as banner above metrics
    passive = st.session_state.get("passive_os_result")
    if passive:
        conf_fn = {"HIGH": st.success, "MEDIUM": st.warning, "LOW": st.error}.get(
            passive.confidence, st.info
        )
        conf_fn(
            f"🖥️ **OS:** {passive.os_family} — {passive.os_detail} "
            f"(confidence: {passive.confidence}, method: {passive.method})"
        )

    # honeypot result — shown as banner
    hp = st.session_state.get("honeypot_report")
    if hp:
        level, label = honeypot_badge(hp.score, hp.verdict)
        getattr(st, level)(f"Honeypot check: {label}")
        if hp.indicators and hp.verdict != "LIKELY_REAL":
            with st.expander("Honeypot indicators"):
                for ind in hp.indicators:
                    st.text(f"  [{ind.weight:.2f}] {ind.name}: {ind.description}")

    # metrics row
    c1, c2, c3 = st.columns(3)
    c1.metric("Open ports", len(open_ports))
    c2.metric("Closed / filtered", len(closed_ports))
    c3.metric("High risk", sum(1 for r in open_ports if r.risk_level == "HIGH"))

    if not open_ports:
        st.info("No open ports found.")
        return

    # main results table
    include_closed = st.session_state.get("dash_include_closed", False)
    rows = results_to_rows(results, include_closed=include_closed)
    try:
        import pandas as pd

        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True, height=420)
    except ImportError:
        st.table(rows)

    # CVE details — expandable per port, only shown if lookup was run
    ports_with_cves = [r for r in open_ports if r.cves]
    if ports_with_cves:
        st.subheader("CVE details")
        for r in sorted(ports_with_cves, key=lambda x: x.port):
            label = f"{r.port}/{r.protocol} — {r.service_name or '?'}"
            if r.service_version:
                label += f" {r.service_version}"
            with st.expander(f"{label} ({len(r.cves)} CVE)"):
                for cve in r.cves[:10]:
                    cve_id = cve.get("cve_id", "?")
                    score = cve.get("cvss_score") or "?"
                    desc = (cve.get("description") or "")[:200]
                    st.markdown(f"**{cve_id}** — CVSS {score}")
                    if desc:
                        st.caption(desc)


# ---------------------------------------------------------------------------
# Charts tab
# ---------------------------------------------------------------------------


def render_charts_tab(results: list[ScanResult]) -> None:
    open_ports = [r for r in results if r.state == PortState.OPEN]
    if not open_ports:
        st.info("No open ports to visualize.")
        return

    try:
        import altair as alt
        import pandas as pd
    except ImportError:
        st.warning("Install chart dependencies: `pip install porthawk[dashboard]`")
        return

    c1, c2 = st.columns(2)

    with c1:
        st.subheader("Risk distribution")
        dist = risk_distribution(results)
        df_risk = pd.DataFrame([{"Risk": k, "Count": v} for k, v in dist.items()])
        color_map = {
            "HIGH": "#ef4444",
            "MEDIUM": "#f59e0b",
            "LOW": "#22c55e",
            "unknown": "#6b7280",
        }
        st.altair_chart(
            alt.Chart(df_risk)
            .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4)
            .encode(
                x=alt.X(
                    "Risk:N",
                    sort=["HIGH", "MEDIUM", "LOW", "unknown"],
                    axis=alt.Axis(labelAngle=0),
                ),
                y="Count:Q",
                color=alt.Color(
                    "Risk:N",
                    scale=alt.Scale(domain=list(color_map.keys()), range=list(color_map.values())),
                    legend=None,
                ),
                tooltip=["Risk:N", "Count:Q"],
            )
            .properties(height=280),
            use_container_width=True,
        )

    with c2:
        st.subheader("Top services")
        svc = service_distribution(results, top_n=10)
        df_svc = pd.DataFrame([{"Service": k, "Count": v} for k, v in svc.items()])
        st.altair_chart(
            alt.Chart(df_svc)
            .mark_bar(color="#3b82f6", cornerRadiusTopRight=4, cornerRadiusBottomRight=4)
            .encode(
                x="Count:Q",
                y=alt.Y("Service:N", sort="-x"),
                tooltip=["Service:N", "Count:Q"],
            )
            .properties(height=280),
            use_container_width=True,
        )

    # latency chart — only if we have enough data points
    with_latency = [r for r in open_ports if r.latency_ms]
    if len(with_latency) >= 3:
        st.subheader("Port response latency")
        df_lat = pd.DataFrame(
            [
                {"Port": f"{r.port}/{r.protocol}", "Latency (ms)": round(r.latency_ms or 0.0, 1)}
                for r in sorted(with_latency, key=lambda x: x.port)
            ]
        )
        st.altair_chart(
            alt.Chart(df_lat)
            .mark_bar(color="#8b5cf6", cornerRadiusTopLeft=4, cornerRadiusTopRight=4)
            .encode(
                x=alt.X("Port:N", sort=None),
                y="Latency (ms):Q",
                tooltip=["Port:N", "Latency (ms):Q"],
            )
            .properties(height=220),
            use_container_width=True,
        )

    # heatmap — host × risk, only useful when scanning CIDR ranges
    hosts = sorted({r.host for r in open_ports})
    if len(hosts) > 1:
        st.subheader("Open ports by host × risk")
        df_heat = pd.DataFrame(
            [{"Host": r.host, "Risk": r.risk_level or "unknown"} for r in open_ports]
        )
        agg = df_heat.groupby(["Host", "Risk"]).size().reset_index(name="Count")
        st.altair_chart(
            alt.Chart(agg)
            .mark_rect()
            .encode(
                x=alt.X("Risk:N", sort=["HIGH", "MEDIUM", "LOW", "unknown"]),
                y="Host:N",
                color=alt.Color("Count:Q", scale=alt.Scale(scheme="reds")),
                tooltip=["Host:N", "Risk:N", "Count:Q"],
            )
            .properties(height=max(200, len(hosts) * 28)),
            use_container_width=True,
        )


# ---------------------------------------------------------------------------
# Network graph tab (PyVis — optional)
# ---------------------------------------------------------------------------


def render_network_tab(results: list[ScanResult]) -> None:
    open_ports = [r for r in results if r.state == PortState.OPEN]
    if not open_ports:
        st.info("No open ports to graph.")
        return

    try:
        from pyvis.network import Network
    except ImportError:
        st.info(
            "Network graph needs PyVis: `pip install pyvis`  \n"
            "The other tabs still work without it."
        )
        return

    net = Network(
        height="480px", width="100%", bgcolor="#0f172a", font_color="#e2e8f0", directed=False
    )
    net.set_options("""{
        "physics": {"stabilization": {"iterations": 80},
                    "barnesHut": {"gravitationalConstant": -4000}},
        "nodes": {"borderWidth": 0, "shadow": true},
        "edges": {"smooth": false}
    }""")

    net.add_node("scanner", label="You", color="#3b82f6", size=28, shape="star", title="Scanner")

    for host in sorted({r.host for r in open_ports}):
        net.add_node(host, label=host, color="#64748b", size=22, shape="dot", title=host)
        net.add_edge("scanner", host, color="#334155", width=2)

    for r in open_ports:
        color = RISK_COLORS.get(r.risk_level or "", "#6b7280")
        node_id = f"{r.host}:{r.port}/{r.protocol}"
        svc = r.service_name or ""
        title = (
            f"Port {r.port}/{r.protocol}\n"
            f"Service: {r.service_name or '?'}\n"
            f"Risk: {r.risk_level or '?'}"
        )
        if r.service_version:
            title += f"\nVersion: {r.service_version}"
        if r.cves:
            title += f"\nCVEs: {len(r.cves)}"
        net.add_node(
            node_id, label=f"{r.port}\n{svc}", color=color, size=14, shape="dot", title=title
        )
        net.add_edge(r.host, node_id, color=color, width=1)

    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w", encoding="utf-8") as f:
        net.save_graph(f.name)
        html = Path(f.name).read_text(encoding="utf-8")
    Path(f.name).unlink(missing_ok=True)

    st.components.v1.html(html, height=500, scrolling=False)
    st.caption("🔴 High  🟡 Medium  🟢 Low  ⚫ Unknown — hover a node for details")


# ---------------------------------------------------------------------------
# Diff tab
# ---------------------------------------------------------------------------


def render_diff_tab() -> None:
    st.subheader("Compare two scans")
    st.caption("Accepts PortHawk .json or Nmap .xml output.")

    c1, c2 = st.columns(2)
    with c1:
        file_a = st.file_uploader("Baseline (A)", type=["json", "xml"], key="diff_a")
        label_a = st.text_input("Label A", value="baseline", key="label_a")
    with c2:
        file_b = st.file_uploader("Current (B)", type=["json", "xml"], key="diff_b")
        label_b = st.text_input("Label B", value="current", key="label_b")

    if not (file_a and file_b):
        return

    show_stable = st.checkbox("Show unchanged ports")
    if not st.button("🔍 Compare", type="primary"):
        return

    try:
        import pandas as pd

        with tempfile.NamedTemporaryFile(
            suffix=Path(file_a.name).suffix or ".json", delete=False
        ) as fa:
            fa.write(file_a.getvalue())
            path_a = fa.name
        with tempfile.NamedTemporaryFile(
            suffix=Path(file_b.name).suffix or ".json", delete=False
        ) as fb:
            fb.write(file_b.getvalue())
            path_b = fb.name

        ra = porthawk.load_results(path_a)
        rb = porthawk.load_results(path_b)
        diff = porthawk.compute_diff(
            ra, rb, label_a=label_a, label_b=label_b, include_stable=show_stable
        )
        Path(path_a).unlink(missing_ok=True)
        Path(path_b).unlink(missing_ok=True)

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("🆕 New", len(diff.new_ports))
        m2.metric("❌ Gone", len(diff.gone_ports))
        m3.metric("🔄 Changed", len(diff.changed_ports))
        m4.metric("✅ Stable", len(diff.stable_ports))

        if diff.has_regressions:
            st.error("⚠️ Regressions — new HIGH or MEDIUM risk ports appeared.")
        elif diff.new_ports or diff.gone_ports or diff.changed_ports:
            st.warning("Changes detected, no high-risk regressions.")
        else:
            st.success("No differences between scans.")

        if diff.new_ports:
            st.subheader("New open ports")
            new_rows = [
                {
                    "Host": c.host,
                    "Port": c.port,
                    "Protocol": c.protocol,
                    "Service": c.after.service_name if c.after else "—",
                    "Risk": (
                        f"{RISK_EMOJI.get(c.after.risk_level or '', '⚪')} {c.after.risk_level or '—'}"
                        if c.after
                        else "—"
                    ),
                    "Version": c.after.service_version if c.after else "—",
                }
                for c in diff.new_ports
            ]
            st.dataframe(pd.DataFrame(new_rows), use_container_width=True, hide_index=True)

        if diff.gone_ports:
            st.subheader("Gone ports")
            gone_rows = [
                {
                    "Host": c.host,
                    "Port": c.port,
                    "Protocol": c.protocol,
                    "Service": c.before.service_name if c.before else "—",
                    "Was risk": (
                        f"{RISK_EMOJI.get(c.before.risk_level or '', '⚪')} {c.before.risk_level or '—'}"
                        if c.before
                        else "—"
                    ),
                }
                for c in diff.gone_ports
            ]
            st.dataframe(pd.DataFrame(gone_rows), use_container_width=True, hide_index=True)

        if diff.changed_ports:
            st.subheader("Changed ports")
            for c in diff.changed_ports:
                st.text(c.describe())

        if diff.stable_ports and show_stable:
            st.subheader("Unchanged ports")
            stable_rows = [
                {
                    "Host": c.host,
                    "Port": c.port,
                    "Proto": c.protocol,
                    "Service": c.after.service_name if c.after else "—",
                }
                for c in diff.stable_ports
            ]
            st.dataframe(pd.DataFrame(stable_rows), use_container_width=True, hide_index=True)

        from porthawk.diff import save_diff_json

        diff_path = save_diff_json(diff)
        st.download_button(
            "📄 Download diff JSON",
            data=diff_path.read_bytes(),
            file_name=diff_path.name,
            mime="application/json",
        )

    except Exception as exc:
        st.error(f"Error comparing scans: {exc}")


# ---------------------------------------------------------------------------
# Export tab
# ---------------------------------------------------------------------------


def render_export_tab() -> None:
    if not st.session_state.get("report"):
        st.info("Run a scan first, then download reports here.")
        return

    report = st.session_state["report"]
    st.subheader("Download scan reports")

    c1, c2, c3, c4 = st.columns(4)
    json_path = None
    for col, (label, mime, save_fn) in zip(
        [c1, c2, c3, c4],
        [
            ("📄 JSON", "application/json", save_json),
            ("📊 CSV", "text/csv", save_csv),
            ("🌐 HTML", "text/html", save_html),
            ("🛡️ SARIF", "application/json", save_sarif),
        ],
        strict=False,
    ):
        p = save_fn(report)
        if json_path is None:
            json_path = p
        col.download_button(
            label, data=p.read_bytes(), file_name=p.name, mime=mime, use_container_width=True
        )

    if json_path:
        st.caption(f"Files also saved to: `{json_path.parent}`")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    target, opts, start_clicked = render_sidebar()

    if start_clicked and target and not st.session_state["scan_running"]:
        _start_scan(target, opts)
        st.rerun()

    # poll every second while scan is running
    if st.session_state["scan_running"]:
        elapsed = int(time.time() - st.session_state["scan_start"])
        st.info(f"⏳ Scanning **{st.session_state['scan_target']}** — {elapsed}s elapsed…")
        time.sleep(1.0)
        st.rerun()

    if st.session_state["scan_error"]:
        st.error(f"Scan failed: {st.session_state['scan_error']}")

    tab_results, tab_charts, tab_graph, tab_diff, tab_export = st.tabs(
        ["📊 Results", "📈 Charts", "🕸️ Graph", "🔍 Diff", "📁 Export"]
    )

    results: list[ScanResult] = st.session_state.get("scan_results") or []

    with tab_results:
        if results:
            st.success(f"Scan complete — **{st.session_state['scan_target']}**")
            render_results_tab(results)
        else:
            st.markdown("""
                ### Welcome to PortHawk

                Enter a target in the sidebar and click **Start Scan**.

                **Target formats:**
                - IPv4 — `192.168.1.1`
                - IPv6 — `2001:db8::1` or `[::1]`
                - Hostname — `scanme.nmap.org`
                - CIDR range — `10.0.0.0/24` or `2001:db8::/64`

                **Scan modes:** TCP, UDP, Stealth, SYN (root), Evasion (root)

                **Enrichment:** banners, CVE lookup, OS fingerprinting (TTL + passive),
                honeypot detection, smart port ordering (ML)
                """)

    with tab_charts:
        if results:
            render_charts_tab(results)
        else:
            st.info("Charts appear here after a scan.")

    with tab_graph:
        if results:
            render_network_tab(results)
        else:
            st.info("Network graph appears here after a scan.")

    with tab_diff:
        render_diff_tab()

    with tab_export:
        render_export_tab()


main()


# ---------------------------------------------------------------------------
# CLI entry point — `porthawk-dashboard` command
# ---------------------------------------------------------------------------


def launch() -> None:
    import subprocess
    import sys

    try:
        subprocess.run(
            [
                sys.executable,
                "-m",
                "streamlit",
                "run",
                str(Path(__file__)),
                "--server.headless",
                "false",
                "--browser.gatherUsageStats",
                "false",
                "--theme.base",
                "dark",
            ],
            check=True,
        )
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    except FileNotFoundError:
        print("Streamlit not found. Install: pip install porthawk[dashboard]")
        sys.exit(1)
