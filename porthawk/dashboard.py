"""Streamlit web dashboard for PortHawk.

Runs as a background server, opens in the browser automatically.
Start with: streamlit run porthawk/dashboard.py
Or via the launcher: python start_dashboard.py
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

# page config must be the very first Streamlit call
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
from porthawk.reporter import build_report, save_csv, save_html, save_json  # noqa: E402
from porthawk.scanner import PortState, ScanResult  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers — pure functions, testable without Streamlit
# ---------------------------------------------------------------------------

RISK_COLORS = {"HIGH": "#ef4444", "MEDIUM": "#f59e0b", "LOW": "#22c55e"}
RISK_EMOJI = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}


def results_to_rows(results: list[ScanResult]) -> list[dict[str, Any]]:
    """Convert open ScanResults to dicts suitable for st.dataframe."""
    rows = []
    for r in results:
        if r.state != PortState.OPEN:
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
                "CVEs": len(r.cves),
                "Latency": f"{r.latency_ms:.1f} ms" if r.latency_ms else "—",
            }
        )
    return rows


def risk_distribution(results: list[ScanResult]) -> dict[str, int]:
    """Count open ports by risk level."""
    counts: dict[str, int] = {}
    for r in results:
        if r.state == PortState.OPEN:
            key = r.risk_level or "unknown"
            counts[key] = counts.get(key, 0) + 1
    return counts


def service_distribution(results: list[ScanResult], top_n: int = 10) -> dict[str, int]:
    """Count open ports by service name, top N."""
    counts: dict[str, int] = {}
    for r in results:
        if r.state == PortState.OPEN:
            key = r.service_name or "unknown"
            counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1])[:top_n])


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
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val


_init_state()


# ---------------------------------------------------------------------------
# Background worker — asyncio.run() inside a daemon thread
# ---------------------------------------------------------------------------


@dataclass
class ScanOptions:
    ports: str | list[int]
    timeout: float
    threads: int
    udp: bool
    banners: bool
    os_detect: bool
    cve_lookup: bool
    include_closed: bool


def _scan_worker(target: str, opts: ScanOptions) -> None:
    """Runs in a daemon thread. Writes directly into session_state when done."""
    try:
        results = asyncio.run(
            porthawk.scan(
                target,
                ports=opts.ports,
                timeout=opts.timeout,
                concurrency=opts.threads,
                udp=opts.udp,
                banners=opts.banners,
                os_detect=opts.os_detect,
                cve_lookup=opts.cve_lookup,
                include_closed=opts.include_closed,
            )
        )
        st.session_state["scan_results"] = results
        st.session_state["scan_error"] = None
        st.session_state["report"] = build_report(
            target,
            results,
            protocol="udp" if opts.udp else "tcp",
            timeout=opts.timeout,
            max_concurrent=opts.threads,
        )
    except Exception as exc:
        st.session_state["scan_results"] = []
        st.session_state["scan_error"] = str(exc)
    finally:
        st.session_state["scan_running"] = False


def _start_scan(target: str, opts: ScanOptions) -> None:
    st.session_state["scan_running"] = True
    st.session_state["scan_results"] = None
    st.session_state["scan_error"] = None
    st.session_state["scan_target"] = target
    st.session_state["scan_start"] = time.time()
    st.session_state["report"] = None

    t = threading.Thread(target=_scan_worker, args=(target, opts), daemon=True)
    t.start()


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------


def render_sidebar() -> tuple[str, ScanOptions, bool]:
    """Renders sidebar settings. Returns (target, options, start_clicked)."""
    with st.sidebar:
        st.markdown("# 🦅 PortHawk")
        st.caption(f"v{porthawk.__version__}")
        st.markdown("---")

        st.subheader("Target")
        target = st.text_input(
            "IP / Hostname / CIDR",
            placeholder="192.168.1.1 or 10.0.0.0/24",
        )

        st.subheader("Ports")
        mode = st.radio(
            "Mode",
            ["Common (100)", "Top 1000", "Full (65535)", "Custom"],
            horizontal=False,
        )

        ports: str | list[int] = "common"
        if mode == "Common (100)":
            ports = "common"
        elif mode == "Top 1000":
            from porthawk.service_db import get_top_ports

            ports = get_top_ports(1000)
        elif mode == "Full (65535)":
            ports = "full"
        elif mode == "Custom":
            custom = st.text_input("Range or list", placeholder="22,80,443 or 1-1024")
            ports = custom if custom else "common"

        st.subheader("Options")
        col1, col2 = st.columns(2)
        with col1:
            banners = st.checkbox("Banners", help="Grab service banners from open ports")
            os_detect = st.checkbox("OS detect", help="TTL-based OS fingerprinting")
            cve_lookup = st.checkbox("CVE lookup", help="NVD API lookup per service")
        with col2:
            udp = st.checkbox("UDP scan", help="UDP instead of TCP (needs root on Linux)")
            include_closed = st.checkbox("Show closed", help="Include closed/filtered in results")

        with st.expander("Advanced"):
            timeout = st.slider("Timeout per port (s)", 0.1, 10.0, 1.0, 0.1)
            threads = st.slider("Concurrency", 10, 1000, 500, 10)

        st.markdown("---")
        start = st.button(
            "🚀 Start Scan",
            disabled=bool(st.session_state["scan_running"]) or not bool(target),
            use_container_width=True,
            type="primary",
        )

    opts = ScanOptions(
        ports=ports,
        timeout=timeout,
        threads=threads,
        udp=udp,
        banners=banners,
        os_detect=os_detect,
        cve_lookup=cve_lookup,
        include_closed=include_closed,
    )
    return target, opts, start


# ---------------------------------------------------------------------------
# Results tab
# ---------------------------------------------------------------------------


def render_results_tab(results: list[ScanResult]) -> None:
    open_ports = [r for r in results if r.state == PortState.OPEN]
    closed_ports = [r for r in results if r.state != PortState.OPEN]

    col1, col2, col3 = st.columns(3)
    col1.metric("Open ports", len(open_ports))
    col2.metric("Closed / filtered", len(closed_ports))
    high_count = sum(1 for r in open_ports if r.risk_level == "HIGH")
    col3.metric("High risk", high_count, delta=None)

    if not open_ports:
        st.info("No open ports found.")
        return

    rows = results_to_rows(results)
    try:
        import pandas as pd

        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True, hide_index=True, height=400)
    except ImportError:
        # fallback without pandas — plain table
        st.table(rows)


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
        st.warning("Charts need altair + pandas: `pip install porthawk[dashboard]`")
        return

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Risk distribution")
        dist = risk_distribution(results)
        df_risk = pd.DataFrame([{"Risk": k, "Count": v} for k, v in dist.items()])
        color_map = {"HIGH": "#ef4444", "MEDIUM": "#f59e0b", "LOW": "#22c55e", "unknown": "#6b7280"}
        chart = (
            alt.Chart(df_risk)
            .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4)
            .encode(
                x=alt.X(
                    "Risk:N", sort=["HIGH", "MEDIUM", "LOW", "unknown"], axis=alt.Axis(labelAngle=0)
                ),
                y=alt.Y("Count:Q"),
                color=alt.Color(
                    "Risk:N",
                    scale=alt.Scale(domain=list(color_map.keys()), range=list(color_map.values())),
                    legend=None,
                ),
                tooltip=["Risk:N", "Count:Q"],
            )
            .properties(height=280)
        )
        st.altair_chart(chart, use_container_width=True)

    with col2:
        st.subheader("Top services")
        svc = service_distribution(results, top_n=10)
        df_svc = pd.DataFrame([{"Service": k, "Count": v} for k, v in svc.items()])
        chart = (
            alt.Chart(df_svc)
            .mark_bar(color="#3b82f6", cornerRadiusTopRight=4, cornerRadiusBottomRight=4)
            .encode(
                x=alt.X("Count:Q"),
                y=alt.Y("Service:N", sort="-x"),
                tooltip=["Service:N", "Count:Q"],
            )
            .properties(height=280)
        )
        st.altair_chart(chart, use_container_width=True)

    # heatmap — only useful when scanning multiple hosts
    hosts = sorted({r.host for r in open_ports})
    if len(hosts) > 1:
        st.subheader("Open ports per host × risk level")
        heatmap_rows = [
            {"Host": r.host, "Risk": r.risk_level or "unknown", "Port": r.port} for r in open_ports
        ]
        df_heat = pd.DataFrame(heatmap_rows)
        agg = df_heat.groupby(["Host", "Risk"]).size().reset_index(name="Count")
        heatmap = (
            alt.Chart(agg)
            .mark_rect()
            .encode(
                x=alt.X("Risk:N", sort=["HIGH", "MEDIUM", "LOW", "unknown"]),
                y=alt.Y("Host:N"),
                color=alt.Color("Count:Q", scale=alt.Scale(scheme="reds")),
                tooltip=["Host:N", "Risk:N", "Count:Q"],
            )
            .properties(height=max(200, len(hosts) * 28))
        )
        st.altair_chart(heatmap, use_container_width=True)


# ---------------------------------------------------------------------------
# Network graph tab — PyVis (optional)
# ---------------------------------------------------------------------------


def render_network_tab(results: list[ScanResult]) -> None:
    open_ports = [r for r in results if r.state == PortState.OPEN]
    if not open_ports:
        st.info("No open ports to graph.")
        return

    try:
        from pyvis.network import Network
    except ImportError:
        st.info("Network graph needs PyVis: `pip install pyvis`")
        return

    net = Network(
        height="480px",
        width="100%",
        bgcolor="#0f172a",
        font_color="#e2e8f0",
        directed=False,
    )
    net.set_options("""{
        "physics": {"stabilization": {"iterations": 80}, "barnesHut": {"gravitationalConstant": -4000}},
        "nodes": {"borderWidth": 0, "shadow": true},
        "edges": {"smooth": false, "shadow": false}
    }""")

    # scanner node at center
    net.add_node("scanner", label="You", color="#3b82f6", size=28, shape="star", title="Scanner")

    hosts = sorted({r.host for r in open_ports})
    for host in hosts:
        net.add_node(host, label=host, color="#64748b", size=22, shape="dot", title=host)
        net.add_edge("scanner", host, color="#334155", width=2)

    for r in open_ports:
        color = RISK_COLORS.get(r.risk_level or "", "#6b7280")
        node_id = f"{r.host}:{r.port}/{r.protocol}"
        label = f"{r.port}\n{r.service_name or ''}"
        title = f"Port {r.port}/{r.protocol}\nService: {r.service_name or '?'}\nRisk: {r.risk_level or '?'}"
        if r.service_version:
            title += f"\nVersion: {r.service_version}"
        net.add_node(node_id, label=label, color=color, size=14, shape="dot", title=title)
        net.add_edge(r.host, node_id, color=color, width=1)

    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w", encoding="utf-8") as f:
        net.save_graph(f.name)
        html = Path(f.name).read_text(encoding="utf-8")
    Path(f.name).unlink(missing_ok=True)

    st.components.v1.html(html, height=500, scrolling=False)
    st.caption("🔴 High  🟡 Medium  🟢 Low  ⚫ Unknown")


# ---------------------------------------------------------------------------
# Diff tab
# ---------------------------------------------------------------------------


def render_diff_tab() -> None:
    st.subheader("Compare two scans")
    st.caption("Load any PortHawk .json or Nmap .xml file from either scan.")

    col1, col2 = st.columns(2)
    with col1:
        file_a = st.file_uploader("Baseline (A)", type=["json", "xml"], key="diff_a")
        label_a = st.text_input("Label A", value="baseline", key="label_a")
    with col2:
        file_b = st.file_uploader("Current (B)", type=["json", "xml"], key="diff_b")
        label_b = st.text_input("Label B", value="current", key="label_b")

    if not (file_a and file_b):
        return
    if not st.button("🔍 Compare", type="primary"):
        return

    suffix_a = Path(file_a.name).suffix or ".json"
    suffix_b = Path(file_b.name).suffix or ".json"

    try:
        import pandas as pd

        with tempfile.NamedTemporaryFile(suffix=suffix_a, delete=False) as fa:
            fa.write(file_a.getvalue())
            path_a = fa.name
        with tempfile.NamedTemporaryFile(suffix=suffix_b, delete=False) as fb:
            fb.write(file_b.getvalue())
            path_b = fb.name

        results_a = porthawk.load_results(path_a)
        results_b = porthawk.load_results(path_b)
        diff = porthawk.compute_diff(results_a, results_b, label_a=label_a, label_b=label_b)

        Path(path_a).unlink(missing_ok=True)
        Path(path_b).unlink(missing_ok=True)

        m1, m2, m3 = st.columns(3)
        m1.metric("🆕 New ports", len(diff.new_ports))
        m2.metric("❌ Gone ports", len(diff.gone_ports))
        m3.metric("🔄 Changed", len(diff.changed_ports))

        if diff.has_regressions:
            st.error("⚠️ Regressions — new HIGH or MEDIUM risk ports detected.")
        elif diff.new_ports or diff.gone_ports or diff.changed_ports:
            st.warning("Changes detected, no high-risk regressions.")
        else:
            st.success("No changes between scans.")

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
            st.subheader("Gone ports (were open, now missing)")
            gone_rows = [
                {
                    "Host": c.host,
                    "Port": c.port,
                    "Protocol": c.protocol,
                    "Service": c.before.service_name if c.before else "—",
                }
                for c in diff.gone_ports
            ]
            st.dataframe(pd.DataFrame(gone_rows), use_container_width=True, hide_index=True)

        if diff.changed_ports:
            st.subheader("Changed ports")
            for c in diff.changed_ports:
                st.text(c.describe())

    except Exception as exc:
        st.error(f"Error comparing scans: {exc}")


# ---------------------------------------------------------------------------
# Export tab
# ---------------------------------------------------------------------------


def render_export_tab() -> None:
    if not st.session_state.get("report"):
        st.info("Run a scan first, then download the reports here.")
        return

    report = st.session_state["report"]
    st.subheader("Download scan reports")

    col1, col2, col3 = st.columns(3)

    with col1:
        json_path = save_json(report)
        st.download_button(
            "📄 JSON",
            data=json_path.read_bytes(),
            file_name=json_path.name,
            mime="application/json",
            use_container_width=True,
        )

    with col2:
        csv_path = save_csv(report)
        st.download_button(
            "📊 CSV",
            data=csv_path.read_bytes(),
            file_name=csv_path.name,
            mime="text/csv",
            use_container_width=True,
        )

    with col3:
        html_path = save_html(report)
        st.download_button(
            "🌐 HTML",
            data=html_path.read_bytes(),
            file_name=html_path.name,
            mime="text/html",
            use_container_width=True,
        )

    st.caption(f"Reports saved to: `{json_path.parent}`")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    target, opts, start_clicked = render_sidebar()

    # kick off scan
    if start_clicked and target and not st.session_state["scan_running"]:
        _start_scan(target, opts)
        st.rerun()

    # poll while scan runs — rerun every second so elapsed time updates
    if st.session_state["scan_running"]:
        elapsed = int(time.time() - st.session_state["scan_start"])
        st.info(f"⏳ Scanning **{st.session_state['scan_target']}** — {elapsed}s elapsed…")
        time.sleep(1.0)
        st.rerun()

    # show error banner if scan failed
    if st.session_state["scan_error"]:
        st.error(f"Scan failed: {st.session_state['scan_error']}")

    # tabs
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

                Enter a target in the sidebar and hit **Start Scan**.

                Works with:
                - Single IP — `192.168.1.1`
                - Hostname — `scanme.nmap.org`
                - CIDR range — `10.0.0.0/24`

                No CLI needed. Results appear here when the scan finishes.
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


# Streamlit runs the whole module, not just __main__
main()


# ---------------------------------------------------------------------------
# Entry point for `porthawk-dashboard` command
# ---------------------------------------------------------------------------


def launch() -> None:
    """Launch the dashboard via subprocess. Registered as CLI entry point."""
    import subprocess
    import sys

    dashboard = Path(__file__)
    try:
        subprocess.run(
            [
                sys.executable,
                "-m",
                "streamlit",
                "run",
                str(dashboard),
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
        print("Streamlit not found. Install with: pip install porthawk[dashboard]")
        sys.exit(1)
