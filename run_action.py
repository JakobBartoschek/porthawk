#!/usr/bin/env python3
"""PortHawk GitHub Action entrypoint.

Reads scan parameters from env vars (set by action.yml inputs),
runs the scan via the porthawk CLI, parses results, writes GitHub
Action outputs, and exits with the right code.

Not meant to be called directly — action.yml maps inputs to PH_* env vars
and calls this script.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _set_output(name: str, value: str) -> None:
    """Write a key=value pair to GITHUB_OUTPUT.

    Modern GitHub Actions use a file instead of the old ::set-output:: syntax.
    Fall back to a plain print for local testing where the file isn't set.
    """
    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as f:
            f.write(f"{name}={value}\n")
    else:
        print(f"[output] {name}={value}")


def _find_latest(pattern: str) -> Path | None:
    """Return the most recently modified file matching the glob in reports/."""
    reports_dir = Path("reports")
    if not reports_dir.exists():
        return None
    matches = sorted(
        reports_dir.glob(pattern),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return matches[0] if matches else None


def main() -> int:
    target = os.environ.get("PH_TARGET", "").strip()
    if not target:
        print("::error::PH_TARGET is required")
        return 1

    ports = os.environ.get("PH_PORTS", "common").strip()
    mode = os.environ.get("PH_MODE", "tcp").strip().lower()
    timeout = os.environ.get("PH_TIMEOUT", "1.0").strip()
    threads = os.environ.get("PH_THREADS", "100").strip()
    extra_formats = os.environ.get("PH_FORMATS", "").strip()
    fail_ports_raw = os.environ.get("PH_FAIL_PORTS", "").strip()

    # always produce json + sarif — those drive artifact upload and Security tab
    fmt_set: set[str] = {"json", "sarif"}
    for fmt in extra_formats.split(","):
        fmt = fmt.strip().lower()
        if fmt in ("html", "csv"):
            fmt_set.add(fmt)

    # build CLI command — avoiding shell interpolation to keep things clean
    cmd = [
        "porthawk",
        "--target", target,
        "--no-live",
        "--output", ",".join(sorted(fmt_set)),
    ]

    # port selection
    if ports == "common":
        cmd.append("--common")
    elif ports == "full":
        cmd.append("--full")
    else:
        cmd.extend(["--ports", ports])

    # scan mode
    if mode == "udp":
        cmd.append("--udp")
    elif mode == "syn":
        cmd.append("--syn")
    elif mode == "stealth":
        cmd.append("--stealth")

    cmd.extend(["--timeout", timeout, "--threads", threads])

    print(f"[porthawk-action] running: {' '.join(cmd)}", flush=True)

    proc = subprocess.run(cmd)
    # porthawk exits 0 on success — anything else is a real error
    if proc.returncode != 0:
        print(f"::error::porthawk exited with code {proc.returncode}")
        return proc.returncode

    # --- parse outputs from the JSON report ---
    json_report = _find_latest("scan_*.json")
    if json_report is None:
        print("::warning::no JSON report found in reports/")
        return 0

    with open(json_report, encoding="utf-8") as f:
        report = json.load(f)

    open_results = [r for r in report.get("results", []) if r.get("state") == "open"]
    open_ports = [str(r["port"]) for r in open_results]

    _set_output("open-ports", ",".join(open_ports))
    _set_output("open-count", str(len(open_ports)))
    _set_output("report-path", str(json_report))

    sarif_report = _find_latest("scan_*.sarif")
    if sarif_report:
        _set_output("sarif-path", str(sarif_report))

    # print a summary line so the workflow log is useful
    total = report.get("metadata", {}).get("total_ports", "?")
    print(
        f"[porthawk-action] done — {len(open_ports)} open / {total} scanned",
        flush=True,
    )
    if open_ports:
        print(f"[porthawk-action] open: {', '.join(open_ports)}", flush=True)

    # --- fail-on-ports check ---
    if fail_ports_raw:
        blocked = {p.strip() for p in fail_ports_raw.split(",") if p.strip()}
        found_blocked = sorted(
            [p for p in open_ports if p in blocked], key=lambda x: int(x)
        )
        if found_blocked:
            print(
                f"::error::fail-on-ports triggered — these ports are open: "
                f"{', '.join(found_blocked)}"
            )
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
