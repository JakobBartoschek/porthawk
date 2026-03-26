"""Compare two port scan results and report what changed.

Works with any two lists of ScanResult — from PortHawk JSON, Nmap XML,
or a live scan. The key is (host, port, protocol).

Change types:
  new     — port OPEN in B but not in A (potential new exposure)
  gone    — port OPEN in A but not in B (service disappeared or firewall added)
  changed — same port, state or service info differs between A and B
  stable  — same port, same state, same service — nothing interesting here
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal

from porthawk.scanner import PortState, ScanResult

ChangeType = Literal["new", "gone", "changed", "stable"]

# fields compared when checking whether a port "changed"
_COMPARE_FIELDS = ("state", "service_name", "service_version", "risk_level")


@dataclass
class PortChange:
    """One port's comparison between scan A and scan B."""

    host: str
    port: int
    protocol: str
    change: ChangeType
    before: ScanResult | None  # None when change == "new"
    after: ScanResult | None  # None when change == "gone"

    def describe(self) -> str:
        """One-line human-readable summary of what changed."""
        label = f"{self.host}:{self.port}/{self.protocol}"
        svc = self.after or self.before
        svc_name = svc.service_name if svc else "unknown"

        if self.change == "new":
            risk = self.after.risk_level if self.after else None
            return f"+ {label}  {svc_name or '?'}  [{risk or 'unclassified'}]"

        if self.change == "gone":
            risk = self.before.risk_level if self.before else None
            return f"- {label}  {svc_name or '?'}  [{risk or 'unclassified'}]"

        if self.change == "changed":
            notes = []
            if self.before and self.after:
                if self.before.state != self.after.state:
                    notes.append(f"state: {self.before.state} → {self.after.state}")
                if self.before.service_version != self.after.service_version:
                    notes.append(
                        f"version: {self.before.service_version or 'none'} → "
                        f"{self.after.service_version or 'none'}"
                    )
                if self.before.service_name != self.after.service_name:
                    notes.append(
                        f"service: {self.before.service_name or '?'} → "
                        f"{self.after.service_name or '?'}"
                    )
                if self.before.risk_level != self.after.risk_level:
                    notes.append(
                        f"risk: {self.before.risk_level or 'none'} → "
                        f"{self.after.risk_level or 'none'}"
                    )
            return f"~ {label}  {svc_name or '?'}  {' | '.join(notes)}"

        # stable
        result = self.after or self.before
        risk_str = result.risk_level if result else None
        return f"  {label}  {svc_name or '?'}  [{risk_str or 'unclassified'}]"


@dataclass
class ScanDiff:
    """Full diff between two scans."""

    label_a: str
    label_b: str
    changes: list[PortChange] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)

    # --- filtered views ---

    @property
    def new_ports(self) -> list[PortChange]:
        return [c for c in self.changes if c.change == "new"]

    @property
    def gone_ports(self) -> list[PortChange]:
        return [c for c in self.changes if c.change == "gone"]

    @property
    def changed_ports(self) -> list[PortChange]:
        return [c for c in self.changes if c.change == "changed"]

    @property
    def stable_ports(self) -> list[PortChange]:
        return [c for c in self.changes if c.change == "stable"]

    @property
    def has_regressions(self) -> bool:
        """True if anything got worse: new HIGH/MEDIUM ports, or state OPEN appeared."""
        for c in self.new_ports:
            if c.after and c.after.risk_level in ("HIGH", "MEDIUM"):
                return True
        return False

    def to_dict(self) -> dict:
        """Serialise to a plain dict — for JSON export."""

        def _result_to_dict(r: ScanResult | None) -> dict | None:
            if r is None:
                return None
            return {
                "host": r.host,
                "port": r.port,
                "protocol": r.protocol,
                "state": r.state.value,
                "service_name": r.service_name,
                "service_version": r.service_version,
                "risk_level": r.risk_level,
                "banner": r.banner,
            }

        return {
            "label_a": self.label_a,
            "label_b": self.label_b,
            "created_at": self.created_at.isoformat(),
            "summary": {
                "new": len(self.new_ports),
                "gone": len(self.gone_ports),
                "changed": len(self.changed_ports),
                "stable": len(self.stable_ports),
            },
            "changes": [
                {
                    "host": c.host,
                    "port": c.port,
                    "protocol": c.protocol,
                    "change": c.change,
                    "before": _result_to_dict(c.before),
                    "after": _result_to_dict(c.after),
                }
                for c in self.changes
            ],
        }


def _result_key(r: ScanResult) -> tuple[str, int, str]:
    return (r.host, r.port, r.protocol)


def _results_changed(a: ScanResult, b: ScanResult) -> bool:
    """Return True if any comparable field differs between the two results."""
    for f in _COMPARE_FIELDS:
        if getattr(a, f) != getattr(b, f):
            return True
    return False


def compute_diff(
    results_a: list[ScanResult],
    results_b: list[ScanResult],
    label_a: str = "scan_a",
    label_b: str = "scan_b",
    include_stable: bool = False,
) -> ScanDiff:
    """Compare two port scan result lists.

    Only OPEN ports are tracked as "active" for the purpose of new/gone
    detection. Changed looks at all ports that appear in both scans.

    Args:
        results_a: Baseline scan (the older / reference scan).
        results_b: Current scan (what we're comparing against the baseline).
        label_a: Human-readable label for scan A (e.g. filename).
        label_b: Human-readable label for scan B.
        include_stable: Include unchanged open ports in the output.
                        Off by default because stable ports are noise.

    Returns:
        ScanDiff with all PortChange entries.
    """
    diff = ScanDiff(label_a=label_a, label_b=label_b)

    map_a: dict[tuple[str, int, str], ScanResult] = {_result_key(r): r for r in results_a}
    map_b: dict[tuple[str, int, str], ScanResult] = {_result_key(r): r for r in results_b}

    all_keys = set(map_a) | set(map_b)

    for key in sorted(all_keys):
        host, port, protocol = key
        a = map_a.get(key)
        b = map_b.get(key)

        if a is None and b is not None:
            # only in B — new port (only interesting if it's OPEN)
            if b.state == PortState.OPEN:
                diff.changes.append(
                    PortChange(
                        host=host, port=port, protocol=protocol, change="new", before=None, after=b
                    )
                )

        elif a is not None and b is None:
            # only in A — port disappeared entirely from the scan
            if a.state == PortState.OPEN:
                diff.changes.append(
                    PortChange(
                        host=host, port=port, protocol=protocol, change="gone", before=a, after=None
                    )
                )

        else:
            # in both scans — check for changes
            assert a is not None and b is not None
            if _results_changed(a, b):
                diff.changes.append(
                    PortChange(
                        host=host, port=port, protocol=protocol, change="changed", before=a, after=b
                    )
                )
            elif include_stable and (a.state == PortState.OPEN or b.state == PortState.OPEN):
                diff.changes.append(
                    PortChange(
                        host=host, port=port, protocol=protocol, change="stable", before=a, after=b
                    )
                )

    return diff


def load_results(path: str | Path) -> list[ScanResult]:
    """Auto-detect format (PortHawk JSON or Nmap XML) and load results.

    Detection is by file extension first, then content sniffing.

    Args:
        path: Path to a PortHawk .json report or Nmap .xml report.

    Returns:
        Flat list of ScanResult.

    Raises:
        ValueError: if the format can't be detected or the file is malformed.
        FileNotFoundError: if the file doesn't exist.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Scan file not found: {p}")

    suffix = p.suffix.lower()

    if suffix == ".xml":
        from porthawk.nmap_import import parse_nmap_xml

        return parse_nmap_xml(p)

    if suffix == ".json":
        return _load_porthawk_json(p)

    # no extension — sniff the first few bytes
    snippet = p.read_text(encoding="utf-8", errors="ignore")[:200].lstrip()
    if snippet.startswith("<?xml") or snippet.startswith("<nmaprun"):
        from porthawk.nmap_import import parse_nmap_xml

        return parse_nmap_xml(p)

    if snippet.startswith("{"):
        return _load_porthawk_json(p)

    raise ValueError(
        f"Cannot detect format for {p}. "
        "Expected a PortHawk .json report or Nmap .xml output (nmap -oX)."
    )


def _load_porthawk_json(path: Path) -> list[ScanResult]:
    """Load results from a PortHawk JSON report file."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc

    raw_results = data.get("results")
    if raw_results is None:
        raise ValueError(
            f"{path} doesn't look like a PortHawk report — no 'results' key. "
            "Run porthawk with -o json to generate one."
        )

    results = []
    for r in raw_results:
        try:
            results.append(ScanResult.model_validate(r))
        except Exception:
            # skip malformed entries rather than blowing up the whole import
            continue

    return results


def save_diff_json(diff: ScanDiff, output_path: Path | None = None) -> Path:
    """Write a ScanDiff to JSON.

    Args:
        diff: ScanDiff from compute_diff().
        output_path: Override default path.

    Returns:
        Path where the file was written.
    """
    from porthawk.reporter import _ensure_reports_dir, _timestamp

    if output_path is None:
        dest = _ensure_reports_dir() / f"diff_{_timestamp()}.json"
    else:
        dest = output_path

    dest.write_text(json.dumps(diff.to_dict(), indent=2), encoding="utf-8")
    return dest
