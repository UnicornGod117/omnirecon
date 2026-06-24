"""
run_onetime_scan — the right-now scan.

Runs the shared engine for a point-in-time picture, optionally layers the
aggressive pentest suite on top, writes a report, and is **stateless by
default**. The single sanctioned bridge to monitor mode is `save=True`, which
records the run into the monitor store (e.g. to seed a baseline).

Used by both the web One-Time area and the CLI.
"""

from __future__ import annotations

import os
from typing import Any, Callable, Dict, List, Optional

from ..engine import EngineOptions, run_engine
from ..engine import report as report_mod
from ..engine.primitives import now_stamp
from .pentest import run as run_pentest

StageCb = Optional[Callable[[str], None]]
ProgressCb = Optional[Callable[[int, int], None]]


def _load_prior_reports(outdir: str, limit: int = 12) -> List[Dict[str, Any]]:
    """Load recent scan_*.json reports from outdir (oldest first) for trends."""
    import glob
    import json
    paths = sorted(glob.glob(os.path.join(outdir, "scan_*.json")),
                   key=lambda p: os.path.getmtime(p))[-limit:]
    out: List[Dict[str, Any]] = []
    for p in paths:
        try:
            with open(p, encoding="utf-8") as f:
                out.append(json.load(f))
        except Exception:
            continue
    return out


def run_onetime_scan(
    opts: EngineOptions,
    outdir: str,
    pentest: bool = False,
    pentest_modules: Optional[List[str]] = None,
    authorized: bool = False,
    save: bool = False,
    db_path: Optional[str] = None,
    export: Optional[List[str]] = None,
    stage_cb: StageCb = None,
    progress_cb: ProgressCb = None,
) -> Dict[str, Any]:
    os.makedirs(outdir, exist_ok=True)

    report = run_engine(opts, stage_cb=stage_cb, progress_cb=progress_cb)
    hosts = report.get("discovery", {}).get("hosts", [])

    if pentest:
        if stage_cb:
            stage_cb("Running pentest suite")
        report["pentest"] = run_pentest(
            hosts, pentest_modules or ["all"], authorized=authorized, stage_cb=stage_cb,
        )
        # Refresh hygiene so pentest-only findings (e.g. SMBv1) are folded in.
        if opts.hygiene:
            from ..engine import hygiene as _hygiene
            report["hygiene"] = _hygiene.analyze(report)

    # Router / gateway audit — active (credential test gated by authorization).
    if getattr(opts, "router_audit", False):
        from ..engine import routeraudit
        report["router_audit"] = routeraudit.assess(report, authorized=authorized,
                                                    stage_cb=stage_cb)
        if opts.hygiene and report["router_audit"].get("findings"):
            from ..engine import hygiene as _hygiene
            _hygiene.fold_in_findings(report, report["router_audit"]["findings"])

    # Trends over time — topology time-lapse + signal trend from prior reports.
    try:
        from ..engine import trends
        prior = _load_prior_reports(outdir, limit=12)
        if prior:
            report["trends"] = trends.from_reports(prior + [report])
    except Exception:
        pass

    # Active plugins probe hosts over the network — one-time mode only.
    if opts.plugins and hosts:
        if stage_cb:
            stage_cb("Running active plugins")
        from ..engine import plugins as plugins_mod
        active = plugins_mod.run_active(
            hosts, authorized=authorized, dirs=opts.plugin_dirs,
            names=opts.plugin_names, stage_cb=stage_cb)
        if active.get("results"):
            report.setdefault("plugins", {})["active"] = active["results"]
        if active.get("skipped"):
            report.setdefault("plugins", {})["skipped"] = active["skipped"]
        if active.get("findings") and opts.hygiene:
            from ..engine import hygiene as _hygiene
            _hygiene.fold_in_findings(report, active["findings"])

    html_path, json_path = report_mod.write_reports(report, outdir, prefix="scan")

    extra_exports: Dict[str, str] = {}
    wanted = [f for f in (export or [])
              if f in ("csv", "md", "pdf", "mermaid", "dot", "graphml")]
    if wanted:
        if stage_cb:
            stage_cb(f"Exporting {', '.join(wanted)}")
        extra_exports = report_mod.write_exports(report, outdir, wanted, prefix="scan")

    result: Dict[str, Any] = {
        "html_path": html_path,
        "json_path": json_path,
        "exports": extra_exports,
        "host_count": len(hosts),
        "saved": False,
        "report": report,
    }

    # The one sanctioned one-time → monitor bridge.
    if save and db_path:
        if stage_cb:
            stage_cb("Saving to monitor store")
        from ..monitor.store import Store
        stamp = now_stamp()
        store = Store(db_path)
        try:
            scan_id = store.record_scan(stamp, json_path, report, source="onetime")
            store.compute_and_store_deltas(scan_id)
        finally:
            store.close()
        result["saved"] = True
        result["stamp"] = stamp

    return result
