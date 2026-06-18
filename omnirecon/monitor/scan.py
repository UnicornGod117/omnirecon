"""
run_monitored_scan — the over-time scan.

Runs the shared engine, writes a report, records it into the monitor store, and
computes deltas against the previous scan. This is the persistent path: every
call accumulates history. Used by both the web Monitor area and the CLI.
"""

from __future__ import annotations

import os
from typing import Any, Callable, Dict, Optional

from ..engine import EngineOptions, run_engine
from ..engine import report as report_mod
from ..engine.primitives import now_stamp
from . import alerts as alerts_mod
from .store import Store

StageCb = Optional[Callable[[str], None]]
ProgressCb = Optional[Callable[[int, int], None]]


def run_monitored_scan(
    opts: EngineOptions,
    db_path: str,
    outdir: str,
    stage_cb: StageCb = None,
    progress_cb: ProgressCb = None,
) -> Dict[str, Any]:
    """Run a scan, persist it, and diff it. Returns a result summary dict."""
    os.makedirs(outdir, exist_ok=True)

    report = run_engine(opts, stage_cb=stage_cb, progress_cb=progress_cb)

    stamp = now_stamp()
    json_path = report_mod.write_json(report, outdir, prefix="monitor")

    if stage_cb:
        stage_cb("Recording to monitor store")
    store = Store(db_path)
    try:
        scan_id = store.record_scan(stamp, json_path, report, source="monitor")
        deltas = store.compute_and_store_deltas(scan_id)
    finally:
        store.close()

    # Fire alerts for qualifying changes (no-op unless an alert config exists).
    alert_result = alerts_mod.dispatch(deltas, stamp, outdir)
    if stage_cb and alert_result.get("dispatched"):
        stage_cb(f"Alerts sent via {', '.join(alert_result.get('channels', []))}")

    return {
        "stamp": stamp,
        "scan_id": scan_id,
        "json_path": json_path,
        "host_count": len(report.get("discovery", {}).get("hosts", [])),
        "delta_count": len(deltas),
        "deltas": deltas,
        "alerts": alert_result,
    }
