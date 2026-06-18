"""
In-process background scan jobs for the web UI.

The browser is the primary front door, so scans run **inside** the web process
(a daemon thread per job) driving the shared engine directly — no subprocess,
no legacy. Stage/progress callbacks are pushed onto a per-job queue that the
SSE endpoint drains line by line.
"""

from __future__ import annotations

import queue
import threading
import uuid
from typing import Any, Dict, Iterator, List, Optional

from omnirecon.engine import DEFAULT_PORTS, EngineOptions
from omnirecon.monitor import run_monitored_scan
from omnirecon.onetime import run_onetime_scan

_DONE = "[DONE]"


class _Job:
    def __init__(self, token: str, mode: str) -> None:
        self.token = token
        self.mode = mode
        self.q: "queue.Queue[str]" = queue.Queue()
        self.running = True
        self.error: Optional[str] = None
        self.result: Optional[Dict[str, Any]] = None


_jobs: Dict[str, _Job] = {}


def _opts_from_config(config: dict) -> EngineOptions:
    subnets: List[str] = [s.strip() for s in (config.get("subnet") or "").split(",") if s.strip()]
    return EngineOptions(
        subnets=subnets,
        discover=bool(config.get("discover", True)),
        probe_ports=bool(config.get("probe_ports", True)),
        ports=DEFAULT_PORTS,
        discovery_mode=config.get("discovery_mode") or "auto",
        arp_prime=bool(config.get("arp_prime")),
        ipv6=bool(config.get("ipv6")),
        udp_probe=bool(config.get("udp_probe")),
        ttl_os=bool(config.get("ttl_os")),
        allow_non_private=bool(config.get("allow_non_private")),
        service_hints=bool(config.get("service_hints")) or bool(config.get("pentest")),
        snmp=bool(config.get("snmp")),
        snmp_communities=config.get("snmp_communities") or "public,private",
        zeroconf=bool(config.get("zeroconf")),
        ssdp=bool(config.get("ssdp")),
        passive=bool(config.get("passive")),
        passive_duration=float(config.get("passive_duration") or 20.0),
        cve=bool(config.get("cve_check")),
        cve_min_score=float(config.get("cve_min_score") or 6.0),
        topology=bool(config.get("topology")),
        tags_file=config.get("tags_file") or None,
        extintel=bool(config.get("extintel")),
        plugins=bool(config.get("plugins")),
    )


def _run(job: _Job, config: dict, db_path: str, outdir: str) -> None:
    def stage(name: str) -> None:
        job.q.put(f"  [{name}]")

    bucket = [-1]

    def progress(done: int, total: int) -> None:
        pct = int(done / max(1, total) * 100)
        if pct // 10 != bucket[0]:
            bucket[0] = pct // 10
            job.q.put(f"    … {pct}%")

    try:
        opts = _opts_from_config(config)
        if job.mode == "onetime":
            pentest = bool(config.get("pentest"))
            authorized = bool(config.get("i_have_authorization"))
            modules = [m.strip() for m in str(config.get("pentest_modules") or "all").split(",")]
            save = bool(config.get("save"))
            export = [f.strip() for f in str(config.get("export") or "").split(",") if f.strip()]
            res = run_onetime_scan(
                opts, outdir, pentest=pentest, pentest_modules=modules,
                authorized=authorized, save=save,
                db_path=db_path if save else None, export=export,
                stage_cb=stage, progress_cb=progress,
            )
            job.q.put(f"  ✓ {res['host_count']} host(s) scanned.")
            hyg = (res.get("report") or {}).get("hygiene", {}).get("summary", {})
            if hyg:
                job.q.put(f"  ✓ Posture {hyg.get('grade','—')} ({hyg.get('score','—')}/100), "
                          f"{hyg.get('total', 0)} finding(s)")
            job.q.put(f"  ✓ Report: {res['json_path']}")
            for fmt, path in (res.get("exports") or {}).items():
                job.q.put(f"  ✓ {fmt.upper()}: {path}")
            if res.get("saved"):
                job.q.put(f"  ✓ [MONITOR] saved baseline as {res['stamp']}")
        else:
            res = run_monitored_scan(
                opts, db_path, outdir, stage_cb=stage, progress_cb=progress,
            )
            job.q.put(f"  ✓ [MONITOR] scan {res['stamp']}: "
                      f"{res['host_count']} host(s), {res['delta_count']} change(s)")
            alert = res.get("alerts") or {}
            if alert.get("dispatched"):
                job.q.put(f"  ✓ [ALERT] {alert['matched']} sent via "
                          f"{', '.join(alert.get('channels', []))}")
        job.result = res
    except Exception as e:  # noqa: BLE001 — surface any failure to the terminal
        job.error = str(e)
        job.q.put(f"  ✗ Error: {e}")
    finally:
        job.running = False
        job.q.put(_DONE)


def start(config: dict, db_path: str, outdir: str) -> str:
    token = uuid.uuid4().hex
    mode = "onetime" if config.get("mode") == "onetime" else "monitor"
    job = _Job(token, mode)
    _jobs[token] = job
    threading.Thread(target=_run, args=(job, config, db_path, outdir), daemon=True).start()
    return token


def stream(token: str) -> Iterator[str]:
    job = _jobs.get(token)
    if job is None:
        yield "[scan not found]"
        return
    while True:
        line = job.q.get()
        yield line
        if line == _DONE:
            break


def status(token: str) -> dict:
    job = _jobs.get(token)
    if job is None:
        return {"running": False, "exit_code": None, "error": "not found"}
    if job.running:
        return {"running": True, "exit_code": None}
    return {"running": False, "exit_code": 0 if job.error is None else 1}
