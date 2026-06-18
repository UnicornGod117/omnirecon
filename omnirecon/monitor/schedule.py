"""
Scheduled collection — register OmniRecon monitor scans with the OS scheduler,
or run a simple foreground daemon loop.

Two ways to run scans on a cadence:

  • register()  — hand the job to the OS so it survives reboots and needs no
    babysitting. Windows → Task Scheduler (schtasks). Linux/macOS → the user
    crontab. This is the resilient path the architecture prefers: a scheduled
    invocation that exits cleanly after each run.

  • daemon()    — a foreground loop that re-scans every N seconds until Ctrl-C.
    Handy for a terminal you're watching or a container with no cron.

All registration is best-effort and returns a structured dict (the CLI prints
it). Nothing here is destructive without an explicit remove().
"""

from __future__ import annotations

import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional

from ..engine.primitives import is_windows

StageCb = Optional[Callable[[str], None]]

TASK_PREFIX = "OmniRecon-"
CRON_MARKER = "# omnirecon-managed"


# ── Interval parsing ──────────────────────────────────────────────────────────

def parse_interval(text: str) -> int:
    """'6h' / '30m' / '90s' / '2d' / bare seconds → seconds. Raises ValueError."""
    s = str(text).strip().lower()
    if not s:
        raise ValueError("empty interval")
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if s[-1] in units:
        num, mult = s[:-1], units[s[-1]]
    else:
        num, mult = s, 1
    try:
        value = float(num)
    except ValueError as exc:
        raise ValueError(f"bad interval {text!r}") from exc
    secs = int(value * mult)
    if secs < 60:
        raise ValueError("interval must be at least 60 seconds")
    return secs


def _interval_to_cron(seconds: int) -> str:
    """Best-effort cron expression for a fixed interval."""
    if seconds % 86400 == 0:
        return "0 2 * * *"                       # daily at 02:00
    if seconds % 3600 == 0:
        return f"0 */{seconds // 3600} * * *"
    minutes = max(1, seconds // 60)
    return f"*/{minutes} * * * *"


# ── Command building ──────────────────────────────────────────────────────────

def build_command(db: Optional[str] = None, subnet: Optional[str] = None,
                  extra_args: Optional[List[str]] = None) -> List[str]:
    """The `monitor scan` invocation a scheduled job should run."""
    cmd = [sys.executable, "-m", "omnirecon", "monitor"]
    if db:
        cmd += ["--db", db]
    cmd += ["scan"]
    if subnet:
        cmd += ["--subnet", subnet]
    cmd += list(extra_args or [])
    return cmd


def _quote_command(cmd: List[str]) -> str:
    return " ".join(f'"{c}"' if " " in c else c for c in cmd)


# ── Windows: Task Scheduler ───────────────────────────────────────────────────

def _win_register(name: str, cmd: List[str], *, interval: Optional[int],
                  cron: Optional[str], at: Optional[str]) -> Dict[str, Any]:
    task = f"{TASK_PREFIX}{name}"
    args = ["schtasks", "/create", "/tn", task, "/tr", _quote_command(cmd), "/f"]
    if at:
        args += ["/sc", "DAILY", "/st", at]
    elif interval and interval % 3600 == 0:
        args += ["/sc", "HOURLY", "/mo", str(interval // 3600)]
    elif interval:
        args += ["/sc", "MINUTE", "/mo", str(max(1, interval // 60))]
    elif cron:
        sc = _cron_to_schtasks(cron)
        if sc is None:
            return {"ok": False, "error": f"cron {cron!r} not expressible as a "
                    "schtasks schedule; use --interval or --at on Windows"}
        args += sc
    else:
        args += ["/sc", "DAILY", "/st", "02:00"]
    try:
        r = subprocess.run(args, capture_output=True, text=True)
    except OSError as e:
        return {"ok": False, "error": str(e)}
    if r.returncode != 0:
        return {"ok": False, "error": (r.stderr or r.stdout).strip()}
    return {"ok": True, "task": task, "scheduler": "Task Scheduler"}


def _cron_to_schtasks(cron: str) -> Optional[List[str]]:
    parts = cron.split()
    if len(parts) != 5:
        return None
    minute, hour, dom, mon, dow = parts
    if minute.startswith("*/") and hour == "*":
        return ["/sc", "MINUTE", "/mo", minute[2:]]
    if hour.startswith("*/") and dom == mon == dow == "*":
        return ["/sc", "HOURLY", "/mo", hour[2:]]
    if minute.isdigit() and hour.isdigit() and dom == mon == dow == "*":
        return ["/sc", "DAILY", "/st", f"{int(hour):02d}:{int(minute):02d}"]
    return None


def _win_list() -> List[Dict[str, str]]:
    try:
        r = subprocess.run(["schtasks", "/query", "/fo", "csv", "/nh"],
                           capture_output=True, text=True)
    except OSError:
        return []
    jobs: List[Dict[str, str]] = []
    for line in r.stdout.splitlines():
        cells = [c.strip().strip('"') for c in line.split('","')]
        if cells and TASK_PREFIX in cells[0]:
            name = cells[0].lstrip("\\").replace(TASK_PREFIX, "", 1)
            jobs.append({"name": name, "next_run": cells[1] if len(cells) > 1 else "",
                         "status": cells[2] if len(cells) > 2 else ""})
    return jobs


def _win_remove(name: str) -> Dict[str, Any]:
    task = f"{TASK_PREFIX}{name}"
    try:
        r = subprocess.run(["schtasks", "/delete", "/tn", task, "/f"],
                           capture_output=True, text=True)
    except OSError as e:
        return {"ok": False, "error": str(e)}
    if r.returncode != 0:
        return {"ok": False, "error": (r.stderr or r.stdout).strip()}
    return {"ok": True, "task": task}


# ── Unix: crontab ─────────────────────────────────────────────────────────────

def _read_crontab() -> str:
    try:
        r = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    except OSError:
        return ""
    return r.stdout if r.returncode == 0 else ""


def _write_crontab(content: str) -> bool:
    try:
        r = subprocess.run(["crontab", "-"], input=content, text=True,
                           capture_output=True)
    except OSError:
        return False
    return r.returncode == 0


def _cron_line(name: str, expr: str, cmd: List[str]) -> str:
    return f"{expr} {_quote_command(cmd)}  {CRON_MARKER} name={name}"


def _unix_register(name: str, cmd: List[str], *, interval: Optional[int],
                   cron: Optional[str], at: Optional[str]) -> Dict[str, Any]:
    if cron:
        expr = cron
    elif at:
        try:
            hh, mm = at.split(":")
            expr = f"{int(mm)} {int(hh)} * * *"
        except ValueError:
            return {"ok": False, "error": f"bad --at time {at!r} (want HH:MM)"}
    elif interval:
        expr = _interval_to_cron(interval)
    else:
        expr = "0 2 * * *"

    existing = [ln for ln in _read_crontab().splitlines()
                if not (CRON_MARKER in ln and f"name={name}" in ln)]
    existing.append(_cron_line(name, expr, cmd))
    if not _write_crontab("\n".join(existing) + "\n"):
        return {"ok": False, "error": "could not write crontab (is cron installed?)"}
    return {"ok": True, "cron": expr, "scheduler": "crontab"}


def _unix_list() -> List[Dict[str, str]]:
    jobs: List[Dict[str, str]] = []
    for ln in _read_crontab().splitlines():
        if CRON_MARKER not in ln:
            continue
        name = "?"
        if "name=" in ln:
            name = ln.split("name=", 1)[1].strip()
        expr = " ".join(ln.split()[:5])
        jobs.append({"name": name, "cron": expr, "status": "registered"})
    return jobs


def _unix_remove(name: str) -> Dict[str, Any]:
    lines = _read_crontab().splitlines()
    kept = [ln for ln in lines
            if not (CRON_MARKER in ln and f"name={name}" in ln)]
    if len(kept) == len(lines):
        return {"ok": False, "error": f"no managed job named {name!r}"}
    if not _write_crontab("\n".join(kept) + ("\n" if kept else "")):
        return {"ok": False, "error": "could not write crontab"}
    return {"ok": True, "name": name}


# ── Public API ────────────────────────────────────────────────────────────────

def register(name: str = "default", *, interval: Optional[int] = None,
             cron: Optional[str] = None, at: Optional[str] = None,
             db: Optional[str] = None, subnet: Optional[str] = None,
             extra_args: Optional[List[str]] = None) -> Dict[str, Any]:
    """Register a recurring `monitor scan` with the OS scheduler."""
    cmd = build_command(db, subnet, extra_args)
    if is_windows():
        result = _win_register(name, cmd, interval=interval, cron=cron, at=at)
    else:
        result = _unix_register(name, cmd, interval=interval, cron=cron, at=at)
    result["command"] = _quote_command(cmd)
    result["name"] = name
    return result


def list_jobs() -> List[Dict[str, str]]:
    return _win_list() if is_windows() else _unix_list()


def remove(name: str) -> Dict[str, Any]:
    return _win_remove(name) if is_windows() else _unix_remove(name)


def daemon(run_once: Callable[[], Any], interval_seconds: int,
           stage_cb: StageCb = None, max_iterations: Optional[int] = None) -> int:
    """Foreground loop: call run_once(), sleep interval_seconds, repeat until
    interrupted. `max_iterations` bounds the loop (tests pass 1). Returns the
    number of completed runs."""
    count = 0
    try:
        while True:
            if stage_cb:
                stage_cb(f"scan #{count + 1}")
            try:
                run_once()
            except Exception as e:  # noqa: BLE001 — one bad scan shouldn't kill the loop
                if stage_cb:
                    stage_cb(f"scan failed: {e}")
            count += 1
            if max_iterations is not None and count >= max_iterations:
                break
            time.sleep(interval_seconds)
    except KeyboardInterrupt:
        if stage_cb:
            stage_cb("daemon stopped")
    return count
