"""
Link quality — latency, jitter, and packet loss to the gateway and the internet.

Sits next to the wireless signal panel: signal tells you the radio strength,
this tells you what the link actually *delivers*. Jitter and loss to the gateway
isolate Wi-Fi/LAN problems from upstream ISP problems.

Pure stdlib (system `ping`). Best-effort; unreachable target → reachable:false.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .primitives import is_windows, safe_run

_TIME_RE = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.I)


def _stats(rtts: List[float]) -> Dict[str, Optional[float]]:
    if not rtts:
        return {"min_ms": None, "avg_ms": None, "max_ms": None, "jitter_ms": None}
    avg = sum(rtts) / len(rtts)
    # Jitter = mean absolute consecutive difference (RFC 3550 flavour).
    diffs = [abs(rtts[i] - rtts[i - 1]) for i in range(1, len(rtts))]
    jitter = (sum(diffs) / len(diffs)) if diffs else 0.0
    return {"min_ms": round(min(rtts), 2), "avg_ms": round(avg, 2),
            "max_ms": round(max(rtts), 2), "jitter_ms": round(jitter, 2)}


def measure_target(ip: str, count: int = 10) -> Dict[str, Any]:
    if is_windows():
        cmd = ["ping", "-n", str(count), "-w", "1000", ip]
    else:
        cmd = ["ping", "-c", str(count), "-W", "1", ip]
    res = safe_run(cmd, timeout=count * 2 + 10)
    out = res.get("stdout", "") or ""
    rtts = [float(m) for m in _TIME_RE.findall(out)]
    received = len(rtts)
    loss = round((count - received) / count * 100, 1) if count else 100.0
    result: Dict[str, Any] = {
        "ip": ip, "sent": count, "received": received,
        "loss_pct": loss, "reachable": received > 0,
    }
    result.update(_stats(rtts))
    return result


def measure(gateway: Optional[str], internet_ip: str = "1.1.1.1",
            count: int = 10, stage_cb=None) -> Dict[str, Any]:
    if stage_cb:
        stage_cb("Measuring link quality")
    out: Dict[str, Any] = {}
    if gateway:
        out["gateway"] = measure_target(gateway, count)
    out["internet"] = measure_target(internet_ip, count)
    return out
