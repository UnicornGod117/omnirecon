"""
Layer-3 path mapping — traceroute to the gateway and the internet.

Turns the flat "everything hangs off the gateway" picture into the real hop
chain (you → AP/router → ISP edge → target) and flags **double-NAT** (more than
one private hop before the path reaches public address space) — a common cause
of port-forwarding and gaming/VoIP headaches on home/SMB networks.

Pure stdlib: shells out to `traceroute` (Linux/macOS) or `tracert` (Windows).
Missing binary → empty result, never an error.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .primitives import is_private_or_lan_ip, is_windows, safe_run, which

_IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")


def _tool() -> Optional[List[str]]:
    if is_windows():
        return ["tracert", "-d", "-w", "800"] if which("tracert") else None
    if which("traceroute"):
        return ["traceroute", "-n", "-w", "1", "-q", "1"]
    return None


def parse_hops(text: str) -> List[Dict[str, Any]]:
    """Parse traceroute/tracert text into ordered hops."""
    hops: List[Dict[str, Any]] = []
    for line in text.splitlines():
        s = line.strip()
        hm = re.match(r"^(\d+)\b", s)
        if not hm:
            continue
        hop_no = int(hm.group(1))
        rest = s[hm.end():]
        ip_m = _IP_RE.search(rest)
        ip = ip_m.group(1) if ip_m else None
        lat_m = re.search(r"([\d.]+)\s*ms", rest)
        timeout = ip is None and "*" in rest
        hops.append({
            "hop": hop_no,
            "ip": ip,
            "rtt_ms": float(lat_m.group(1)) if lat_m else None,
            "timeout": timeout,
            "private": bool(ip and is_private_or_lan_ip(ip)),
        })
    return hops


def trace(target: str, max_hops: int = 20, timeout: int = 40) -> Dict[str, Any]:
    """Traceroute to a single target. Returns {target, hops, error?}."""
    tool = _tool()
    if not tool:
        return {"target": target, "hops": [], "error": "no traceroute/tracert binary"}
    mflag = "-h" if not is_windows() else "-h"
    cmd = tool + [mflag, str(max_hops), target]
    res = safe_run(cmd, timeout=timeout)
    if res.get("error"):
        return {"target": target, "hops": [], "error": res["error"]}
    return {"target": target, "hops": parse_hops(res.get("stdout", ""))}


def analyze(internet_trace: Dict[str, Any]) -> Dict[str, Any]:
    """Derive hop count, edge hop, and double-NAT from an internet trace."""
    hops = internet_trace.get("hops", [])
    responded = [h for h in hops if h.get("ip")]
    private_lead = 0
    for h in hops:
        if h.get("ip") and h["private"]:
            private_lead += 1
        elif h.get("ip"):
            break
    first_public = next((h["ip"] for h in hops if h.get("ip") and not h["private"]), None)
    return {
        "hop_count": len(responded),
        "private_hops_before_public": private_lead,
        "double_nat": private_lead >= 2,
        "isp_edge_ip": first_public,
    }


def map_paths(gateway: Optional[str], internet_host: str = "8.8.8.8",
              stage_cb=None) -> Dict[str, Any]:
    """Trace to the internet (and the gateway) and analyze the result."""
    if stage_cb:
        stage_cb("Tracing network path")
    out: Dict[str, Any] = {}
    inet = trace(internet_host)
    out["internet"] = inet
    out.update(analyze(inet))
    if gateway:
        out["gateway"] = trace(gateway, max_hops=4, timeout=15)
    return out
