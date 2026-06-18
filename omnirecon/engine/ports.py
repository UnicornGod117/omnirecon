"""
Threaded TCP port scanning over discovered hosts.

Mode-agnostic: it just fills in each host's open_ports list. Service
identification (banners, TLS, HTTP) is the job of enrichment.py.
"""

from __future__ import annotations

import concurrent.futures as cf
from typing import Any, Callable, Dict, List, Optional

from .primitives import tcp_probe

ProgressCb = Optional[Callable[[int, int], None]]

# A pragmatic default set covering common management, web, file, and IoT ports.
DEFAULT_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1433, 1521, 3306, 3389, 5000, 5001, 5432, 5900, 5901,
    8000, 8006, 8080, 8443, 8888, 9090, 9100, 10000,
]


def scan_ports(
    hosts: List[Dict[str, Any]],
    ports: Optional[List[int]] = None,
    workers: int = 256,
    timeout: float = 0.7,
    progress_cb: ProgressCb = None,
) -> List[Dict[str, Any]]:
    """Probe each host across `ports`, updating host['open_ports'] in place."""
    ports = ports or DEFAULT_PORTS
    tasks = [(h, p) for h in hosts for p in ports]
    total = len(tasks)
    done = 0

    results: Dict[str, List[int]] = {h["ip"]: [] for h in hosts}

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(tcp_probe, h["ip"], p, timeout): (h["ip"], p)
                for (h, p) in tasks}
        for fut in cf.as_completed(futs):
            done += 1
            if progress_cb:
                progress_cb(done, total)
            ip, port = futs[fut]
            try:
                if fut.result():
                    results[ip].append(port)
            except Exception:
                pass

    for h in hosts:
        h["open_ports"] = sorted(results.get(h["ip"], []))
    return hosts
