"""
Zeroconf / mDNS active discovery — browse common Bonjour/Avahi service types
and map advertised IPs to names + services. Optional: needs `zeroconf`.
Returns {ip: {"names": [...], "services": [...]}}.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

from .primitives import is_private_or_lan_ip

try:
    from zeroconf import ServiceBrowser, Zeroconf  # type: ignore
    _HAS_ZEROCONF = True
except ImportError:
    _HAS_ZEROCONF = False

_SERVICE_TYPES = [
    "_http._tcp.local.", "_https._tcp.local.", "_workstation._tcp.local.",
    "_ssh._tcp.local.", "_smb._tcp.local.", "_printer._tcp.local.",
    "_ipp._tcp.local.", "_airplay._tcp.local.", "_googlecast._tcp.local.",
    "_raop._tcp.local.", "_apple-mobdev2._tcp.local.", "_homekit._tcp.local.",
    "_matter._tcp.local.",
]


def available() -> bool:
    return _HAS_ZEROCONF


def discover(timeout_s: float = 3.0) -> Dict[str, Dict[str, Any]]:
    if not _HAS_ZEROCONF:
        return {}
    zc = Zeroconf()
    results: Dict[str, Dict[str, Any]] = {}

    def add(ip: str, name: Optional[str], stype: str) -> None:
        if not ip or not is_private_or_lan_ip(ip):
            return
        results.setdefault(ip, {"names": set(), "services": set()})
        if name:
            results[ip]["names"].add(name)
        results[ip]["services"].add(stype)

    class _Listener:
        def add_service(self, zeroconf, stype, name):
            try:
                info = zeroconf.get_service_info(stype, name, timeout=500)
                if not info:
                    return
                for ip in getattr(info, "parsed_addresses", lambda: [])():
                    add(ip, getattr(info, "server", None), stype)
            except Exception:
                pass

        def update_service(self, *a):
            pass

        def remove_service(self, *a):
            pass

    try:
        for st in _SERVICE_TYPES:
            ServiceBrowser(zc, st, _Listener())
        time.sleep(max(0.5, float(timeout_s)))
    finally:
        try:
            zc.close()
        except Exception:
            pass

    return {ip: {"names": sorted(d["names"]), "services": sorted(d["services"])}
            for ip, d in results.items()}
