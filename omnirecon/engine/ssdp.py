"""
SSDP / UPnP active discovery — pure-socket M-SEARCH multicast (no scapy).
Collects responding devices and enriches them with their UPnP description XML
(friendlyName, manufacturer, modelName, …).
"""

from __future__ import annotations

import re
import socket
import time
from typing import Any, Dict, List, Set

from .primitives import is_private_or_lan_ip

_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 3\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
)


def _fetch_upnp_description(url: str, timeout: float = 3.0) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    try:
        import requests
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "OmniRecon/7"})
        if r.status_code != 200:
            return out
        for tag in ("friendlyName", "manufacturer", "modelName",
                    "modelNumber", "serialNumber"):
            m = re.search(rf"<{tag}>([^<]{{0,200}})</{tag}>", r.text, re.I)
            if m:
                out[tag] = m.group(1).strip()
    except Exception:
        pass
    return out


def discover(timeout_s: float = 5.0, max_responses: int = 128) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
        sock.settimeout(timeout_s)
        sock.sendto(_MSEARCH.encode(), ("239.255.255.250", 1900))

        deadline = time.time() + timeout_s
        while time.time() < deadline and len(results) < max_responses:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                if not is_private_or_lan_ip(ip) or ip in seen:
                    continue
                resp = data.decode("utf-8", "ignore")
                entry: Dict[str, Any] = {"ip": ip, "server": None,
                                         "location": None, "usn": None, "st": None}
                for line in resp.splitlines():
                    k, _, v = line.partition(":")
                    k, v = k.strip().lower(), v.strip()
                    if k in entry:
                        entry[k] = v
                if entry["location"]:
                    entry.update(_fetch_upnp_description(entry["location"]))
                seen.add(ip)
                results.append(entry)
            except socket.timeout:
                break
            except Exception:
                continue
    except Exception:
        pass
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
    return results
