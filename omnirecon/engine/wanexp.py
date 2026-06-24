"""
WAN exposure — UPnP IGD port-forward enumeration on the router.

The biggest invisible hole on a home/SMB network is a port the router has
forwarded to the internet — often opened automatically by a device via UPnP IGD
without anyone realising. This module asks the router (over the LAN) which ports
it is forwarding to the WAN and what its external IP is, then flags the exposure.

LAN-only network I/O against the gateway's UPnP control service. Opt-in. Pure
stdlib (urllib) — `requests` used if present. Empty result if no IGD answers.
"""

from __future__ import annotations

import re
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin
from urllib.request import Request, urlopen

_MSEARCH_TARGETS = [
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
]


def _discover_igd_locations(timeout: float = 3.0) -> List[str]:
    locations: List[str] = []
    for st in _MSEARCH_TARGETS:
        msg = ("M-SEARCH * HTTP/1.1\r\n"
               "HOST: 239.255.255.250:1900\r\n"
               'MAN: "ssdp:discover"\r\n'
               "MX: 2\r\n"
               f"ST: {st}\r\n\r\n").encode()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(timeout)
        try:
            s.sendto(msg, ("239.255.255.250", 1900))
            while True:
                try:
                    data, _ = s.recvfrom(2048)
                except socket.timeout:
                    break
                m = re.search(rb"LOCATION:\s*(\S+)", data, re.I)
                if m:
                    loc = m.group(1).decode("ascii", "ignore").strip()
                    if loc not in locations:
                        locations.append(loc)
        except Exception:
            pass
        finally:
            s.close()
    return locations


def _http_get(url: str, timeout: float = 4.0) -> Optional[str]:
    try:
        req = Request(url, headers={"User-Agent": "OmniRecon/7"})
        with urlopen(req, timeout=timeout) as r:  # noqa: S310 (LAN only)
            return r.read(65536).decode("utf-8", "ignore")
    except Exception:
        return None


def _find_wan_service(xml: str, base_url: str) -> Optional[Dict[str, str]]:
    for svc_type in ("WANIPConnection", "WANPPPConnection"):
        # Match a <service> block carrying this serviceType.
        for block in re.findall(r"<service>(.*?)</service>", xml, re.S | re.I):
            if svc_type in block:
                st = re.search(r"<serviceType>(.*?)</serviceType>", block, re.S | re.I)
                cu = re.search(r"<controlURL>(.*?)</controlURL>", block, re.S | re.I)
                if st and cu:
                    return {"service_type": st.group(1).strip(),
                            "control_url": urljoin(base_url, cu.group(1).strip())}
    return None


def _soap(control_url: str, service_type: str, action: str,
          body_args: str = "", timeout: float = 4.0) -> Optional[str]:
    envelope = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        f'<s:Body><u:{action} xmlns:u="{service_type}">{body_args}'
        f'</u:{action}></s:Body></s:Envelope>'
    ).encode()
    try:
        req = Request(control_url, data=envelope, headers={
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": f'"{service_type}#{action}"',
            "User-Agent": "OmniRecon/7",
        })
        with urlopen(req, timeout=timeout) as r:  # noqa: S310 (LAN only)
            return r.read(65536).decode("utf-8", "ignore")
    except Exception:
        return None


def _tag(xml: Optional[str], name: str) -> Optional[str]:
    if not xml:
        return None
    m = re.search(rf"<{name}>(.*?)</{name}>", xml, re.S | re.I)
    return m.group(1).strip() if m else None


def _enumerate_mappings(control_url: str, service_type: str,
                        limit: int = 64) -> List[Dict[str, Any]]:
    mappings: List[Dict[str, Any]] = []
    for i in range(limit):
        resp = _soap(control_url, service_type, "GetGenericPortMappingEntry",
                     f"<NewPortMappingIndex>{i}</NewPortMappingIndex>")
        if not resp or "GetGenericPortMappingEntryResponse" not in resp:
            break
        mappings.append({
            "external_port": _tag(resp, "NewExternalPort"),
            "protocol": _tag(resp, "NewProtocol"),
            "internal_client": _tag(resp, "NewInternalClient"),
            "internal_port": _tag(resp, "NewInternalPort"),
            "description": _tag(resp, "NewPortMappingDescription"),
            "enabled": _tag(resp, "NewEnabled"),
        })
    return mappings


def _finding(severity, ip, title, detail, rec):
    return {"severity": severity, "category": "WAN Exposure", "ip": ip,
            "title": title, "detail": detail, "recommendation": rec}


def assess(stage_cb=None) -> Dict[str, Any]:
    """Discover the IGD, read its external IP + port forwards, and flag them."""
    if stage_cb:
        stage_cb("Assessing WAN exposure (UPnP IGD)")
    out: Dict[str, Any] = {"igd_found": False, "external_ip": None,
                           "port_mappings": [], "findings": []}
    locations = _discover_igd_locations()
    if not locations:
        return out

    for loc in locations:
        xml = _http_get(loc)
        if not xml:
            continue
        svc = _find_wan_service(xml, loc)
        if not svc:
            continue
        out["igd_found"] = True
        out["igd_location"] = loc
        ext = _soap(svc["control_url"], svc["service_type"], "GetExternalIPAddress")
        out["external_ip"] = _tag(ext, "NewExternalIPAddress")
        out["port_mappings"] = _enumerate_mappings(svc["control_url"], svc["service_type"])
        break

    if out["igd_found"]:
        out["findings"].append(_finding(
            "medium", None, "UPnP IGD is open to the LAN",
            "The router accepts UPnP IGD control requests, so any LAN device "
            "(including malware) can silently open inbound ports to the internet.",
            "Disable UPnP on the router unless a specific device needs it."))
        active = [m for m in out["port_mappings"]
                  if (m.get("enabled") in ("1", "true", "True", None))]
        if active:
            ports = ", ".join(
                f"{m.get('external_port')}/{m.get('protocol')}→"
                f"{m.get('internal_client')}:{m.get('internal_port')}"
                f"({m.get('description') or '?'})" for m in active[:12])
            out["findings"].append(_finding(
                "high", None, f"{len(active)} inbound port(s) forwarded to the internet",
                f"The router forwards: {ports}.",
                "Review each forward; remove any you didn't intend to expose."))
    return out
