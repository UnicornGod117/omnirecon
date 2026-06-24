"""
Router / gateway security audit.

The gateway is the highest-value box on the LAN, so it gets its own audit:

  - admin-interface detection (HTTP/HTTPS on the gateway, server + realm + title),
  - default-credential check against HTTP Basic auth (ONLY when authorized —
    this actively attempts logins),
  - UPnP exposure (folded from the WAN-exposure module),
  - firmware/version → CVE hint (flags a version banner worth CVE-correlating).

The passive parts (interface detection, UPnP) run freely; the credential test is
gated behind explicit authorization, exactly like the pentest suite. `requests`
is used if present, else urllib. Never raises.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import Request, urlopen

# A deliberately tiny, well-known default-credential list (router admin panels).
_DEFAULT_CREDS: List[Tuple[str, str]] = [
    ("admin", "admin"), ("admin", "password"), ("admin", ""),
    ("admin", "1234"), ("root", "root"), ("user", "user"),
    ("admin", "admin1234"),
]

_ADMIN_PORTS = [80, 443, 8080, 8443, 8000]


def _finding(severity, ip, title, detail, rec):
    return {"severity": severity, "category": "Router", "ip": ip,
            "title": title, "detail": detail, "recommendation": rec}


def _get(url: str, timeout: float = 4.0, auth: Optional[Tuple[str, str]] = None):
    """Return (status, headers, body) or None. Tries requests, falls back to urllib."""
    try:
        import requests
        r = requests.get(url, timeout=timeout, verify=False,
                         auth=auth, headers={"User-Agent": "OmniRecon/7"})
        return r.status_code, dict(r.headers), r.text[:4096]
    except ImportError:
        pass
    except Exception:
        return None
    try:
        import base64
        headers = {"User-Agent": "OmniRecon/7"}
        if auth:
            tok = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
            headers["Authorization"] = f"Basic {tok}"
        with urlopen(Request(url, headers=headers), timeout=timeout) as resp:  # noqa: S310
            return resp.status, dict(resp.headers), resp.read(4096).decode("utf-8", "ignore")
    except Exception as e:  # urllib raises on 401 — capture the code
        code = getattr(e, "code", None)
        if code:
            hdrs = dict(getattr(e, "headers", {}) or {})
            return code, hdrs, ""
        return None


def _detect_admin(gateway: str, open_ports: List[int]) -> Optional[Dict[str, Any]]:
    ports = [p for p in _ADMIN_PORTS if not open_ports or p in open_ports] or _ADMIN_PORTS
    for port in ports:
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{gateway}:{port}/"
        res = _get(url)
        if not res:
            continue
        status, headers, body = res
        title = None
        m = re.search(r"<title>(.*?)</title>", body or "", re.I | re.S)
        if m:
            title = m.group(1).strip()[:120]
        realm = None
        wa = headers.get("WWW-Authenticate") or headers.get("www-authenticate")
        if wa:
            rm = re.search(r'realm="?([^"]+)"?', wa)
            realm = rm.group(1) if rm else wa
        return {"url": url, "status": status, "server": headers.get("Server"),
                "title": title, "realm": realm,
                "basic_auth": bool(wa and "basic" in wa.lower())}
    return None


def _try_default_creds(url: str) -> List[Tuple[str, str]]:
    worked = []
    for user, pw in _DEFAULT_CREDS:
        res = _get(url, auth=(user, pw))
        if res and res[0] and 200 <= res[0] < 300:
            worked.append((user, pw))
            if len(worked) >= 2:
                break
    return worked


def assess(report: Dict[str, Any], authorized: bool = False,
           stage_cb=None) -> Dict[str, Any]:
    """Audit the gateway. Credential testing only runs when authorized=True."""
    if stage_cb:
        stage_cb("Auditing router / gateway")
    gateway = (report.get("routes") or {}).get("default_gateway")
    out: Dict[str, Any] = {"gateway": gateway, "admin": None,
                           "default_creds": [], "findings": [],
                           "authorized": authorized}
    if not gateway:
        return out

    hosts = (report.get("discovery") or {}).get("hosts", [])
    gw_host = next((h for h in hosts if h.get("ip") == gateway), {})
    admin = _detect_admin(gateway, gw_host.get("open_ports", []))
    out["admin"] = admin

    if admin:
        out["findings"].append(_finding(
            "info", gateway, "Router admin interface reachable",
            f"Admin UI at {admin['url']} (server: {admin.get('server') or '?'}).",
            "Restrict admin access to the LAN; use a strong password."))
        if not admin["url"].startswith("https"):
            out["findings"].append(_finding(
                "medium", gateway, "Router admin over plaintext HTTP",
                f"The admin UI at {admin['url']} is served without TLS.",
                "Enable HTTPS for the router admin interface."))
        # Credential test — active, authorization-gated.
        if authorized and admin.get("basic_auth"):
            worked = _try_default_creds(admin["url"])
            out["default_creds"] = worked
            if worked:
                out["findings"].append(_finding(
                    "high", gateway, "Default credentials accepted on router",
                    f"{admin['url']} accepted default login(s): "
                    + ", ".join(f"{u}/{p or '<blank>'}" for u, p in worked),
                    "Change the router admin password immediately."))

    # UPnP exposure, folded from the WAN-exposure module if it ran.
    wan = report.get("wan_exposure") or {}
    if wan.get("igd_found"):
        out["findings"].append(_finding(
            "medium", gateway, "Router exposes UPnP IGD",
            "Any LAN device can open inbound WAN ports via UPnP on this router.",
            "Disable UPnP unless a specific device requires it."))

    # Firmware/version → CVE hint from the gateway's own banner.
    banner = (admin or {}).get("server") or gw_host.get("vendor") or ""
    if re.search(r"\d+\.\d+", banner):
        out["firmware_banner"] = banner
        out["findings"].append(_finding(
            "info", gateway, "Router firmware/version exposed",
            f"The gateway advertises '{banner}'.",
            "Cross-reference this version against vendor advisories / CVEs and update."))
    return out
