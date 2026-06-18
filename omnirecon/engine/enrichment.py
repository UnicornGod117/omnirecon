"""
Service hints + name resolution — passive, non-aggressive identification of
what sits behind each open port (banner · HTTP headers/title · TLS cert) plus
NetBIOS / mDNS hostname resolution. This is enrichment, not pentest: one light
connection per port, no vulnerability probing.

Results land in host['service_hints'][str(port)] = {banner, http, http_title, tls}.
"""

from __future__ import annotations

import concurrent.futures as cf
import re
import socket
from typing import Any, Callable, Dict, List, Optional

from .primitives import (
    grab_banner, is_linux, is_private_or_lan_ip, is_windows, safe_run, which,
)
from .tls import fetch_cert

ProgressCb = Optional[Callable[[int, int], None]]

_TLS_PORTS = {443, 4443, 8443, 993, 995, 5001}
_HTTP_PLAIN = {80, 8000, 8006, 8008, 8080, 8888, 9090}
_TITLE_RE = re.compile(r"<title[^>]*>([^<]{1,250})</title>", re.I | re.S)


# ── Hostname resolution (system tools) ────────────────────────────────────────

def netbios_name(ip: str, timeout_s: float = 3.0) -> Optional[str]:
    if not is_private_or_lan_ip(ip):
        return None
    try:
        if is_windows():
            res = safe_run(["nbtstat", "-A", ip], int(timeout_s))
            for line in res.get("stdout", "").splitlines():
                m = re.search(r"^\s*([A-Z0-9\-_]+)\s+<00>\s+UNIQUE", line, re.I)
                if m:
                    return m.group(1)
        elif which("nmblookup"):
            res = safe_run(["nmblookup", "-A", ip], int(timeout_s))
            for line in res.get("stdout", "").splitlines():
                m = re.search(r"^\s*([A-Z0-9\-_]+)\s+<00>\s+-\s+.*<ACTIVE>", line, re.I)
                if m:
                    return m.group(1)
    except Exception:
        pass
    return None


def mdns_name_system(ip: str, timeout_s: float = 2.0) -> Optional[str]:
    if not (is_private_or_lan_ip(ip) and is_linux() and which("avahi-resolve-address")):
        return None
    try:
        res = safe_run(["avahi-resolve-address", ip], int(timeout_s))
        out = res.get("stdout", "")
        if res.get("returncode") == 0 and out:
            parts = out.split()
            if len(parts) >= 2:
                return parts[1].strip()
    except Exception:
        pass
    return None


# ── Service hints ─────────────────────────────────────────────────────────────

def _http_headers(ip: str, port: int, use_tls: bool, timeout: float = 3.0) -> Dict[str, Any]:
    try:
        import requests
    except ImportError:
        return {}
    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{ip}:{port}/"
    out: Dict[str, Any] = {"url": url}
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                         headers={"User-Agent": "OmniRecon/7"}, allow_redirects=True)
        out["status_code"] = r.status_code
        keep = {"server", "via", "x-powered-by", "www-authenticate",
                "content-type", "location"}
        out["headers"] = {k: v for k, v in r.headers.items() if k.lower() in keep}
        ct = r.headers.get("content-type", "")
        if "html" in ct.lower() or not ct:
            m = _TITLE_RE.search(r.text[:12288])
            if m:
                out["title"] = re.sub(r"\s+", " ", m.group(1)).strip()
    except Exception as e:
        out["error"] = repr(e)
    return out


def _hint_for_port(ip: str, port: int) -> Dict[str, Any]:
    hint: Dict[str, Any] = {}

    if port == 22:
        b = grab_banner(ip, port, timeout=1.0)
        if b and b.startswith("SSH-"):
            hint["banner"] = b[:200]
    elif port == 21:
        b = grab_banner(ip, port, timeout=1.5)
        if b:
            hint["banner"] = b[:200]

    if port in _HTTP_PLAIN:
        http = _http_headers(ip, port, use_tls=False)
        if http:
            hint["http"] = http
            if http.get("title"):
                hint["http_title"] = http["title"]

    if port in _TLS_PORTS:
        cert = fetch_cert(ip, port)
        if cert:
            hint["tls"] = cert
        http = _http_headers(ip, port, use_tls=True)
        if http:
            hint["http"] = http
            if http.get("title"):
                hint["http_title"] = http["title"]

    return hint


def enrich_hosts(hosts: List[Dict[str, Any]], workers: int = 32,
                 progress_cb: ProgressCb = None) -> List[Dict[str, Any]]:
    """Populate service_hints for every open port across all hosts."""
    tasks = [(h, p) for h in hosts for p in (h.get("open_ports") or [])]
    total = len(tasks)
    done = 0
    by_ip: Dict[str, Dict[str, Any]] = {h["ip"]: h for h in hosts}

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_hint_for_port, h["ip"], p): (h["ip"], p) for (h, p) in tasks}
        for fut in cf.as_completed(futs):
            done += 1
            if progress_cb:
                progress_cb(done, total)
            ip, port = futs[fut]
            try:
                hint = fut.result()
            except Exception:
                hint = {}
            if hint:
                by_ip[ip].setdefault("service_hints", {})[str(port)] = hint

    return hosts
