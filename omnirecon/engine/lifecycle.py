"""
Software lifecycle intel — flag end-of-life service versions.

Reads the service banners the engine already grabbed (SSH/HTTP/etc.), extracts
product + version, and checks them against endoflife.date. An EOL component
(no more security patches) is a high-signal finding that CVE matching alone
misses.

Opt-in network I/O (endoflife.date public API), cached per run. `requests` is
used if present, else urllib. Unknown products are skipped silently.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import Request, urlopen

# Banner token → endoflife.date product slug.
_PRODUCT_MAP = {
    "apache": "apache", "httpd": "apache", "nginx": "nginx",
    "openssh": "openssh", "php": "php", "mysql": "mysql",
    "mariadb": "mariadb", "postgresql": "postgresql", "openssl": "openssl",
    "lighttpd": "lighttpd", "samba": "samba", "python": "python",
    "iis": "internet-explorer",  # placeholder; many IIS map to windows-server
    "ubuntu": "ubuntu", "debian": "debian",
}

_VERSION_RE = re.compile(
    r"([A-Za-z][A-Za-z0-9+_-]*?)[/_ ]v?(\d+\.\d+(?:\.\d+)?)", re.I)


def extract_products(text: str) -> List[Tuple[str, str]]:
    """Pull (product_slug, version) pairs from a banner/Server string."""
    out: List[Tuple[str, str]] = []
    for m in _VERSION_RE.finditer(text or ""):
        token = m.group(1).lower()
        slug = _PRODUCT_MAP.get(token)
        if slug:
            out.append((slug, m.group(2)))
    return out


def _http_json(url: str, timeout: float = 6.0) -> Optional[Any]:
    try:
        import requests
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "OmniRecon/7"})
        if r.status_code == 200:
            return r.json()
        return None
    except ImportError:
        pass
    except Exception:
        return None
    try:
        req = Request(url, headers={"User-Agent": "OmniRecon/7"})
        with urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8", "ignore"))
    except Exception:
        return None


def _eol_for_version(cycles: List[Dict[str, Any]], version: str) -> Optional[Dict[str, Any]]:
    parts = version.split(".")
    candidates = [".".join(parts[:2]), parts[0]]
    for cand in candidates:
        for c in cycles:
            if str(c.get("cycle")) == cand:
                return c
    return None


def _is_eol(eol_value: Any) -> Optional[bool]:
    if isinstance(eol_value, bool):
        return eol_value
    if isinstance(eol_value, str):
        try:
            return dt.date.fromisoformat(eol_value) < dt.date.today()
        except ValueError:
            return None
    return None


def _gather_banners(host: Dict[str, Any]) -> List[str]:
    texts: List[str] = []
    for hint in (host.get("service_hints") or {}).values():
        if isinstance(hint, dict):
            for key in ("banner", "server", "http_server", "http_title"):
                v = hint.get(key)
                if isinstance(v, str):
                    texts.append(v)
    if isinstance(host.get("service_hint"), str):
        texts.append(host["service_hint"])
    return texts


def enrich(report: Dict[str, Any], stage_cb=None) -> Dict[str, Any]:
    """Check discovered service versions against endoflife.date."""
    if stage_cb:
        stage_cb("Checking software lifecycle (endoflife.date)")
    hosts = (report.get("discovery") or {}).get("hosts", [])
    cache: Dict[str, Optional[List[Dict[str, Any]]]] = {}
    findings: List[Dict[str, Any]] = []
    by_host: Dict[str, List[Dict[str, Any]]] = {}

    for h in hosts:
        ip = h.get("ip")
        seen: set = set()
        for text in _gather_banners(h):
            for slug, version in extract_products(text):
                if (slug, version) in seen:
                    continue
                seen.add((slug, version))
                if slug not in cache:
                    cache[slug] = _http_json(f"https://endoflife.date/api/{slug}.json")
                cycles = cache[slug]
                if not isinstance(cycles, list):
                    continue
                cyc = _eol_for_version(cycles, version)
                if not cyc:
                    continue
                eol = _is_eol(cyc.get("eol"))
                latest = cyc.get("latest")
                entry = {"product": slug, "version": version,
                         "cycle": cyc.get("cycle"), "eol": cyc.get("eol"),
                         "is_eol": eol, "latest": latest}
                by_host.setdefault(ip, []).append(entry)
                if eol:
                    findings.append({
                        "severity": "high", "category": "Lifecycle", "ip": ip,
                        "title": f"End-of-life software: {slug} {version}",
                        "detail": f"{slug} {version} (cycle {cyc.get('cycle')}) is past "
                                  f"end-of-life ({cyc.get('eol')}) — no security patches.",
                        "recommendation": f"Upgrade to a supported release "
                                          f"(latest {slug}: {latest}).",
                    })
    return {"by_host": by_host, "findings": findings}
