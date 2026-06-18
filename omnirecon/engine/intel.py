"""
Vulnerability intelligence — correlate discovered services against NVD CVEs and
the CISA Known Exploited Vulnerabilities (KEV) catalog.

Harvests service strings (SSH banners, HTTP Server headers, SNMP sysDescr, TLS
CN), queries NVD 2.0 with a 7-day local cache, classifies impact, filters by
CVSS, and flags KEV membership. Opt-in and network-dependent; degrades
gracefully with no internet / no requests / rate limiting.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Set

_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json")
_RATE_DELAY_NO_KEY = 6.2
_RATE_DELAY_KEY = 0.7
_CACHE_TTL = 7 * 86400

_CACHE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "reports", "cve_cache.json",
)

_IMPACT_PATTERNS = [
    (r"remote code exec|rce|arbitrary code|unauthenticated.*exec|execute arbitrary",
     "Remote Code Execution", "🔴"),
    (r"privilege esc|elevat.*privilege|local privilege|gain.*root|become.*admin",
     "Privilege Escalation", "🟠"),
    (r"denial.of.service|dos\b|crash|infinite loop|resource exhaust|memory leak",
     "Denial of Service", "🟢"),
    (r"authentication bypass|bypass.*auth|skip.*auth|unauthenticated access",
     "Authentication Bypass", "🟠"),
    (r"sql injection|sqli|os command inject|command inject|ldap inject|xpath inject",
     "Injection", "🔴"),
    (r"cross.site script|xss\b|reflected.*script|stored.*script", "XSS", "🟡"),
    (r"information disclos|sensitive.*data|credential.*expos|password.*expos|"
     r"path traversal|directory traversal|file read", "Information Disclosure", "🟡"),
    (r"buffer overflow|heap overflow|stack overflow|memory corruption|use.after.free",
     "Memory Corruption", "🔴"),
    (r"man.in.the.middle|mitm|ssl strip|certificate.*forg|weak.*cipher|"
     r"downgrade.*attack|poodle|beast\b|heartbleed", "Cryptographic Weakness", "🟠"),
]


def classify_impact(description: str) -> tuple:
    d = (description or "").lower()
    for pat, label, icon in _IMPACT_PATTERNS:
        if re.search(pat, d):
            return label, icon
    return "Other", "⚪"


def _load_cache() -> Dict[str, Any]:
    if not os.path.exists(_CACHE_PATH):
        return {}
    try:
        with open(_CACHE_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
        cutoff = time.time() - _CACHE_TTL
        return {k: v["data"] for k, v in raw.items()
                if isinstance(v, dict) and "ts" in v and v["ts"] >= cutoff}
    except Exception:
        return {}


def _save_cache(cache: Dict[str, Any]) -> None:
    try:
        os.makedirs(os.path.dirname(_CACHE_PATH), exist_ok=True)
        now = time.time()
        with open(_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump({k: {"data": v, "ts": now} for k, v in cache.items()}, f)
    except Exception:
        pass


def _extract_service_strings(hosts: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
    svc_to_ips: Dict[str, Set[str]] = {}

    def add(svc: str, ip: str) -> None:
        svc = (svc or "").strip()
        if len(svc) >= 3:
            svc_to_ips.setdefault(svc, set()).add(ip)

    for h in hosts:
        ip = h.get("ip", "")
        for hint in (h.get("service_hints") or {}).values():
            if not isinstance(hint, dict):
                continue
            banner = hint.get("banner", "")
            if banner.startswith("SSH-"):
                m = re.search(r"SSH-\d+\.\d+-(\S+)", banner)
                if m:
                    add(m.group(1), ip)
            http = hint.get("http") or {}
            srv = (http.get("headers") or {}).get("server") or (http.get("headers") or {}).get("Server")
            if srv:
                add(srv[:100], ip)
            tls = hint.get("tls") or {}
            cn = tls.get("common_name") or tls.get("subject")
            if cn:
                add(str(cn)[:80], ip)
        snmp = h.get("snmp") or {}
        if snmp.get("sysDescr"):
            add(snmp["sysDescr"][:120], ip)
    return svc_to_ips


def _query_nvd(keyword: str, results: int, rate_delay: float,
               api_key: Optional[str] = None) -> List[Dict[str, Any]]:
    try:
        import requests
    except ImportError:
        return []
    headers = {"User-Agent": "OmniRecon/7"}
    if api_key:
        headers["apiKey"] = api_key
    try:
        r = requests.get(_NVD_API, headers=headers, timeout=20, params={
            "keywordSearch": keyword,
            "resultsPerPage": min(max(1, results), 2000), "startIndex": 0,
        })
        if r.status_code != 200:
            time.sleep(rate_delay)
            return []
        data = r.json()
    except Exception:
        time.sleep(rate_delay)
        return []

    out: List[Dict[str, Any]] = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        score = severity = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                cvss = metrics[key][0].get("cvssData", {})
                score = cvss.get("baseScore")
                severity = cvss.get("baseSeverity") or metrics[key][0].get("baseSeverity")
                break
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        label, icon = classify_impact(desc)
        out.append({
            "id": cve.get("id", ""), "score": score, "severity": severity,
            "description": desc[:300], "published": cve.get("published", "")[:10],
            "impact": label, "impact_icon": icon, "kev": False,
        })
    time.sleep(rate_delay)
    return out


def _load_kev() -> Set[str]:
    try:
        import requests
        r = requests.get(_KEV_URL, timeout=20, headers={"User-Agent": "OmniRecon/7"})
        r.raise_for_status()
        return {v["cveID"] for v in r.json().get("vulnerabilities", []) if v.get("cveID")}
    except Exception:
        return set()


def correlate(hosts: List[Dict[str, Any]], min_score: float = 6.0,
              results_per_query: int = 10, use_kev: bool = True,
              api_key: Optional[str] = None) -> Dict[str, Any]:
    """Returns {by_host: {ip: [cve,...]}, findings: [...], queried: [...], kev_loaded: N}."""
    svc_to_ips = _extract_service_strings(hosts)
    if not svc_to_ips:
        return {"by_host": {}, "findings": [], "queried": [],
                "note": "No service versions to correlate (run with service hints)."}

    kev = _load_kev() if use_kev else set()
    cache = _load_cache()
    rate_delay = _RATE_DELAY_KEY if api_key else _RATE_DELAY_NO_KEY

    by_host: Dict[str, List[Dict[str, Any]]] = {}
    for svc, ips in svc_to_ips.items():
        key = hashlib.md5(f"{svc}|rpp={results_per_query}".encode(),
                          usedforsecurity=False).hexdigest()
        if key in cache:
            cve_list = cache[key]
        else:
            cve_list = _query_nvd(svc, results_per_query, rate_delay, api_key)
            cache[key] = cve_list
            _save_cache(cache)

        if min_score > 0:
            cve_list = [c for c in cve_list if c.get("score") is not None
                        and float(c["score"]) >= min_score]
        for c in cve_list:
            c["kev"] = c["id"] in kev

        high = [c for c in cve_list if (c.get("score") or 0) >= 4.0]
        info = [c for c in cve_list if (c.get("score") or 0) < 4.0]
        filtered = high if high else info[:3]

        for ip in ips:
            existing = by_host.setdefault(ip, [])
            seen = {c["id"] for c in existing}
            for c in filtered:
                if c["id"] not in seen:
                    c2 = dict(c); c2["service"] = svc; c2["ip"] = ip
                    existing.append(c2)
                    seen.add(c["id"])

    findings: List[Dict[str, Any]] = []
    for ip in by_host:
        by_host[ip].sort(key=lambda c: (not c.get("kev", False), -(c.get("score") or 0)))
        findings.extend(by_host[ip])
    findings.sort(key=lambda c: (not c.get("kev", False), -(c.get("score") or 0)))

    return {"by_host": by_host, "findings": findings,
            "queried": sorted(svc_to_ips.keys()), "kev_loaded": len(kev)}
