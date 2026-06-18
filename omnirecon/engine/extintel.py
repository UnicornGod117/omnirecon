"""
External intelligence — cross-reference public IPs against Shodan, Censys, and
VirusTotal.

This is opt-in network I/O, in the same spirit as `intel.py` (NVD/KEV): given a
finished report, it looks up the *publicly routable* addresses involved (the
host's own public IP, plus any non-RFC1918 hosts discovered) and attaches what
the three big exposure databases know about them.

Private/LAN addresses are skipped — third-party databases have nothing useful to
say about 192.168.x.x, and we never want to leak an internal target list. Each
provider is independent: missing an API key just skips that provider.

Stdlib only (urllib). No SDKs. Degrades to {} when no keys are configured.

Keys come from (first found wins):
    1. the path passed to enrich(config_path=…)
    2. $OMNIRECON_EXTINTEL
    3. reports/extintel.json
    4. .omnirecon/extintel.json
    5. environment variables (SHODAN_API_KEY, CENSYS_API_ID, CENSYS_API_SECRET,
       VT_API_KEY / VIRUSTOTAL_API_KEY)

Config file shape (see examples/extintel.json):
    {
      "shodan_api_key": "…",
      "censys_api_id": "…",
      "censys_api_secret": "…",
      "virustotal_api_key": "…",
      "max_targets": 8
    }
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional

from .primitives import is_private_or_lan_ip

StageCb = Optional[Callable[[str], None]]

DEFAULT_CONFIG_FILES = [
    os.path.join("reports", "extintel.json"),
    os.path.join(".omnirecon", "extintel.json"),
]
_TIMEOUT = 10


# ── Config ────────────────────────────────────────────────────────────────────

def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    """Merge a config file (if any) with environment-variable fallbacks."""
    cfg: Dict[str, Any] = {}
    candidates: List[str] = []
    if path:
        candidates.append(path)
    elif os.environ.get("OMNIRECON_EXTINTEL"):
        candidates.append(os.environ["OMNIRECON_EXTINTEL"])
    else:
        candidates.extend(DEFAULT_CONFIG_FILES)
    for cand in candidates:
        if cand and os.path.exists(cand):
            try:
                with open(cand, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    cfg.update(loaded)
                break
            except (OSError, ValueError):
                continue
    cfg.setdefault("shodan_api_key", os.environ.get("SHODAN_API_KEY", ""))
    cfg.setdefault("censys_api_id", os.environ.get("CENSYS_API_ID", ""))
    cfg.setdefault("censys_api_secret", os.environ.get("CENSYS_API_SECRET", ""))
    cfg.setdefault("virustotal_api_key",
                   os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY", ""))
    return cfg


def _has_any_key(cfg: Dict[str, Any]) -> bool:
    return bool(cfg.get("shodan_api_key") or cfg.get("virustotal_api_key")
                or (cfg.get("censys_api_id") and cfg.get("censys_api_secret")))


# ── HTTP ──────────────────────────────────────────────────────────────────────

def _get_json(url: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}"}
    except (urllib.error.URLError, ValueError, OSError) as e:
        return {"error": str(e)}


# ── Providers ─────────────────────────────────────────────────────────────────

def query_shodan(ip: str, key: str) -> Dict[str, Any]:
    data = _get_json(f"https://api.shodan.io/shodan/host/{ip}?key={key}")
    if "error" in data:
        return data
    return {
        "org": data.get("org"),
        "isp": data.get("isp"),
        "os": data.get("os"),
        "hostnames": data.get("hostnames") or [],
        "ports": sorted(data.get("ports") or []),
        "tags": data.get("tags") or [],
        "vulns": sorted(data.get("vulns") or []),
        "country": data.get("country_name"),
    }


def query_virustotal(ip: str, key: str) -> Dict[str, Any]:
    data = _get_json(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                     headers={"x-apikey": key})
    if "error" in data:
        return data
    attrs = (data.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    return {
        "malicious": int(stats.get("malicious", 0)),
        "suspicious": int(stats.get("suspicious", 0)),
        "harmless": int(stats.get("harmless", 0)),
        "reputation": attrs.get("reputation"),
        "as_owner": attrs.get("as_owner"),
        "country": attrs.get("country"),
    }


def query_censys(ip: str, api_id: str, api_secret: str) -> Dict[str, Any]:
    token = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
    data = _get_json(f"https://search.censys.io/api/v2/hosts/{ip}",
                     headers={"Authorization": f"Basic {token}"})
    if "error" in data:
        return data
    result = (data.get("result") or {})
    services = result.get("services") or []
    return {
        "services": [{"port": s.get("port"), "service": s.get("service_name")}
                     for s in services],
        "ports": sorted({s.get("port") for s in services if s.get("port")}),
        "asn": (result.get("autonomous_system") or {}).get("name"),
        "country": (result.get("location") or {}).get("country"),
    }


# ── Findings ──────────────────────────────────────────────────────────────────

def _findings_for(ip: str, providers: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    vt = providers.get("virustotal") or {}
    mal = vt.get("malicious") or 0
    if isinstance(mal, int) and mal > 0:
        sev = "high" if mal >= 5 else "medium"
        out.append({
            "severity": sev, "category": "Reputation", "ip": ip,
            "title": "IP flagged malicious by VirusTotal",
            "detail": f"{mal} vendor(s) flag {ip} as malicious "
                      f"(suspicious: {vt.get('suspicious', 0)}).",
            "recommendation": "Investigate this address; if it is yours, request "
                              "delisting and check for compromise.",
            "source": "virustotal",
        })
    shodan = providers.get("shodan") or {}
    vulns = shodan.get("vulns") or []
    if vulns:
        shown = ", ".join(vulns[:8]) + (" …" if len(vulns) > 8 else "")
        out.append({
            "severity": "high", "category": "Exposure", "ip": ip,
            "title": "Known vulnerabilities indexed by Shodan",
            "detail": f"Shodan associates {len(vulns)} CVE(s) with {ip}: {shown}.",
            "recommendation": "Patch the affected services; confirm the host "
                              "should be internet-exposed at all.",
            "source": "shodan",
        })
    return out


# ── Entry point ───────────────────────────────────────────────────────────────

def _target_ips(report: Dict[str, Any]) -> List[str]:
    ips: List[str] = []
    pub = report.get("public_ip")
    if isinstance(pub, str) and pub and not is_private_or_lan_ip(pub):
        ips.append(pub)
    elif isinstance(pub, dict) and pub.get("ip") and not is_private_or_lan_ip(pub["ip"]):
        ips.append(pub["ip"])
    for h in (report.get("discovery") or {}).get("hosts", []):
        ip = h.get("ip")
        if ip and not is_private_or_lan_ip(ip) and ip not in ips:
            ips.append(ip)
    return ips


def enrich(report: Dict[str, Any], config_path: Optional[str] = None,
           stage_cb: StageCb = None) -> Dict[str, Any]:
    """Look up the report's public IPs and return an external-intel block."""
    cfg = load_config(config_path)
    if not _has_any_key(cfg):
        return {"by_ip": {}, "findings": [], "skipped": "no API keys configured"}

    targets = _target_ips(report)[: int(cfg.get("max_targets", 8) or 8)]
    if not targets:
        return {"by_ip": {}, "findings": [], "skipped": "no public IPs to query"}

    by_ip: Dict[str, Any] = {}
    findings: List[Dict[str, Any]] = []
    enabled: List[str] = []
    if cfg.get("shodan_api_key"):
        enabled.append("shodan")
    if cfg.get("virustotal_api_key"):
        enabled.append("virustotal")
    if cfg.get("censys_api_id") and cfg.get("censys_api_secret"):
        enabled.append("censys")

    for ip in targets:
        if stage_cb:
            stage_cb(f"external intel {ip}")
        providers: Dict[str, Any] = {}
        if cfg.get("shodan_api_key"):
            providers["shodan"] = query_shodan(ip, cfg["shodan_api_key"])
        if cfg.get("virustotal_api_key"):
            providers["virustotal"] = query_virustotal(ip, cfg["virustotal_api_key"])
        if cfg.get("censys_api_id") and cfg.get("censys_api_secret"):
            providers["censys"] = query_censys(ip, cfg["censys_api_id"],
                                               cfg["censys_api_secret"])
        by_ip[ip] = providers
        findings.extend(_findings_for(ip, providers))

    return {"by_ip": by_ip, "findings": findings, "providers": enabled,
            "queried": targets}
