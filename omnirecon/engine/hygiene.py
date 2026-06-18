"""
Network hygiene analysis + exposure mapping.

A pure, post-discovery pass over the normalized report. It turns the raw facts
the engine already collected (open ports, TLS certs, DNS servers, device roles)
into *findings* — concrete, severity-rated issues an auditor cares about — and a
per-host *exposure map* that groups open ports into operational categories with
risk notes.

This module reads the report and returns analysis; it performs no I/O and runs
no probes, so it is free to run on every scan. Mode- and interface-agnostic.

Output:
    {
      "findings":  [ {severity, category, ip, title, detail, recommendation}, … ],
      "by_host":   { ip: {exposure: {group: [ports…]}, risk_notes: [...], findings: [...]} },
      "summary":   {counts: {high,medium,low,info}, grade: "B", score: 82, total: N},
    }
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

# ── Port taxonomy ─────────────────────────────────────────────────────────────

_PORT_SERVICE: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 515: "LPD", 587: "Submission", 631: "IPP",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS",
    3306: "MySQL", 3389: "RDP", 5000: "HTTP-alt", 5001: "HTTPS-alt",
    5432: "PostgreSQL", 5900: "VNC", 5901: "VNC", 6379: "Redis", 8000: "HTTP-alt",
    8006: "HTTP-alt", 8080: "HTTP-alt", 8443: "HTTPS-alt", 8888: "HTTP-alt",
    9090: "HTTP-alt", 9100: "JetDirect", 10000: "Webmin", 27017: "MongoDB",
}

_GROUPS: List[Tuple[str, set]] = [
    ("Management / Remote", {22, 23, 3389, 5900, 5901, 10000}),
    ("Web", {80, 443, 5000, 5001, 8000, 8006, 8080, 8443, 8888, 9090}),
    ("File Sharing", {21, 139, 445, 2049}),
    ("Mail", {25, 110, 143, 465, 587, 993, 995}),
    ("Database", {1433, 1521, 3306, 5432, 6379, 27017}),
    ("Printing", {515, 631, 9100}),
]

# Ports whose plaintext nature is itself the problem.
_PLAINTEXT = {23: "Telnet", 21: "FTP", 110: "POP3", 143: "IMAP", 25: "SMTP"}
_REMOTE_MGMT = {22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC", 5901: "VNC", 10000: "Webmin"}
_EXPOSED_DB = {1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 5432: "PostgreSQL",
               6379: "Redis", 27017: "MongoDB"}

# Roles considered legitimate homes for management / server services.
_SERVER_ROLES = {"server", "fileserver", "nas", "infra", "infrastructure",
                 "router", "gateway", "switch", "hypervisor", "dc"}

# Public resolvers — using one on a LAN host is worth noting for privacy/policy.
_PUBLIC_DNS = {
    "8.8.8.8": "Google", "8.8.4.4": "Google", "1.1.1.1": "Cloudflare",
    "1.0.0.1": "Cloudflare", "9.9.9.9": "Quad9", "208.67.222.222": "OpenDNS",
    "208.67.220.220": "OpenDNS", "4.2.2.2": "Level3",
}

_WEAK_TLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

_SEV_PENALTY = {"high": 15, "medium": 7, "low": 3, "info": 0}


def service_name(port: int) -> str:
    return _PORT_SERVICE.get(port, str(port))


# ── Exposure mapping ──────────────────────────────────────────────────────────

def map_exposure(open_ports: List[int]) -> Dict[str, List[str]]:
    """Group a host's open ports into operational categories."""
    ports = set(open_ports or [])
    out: Dict[str, List[str]] = {}
    for label, members in _GROUPS:
        hit = sorted(ports & members)
        if hit:
            out[label] = [f"{service_name(p)} ({p})" for p in hit]
    other = sorted(ports - {p for _, m in _GROUPS for p in m})
    if other:
        out["Other"] = [f"{service_name(p)} ({p})" for p in other]
    return out


# ── Finding builders ──────────────────────────────────────────────────────────

def _finding(severity: str, category: str, ip: Optional[str], title: str,
             detail: str, recommendation: str) -> Dict[str, Any]:
    return {"severity": severity, "category": category, "ip": ip,
            "title": title, "detail": detail, "recommendation": recommendation}


def _role_of(host: Dict[str, Any]) -> str:
    role = host.get("role") or (host.get("tags") or {}).get("role") or ""
    return str(role).strip().lower()


def _is_server(host: Dict[str, Any]) -> bool:
    return _role_of(host) in _SERVER_ROLES


def _host_findings(host: Dict[str, Any]) -> List[Dict[str, Any]]:
    ip = host.get("ip")
    ports = set(host.get("open_ports") or [])
    name = host.get("device_name") or host.get("reverse_dns")
    findings: List[Dict[str, Any]] = []

    # Plaintext / legacy protocols
    if 23 in ports:
        findings.append(_finding(
            "high", "Insecure Protocol", ip, "Telnet exposed",
            "Port 23 (Telnet) is open — credentials and sessions travel in cleartext.",
            "Disable Telnet and use SSH instead."))
    if 21 in ports:
        findings.append(_finding(
            "medium", "Insecure Protocol", ip, "FTP exposed",
            "Port 21 (FTP) is open — transfers and logins are unencrypted.",
            "Replace with SFTP/FTPS, or restrict to a trusted network."))
    for p, svc in ((110, "POP3"), (143, "IMAP")):
        if p in ports:
            findings.append(_finding(
                "low", "Insecure Protocol", ip, f"{svc} (plaintext) exposed",
                f"Port {p} ({svc}) is open without implicit TLS.",
                f"Prefer the TLS variant ({svc}S) and disable the plaintext port."))

    # SMB / file sharing exposure
    if ports & {139, 445}:
        findings.append(_finding(
            "low", "Exposure", ip, "SMB file sharing exposed",
            f"SMB ports {sorted(ports & {139, 445})} are reachable.",
            "Restrict SMB to trusted hosts; ensure SMBv1 is disabled."))

    # Exposed databases
    for p, svc in _EXPOSED_DB.items():
        if p in ports:
            findings.append(_finding(
                "medium", "Exposure", ip, f"{svc} database port exposed",
                f"Port {p} ({svc}) is reachable on the network.",
                "Bind the database to localhost or a private segment; require auth."))

    # Management interface on a device that isn't a server
    if not _is_server(host) and not host.get("is_self"):
        mgmt = sorted(ports & set(_REMOTE_MGMT))
        if mgmt:
            svc = ", ".join(f"{_REMOTE_MGMT[p]} ({p})" for p in mgmt)
            findings.append(_finding(
                "medium", "Exposure", ip, "Management interface on a non-server",
                f"{svc} is open on {name or ip} (role: {_role_of(host) or 'untagged'}).",
                "Confirm remote admin is intended here; tag the device's role to suppress."))

    # Plaintext HTTP management surface (HTTP open, no HTTPS counterpart)
    http_plain = ports & {80, 8000, 8006, 8080, 8888, 9090}
    https_any = ports & {443, 8443, 5001}
    if http_plain and not https_any:
        findings.append(_finding(
            "low", "Insecure Protocol", ip, "HTTP management interface (no TLS)",
            f"HTTP ports {sorted(http_plain)} are open with no HTTPS counterpart.",
            "Serve the admin UI over HTTPS and redirect HTTP."))

    # Missing reverse DNS on an otherwise reachable host
    if ports and not name and not host.get("is_self"):
        findings.append(_finding(
            "low", "Hygiene", ip, "Missing reverse DNS / name",
            f"{ip} has open ports but no resolvable name.",
            "Add a PTR record / DHCP reservation so the asset is identifiable."))

    # TLS certificate findings from service hints
    findings.extend(_cert_findings(host, ip))
    return findings


def _cert_findings(host: Dict[str, Any], ip: Optional[str]) -> List[Dict[str, Any]]:
    import datetime as dt
    out: List[Dict[str, Any]] = []
    now = dt.datetime.now()
    for port_str, hint in (host.get("service_hints") or {}).items():
        tls = hint.get("tls") if isinstance(hint, dict) else None
        if not isinstance(tls, dict):
            continue
        subject = tls.get("subject") or tls.get("common_name") or ""
        proto = tls.get("protocol")
        if proto in _WEAK_TLS:
            out.append(_finding(
                "medium", "TLS", ip, f"Weak TLS protocol on :{port_str}",
                f"{ip}:{port_str} negotiated {proto}.",
                "Disable SSLv3/TLSv1.0/1.1; require TLS 1.2+."))
        not_after = tls.get("not_after")
        if not_after:
            try:
                exp = dt.datetime.fromisoformat(
                    str(not_after).replace("Z", "+00:00")).replace(tzinfo=None)
                days = (exp - now).days
                if days < 0:
                    out.append(_finding(
                        "high", "TLS", ip, f"Expired certificate on :{port_str}",
                        f"{subject or ip}:{port_str} expired {abs(days)} day(s) ago.",
                        "Renew/replace the certificate immediately."))
                elif days <= 30:
                    out.append(_finding(
                        "medium", "TLS", ip, f"Certificate expiring on :{port_str}",
                        f"{subject or ip}:{port_str} expires in {days} day(s).",
                        "Renew the certificate before it lapses."))
            except (ValueError, TypeError):
                pass
        if tls.get("is_self_signed"):
            out.append(_finding(
                "low", "TLS", ip, f"Self-signed certificate on :{port_str}",
                f"{subject or ip}:{port_str} presents a self-signed certificate.",
                "Use a CA-issued (or internal-CA) certificate for trust."))
    return out


def _local_findings(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    dns = report.get("dns_servers") or []
    servers = dns if isinstance(dns, list) else dns.get("servers", []) if isinstance(dns, dict) else []
    public = [(s, _PUBLIC_DNS[s]) for s in servers if s in _PUBLIC_DNS]
    if public:
        listed = ", ".join(f"{ip} ({who})" for ip, who in public)
        out.append(_finding(
            "info", "Privacy", None, "Public DNS resolver in use",
            f"This host resolves via public DNS: {listed}.",
            "Use an internal resolver if DNS query privacy/logging matters."))
    return out


# ── SMBv1 from pentest, if present ────────────────────────────────────────────

def _pentest_findings(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    pentest = report.get("pentest") or {}
    for ip, modules in pentest.items():
        smb = (modules or {}).get("smb_enum") or {}
        if isinstance(smb, dict) and (smb.get("smbv1") or smb.get("smb_v1")):
            out.append(_finding(
                "high", "Legacy Protocol", ip, "SMBv1 enabled",
                f"{ip} accepts the deprecated, exploitable SMBv1 dialect.",
                "Disable SMBv1 (EternalBlue / WannaCry vector)."))
    return out


# ── Entry point ───────────────────────────────────────────────────────────────

def _grade(score: int) -> str:
    return ("A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70
            else "D" if score >= 60 else "F")


def analyze(report: Dict[str, Any]) -> Dict[str, Any]:
    hosts = (report.get("discovery") or {}).get("hosts", [])

    findings: List[Dict[str, Any]] = []
    by_host: Dict[str, Any] = {}

    for h in hosts:
        ip = h.get("ip")
        hf = _host_findings(h)
        findings.extend(hf)
        by_host[ip] = {
            "exposure": map_exposure(h.get("open_ports") or []),
            "risk_notes": [f["title"] for f in hf],
            "findings": hf,
        }

    findings.extend(_local_findings(report))
    findings.extend(_pentest_findings(report))

    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    score = 100
    for sev, n in counts.items():
        score -= _SEV_PENALTY.get(sev, 0) * n
    score = max(0, min(100, score))

    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: (order.get(f["severity"], 9), f.get("category", "")))

    return {
        "findings": findings,
        "by_host": by_host,
        "summary": {"counts": counts, "score": score, "grade": _grade(score),
                    "total": len(findings)},
    }
