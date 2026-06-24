"""
Network anomaly analysis — ARP spoofing / MITM and rogue DHCP.

Pure, post-collection analysis over the normalized report (no I/O), so it is
safe to run on every scan and folds straight into hygiene. Builds directly on
the ARP/neighbor table and passive observations the engine already gathers.

Detects:
  - One MAC claiming multiple IPs (ARP-cache poisoning signature).
  - The gateway sharing a MAC with another host (classic MITM positioning).
  - A gateway MAC that changed vs a supplied baseline (monitor mode).
  - More than one DHCP server answering on the segment (rogue DHCP).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def _finding(severity, ip, title, detail, rec, category="Anomaly"):
    return {"severity": severity, "category": category, "ip": ip,
            "title": title, "detail": detail, "recommendation": rec}


def analyze(report: Dict[str, Any],
            baseline_gateway_mac: Optional[str] = None) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    nb = (report.get("neighbors") or {}).get("neighbors", [])
    gateway = (report.get("routes") or {}).get("default_gateway")

    # MAC → set of IPs (ignore incomplete entries).
    mac_to_ips: Dict[str, set] = {}
    gw_mac: Optional[str] = None
    for n in nb:
        mac = (n.get("mac") or "").lower()
        ip = n.get("ip")
        if not mac or not ip:
            continue
        mac_to_ips.setdefault(mac, set()).add(ip)
        if ip == gateway:
            gw_mac = mac

    for mac, ips in mac_to_ips.items():
        # Link-local/multicast/broadcast macs aren't host identities.
        if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            continue
        ipv4s = {ip for ip in ips if ":" not in ip}
        if len(ipv4s) > 1:
            sev = "high" if gateway in ipv4s else "medium"
            findings.append(_finding(
                sev, gateway if gateway in ipv4s else sorted(ipv4s)[0],
                "One MAC claims multiple IPs",
                f"MAC {mac} is mapped to {sorted(ipv4s)} in the ARP table — "
                "a hallmark of ARP-cache poisoning / MITM.",
                "Verify these are legitimately the same device (e.g. a router with "
                "several VIPs); otherwise investigate for ARP spoofing."))

    # Gateway MAC also serving another IP → attacker likely positioned as MITM.
    if gw_mac and gateway:
        others = sorted(ip for ip in mac_to_ips.get(gw_mac, set())
                        if ip != gateway and ":" not in ip)
        if others:
            findings.append(_finding(
                "high", gateway, "Gateway MAC shared with another host",
                f"The gateway ({gateway}) and {others} share MAC {gw_mac}.",
                "Strong ARP-spoofing indicator — isolate and investigate immediately.",
                category="MITM"))

    # Gateway MAC changed vs a known baseline (monitor mode passes this in).
    if baseline_gateway_mac and gw_mac and \
            baseline_gateway_mac.lower() != gw_mac.lower():
        findings.append(_finding(
            "high", gateway, "Gateway MAC changed",
            f"The gateway MAC changed from {baseline_gateway_mac} to {gw_mac} "
            "since the baseline.",
            "Could be a hardware swap — or an attacker impersonating the gateway. "
            "Confirm the change was expected.", category="MITM"))

    # Rogue DHCP — more than one server answering.
    dhcp_servers = report.get("dhcp_servers")
    if isinstance(dhcp_servers, list) and len(dhcp_servers) > 1:
        findings.append(_finding(
            "high", None, "Multiple DHCP servers on the segment",
            f"DHCP offers seen from {dhcp_servers} — a rogue DHCP server can "
            "redirect traffic (DNS/gateway hijack).",
            "Confirm every DHCP server is authorised; shut down any rogue server.",
            category="Rogue DHCP"))

    return findings
