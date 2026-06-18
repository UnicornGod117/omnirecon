"""
Example AnalysisPlugin — flags hosts with a large attack surface.

Analysis plugins are pure: they read the finished report and return findings.
They run on every scan (including monitor mode), so they must do no I/O.

Drop a file like this into ./plugins (or $OMNIRECON_PLUGINS) and run a scan with
plugins enabled (web checkbox, or `omnirecon scan --plugins`).
"""

from omnirecon.engine.plugins import AnalysisPlugin, finding

THRESHOLD = 8


class AttackSurfacePlugin(AnalysisPlugin):
    name = "attack-surface"
    description = f"Flag hosts exposing {THRESHOLD}+ open ports"

    def analyze(self, report):
        out = []
        hosts = (report.get("discovery") or {}).get("hosts", [])
        for h in hosts:
            ports = h.get("open_ports") or []
            if len(ports) >= THRESHOLD and not h.get("is_self"):
                name = h.get("device_name") or h.get("ip")
                out.append(finding(
                    "low", "Attack Surface", h.get("ip"),
                    "Large attack surface",
                    f"{name} exposes {len(ports)} open ports: {sorted(ports)}.",
                    "Review whether every listening service is required; close "
                    "or firewall the ones that are not.",
                ))
        return out
