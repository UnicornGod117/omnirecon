"""
Topology — derive a simple network graph from discovered hosts.

Produces structured nodes + edges (gateway-centric star, with this host and the
gateway highlighted) that any front-end can render. Mode/interface-agnostic.
"""

from __future__ import annotations

from typing import Any, Dict, List


def build(hosts: List[Dict[str, Any]], routes: Dict[str, Any]) -> Dict[str, Any]:
    gateway = (routes or {}).get("default_gateway")
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    # Synthesize a gateway node even if it wasn't separately discovered.
    gw_present = any(h["ip"] == gateway for h in hosts)
    if gateway and not gw_present:
        nodes.append({"id": gateway, "label": gateway, "role": "gateway",
                      "device_type": "Network / NAS"})

    for h in hosts:
        role = "gateway" if h["ip"] == gateway else ("self" if h.get("is_self") else "host")
        label = h.get("device_name") or h["ip"]
        nodes.append({
            "id": h["ip"],
            "label": label,
            "ip": h["ip"],
            "role": role,
            "device_type": h.get("device_type"),
            "icon": h.get("device_icon"),
            "vendor": h.get("vendor"),
            "open_ports": h.get("open_ports", []),
        })
        # Star topology: everything hangs off the gateway.
        if gateway and h["ip"] != gateway:
            edges.append({"from": gateway, "to": h["ip"]})

    return {
        "gateway": gateway,
        "node_count": len(nodes),
        "nodes": nodes,
        "edges": edges,
    }
