"""
Topology — derive a simple network graph from discovered hosts.

Produces structured nodes + edges (gateway-centric star, with this host and the
gateway highlighted) that any front-end can render. Mode/interface-agnostic.

The gateway node is enriched with everything we know about the router we are
riding: its ARP/MAC + vendor, and — when we are on Wi-Fi — the wireless link
details (SSID, BSSID, RSSI / signal quality, channel/band, PHY rates, BSS
beacon info). This lets a front-end map *which* AP/router we are attached to and
how strong that uplink is.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def _neighbor_lookup(neighbors: Optional[Dict[str, Any]],
                     ip: Optional[str]) -> Dict[str, Any]:
    """Pull the ARP/NDP entry for an IP out of a neighbor table dict."""
    if not neighbors or not ip:
        return {}
    for n in neighbors.get("neighbors", []):
        if n.get("ip") == ip:
            return n
    return {}


def build(hosts: List[Dict[str, Any]],
          routes: Dict[str, Any],
          wifi: Optional[Dict[str, Any]] = None,
          neighbors: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    gateway = (routes or {}).get("default_gateway")
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    gw_host = next((h for h in hosts if h.get("ip") == gateway), None)
    gw_arp = _neighbor_lookup(neighbors, gateway)

    # Consolidated picture of the router/AP we hang off, for front-ends to map.
    gateway_info: Dict[str, Any] = {
        "ip": gateway,
        "mac": (gw_host or {}).get("mac") or gw_arp.get("mac"),
        "vendor": (gw_host or {}).get("vendor"),
        "device_name": (gw_host or {}).get("device_name")
        or (gw_host or {}).get("reverse_dns"),
        "arp_state": gw_arp.get("state"),
        "interface": gw_arp.get("interface"),
        "open_ports": (gw_host or {}).get("open_ports", []),
        "uplink": "wireless" if (wifi or {}).get("connected") else "wired/unknown",
        "wifi": wifi if (wifi or {}).get("connected") else None,
    }

    # Synthesize a gateway node even if it wasn't separately discovered.
    gw_present = gw_host is not None
    if gateway and not gw_present:
        nodes.append({"id": gateway, "label": gateway, "ip": gateway,
                      "role": "gateway", "device_type": "Network / NAS",
                      "mac": gateway_info["mac"], "gateway_info": gateway_info})

    for h in hosts:
        role = "gateway" if h["ip"] == gateway else ("self" if h.get("is_self") else "host")
        label = h.get("device_name") or h["ip"]
        node: Dict[str, Any] = {
            "id": h["ip"],
            "label": label,
            "ip": h["ip"],
            "role": role,
            "device_type": h.get("device_type"),
            "icon": h.get("device_icon"),
            "vendor": h.get("vendor"),
            "mac": h.get("mac"),
            "open_ports": h.get("open_ports", []),
        }
        if role == "gateway":
            node["gateway_info"] = gateway_info
        nodes.append(node)
        # Star topology: everything hangs off the gateway.
        if gateway and h["ip"] != gateway:
            edge = {"from": gateway, "to": h["ip"]}
            # Highlight our own uplink edge with the live signal reading.
            if h.get("is_self") and gateway_info.get("wifi"):
                w = gateway_info["wifi"]
                edge["uplink"] = True
                edge["signal_dbm"] = w.get("signal_dbm")
                edge["signal_pct"] = w.get("signal_pct")
                edge["label"] = "Wi-Fi"
            edges.append(edge)

    return {
        "gateway": gateway,
        "gateway_info": gateway_info,
        "wifi": wifi,
        "node_count": len(nodes),
        "nodes": nodes,
        "edges": edges,
    }
