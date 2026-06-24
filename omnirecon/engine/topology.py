"""
Topology — derive a network graph from discovered hosts and turn it into a real
map rather than a flat star.

Beyond the gateway-centric node/edge set it now derives:
  - the router/AP uplink (MAC/vendor/ARP + Wi-Fi signal/BSSID/BSS),
  - subnet segments (nodes grouped by the network they live on),
  - per-AP grouping of wireless clients (by associated BSSID),
  - Layer-2 switch nodes + the ports hosts plug into (from LLDP/CDP),
  - real communication edges (who talks to whom, from passive capture),
  - critical-node / single-point-of-failure inference,
  - exports to GraphML / Graphviz DOT / Mermaid for other tools.

All inputs beyond `hosts`/`routes` are optional, so callers can pass only what
they collected. Mode/interface-agnostic, pure (no I/O).
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional


def _neighbor_lookup(neighbors: Optional[Dict[str, Any]],
                     ip: Optional[str]) -> Dict[str, Any]:
    if not neighbors or not ip:
        return {}
    for n in neighbors.get("neighbors", []):
        if n.get("ip") == ip:
            return n
    return {}


def _subnet_of(ip: str, local_networks: Optional[List[Dict[str, Any]]]) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net in local_networks or []:
        try:
            if addr in ipaddress.ip_network(net.get("cidr"), strict=False):
                return net.get("cidr")
        except Exception:
            continue
    return None


def _segments(hosts: List[Dict[str, Any]],
              local_networks: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    by_cidr: Dict[str, List[str]] = {}
    for h in hosts:
        cidr = _subnet_of(h["ip"], local_networks) or "other"
        by_cidr.setdefault(cidr, []).append(h["ip"])
    return [{"cidr": c, "host_count": len(ips), "hosts": sorted(ips)}
            for c, ips in sorted(by_cidr.items())]


def _critical_nodes(hosts: List[Dict[str, Any]], gateway: Optional[str],
                    dns_servers: Optional[List[str]],
                    conversations: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Infer load-bearing nodes (gateway, DNS, busiest hubs) → SPOF candidates."""
    crit: Dict[str, Dict[str, Any]] = {}
    if gateway:
        crit[gateway] = {"ip": gateway, "reasons": ["default gateway"]}
    for d in dns_servers or []:
        if any(h["ip"] == d for h in hosts) or d == gateway:
            crit.setdefault(d, {"ip": d, "reasons": []})["reasons"].append("DNS resolver")
    # Conversation hubs: hosts talking to many distinct peers.
    peers: Dict[str, set] = {}
    for c in conversations or []:
        peers.setdefault(c["a"], set()).add(c["b"])
        peers.setdefault(c["b"], set()).add(c["a"])
    for ip, p in peers.items():
        if len(p) >= 5:
            crit.setdefault(ip, {"ip": ip, "reasons": []})["reasons"].append(
                f"communication hub ({len(p)} peers)")
    out = list(crit.values())
    for c in out:
        c["spof"] = "default gateway" in c["reasons"] or len(c["reasons"]) >= 2
    return out


def build(hosts: List[Dict[str, Any]],
          routes: Dict[str, Any],
          wifi: Optional[Dict[str, Any]] = None,
          neighbors: Optional[Dict[str, Any]] = None,
          local_networks: Optional[List[Dict[str, Any]]] = None,
          dns_servers: Optional[List[str]] = None,
          l2_neighbors: Optional[List[Dict[str, Any]]] = None,
          conversations: Optional[List[Dict[str, Any]]] = None,
          ap_survey: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    gateway = (routes or {}).get("default_gateway")
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    gw_host = next((h for h in hosts if h.get("ip") == gateway), None)
    gw_arp = _neighbor_lookup(neighbors, gateway)

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

    if gateway and gw_host is None:
        nodes.append({"id": gateway, "label": gateway, "ip": gateway,
                      "role": "gateway", "device_type": "Network / NAS",
                      "mac": gateway_info["mac"], "gateway_info": gateway_info})

    for h in hosts:
        role = "gateway" if h["ip"] == gateway else ("self" if h.get("is_self") else "host")
        node: Dict[str, Any] = {
            "id": h["ip"], "label": h.get("device_name") or h["ip"], "ip": h["ip"],
            "role": role, "device_type": h.get("device_type"),
            "icon": h.get("device_icon"), "vendor": h.get("vendor"),
            "mac": h.get("mac"), "open_ports": h.get("open_ports", []),
            "subnet": _subnet_of(h["ip"], local_networks),
        }
        if role == "gateway":
            node["gateway_info"] = gateway_info
        nodes.append(node)
        if gateway and h["ip"] != gateway:
            edge = {"from": gateway, "to": h["ip"], "type": "l3"}
            if h.get("is_self") and gateway_info.get("wifi"):
                w = gateway_info["wifi"]
                edge.update({"uplink": True, "label": "Wi-Fi",
                             "signal_dbm": w.get("signal_dbm"),
                             "signal_pct": w.get("signal_pct")})
            edges.append(edge)

    # Layer-2 switch nodes + the port each link plugs into (from LLDP/CDP).
    switches: List[Dict[str, Any]] = []
    for sw in l2_neighbors or []:
        sid = "sw:" + (sw.get("chassis_id") or sw.get("system_name")
                       or sw.get("source_mac") or "switch")
        label = sw.get("system_name") or sw.get("chassis_id") or "switch"
        nodes.append({
            "id": sid, "label": f"switch {label}", "role": "switch",
            "device_type": "Switch", "mgmt_addr": sw.get("mgmt_addr"),
            "port": sw.get("port_id"), "vlan": sw.get("vlan"),
            "protocol": sw.get("protocol"),
        })
        switches.append({"id": sid, **sw})
        if gateway:
            edges.append({"from": sid, "to": gateway, "type": "l2"})

    # Real communication edges from passive capture (overlay, dashed).
    comm_edges: List[Dict[str, Any]] = []
    host_ids = {h["ip"] for h in hosts}
    for c in conversations or []:
        if c["a"] in host_ids and c["b"] in host_ids:
            comm_edges.append({"from": c["a"], "to": c["b"], "type": "comm",
                               "packets": c.get("packets")})

    # Per-AP grouping of wireless clients (by associated BSSID).
    ap_groups: List[Dict[str, Any]] = []
    for ap in ap_survey or []:
        if ap.get("connected"):
            ap_groups.append({"bssid": ap.get("bssid"), "ssid": ap.get("ssid"),
                              "clients": [h["ip"] for h in hosts if h.get("is_self")]})

    return {
        "gateway": gateway,
        "gateway_info": gateway_info,
        "wifi": wifi,
        "node_count": len(nodes),
        "nodes": nodes,
        "edges": edges,
        "comm_edges": comm_edges,
        "segments": _segments(hosts, local_networks),
        "switches": switches,
        "ap_groups": ap_groups,
        "critical_nodes": _critical_nodes(hosts, gateway, dns_servers, conversations),
    }


# ── Exports ───────────────────────────────────────────────────────────────────

def to_mermaid(topo: Dict[str, Any]) -> str:
    """Render the graph as a Mermaid flowchart."""
    def nid(x: str) -> str:
        return "n_" + "".join(ch if ch.isalnum() else "_" for ch in str(x))
    lines = ["graph TD"]
    for n in topo.get("nodes", []):
        label = str(n.get("label") or n.get("id")).replace('"', "'")
        shape = ("([%s])" if n.get("role") == "gateway" else
                 "{{%s}}" if n.get("role") == "switch" else
                 "[%s]") % label
        lines.append(f"  {nid(n['id'])}{shape}")
    for e in topo.get("edges", []):
        arrow = "-.->" if e.get("type") == "l2" else "-->"
        lbl = f"|{e['label']}|" if e.get("label") else ""
        lines.append(f"  {nid(e['from'])} {arrow}{lbl} {nid(e['to'])}")
    for e in topo.get("comm_edges", []):
        lines.append(f"  {nid(e['from'])} -.-> {nid(e['to'])}")
    return "\n".join(lines)


def to_dot(topo: Dict[str, Any]) -> str:
    """Render the graph as Graphviz DOT."""
    def q(x: str) -> str:
        return '"' + str(x).replace('"', '\\"') + '"'
    lines = ["graph omnirecon {", "  layout=neato;", "  node [style=filled];"]
    for n in topo.get("nodes", []):
        color = {"gateway": "gold", "self": "lightblue",
                 "switch": "lightgreen"}.get(n.get("role"), "white")
        lines.append(f"  {q(n['id'])} [label={q(n.get('label') or n['id'])}, "
                     f"fillcolor={q(color)}];")
    seen = set()
    for e in topo.get("edges", []):
        key = tuple(sorted((e["from"], e["to"])))
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"  {q(e['from'])} -- {q(e['to'])};")
    lines.append("}")
    return "\n".join(lines)


def to_graphml(topo: Dict[str, Any]) -> str:
    """Render the graph as GraphML (Cytoscape/Gephi/yEd importable)."""
    import xml.sax.saxutils as su
    parts = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
             '<key id="label" for="node" attr.name="label" attr.type="string"/>',
             '<key id="role" for="node" attr.name="role" attr.type="string"/>',
             '<graph edgedefault="undirected">']
    for n in topo.get("nodes", []):
        parts.append(f'<node id={su.quoteattr(str(n["id"]))}>'
                     f'<data key="label">{su.escape(str(n.get("label") or n["id"]))}</data>'
                     f'<data key="role">{su.escape(str(n.get("role") or ""))}</data></node>')
    for i, e in enumerate(topo.get("edges", []) + topo.get("comm_edges", [])):
        parts.append(f'<edge id="e{i}" source={su.quoteattr(str(e["from"]))} '
                     f'target={su.quoteattr(str(e["to"]))}/>')
    parts.append('</graph></graphml>')
    return "\n".join(parts)


def export(topo: Dict[str, Any], fmt: str) -> str:
    return {"mermaid": to_mermaid, "dot": to_dot,
            "graphml": to_graphml}[fmt](topo)
