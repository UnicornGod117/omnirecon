#!/usr/bin/env python3
import argparse
import concurrent.futures as cf
import datetime as dt
import html
import ipaddress
import itertools
import json
import os
import platform
import re
import socket
import subprocess
import sys
import textwrap
import time
from typing import Any, Dict, List, Optional, Tuple

import psutil
import requests

# Module-level pool for reverse DNS — avoids mutating the global socket timeout
_RDNS_POOL: cf.ThreadPoolExecutor = cf.ThreadPoolExecutor(max_workers=64, thread_name_prefix="rdns")


# ----------------------------
# Utilities
# ----------------------------

def now_stamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def safe_run(cmd: List[str], timeout: int = 10) -> Dict[str, Any]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "cmd": cmd,
            "returncode": p.returncode,
            "stdout": p.stdout.strip(),
            "stderr": p.stderr.strip()
        }
    except Exception as e:
        return {"cmd": cmd, "error": repr(e)}


def is_windows() -> bool:
    return platform.system().lower().startswith("win")


def is_macos() -> bool:
    return platform.system().lower() == "darwin"


def is_linux() -> bool:
    return platform.system().lower() == "linux"


def resolve_reverse(ip: str, timeout: float = 1.5) -> Optional[str]:
    try:
        fut = _RDNS_POOL.submit(socket.gethostbyaddr, ip)
        name, _, _ = fut.result(timeout=timeout)
        return name
    except Exception:
        return None


def tcp_probe(ip: str, port: int, timeout: float = 0.7) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def ping(ip: str, count: int = 1, timeout_s: int = 1) -> bool:
    # Best-effort cross-platform ping. Some systems restrict ICMP or require privileges.
    if is_windows():
        cmd = ["ping", "-n", str(count), "-w", str(timeout_s * 1000), ip]
    else:
        # -W is per-packet timeout in seconds on Linux; macOS differs slightly but tolerates -W in many versions.
        cmd = ["ping", "-c", str(count), "-W", str(timeout_s), ip]
    res = safe_run(cmd, timeout=timeout_s * count + 2)
    if "error" in res:
        return False
    return res.get("returncode", 1) == 0


# ----------------------------
# Data collection
# ----------------------------

def get_system_info() -> Dict[str, Any]:
    return {
        "timestamp_local": dt.datetime.now().isoformat(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "python": sys.version,
        "boot_time": dt.datetime.fromtimestamp(psutil.boot_time(), tz=dt.timezone.utc).isoformat(),
        "uptime_seconds": int(time.time() - psutil.boot_time()),
    }


def get_identity_info() -> Dict[str, Any]:
    hostname = socket.gethostname()
    fqdn = socket.getfqdn()
    return {"hostname": hostname, "fqdn": fqdn}


def get_public_ip() -> Dict[str, Any]:
    out = {"public_ip": None, "service": None, "error": None}
    services = [
        ("ipify", "https://api.ipify.org?format=json"),
        ("ifconfig.co", "https://ifconfig.co/json"),
    ]
    for name, url in services:
        try:
            r = requests.get(url, timeout=5, headers={"User-Agent": "OmniRecon/6.0"})
            r.raise_for_status()
            data = r.json()
            ip = data.get("ip") or data.get("ip_addr") or data.get("address")
            if ip:
                out["public_ip"] = ip
                out["service"] = name
                return out
        except Exception as e:
            out["error"] = f"{name}: {e!r}"
    return out


def get_interfaces() -> Dict[str, Any]:
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    out: Dict[str, Any] = {}
    for ifname, addr_list in addrs.items():
        entry = {
            "stats": {
                "isup": getattr(stats.get(ifname), "isup", None),
                "duplex": str(getattr(stats.get(ifname), "duplex", None)),
                "speed_mbps": getattr(stats.get(ifname), "speed", None),
                "mtu": getattr(stats.get(ifname), "mtu", None),
            },
            "addresses": []
        }
        for a in addr_list:
            entry["addresses"].append({
                "family": str(a.family),
                "address": a.address,
                "netmask": a.netmask,
                "broadcast": a.broadcast
            })
        out[ifname] = entry
    return out


def get_routes_and_gateway() -> Dict[str, Any]:
    """
    Default gateway: best-effort.
    - Windows: parse `route print -4`
    - macOS/Linux: parse `ip route` or `route -n get default` / `netstat -rn`
    """
    out: Dict[str, Any] = {"default_gateway": None, "raw": None}

    if is_windows():
        raw = safe_run(["route", "print", "-4"], timeout=10)
        out["raw"] = raw
        if "stdout" in raw and raw["stdout"]:
            # Look for 0.0.0.0 route line: "0.0.0.0          0.0.0.0      GATEWAY ..."
            for line in raw["stdout"].splitlines():
                line = line.strip()
                if line.startswith("0.0.0.0") and "0.0.0.0" in line:
                    parts = re.split(r"\s+", line)
                    if len(parts) >= 3:
                        out["default_gateway"] = parts[2]
                        break
        return out

    # macOS/Linux
    if is_linux():
        raw = safe_run(["ip", "route"], timeout=10)
        out["raw"] = raw
        if "stdout" in raw and raw["stdout"]:
            for line in raw["stdout"].splitlines():
                if line.startswith("default "):
                    # default via 192.168.1.1 dev wlan0 ...
                    m = re.search(r"\bvia\s+(\d+\.\d+\.\d+\.\d+)", line)
                    if m:
                        out["default_gateway"] = m.group(1)
                        break
        return out

    if is_macos():
        raw = safe_run(["route", "-n", "get", "default"], timeout=10)
        out["raw"] = raw
        if "stdout" in raw and raw["stdout"]:
            for line in raw["stdout"].splitlines():
                if "gateway:" in line:
                    out["default_gateway"] = line.split("gateway:")[-1].strip()
                    break
        return out

    # fallback
    out["raw"] = {"error": "Unsupported platform for route parsing"}
    return out


def get_dns_config() -> Dict[str, Any]:
    out: Dict[str, Any] = {"dns_servers": [], "raw": None}

    def _valid_ip(addr: str) -> bool:
        try:
            ipaddress.ip_address(addr.strip())
            return True
        except ValueError:
            return False

    try:
        if is_windows():
            raw = safe_run(["ipconfig", "/all"], timeout=12)
            out["raw"] = raw
            if raw.get("stdout"):
                # Parse "DNS Servers . . . . . . . . . . . : x.x.x.x"
                dns = []
                capture = False
                for line in raw["stdout"].splitlines():
                    if "DNS Servers" in line:
                        capture = True
                        addr = line.split(":", 1)[-1].strip()
                        if _valid_ip(addr):
                            dns.append(addr)
                        continue
                    if capture:
                        cont = line.strip()
                        if _valid_ip(cont):
                            dns.append(cont)
                        elif cont == "" or ":" in cont:
                            capture = False
                out["dns_servers"] = sorted(set(dns))
        elif is_macos():
            raw = safe_run(["scutil", "--dns"], timeout=12)
            out["raw"] = raw
            if raw.get("stdout"):
                candidates = re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", raw["stdout"])
                out["dns_servers"] = sorted({s for s in candidates if _valid_ip(s)})
        else:
            # Linux-ish: resolv.conf
            raw = safe_run(["cat", "/etc/resolv.conf"], timeout=6)
            out["raw"] = raw
            if raw.get("stdout"):
                dns = []
                for line in raw["stdout"].splitlines():
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2 and _valid_ip(parts[1]):
                            dns.append(parts[1])
                out["dns_servers"] = sorted(set(dns))
    except Exception as e:
        out["raw"] = {"error": repr(e)}

    return out


def get_listening_ports() -> List[Dict[str, Any]]:
    listening = []
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status == psutil.CONN_LISTEN:
                listening.append({
                    "local_ip": getattr(c.laddr, "ip", None),
                    "local_port": getattr(c.laddr, "port", None),
                    "pid": c.pid,
                })
    except Exception as e:
        listening.append({"error": repr(e)})
    return listening


def get_active_connections(limit: int = 200) -> List[Dict[str, Any]]:
    rows = []
    try:
        conns = psutil.net_connections(kind="inet")
        for c in conns[:limit]:
            rows.append({
                "status": c.status,
                "local": f"{getattr(c.laddr, 'ip', '')}:{getattr(c.laddr, 'port', '')}" if c.laddr else None,
                "remote": f"{getattr(c.raddr, 'ip', '')}:{getattr(c.raddr, 'port', '')}" if c.raddr else None,
                "pid": c.pid,
            })
    except Exception as e:
        rows.append({"error": repr(e)})
    return rows


def get_neighbor_table() -> Dict[str, Any]:
    """
    ARP/neighbor table: best-effort.
    - Windows: `arp -a`
    - macOS/Linux: `arp -a` or `ip neigh`
    """
    out: Dict[str, Any] = {"neighbors": [], "raw": []}

    if is_linux():
        raw = safe_run(["ip", "neigh"], timeout=8)
        out["raw"].append(raw)
        if raw.get("stdout"):
            # e.g. "192.168.1.10 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
            for line in raw["stdout"].splitlines():
                m = re.search(r"^(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)\s+(?:lladdr\s+([0-9a-f:]{17})\s+)?(\S+)", line.strip(), re.I)
                if m:
                    out["neighbors"].append({
                        "ip": m.group(1),
                        "interface": m.group(2),
                        "mac": m.group(3),
                        "state": m.group(4),
                    })
        return out

    # macOS / Windows / fallback
    raw = safe_run(["arp", "-a"], timeout=8)
    out["raw"].append(raw)
    if raw.get("stdout"):
        for line in raw["stdout"].splitlines():
            line = line.strip()
            # Windows format: "  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic"
            m_win = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]{17})\s+(\S+)", line, re.I)
            if m_win:
                out["neighbors"].append({
                    "ip": m_win.group(1),
                    "mac": m_win.group(2).lower().replace("-", ":"),
                    "state": m_win.group(3),
                    "interface": None,
                })
                continue
            # macOS-ish: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"
            m_os = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{17}|<incomplete>)\s+on\s+(\S+)", line, re.I)
            if m_os:
                out["neighbors"].append({
                    "ip": m_os.group(1),
                    "mac": None if m_os.group(2) == "<incomplete>" else m_os.group(2).lower(),
                    "state": None,
                    "interface": m_os.group(3),
                })
    return out


def get_local_ipv4_networks() -> List[Dict[str, Any]]:
    nets = []
    addrs = psutil.net_if_addrs()
    for ifname, addr_list in addrs.items():
        for a in addr_list:
            if a.family == socket.AF_INET:
                ip = a.address
                mask = a.netmask
                if ip and mask:
                    try:
                        # Convert netmask to prefix length
                        prefix = sum(bin(int(octet)).count("1") for octet in mask.split("."))
                        cidr = f"{ip}/{prefix}"
                        net = ipaddress.ip_network(cidr, strict=False)
                        nets.append({
                            "interface": ifname,
                            "ip": ip,
                            "netmask": mask,
                            "cidr": str(net),
                            "network_address": str(net.network_address),
                            "broadcast_address": str(net.broadcast_address),
                            "num_addresses": net.num_addresses,
                        })
                    except Exception:
                        pass
    # De-duplicate by cidr
    seen = set()
    out = []
    for n in nets:
        if n["cidr"] not in seen:
            seen.add(n["cidr"])
            out.append(n)
    return out


def connectivity_checks(default_gw: Optional[str]) -> Dict[str, Any]:
    targets = []
    if default_gw:
        targets.append(("default_gateway", default_gw))
    targets.extend([
        ("google_dns", "8.8.8.8"),
        ("cloudflare_dns", "1.1.1.1"),
    ])

    urls = [
        ("https_google", "https://www.google.com/generate_204"),
        ("https_cloudflare", "https://1.1.1.1/cdn-cgi/trace"),
    ]

    def _do_ping(name: str, ip: str) -> Dict[str, Any]:
        return {"target": name, "ip": ip, "reachable": ping(ip, count=1, timeout_s=1)}

    def _do_http(name: str, url: str) -> Dict[str, Any]:
        try:
            r = requests.get(url, timeout=5, headers={"User-Agent": "OmniRecon/6.0"})
            return {"target": name, "url": url, "status_code": r.status_code,
                    "ok": 200 <= r.status_code < 400}
        except Exception as e:
            return {"target": name, "url": url, "error": repr(e), "ok": False}

    results: Dict[str, Any] = {"ping": [], "http": []}
    with cf.ThreadPoolExecutor(max_workers=len(targets) + len(urls)) as ex:
        ping_futs = [ex.submit(_do_ping, name, ip) for name, ip in targets]
        http_futs = [ex.submit(_do_http, name, url) for name, url in urls]
        results["ping"] = [f.result() for f in ping_futs]
        results["http"] = [f.result() for f in http_futs]

    return results


def discover_hosts(subnets: List[str], max_hosts_per_subnet: int, workers: int) -> List[Dict[str, Any]]:
    """
    Ping-sweep + reverse DNS over provided CIDRs.
    Caps per subnet to avoid accidental huge scans.
    """
    discovered: List[Dict[str, Any]] = []

    def check_ip(ip: str) -> Optional[Dict[str, Any]]:
        alive = ping(ip, count=1, timeout_s=1)
        if not alive:
            return None
        return {
            "ip": ip,
            "reverse_dns": resolve_reverse(ip),
        }

    for cidr in subnets:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except Exception:
            continue

        # Use islice to cap without materialising the full address list
        hosts = list(itertools.islice(net.hosts(), max_hosts_per_subnet))

        with cf.ThreadPoolExecutor(max_workers=workers) as ex:
            futures = [ex.submit(check_ip, str(h)) for h in hosts]
            for fut in cf.as_completed(futures):
                try:
                    r = fut.result()
                    if r:
                        discovered.append(r)
                except Exception:
                    pass

    # De-duplicate
    seen = set()
    out = []
    for h in discovered:
        if h["ip"] not in seen:
            seen.add(h["ip"])
            out.append(h)
    return sorted(out, key=lambda x: tuple(int(p) for p in x["ip"].split(".")))


def port_probe_hosts(hosts: List[Dict[str, Any]], ports: List[int], workers: int) -> List[Dict[str, Any]]:
    def probe(ip: str) -> Dict[str, Any]:
        open_ports = []
        for p in ports:
            if tcp_probe(ip, p, timeout=0.6):
                open_ports.append(p)
        return {"ip": ip, "open_ports": open_ports}

    results = []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(probe, h["ip"]): h["ip"] for h in hosts}
        for fut in cf.as_completed(futures):
            try:
                results.append(fut.result())
            except Exception:
                pass

    by_ip = {r["ip"]: r["open_ports"] for r in results}
    enriched = []
    for h in hosts:
        hh = dict(h)
        hh["open_ports"] = by_ip.get(h["ip"], [])
        enriched.append(hh)
    return enriched


# ----------------------------
# HTML report rendering
# ----------------------------

def html_escape(s: str) -> str:
    return html.escape(str(s), quote=True)


def render_html(report: Dict[str, Any]) -> str:
    def section(title: str, body: str) -> str:
        return f"<section><h2>{html_escape(title)}</h2>{body}</section>"

    def pre(obj: Any) -> str:
        txt = json.dumps(obj, indent=2, ensure_ascii=False)
        return f"<pre>{html_escape(txt)}</pre>"

    # Summaries
    sysinfo = report.get("system", {})
    ident = report.get("identity", {})
    pub = report.get("public_ip", {})
    gw = report.get("routes", {}).get("default_gateway")

    summary_items = [
        f"<li><b>Timestamp</b>: {html_escape(sysinfo.get('timestamp_local', ''))}</li>",
        f"<li><b>Host</b>: {html_escape(ident.get('hostname', ''))} ({html_escape(ident.get('fqdn',''))})</li>",
        f"<li><b>OS</b>: {html_escape(sysinfo.get('platform',''))}</li>",
        f"<li><b>Default gateway</b>: {html_escape(str(gw))}</li>",
        f"<li><b>Public IP</b>: {html_escape(str(pub.get('public_ip')))} (via {html_escape(str(pub.get('service')))})</li>",
    ]
    summary = "<ul>" + "\n".join(summary_items) + "</ul>"

    # Host discovery table
    hosts = report.get("discovery", {}).get("hosts", [])
    host_rows = []
    for h in hosts:
        host_rows.append(
            "<tr>"
            f"<td>{html_escape(h.get('ip',''))}</td>"
            f"<td>{html_escape(str(h.get('reverse_dns') or ''))}</td>"
            f"<td>{html_escape(', '.join(map(str, h.get('open_ports', []))) )}</td>"
            "</tr>"
        )
    host_table = (
        (
            "<table><thead><tr><th>IP</th><th>Reverse DNS</th><th>Open ports (probed)</th></tr></thead>"
            "<tbody>" + "\n".join(host_rows) + "</tbody></table>"
        )
        if hosts
        else "<p>No discovery performed (or no hosts responded).</p>"
    )

    css = """
    body{font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial; margin:24px; line-height:1.4}
    h1{margin-bottom:0}
    .meta{color:#555; margin-top:4px}
    section{margin-top:22px; padding-top:6px; border-top:1px solid #ddd}
    pre{background:#f6f8fa; padding:12px; overflow:auto; border:1px solid #e5e7eb; border-radius:8px}
    table{border-collapse:collapse; width:100%; margin-top:10px}
    th,td{border:1px solid #e5e7eb; padding:8px; text-align:left; vertical-align:top}
    th{background:#f3f4f6}
    """

    html = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>OmniRecon Lite Report</title>
<style>{css}</style>
</head>
<body>
<h1>OmniRecon Lite Report</h1>
<div class="meta">Generated by omnirecon_lite.py</div>

{section("Executive summary", summary)}
{section("Interfaces", pre(report.get("interfaces", {})))}
{section("Local IPv4 networks", pre(report.get("local_ipv4_networks", [])))}
{section("Routing & default gateway (raw)", pre(report.get("routes", {})))}
{section("DNS configuration (raw + parsed)", pre(report.get("dns", {})))}
{section("Connectivity checks", pre(report.get("connectivity", {})))}
{section("Neighbor table (ARP / NDP)", pre(report.get("neighbors", {})))}
{section("Host discovery", host_table)}
{section("Listening ports on this device", pre(report.get("listening_ports", [])))}
{section("Active connections (sampled)", pre(report.get("active_connections", [])))}
{section("Raw report JSON", pre(report))}
</body>
</html>
"""
    return html


# ----------------------------
# Main
# ----------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Extensive local network diagnostic + HTML/JSON report (device-side).",
        formatter_class=argparse.RawTextHelpFormatter
    )
    ap.add_argument("--outdir", default=".", help="Directory for output files (default: current directory).")
    ap.add_argument("--discover", action="store_true", help="Perform ping-based host discovery over local subnets.")
    ap.add_argument("--subnet", action="append", default=[],
                    help="CIDR subnet(s) to discover, e.g. 192.168.1.0/24 (can repeat). If omitted, uses interface-derived IPv4 networks.")
    ap.add_argument("--max-hosts", type=int, default=512,
                    help="Safety cap: max hosts to probe per subnet during discovery (default: 512).")
    ap.add_argument("--probe-ports", action="store_true",
                    help="After discovery, probe a conservative set of common TCP ports on discovered hosts.")
    ap.add_argument("--ports", default="22,53,80,443,445,3389,5357,8006,8080,8443",
                    help="Comma-separated ports for --probe-ports (default: common admin/service ports).")
    ap.add_argument("--workers", type=int, default=128, help="Thread workers for discovery/probing (default: 128).")
    ap.add_argument("--active-limit", type=int, default=200, help="Max active connections to include (default: 200).")
    args = ap.parse_args()

    stamp = now_stamp()
    outdir = os.path.abspath(args.outdir)
    os.makedirs(outdir, exist_ok=True)

    report: Dict[str, Any] = {}
    report["system"] = get_system_info()
    report["identity"] = get_identity_info()
    report["public_ip"] = get_public_ip()
    report["interfaces"] = get_interfaces()
    report["local_ipv4_networks"] = get_local_ipv4_networks()
    report["routes"] = get_routes_and_gateway()
    report["dns"] = get_dns_config()
    report["neighbors"] = get_neighbor_table()

    gw = report["routes"].get("default_gateway")
    report["connectivity"] = connectivity_checks(gw)

    report["listening_ports"] = get_listening_ports()
    report["active_connections"] = get_active_connections(limit=args.active_limit)

    discovery_block: Dict[str, Any] = {"performed": False, "subnets": [], "hosts": []}

    if args.discover:
        discovery_block["performed"] = True
        if args.subnet:
            subnets = args.subnet
        else:
            subnets = [n["cidr"] for n in report.get("local_ipv4_networks", []) if n.get("cidr")]
        discovery_block["subnets"] = subnets

        hosts = discover_hosts(subnets=subnets, max_hosts_per_subnet=args.max_hosts, workers=args.workers)

        if args.probe_ports and hosts:
            ports = []
            for p in args.ports.split(","):
                p = p.strip()
                if p.isdigit():
                    ports.append(int(p))
            ports = sorted(list(dict.fromkeys([p for p in ports if 1 <= p <= 65535])))
            hosts = port_probe_hosts(hosts, ports=ports, workers=max(8, args.workers // 2))
            discovery_block["probed_ports"] = ports

        discovery_block["hosts"] = hosts

    report["discovery"] = discovery_block

    # Write files
    json_path = os.path.join(outdir, f"network_report_{stamp}.json")
    html_path = os.path.join(outdir, f"network_report_{stamp}.html")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(render_html(report))

    print(f"\nReport written:")
    print(f"  HTML: {html_path}")
    print(f"  JSON: {json_path}\n")
    print("Tip:")
    print("  Start with the HTML file in a browser. The JSON is there for deeper inspection or scripting.\n")


if __name__ == "__main__":
    main()
