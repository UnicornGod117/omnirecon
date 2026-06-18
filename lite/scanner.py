"""
Data collection and scan orchestration for OmniRecon Lite.

All public functions are pure (no side effects beyond network I/O).
run_scan(config) is the main entry point — returns a completed report dict.
write_reports(report, outdir) saves HTML + JSON files.
"""

import concurrent.futures as cf
import datetime as dt
import html as _html
import ipaddress
import itertools
import json
import os
import re
import socket
import sys
import time
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

import psutil
import requests

from .utils import (
    grab_banner, is_linux, is_macos, is_windows,
    now_stamp, ping, resolve_reverse, safe_run, tcp_probe,
)

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                 3389, 5357, 5900, 8006, 8080, 8443, 8888, 9090]

# Ports we attempt a lightweight banner grab on for a basic service hint.
_HINT_PORTS = [22, 80, 443, 8080, 21, 23]


# ── OUI vendor + device-type (lite, standalone) ───────────────────────────────

_OUI_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "oui.txt")
_OUI_MAP: Optional[Dict[str, str]] = None
_OUI_LINE = re.compile(r"^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$")

_DEVICE_KEYWORDS = [
    (("apple",), "Apple"),
    (("samsung", "lg electronics", "motorola", "xiaomi", "huawei"), "Mobile"),
    (("dell", "lenovo", "hewlett", "hp inc", "asus", "acer", "intel corporate", "ampak"), "PC / Laptop"),
    (("cisco", "ubiquiti", "netgear", "tp-link", "mikrotik", "synology", "qnap"), "Network / NAS"),
    (("google", "amazon", "espressif", "ring", "tuya", "shenzhen"), "IoT / Smart"),
    (("canon", "epson", "brother", "xerox", "lexmark"), "Printer"),
    (("hikvision", "dahua", "axis"), "IP Camera"),
]


def _load_oui() -> Dict[str, str]:
    global _OUI_MAP
    if _OUI_MAP is not None:
        return _OUI_MAP
    table: Dict[str, str] = {}
    try:
        with open(_OUI_FILE, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = _OUI_LINE.match(line.strip())
                if m:
                    table[m.group(1).replace("-", "").lower()] = m.group(2).strip()
    except OSError:
        pass
    _OUI_MAP = table
    return table


def _vendor_for_mac(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    norm = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    return _load_oui().get(norm[:6]) if len(norm) >= 6 else None


def _device_type(vendor: Optional[str]) -> str:
    if not vendor:
        return "Unknown"
    v = vendor.lower()
    for kws, label in _DEVICE_KEYWORDS:
        if any(k in v for k in kws):
            return label
    return "Unknown"


# ── Data collectors ───────────────────────────────────────────────────────────

def get_system_info() -> Dict[str, Any]:
    import platform
    return {
        "timestamp_local": dt.datetime.now().isoformat(),
        "platform": platform.platform(),
        "system":   platform.system(),
        "release":  platform.release(),
        "machine":  platform.machine(),
        "python":   sys.version.split()[0],
        "boot_time": dt.datetime.fromtimestamp(
            psutil.boot_time(), tz=dt.timezone.utc
        ).isoformat(),
        "uptime_seconds": int(time.time() - psutil.boot_time()),
    }


def get_identity_info() -> Dict[str, Any]:
    return {"hostname": socket.gethostname(), "fqdn": socket.getfqdn()}


def get_public_ip() -> Dict[str, Any]:
    out: Dict[str, Any] = {"public_ip": None, "service": None, "error": None}
    for name, url in [
        ("ipify",      "https://api.ipify.org?format=json"),
        ("ifconfig.co","https://ifconfig.co/json"),
    ]:
        try:
            r = requests.get(url, timeout=5, headers={"User-Agent": "OmniRecon-Lite/7"})
            r.raise_for_status()
            ip = r.json().get("ip") or r.json().get("ip_addr")
            if ip:
                out.update({"public_ip": ip, "service": name})
                return out
        except Exception as e:
            out["error"] = repr(e)
    return out


def get_interfaces() -> Dict[str, Any]:
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    out: Dict[str, Any] = {}
    for name, addr_list in addrs.items():
        s = stats.get(name)
        out[name] = {
            "up":      getattr(s, "isup", None),
            "speed":   getattr(s, "speed", None),
            "mtu":     getattr(s, "mtu", None),
            "addresses": [
                {"family": str(a.family), "address": a.address,
                 "netmask": a.netmask}
                for a in addr_list
            ],
        }
    return out


def get_routes_and_gateway() -> Dict[str, Any]:
    out: Dict[str, Any] = {"default_gateway": None}
    if is_windows():
        raw = safe_run(["route", "print", "-4"])
        for line in raw.get("stdout", "").splitlines():
            line = line.strip()
            if line.startswith("0.0.0.0") and "0.0.0.0" in line:
                parts = re.split(r"\s+", line)
                if len(parts) >= 3:
                    out["default_gateway"] = parts[2]
                    break
    elif is_linux():
        raw = safe_run(["ip", "route"])
        for line in raw.get("stdout", "").splitlines():
            if line.startswith("default "):
                m = re.search(r"\bvia\s+(\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    out["default_gateway"] = m.group(1)
                    break
    elif is_macos():
        raw = safe_run(["route", "-n", "get", "default"])
        for line in raw.get("stdout", "").splitlines():
            if "gateway:" in line:
                out["default_gateway"] = line.split("gateway:")[-1].strip()
                break
    return out


def get_dns_servers() -> List[str]:
    def _valid(addr: str) -> bool:
        try:
            ipaddress.ip_address(addr.strip())
            return True
        except ValueError:
            return False

    dns: List[str] = []
    try:
        if is_windows():
            raw = safe_run(["ipconfig", "/all"], timeout=12)
            capture = False
            for line in raw.get("stdout", "").splitlines():
                if "DNS Servers" in line:
                    capture = True
                    addr = line.split(":", 1)[-1].strip()
                    if _valid(addr):
                        dns.append(addr)
                    continue
                if capture:
                    cont = line.strip()
                    if _valid(cont):
                        dns.append(cont)
                    elif not cont or ":" in cont:
                        capture = False
        elif is_macos():
            raw = safe_run(["scutil", "--dns"])
            for m in re.finditer(r"nameserver\[\d+\]\s*:\s*(\S+)", raw.get("stdout", "")):
                if _valid(m.group(1)):
                    dns.append(m.group(1))
        else:
            raw = safe_run(["cat", "/etc/resolv.conf"])
            for line in raw.get("stdout", "").splitlines():
                parts = line.strip().split()
                if parts and parts[0] == "nameserver" and len(parts) >= 2 and _valid(parts[1]):
                    dns.append(parts[1])
    except Exception:
        pass
    return sorted(set(dns))


def get_local_ipv4_networks() -> List[Dict[str, Any]]:
    seen: set = set()
    out: List[Dict[str, Any]] = []
    for ifname, addr_list in psutil.net_if_addrs().items():
        for a in addr_list:
            if a.family == socket.AF_INET and a.address and a.netmask:
                try:
                    prefix = sum(bin(int(o)).count("1") for o in a.netmask.split("."))
                    net = ipaddress.ip_network(f"{a.address}/{prefix}", strict=False)
                    cidr = str(net)
                    if cidr not in seen:
                        seen.add(cidr)
                        out.append({
                            "interface": ifname,
                            "ip": a.address,
                            "cidr": cidr,
                            "num_addresses": net.num_addresses,
                        })
                except Exception:
                    pass
    return out


def get_neighbor_table() -> List[Dict[str, Any]]:
    neighbors: List[Dict[str, Any]] = []
    if is_linux():
        raw = safe_run(["ip", "neigh"])
        for line in raw.get("stdout", "").splitlines():
            m = re.search(
                r"^(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)\s+(?:lladdr\s+([0-9a-f:]{17})\s+)?(\S+)",
                line.strip(), re.I,
            )
            if m:
                neighbors.append({"ip": m.group(1), "interface": m.group(2),
                                   "mac": m.group(3), "state": m.group(4)})
    else:
        raw = safe_run(["arp", "-a"])
        for line in raw.get("stdout", "").splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]{17})\s+(\S+)", line, re.I)
            if m:
                neighbors.append({"ip": m.group(1),
                                   "mac": m.group(2).lower().replace("-", ":"),
                                   "state": m.group(3), "interface": None})
                continue
            m2 = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{17}|<incomplete>)\s+on\s+(\S+)", line, re.I)
            if m2:
                neighbors.append({"ip": m2.group(1),
                                   "mac": None if m2.group(2) == "<incomplete>" else m2.group(2).lower(),
                                   "state": None, "interface": m2.group(3)})
    return neighbors


def get_listening_ports() -> List[Dict[str, Any]]:
    out = []
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status == psutil.CONN_LISTEN:
                out.append({
                    "ip":   getattr(c.laddr, "ip", None),
                    "port": getattr(c.laddr, "port", None),
                    "pid":  c.pid,
                })
    except Exception:
        pass
    return out


def connectivity_check(default_gw: Optional[str]) -> Dict[str, Any]:
    targets = []
    if default_gw:
        targets.append(("gateway", default_gw))
    targets += [("google_dns", "8.8.8.8"), ("cloudflare_dns", "1.1.1.1")]

    results: Dict[str, bool] = {}
    with cf.ThreadPoolExecutor(max_workers=len(targets)) as ex:
        futs = {ex.submit(ping, ip): name for name, ip in targets}
        for fut, name in futs.items():
            try:
                results[name] = fut.result()
            except Exception:
                results[name] = False
    return results


# ── Discovery & port scan ─────────────────────────────────────────────────────

def discover_hosts(
    subnets: List[str],
    max_per_subnet: int = 512,
    workers: int = 128,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> List[Dict[str, Any]]:
    discovered: List[Dict[str, Any]] = []
    all_hosts: List[str] = []
    for cidr in subnets:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            all_hosts.extend(str(h) for h in itertools.islice(net.hosts(), max_per_subnet))
        except Exception:
            pass

    total = len(all_hosts)
    done  = 0

    def check(ip: str) -> Optional[Dict[str, Any]]:
        return {"ip": ip, "hostname": resolve_reverse(ip)} if ping(ip) else None

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(check, ip): ip for ip in all_hosts}
        for fut in cf.as_completed(futs):
            done += 1
            if progress_cb:
                progress_cb(done, total)
            try:
                r = fut.result()
                if r:
                    discovered.append(r)
            except Exception:
                pass

    seen: set = set()
    out: List[Dict[str, Any]] = []
    for h in discovered:
        if h["ip"] not in seen:
            seen.add(h["ip"])
            out.append(h)
    return sorted(out, key=lambda x: tuple(int(p) for p in x["ip"].split(".")))


def port_probe_hosts(
    hosts: List[Dict[str, Any]],
    ports: List[int],
    workers: int = 64,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> List[Dict[str, Any]]:
    total = len(hosts)
    done  = 0

    def probe(host: Dict[str, Any]) -> Dict[str, Any]:
        ip = host["ip"]
        open_ports = [p for p in ports if tcp_probe(ip, p)]
        return {**host, "open_ports": open_ports}

    results: Dict[str, Dict[str, Any]] = {}
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(probe, h): h["ip"] for h in hosts}
        for fut in cf.as_completed(futs):
            done += 1
            if progress_cb:
                progress_cb(done, total)
            try:
                r = fut.result()
                results[r["ip"]] = r
            except Exception:
                pass

    return [results.get(h["ip"], {**h, "open_ports": []}) for h in hosts]


# ── Host enrichment (vendor / device-type / basic service hint) ───────────────

def _enrich_hosts(hosts: List[Dict[str, Any]], want_hints: bool) -> List[Dict[str, Any]]:
    """Add mac/vendor/device_type and an optional basic service hint per host."""
    # ip → mac from the OS ARP/neighbor table.
    ip_mac: Dict[str, str] = {}
    for n in get_neighbor_table():
        if n.get("ip") and n.get("mac"):
            ip_mac[n["ip"]] = n["mac"]

    def _enrich(host: Dict[str, Any]) -> Dict[str, Any]:
        mac = ip_mac.get(host["ip"])
        vendor = _vendor_for_mac(mac)
        host["mac"] = mac
        host["vendor"] = vendor
        host["device_type"] = _device_type(vendor)
        if want_hints:
            for p in _HINT_PORTS:
                if p in (host.get("open_ports") or []):
                    b = grab_banner(host["ip"], p)
                    if b:
                        host["service_hint"] = f"{p}: {b}"
                        break
        return host

    with cf.ThreadPoolExecutor(max_workers=32) as ex:
        return list(ex.map(_enrich, hosts))


# ── Scan orchestrator ─────────────────────────────────────────────────────────

ScanConfig = Dict[str, Any]


def run_scan(
    config: ScanConfig,
    stage_cb: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """
    Run a full lite scan. Returns the completed report dict.

    config keys:
      discover      bool   — run host discovery
      probe_ports   bool   — TCP port scan discovered hosts
      ports         list   — port list (default: DEFAULT_PORTS)
      subnets       list   — CIDRs to scan; auto-detected if empty
      max_per_subnet int   — safety cap per CIDR
      workers       int    — thread workers
      progress_cb   fn     — called with (done, total) during discovery/port scan
    """

    def stage(name: str) -> None:
        if stage_cb:
            stage_cb(name)

    report: Dict[str, Any] = {}

    stage("System info")
    report["system"] = get_system_info()

    stage("Identity & interfaces")
    report["identity"]   = get_identity_info()
    report["interfaces"] = get_interfaces()

    stage("Routes & DNS")
    report["routes"]      = get_routes_and_gateway()
    report["dns_servers"] = get_dns_servers()

    stage("Neighbors (ARP)")
    report["neighbors"] = get_neighbor_table()

    stage("Connectivity")
    gw = report["routes"].get("default_gateway")
    report["connectivity"] = connectivity_check(gw)

    stage("Local ports")
    report["listening_ports"] = get_listening_ports()

    local_nets = get_local_ipv4_networks()
    report["local_networks"] = local_nets

    stage("Public IP")
    report["public_ip"] = get_public_ip()

    discovery: Dict[str, Any] = {"performed": False, "subnets": [], "hosts": []}

    if config.get("discover"):
        subnets = config.get("subnets") or [n["cidr"] for n in local_nets if n.get("cidr")]
        discovery["performed"] = True
        discovery["subnets"]   = subnets

        stage(f"Discovering hosts on {', '.join(subnets)}")
        hosts = discover_hosts(
            subnets,
            max_per_subnet=config.get("max_per_subnet", 512),
            workers=config.get("workers", 128),
            progress_cb=config.get("progress_cb"),
        )

        if config.get("probe_ports") and hosts:
            ports = config.get("ports") or DEFAULT_PORTS
            stage(f"Port scanning {len(hosts)} host(s)")
            hosts = port_probe_hosts(
                hosts,
                ports=ports,
                workers=max(8, config.get("workers", 64) // 2),
                progress_cb=config.get("progress_cb"),
            )
            discovery["probed_ports"] = ports

        if hosts:
            stage("Identifying vendors & devices")
            hosts = _enrich_hosts(hosts, want_hints=config.get("service_hints", False))

        discovery["hosts"] = hosts

    report["discovery"] = discovery
    return report


# ── Report writing ────────────────────────────────────────────────────────────

def write_reports(report: Dict[str, Any], outdir: str) -> Tuple[str, str]:
    """Write HTML + JSON reports. Returns (html_path, json_path)."""
    os.makedirs(outdir, exist_ok=True)
    stamp     = now_stamp()
    json_path = os.path.join(outdir, f"lite_report_{stamp}.json")
    html_path = os.path.join(outdir, f"lite_report_{stamp}.html")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(_render_html(report))

    return html_path, json_path


def _render_html(report: Dict[str, Any]) -> str:
    def esc(s: Any) -> str:
        return _html.escape(str(s), quote=True)

    def section(title: str, body: str) -> str:
        return f'<section><h2>{esc(title)}</h2>{body}</section>'

    def pre(obj: Any) -> str:
        return f'<pre>{esc(json.dumps(obj, indent=2, ensure_ascii=False))}</pre>'

    sys_  = report.get("system", {})
    ident = report.get("identity", {})
    pub   = report.get("public_ip", {})
    gw    = report.get("routes", {}).get("default_gateway")
    conn  = report.get("connectivity", {})
    gw_ok = conn.get("gateway", False)

    summary = (
        f'<ul>'
        f'<li><b>Timestamp</b>: {esc(sys_.get("timestamp_local",""))}</li>'
        f'<li><b>Host</b>: {esc(ident.get("hostname",""))} ({esc(ident.get("fqdn",""))})</li>'
        f'<li><b>OS</b>: {esc(sys_.get("platform",""))}</li>'
        f'<li><b>Uptime</b>: {esc(sys_.get("uptime_seconds",""))}s</li>'
        f'<li><b>Gateway</b>: {esc(gw)} {"✓" if gw_ok else "✗"}</li>'
        f'<li><b>Public IP</b>: {esc(pub.get("public_ip"))} (via {esc(pub.get("service"))})</li>'
        f'<li><b>DNS</b>: {esc(", ".join(report.get("dns_servers",[]) or []))}</li>'
        f'</ul>'
    )

    hosts = report.get("discovery", {}).get("hosts", [])
    if hosts:
        rows = "".join(
            f'<tr><td>{esc(h["ip"])}</td>'
            f'<td>{esc(h.get("hostname") or "")}</td>'
            f'<td>{esc(", ".join(map(str, h.get("open_ports", []))))}</td></tr>'
            for h in hosts
        )
        host_table = (
            '<table><thead><tr><th>IP</th><th>Hostname</th><th>Open Ports</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>'
        )
    else:
        host_table = '<p>No discovery performed, or no hosts responded.</p>'

    css = (
        'body{font-family:system-ui,sans-serif;margin:24px;line-height:1.5;color:#111}'
        'h1{margin-bottom:4px} .meta{color:#666;margin-bottom:24px}'
        'section{margin-top:24px;padding-top:8px;border-top:1px solid #ddd}'
        'pre{background:#f6f8fa;padding:12px;overflow:auto;border:1px solid #e5e7eb;border-radius:6px;font-size:12px}'
        'table{border-collapse:collapse;width:100%;margin-top:8px}'
        'th,td{border:1px solid #e5e7eb;padding:8px;text-align:left}'
        'th{background:#f3f4f6}'
    )

    return (
        f'<!doctype html><html><head><meta charset="utf-8">'
        f'<title>OmniRecon Lite</title><style>{css}</style></head><body>'
        f'<h1>OmniRecon Lite</h1>'
        f'<div class="meta">Generated {esc(sys_.get("timestamp_local",""))}</div>'
        f'{section("Summary", summary)}'
        f'{section("Host Discovery", host_table)}'
        f'{section("Neighbors (ARP)", pre(report.get("neighbors", [])))}'
        f'{section("Listening Ports", pre(report.get("listening_ports", [])))}'
        f'{section("Interfaces", pre(report.get("interfaces", {})))}'
        f'{section("Full Report (JSON)", pre(report))}'
        f'</body></html>'
    )
