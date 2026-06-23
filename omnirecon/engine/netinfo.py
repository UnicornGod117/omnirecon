"""
Host-local network facts — what the scanning machine knows about itself and its
immediate surroundings without probing other hosts.

system · identity · interfaces · routes/gateway · DNS · ARP/NDP neighbor table
(IPv4 + optional IPv6) · local IPv4 networks (virtual-iface aware) · listening
ports · active connections · connectivity checks · public IP.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import re
import socket
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import psutil

from .primitives import (
    is_linux, is_macos, is_windows, ping_with_ttl, safe_run, which,
)


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


def get_public_ip(timeout: float = 5.0) -> Dict[str, Any]:
    out: Dict[str, Any] = {"public_ip": None, "service": None, "error": None}
    try:
        import requests
    except ImportError:
        out["error"] = "requests not installed"
        return out
    for name, url in [("ipify", "https://api.ipify.org?format=json"),
                      ("ifconfig.co", "https://ifconfig.co/json")]:
        try:
            r = requests.get(url, timeout=timeout, headers={"User-Agent": "OmniRecon/7"})
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
            "up": getattr(s, "isup", None),
            "speed": getattr(s, "speed", None),
            "mtu": getattr(s, "mtu", None),
            "addresses": [
                {"family": str(a.family), "address": a.address, "netmask": a.netmask}
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


# ── Wi-Fi / wireless uplink ─────────────────────────────────────────────────────
#
# Describes the wireless link between this machine and the router/AP it is
# associated with: SSID, the AP's BSSID (radio MAC), RSSI / signal quality,
# channel + band, negotiated PHY rates, and BSS-level beacon details. This is
# what lets the topology pinpoint *which* AP/router we are riding and how strong
# the link is. Returns {"connected": False, ...} on wired-only hosts.

_WIFI_SIGNAL_LABELS = (
    (-50, "excellent"), (-60, "good"), (-67, "fair"), (-75, "weak"),
)


def _band_from_freq(mhz: Optional[int]) -> Optional[str]:
    if not mhz:
        return None
    if 2400 <= mhz < 2500:
        return "2.4 GHz"
    if 4900 <= mhz < 5900:
        return "5 GHz"
    if 5925 <= mhz <= 7125:
        return "6 GHz"
    return None


def _dbm_to_pct(dbm: Optional[int]) -> Optional[int]:
    """Rough RSSI→quality mapping (-100 dBm ≈ 0 %, -50 dBm ≈ 100 %)."""
    if dbm is None:
        return None
    return max(0, min(100, int(2 * (dbm + 100))))


def _pct_to_dbm(pct: Optional[int]) -> Optional[int]:
    if pct is None:
        return None
    return int(pct / 2 - 100)


def _signal_label(dbm: Optional[int]) -> Optional[str]:
    if dbm is None:
        return None
    for threshold, label in _WIFI_SIGNAL_LABELS:
        if dbm >= threshold:
            return label
    return "very weak"


def _wifi_finalize(info: Dict[str, Any]) -> Dict[str, Any]:
    """Fill derived fields (band, signal %/dBm, SNR, quality label)."""
    if info.get("signal_dbm") is None and info.get("signal_pct") is not None:
        info["signal_dbm"] = _pct_to_dbm(info["signal_pct"])
    if info.get("signal_pct") is None and info.get("signal_dbm") is not None:
        info["signal_pct"] = _dbm_to_pct(info["signal_dbm"])
    if info.get("band") is None:
        info["band"] = _band_from_freq(info.get("frequency_mhz"))
    if (info.get("snr_db") is None and info.get("signal_dbm") is not None
            and info.get("noise_dbm") is not None):
        info["snr_db"] = info["signal_dbm"] - info["noise_dbm"]
    info["signal_quality"] = _signal_label(info.get("signal_dbm"))
    return info


def _wifi_linux() -> Dict[str, Any]:
    info: Dict[str, Any] = {"connected": False}
    raw: Dict[str, Any] = {}

    iface: Optional[str] = None
    if which("iw"):
        dev = safe_run(["iw", "dev"], timeout=6)
        raw["iw_dev"] = dev.get("stdout")
        for line in (dev.get("stdout") or "").splitlines():
            m = re.search(r"^\s*Interface\s+(\S+)", line)
            if m:
                iface = m.group(1)
                break

    if iface and which("iw"):
        info["interface"] = iface
        link = safe_run(["iw", "dev", iface, "link"], timeout=6)
        out = link.get("stdout") or ""
        raw["iw_link"] = out
        if out.strip() and "Not connected" not in out:
            info["connected"] = True
            patterns = {
                "bssid": (r"Connected to ([0-9a-f:]{17})", str),
                "ssid": (r"\bSSID:\s*(.+)", str),
                "frequency_mhz": (r"\bfreq:\s*(\d+)", int),
                "signal_dbm": (r"\bsignal:\s*(-?\d+)\s*dBm", int),
                "tx_rate_mbps": (r"tx bitrate:\s*([\d.]+)\s*MBit/s", float),
                "rx_rate_mbps": (r"rx bitrate:\s*([\d.]+)\s*MBit/s", float),
                "beacon_interval": (r"beacon int:\s*(\d+)", int),
                "dtim_period": (r"dtim period:\s*(\d+)", int),
            }
            for key, (pat, cast) in patterns.items():
                m = re.search(pat, out, re.I)
                if m:
                    val = m.group(1).strip()
                    info[key] = cast(val) if cast is not str else val
            if info.get("bssid"):
                info["bssid"] = info["bssid"].lower()
            m = re.search(r"bss flags:\s*(.+)", out, re.I)
            if m:
                info["bss_flags"] = m.group(1).strip()
        # Channel width / center freq / tx power live in `iw dev <iface> info`.
        st = safe_run(["iw", "dev", iface, "info"], timeout=6)
        raw["iw_info"] = st.get("stdout")
        m = re.search(r"channel\s+(\d+).*?width:\s*(\d+)\s*MHz",
                      st.get("stdout") or "", re.I | re.S)
        if m:
            info["channel"] = int(m.group(1))
            info["channel_width_mhz"] = int(m.group(2))
        m = re.search(r"txpower\s+([\d.]+)\s*dBm", st.get("stdout") or "", re.I)
        if m:
            info["tx_power_dbm"] = float(m.group(1))

    # nmcli supplements security + a signal % even when iw is missing.
    if which("nmcli"):
        nm = safe_run(["nmcli", "-t", "-f",
                       "IN-USE,SSID,BSSID,CHAN,FREQ,SIGNAL,RATE,SECURITY",
                       "device", "wifi"], timeout=8)
        raw["nmcli"] = nm.get("stdout")
        for line in (nm.get("stdout") or "").splitlines():
            if not line.startswith("*"):
                continue
            # nmcli escapes the ':' inside BSSID as '\:' — undo that.
            parts = re.split(r"(?<!\\):", line)
            parts = [p.replace("\\:", ":") for p in parts]
            if len(parts) >= 8:
                info["connected"] = True
                info.setdefault("ssid", parts[1] or None)
                info.setdefault("bssid", (parts[2] or "").lower() or None)
                if parts[3].isdigit():
                    info.setdefault("channel", int(parts[3]))
                fm = re.search(r"(\d+)", parts[4])
                if fm:
                    info.setdefault("frequency_mhz", int(fm.group(1)))
                if parts[5].isdigit():
                    info.setdefault("signal_pct", int(parts[5]))
                info.setdefault("tx_rate", parts[6] or None)
                info["security"] = parts[7] or "Open"
            break

    info["raw"] = raw
    return info


def _wifi_macos() -> Dict[str, Any]:
    info: Dict[str, Any] = {"connected": False}
    raw: Dict[str, Any] = {}
    airport = ("/System/Library/PrivateFrameworks/Apple80211.framework/"
               "Versions/Current/Resources/airport")
    a = safe_run([airport, "-I"], timeout=8)
    out = a.get("stdout") or ""
    raw["airport_I"] = out
    fields = {}
    for line in out.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            fields[k.strip().lower()] = v.strip()
    if fields.get("ssid") or fields.get("bssid"):
        info["connected"] = True
        info["ssid"] = fields.get("ssid")
        info["bssid"] = (fields.get("bssid") or "").lower() or None
        for src, dst, cast in (("agrctlrssi", "signal_dbm", int),
                               ("agrctlnoise", "noise_dbm", int),
                               ("lasttxrate", "tx_rate_mbps", float),
                               ("maxrate", "max_rate_mbps", float)):
            try:
                if fields.get(src) not in (None, ""):
                    info[dst] = cast(fields[src])
            except ValueError:
                pass
        ch = fields.get("channel", "")
        cm = re.match(r"(\d+)(?:,(\d+))?", ch)
        if cm:
            info["channel"] = int(cm.group(1))
            if cm.group(2):
                info["channel_width_mhz"] = int(cm.group(2))
        info["phy_mode"] = fields.get("phymode") or fields.get("802.11 auth")
        info["security"] = fields.get("link auth")
    info["raw"] = raw
    return info


def _wifi_windows() -> Dict[str, Any]:
    info: Dict[str, Any] = {"connected": False}
    raw: Dict[str, Any] = {}
    w = safe_run(["netsh", "wlan", "show", "interfaces"], timeout=10)
    out = w.get("stdout") or ""
    raw["netsh"] = out
    fields = {}
    for line in out.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            fields[k.strip().lower()] = v.strip()
    if fields.get("state", "").lower() == "connected" or fields.get("bssid"):
        info["connected"] = True
        info["interface"] = fields.get("name")
        info["ssid"] = fields.get("ssid")
        info["bssid"] = (fields.get("bssid") or "").lower() or None
        info["phy_mode"] = fields.get("radio type")
        info["security"] = fields.get("authentication")
        info["band"] = fields.get("band") or None
        for src, dst, cast in (("channel", "channel", int),
                               ("receive rate (mbps)", "rx_rate_mbps", float),
                               ("transmit rate (mbps)", "tx_rate_mbps", float)):
            try:
                if fields.get(src):
                    info[dst] = cast(fields[src])
            except ValueError:
                pass
        sm = re.search(r"(\d+)", fields.get("signal", ""))
        if sm:
            info["signal_pct"] = int(sm.group(1))
    info["raw"] = raw
    return info


def get_wifi_info() -> Dict[str, Any]:
    """Describe the wireless uplink to the connected router/AP (if any)."""
    try:
        if is_windows():
            info = _wifi_windows()
        elif is_macos():
            info = _wifi_macos()
        elif is_linux():
            info = _wifi_linux()
        else:
            info = {"connected": False, "error": "unsupported platform"}
    except Exception as e:  # never let link probing abort a scan
        return {"connected": False, "error": repr(e)}
    return _wifi_finalize(info)


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


_VIRTUAL_RE = re.compile(
    r"(hyper.?v|vethernet|vmnet|vmware|docker|virbr|br-|vboxnet"
    r"|tun|tap|wsl|tailscale|utun|awdl|llw|bridge|dummy|lo$)", re.I)


def is_virtual_interface(name: str) -> bool:
    return bool(_VIRTUAL_RE.search(name))


def get_local_ipv4_networks(default_iface: Optional[str] = None,
                            exclude_virtual: bool = True) -> List[Dict[str, Any]]:
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    nets: List[Dict[str, Any]] = []
    for ifname, addr_list in addrs.items():
        if exclude_virtual and is_virtual_interface(ifname):
            continue
        st = stats.get(ifname)
        isup = getattr(st, "isup", False)
        for a in addr_list:
            if a.family != socket.AF_INET or not a.address or not a.netmask:
                continue
            try:
                prefix = sum(bin(int(o)).count("1") for o in a.netmask.split("."))
                net = ipaddress.ip_network(f"{a.address}/{prefix}", strict=False)
                if net.is_loopback or net.is_link_local or net.prefixlen >= 32:
                    continue
                nets.append({
                    "interface": ifname, "ip": a.address, "netmask": a.netmask,
                    "cidr": str(net), "num_addresses": net.num_addresses,
                    "is_default_iface": (ifname == default_iface), "isup": isup,
                })
            except Exception:
                pass
    seen: Set[str] = set()
    unique: List[Dict[str, Any]] = []
    for n in nets:
        if n["cidr"] not in seen:
            seen.add(n["cidr"])
            unique.append(n)
    unique.sort(key=lambda n: (0 if n["is_default_iface"] else 1,
                               0 if n["isup"] else 1, n["num_addresses"]))
    return unique


def get_local_ipv4_addresses() -> set:
    out: set = set()
    for addr_list in psutil.net_if_addrs().values():
        for a in addr_list:
            if a.family == socket.AF_INET and a.address:
                out.add(a.address)
    return out


def get_neighbor_table(include_ipv6: bool = False) -> Dict[str, Any]:
    out: Dict[str, Any] = {"neighbors": [], "raw": []}
    if is_linux() and which("ip"):
        raw4 = safe_run(["ip", "neigh", "show"], timeout=8)
        out["raw"].append(raw4)
        for line in (raw4.get("stdout") or "").splitlines():
            m = re.search(
                r"^(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)\s+(?:lladdr\s+([0-9a-f:]{17})\s+)?(\S+)",
                line.strip(), re.I)
            if m:
                out["neighbors"].append({
                    "ip": m.group(1), "version": 4, "interface": m.group(2),
                    "mac": m.group(3).lower() if m.group(3) else None,
                    "state": m.group(4)})
    else:
        raw4 = safe_run(["arp", "-a"], timeout=8)
        out["raw"].append(raw4)
        for line in (raw4.get("stdout") or "").splitlines():
            line = line.strip()
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]{17})\s+(\S+)", line, re.I)
            if m:
                out["neighbors"].append({
                    "ip": m.group(1), "version": 4,
                    "mac": m.group(2).lower().replace("-", ":"),
                    "state": m.group(3), "interface": None})
                continue
            m2 = re.search(
                r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{17}|<incomplete>)\s+on\s+(\S+)",
                line, re.I)
            if m2:
                out["neighbors"].append({
                    "ip": m2.group(1), "version": 4,
                    "mac": None if m2.group(2) == "<incomplete>" else m2.group(2).lower(),
                    "state": None, "interface": m2.group(3)})

    if include_ipv6:
        if is_linux() and which("ip"):
            raw6 = safe_run(["ip", "-6", "neigh", "show"], timeout=8)
            out["raw"].append(raw6)
            for line in (raw6.get("stdout") or "").splitlines():
                m = re.search(
                    r"^([0-9a-f:]+)\s+dev\s+(\S+)\s+(?:lladdr\s+([0-9a-f:]{17})\s+)?(\S+)",
                    line.strip(), re.I)
                if m and ":" in m.group(1):
                    out["neighbors"].append({
                        "ip": m.group(1), "version": 6, "interface": m.group(2),
                        "mac": m.group(3).lower() if m.group(3) else None,
                        "state": m.group(4)})
        elif is_windows():
            raw6 = safe_run(["netsh", "interface", "ipv6", "show", "neighbors"], timeout=10)
            out["raw"].append(raw6)
            for line in (raw6.get("stdout") or "").splitlines():
                m = re.search(r"([0-9a-f:]{4,})\s+([0-9a-f-]{17}|)\s+(\S+)", line.strip(), re.I)
                if m and ":" in m.group(1) and len(m.group(1)) > 6:
                    mac = m.group(2).lower().replace("-", ":") if m.group(2) else None
                    out["neighbors"].append({"ip": m.group(1), "version": 6,
                                             "mac": mac, "state": m.group(3),
                                             "interface": None})
        elif is_macos() and which("ndp"):
            raw6 = safe_run(["ndp", "-a"], timeout=8)
            out["raw"].append(raw6)
            for line in (raw6.get("stdout") or "").splitlines():
                m = re.search(
                    r"([0-9a-f:]+%?\S*)\s+([0-9a-f:]{17}|<incomplete>)\s+(\S+)",
                    line.strip(), re.I)
                if m and ":" in m.group(1):
                    out["neighbors"].append({
                        "ip": m.group(1).split("%")[0], "version": 6,
                        "mac": None if m.group(2) == "<incomplete>" else m.group(2).lower(),
                        "state": m.group(3), "interface": None})
    return out


def build_neighbor_maps(nb: Dict[str, Any]) -> Tuple[Dict[str, str], Dict[str, str]]:
    ip_mac: Dict[str, str] = {}
    ip_state: Dict[str, str] = {}
    for n in nb.get("neighbors", []):
        ip = n.get("ip")
        if ip:
            if n.get("mac"):
                ip_mac[ip] = n["mac"]
            ip_state[ip] = (n.get("state") or "").upper()
    return ip_mac, ip_state


def arp_lookup(nb_or_list) -> Dict[str, str]:
    """Convenience ip→mac map. Accepts a neighbor table dict or a neighbor list."""
    neighbors = nb_or_list.get("neighbors", []) if isinstance(nb_or_list, dict) else nb_or_list
    return {n["ip"]: n["mac"] for n in neighbors if n.get("ip") and n.get("mac")}


def get_listening_ports() -> List[Dict[str, Any]]:
    out = []
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status == psutil.CONN_LISTEN:
                out.append({"ip": getattr(c.laddr, "ip", None),
                            "port": getattr(c.laddr, "port", None), "pid": c.pid})
    except Exception:
        pass
    return out


def get_active_connections(limit: int = 200) -> List[Dict[str, Any]]:
    out = []
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status == "ESTABLISHED" and c.raddr:
                out.append({
                    "local": f"{getattr(c.laddr, 'ip', '')}:{getattr(c.laddr, 'port', '')}",
                    "remote": f"{getattr(c.raddr, 'ip', '')}:{getattr(c.raddr, 'port', '')}",
                    "pid": c.pid,
                })
                if len(out) >= limit:
                    break
    except Exception:
        pass
    return out


def connectivity_checks(gw: Optional[str]) -> Dict[str, Any]:
    targets = []
    if gw:
        targets.append(("default_gateway", gw))
    targets += [("google_dns", "8.8.8.8"), ("cloudflare_dns", "1.1.1.1")]
    results: Dict[str, Any] = {"ping": [], "http": []}
    for name, ip in targets:
        alive, ttl = ping_with_ttl(ip, timeout_s=1)
        results["ping"].append({"target": name, "ip": ip, "reachable": alive, "ttl": ttl})
    try:
        import requests
        for name, url in [("https_google", "https://www.google.com/generate_204"),
                          ("https_cloudflare", "https://1.1.1.1/cdn-cgi/trace")]:
            try:
                r = requests.get(url, timeout=5, headers={"User-Agent": "OmniRecon/7"})
                results["http"].append({"target": name, "url": url,
                                        "status_code": r.status_code,
                                        "ok": 200 <= r.status_code < 400})
            except Exception as e:
                results["http"].append({"target": name, "url": url,
                                        "error": repr(e), "ok": False})
    except ImportError:
        pass
    return results
