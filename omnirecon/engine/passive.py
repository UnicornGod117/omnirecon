"""
Passive sniffing engine (scapy).

Listens on the wire for a fixed duration and harvests host observations from
ARP, mDNS, NetBIOS-NS, SSDP, DHCP, and LLMNR — without sending a single packet.
Optional and privileged: needs `scapy` and root/Administrator (plus Npcap on
Windows). Degrades to an empty result otherwise.
"""

from __future__ import annotations

import re
import struct
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from .primitives import (
    ip_sort_key, is_private_or_lan_ip, is_root, is_windows,
)

try:
    import scapy.all as scapy  # type: ignore
    _HAS_SCAPY = True
except Exception:
    _HAS_SCAPY = False


def available() -> Tuple[bool, str]:
    if not _HAS_SCAPY:
        return False, "scapy not installed (pip install scapy" + (
            "; Windows also needs Npcap)" if is_windows() else ")")
    if not is_root():
        return False, "passive sniffing requires root/Administrator"
    return True, ""


class PassiveResult:
    """Accumulates passive observations from packet capture."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.hosts: Dict[str, Dict[str, Any]] = {}
        self.packet_counts: Dict[str, int] = {}

    def _ensure(self, ip: str) -> Dict[str, Any]:
        if ip not in self.hosts:
            self.hosts[ip] = {"ip": ip, "mac": None, "names": set(),
                              "services": set(), "protocols": set()}
        return self.hosts[ip]

    def observe(self, ip: str, mac: Optional[str] = None, name: Optional[str] = None,
                service: Optional[str] = None, protocol: Optional[str] = None) -> None:
        if not ip or not is_private_or_lan_ip(ip):
            return
        with self._lock:
            h = self._ensure(ip)
            if mac and not h["mac"]:
                h["mac"] = mac.lower()
            if name and len(name) > 1:
                h["names"].add(name.strip("."))
            if service:
                h["services"].add(service)
            if protocol:
                h["protocols"].add(protocol)
            self.packet_counts[ip] = self.packet_counts.get(ip, 0) + 1

    def to_list(self) -> List[Dict[str, Any]]:
        with self._lock:
            out = [{
                "ip": ip, "mac": h["mac"], "names": sorted(h["names"]),
                "services": sorted(h["services"]), "protocols": sorted(h["protocols"]),
                "packet_count": self.packet_counts.get(ip, 0),
            } for ip, h in self.hosts.items()]
        return sorted(out, key=lambda x: ip_sort_key(x["ip"]))


# ── DNS name decoding (shared by mDNS / LLMNR) ────────────────────────────────

def _decode_dns_name(data: bytes, offset: int) -> Tuple[str, int]:
    labels: List[str] = []
    visited: set = set()
    while offset < len(data):
        if offset in visited:
            break
        visited.add(offset)
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            name, _ = _decode_dns_name(data, ptr)
            labels.append(name)
            offset += 2
            break
        offset += 1
        if offset + length > len(data):
            break
        labels.append(data[offset:offset + length].decode("utf-8", "ignore"))
        offset += length
    return ".".join(labels), offset


# ── Per-protocol handlers ─────────────────────────────────────────────────────

def _handle_arp(pkt: Any, result: PassiveResult) -> None:
    if not pkt.haslayer(scapy.ARP):
        return
    arp = pkt[scapy.ARP]
    if arp.op == 1:
        result.observe(arp.psrc, mac=arp.hwsrc, protocol="ARP")
    elif arp.op == 2:
        result.observe(arp.psrc, mac=arp.hwsrc, protocol="ARP")
        if arp.pdst and arp.pdst != "0.0.0.0":
            result.observe(arp.pdst, mac=arp.hwdst, protocol="ARP")


def _handle_mdns(pkt: Any, result: PassiveResult) -> None:
    if not (pkt.haslayer(scapy.UDP) and pkt[scapy.UDP].dport == 5353):
        return
    if not pkt.haslayer(scapy.IP):
        return
    src_ip = pkt[scapy.IP].src
    try:
        raw = bytes(pkt[scapy.UDP].payload)
        if len(raw) < 12:
            return
        an_count = struct.unpack("!H", raw[6:8])[0]
        if an_count == 0:
            return
        qd_count = struct.unpack("!H", raw[4:6])[0]
        offset = 12
        for _ in range(qd_count):
            _, offset = _decode_dns_name(raw, offset)
            offset += 4
        for _ in range(an_count):
            if offset >= len(raw):
                break
            name, offset = _decode_dns_name(raw, offset)
            if offset + 10 > len(raw):
                break
            rtype, _, _, rdlen = struct.unpack("!HHIH", raw[offset:offset + 10])
            offset += 10
            rdata_end = offset + rdlen
            if rtype == 1 and rdlen == 4:
                ip = ".".join(str(b) for b in raw[offset:offset + 4])
                if is_private_or_lan_ip(ip):
                    result.observe(ip, name=name.rstrip("."), protocol="mDNS")
                    result.observe(src_ip, protocol="mDNS")
            elif rtype == 12:
                result.observe(src_ip, service=name.rstrip("."), protocol="mDNS")
            offset = rdata_end
    except Exception:
        pass


def _handle_netbios_ns(pkt: Any, result: PassiveResult) -> None:
    if not (pkt.haslayer(scapy.UDP) and pkt[scapy.UDP].dport in (137, 138)):
        return
    if not pkt.haslayer(scapy.IP):
        return
    src_ip = pkt[scapy.IP].src
    try:
        raw = bytes(pkt[scapy.UDP].payload)
        if len(raw) < 12:
            return
        for match in re.finditer(rb"([A-Z]{32})", raw):
            encoded = match.group(1)
            try:
                decoded = "".join(
                    chr(((encoded[i] - 65) << 4) | (encoded[i + 1] - 65))
                    for i in range(0, 32, 2)
                ).rstrip("\x00").strip()
                if decoded and decoded.isprintable():
                    result.observe(src_ip, name=decoded, protocol="NetBIOS-NS")
                    break
            except Exception:
                pass
    except Exception:
        pass


def _handle_ssdp(pkt: Any, result: PassiveResult) -> None:
    if not (pkt.haslayer(scapy.UDP) and pkt[scapy.UDP].dport == 1900):
        return
    if not pkt.haslayer(scapy.IP):
        return
    src_ip = pkt[scapy.IP].src
    try:
        raw = bytes(pkt[scapy.UDP].payload).decode("utf-8", "ignore")
        if "NOTIFY" not in raw and "HTTP/1.1" not in raw:
            return
        server_m = re.search(r"SERVER:\s*(.+)", raw, re.I)
        nt_m = re.search(r"^NT:\s*(.+)", raw, re.I | re.M)
        service = nt_m.group(1).strip() if nt_m else None
        if server_m:
            result.observe(src_ip, name=server_m.group(1).strip()[:80],
                           service=service or "SSDP", protocol="SSDP")
        else:
            result.observe(src_ip, service=service or "SSDP", protocol="SSDP")
    except Exception:
        pass


def _handle_dhcp(pkt: Any, result: PassiveResult) -> None:
    if not pkt.haslayer(scapy.IP):
        return
    if not (pkt.haslayer(scapy.UDP) and pkt[scapy.UDP].dport in (67, 68)):
        return
    src_ip = pkt[scapy.IP].src
    try:
        raw = bytes(pkt[scapy.UDP].payload)
        if len(raw) < 240 or raw[:4] != b"\x01\x01\x06\x00":
            return
        if raw[236:240] != b"\x63\x82\x53\x63":
            return
        i = 240
        while i < len(raw) - 1:
            opt = raw[i]; i += 1
            if opt == 255:
                break
            if opt == 0:
                continue
            if i >= len(raw):
                break
            length = raw[i]; i += 1
            if i + length > len(raw):
                break
            data = raw[i:i + length]; i += length
            if opt == 12:
                hostname = data.decode("utf-8", "ignore").strip()
                if hostname:
                    result.observe(src_ip, name=hostname, protocol="DHCP")
    except Exception:
        pass


def _handle_llmnr(pkt: Any, result: PassiveResult) -> None:
    if not (pkt.haslayer(scapy.UDP) and pkt[scapy.UDP].dport == 5355):
        return
    if not pkt.haslayer(scapy.IP):
        return
    src_ip = pkt[scapy.IP].src
    try:
        raw = bytes(pkt[scapy.UDP].payload)
        if len(raw) < 12:
            return
        qd_count = struct.unpack("!H", raw[4:6])[0]
        offset = 12
        for _ in range(qd_count):
            name, offset = _decode_dns_name(raw, offset)
            offset += 4
            if name:
                result.observe(src_ip, protocol="LLMNR")
    except Exception:
        pass


def sniff(duration_s: float, interface: Optional[str] = None,
          stage_cb=None) -> PassiveResult:
    """Capture for duration_s seconds, harvesting passive observations."""
    result = PassiveResult()
    ok, _ = available()
    if not ok:
        return result

    if stage_cb:
        stage_cb(f"Passive sniff: listening {duration_s:.0f}s")

    def handle(pkt: Any) -> None:
        try:
            _handle_arp(pkt, result)
            _handle_mdns(pkt, result)
            _handle_netbios_ns(pkt, result)
            _handle_ssdp(pkt, result)
            _handle_dhcp(pkt, result)
            _handle_llmnr(pkt, result)
        except Exception:
            pass

    try:
        kwargs = {"iface": interface} if interface else {}
        scapy.sniff(prn=handle, timeout=duration_s, store=False,
                    filter="arp or udp or (ip and icmp)", **kwargs)
    except Exception:
        pass
    return result
