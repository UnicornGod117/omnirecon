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
        # Extended passive intel.
        self.conversations: Dict[Tuple[str, str], int] = {}
        self.vlans: set = set()
        self.dhcp_servers: set = set()
        self.os_fingerprints: Dict[str, str] = {}
        self.pcap: List[Any] = []
        self.capture_pcap: bool = False

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

    def observe_conversation(self, src: str, dst: str) -> None:
        if not (is_private_or_lan_ip(src) and is_private_or_lan_ip(dst)) or src == dst:
            return
        key = tuple(sorted((src, dst)))
        with self._lock:
            self.conversations[key] = self.conversations.get(key, 0) + 1

    def observe_vlan(self, vlan_id: int) -> None:
        if vlan_id:
            with self._lock:
                self.vlans.add(int(vlan_id))

    def observe_dhcp_server(self, ip: str) -> None:
        if ip and is_private_or_lan_ip(ip):
            with self._lock:
                self.dhcp_servers.add(ip)

    def observe_osfp(self, ip: str, guess: str) -> None:
        if ip and guess:
            with self._lock:
                self.os_fingerprints.setdefault(ip, guess)

    def to_list(self) -> List[Dict[str, Any]]:
        with self._lock:
            out = [{
                "ip": ip, "mac": h["mac"], "names": sorted(h["names"]),
                "services": sorted(h["services"]), "protocols": sorted(h["protocols"]),
                "packet_count": self.packet_counts.get(ip, 0),
                "os_fingerprint": self.os_fingerprints.get(ip),
            } for ip, h in self.hosts.items()]
        return sorted(out, key=lambda x: ip_sort_key(x["ip"]))

    def conversation_list(self) -> List[Dict[str, Any]]:
        with self._lock:
            return sorted(
                ({"a": a, "b": b, "packets": n}
                 for (a, b), n in self.conversations.items()),
                key=lambda c: c["packets"], reverse=True)

    def extras(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "conversations": sorted(
                    ({"a": a, "b": b, "packets": n}
                     for (a, b), n in self.conversations.items()),
                    key=lambda c: c["packets"], reverse=True),
                "vlans": sorted(self.vlans),
                "dhcp_servers": sorted(self.dhcp_servers),
                "os_fingerprints": dict(self.os_fingerprints),
            }


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
        if len(raw) < 240 or raw[236:240] != b"\x63\x82\x53\x63":
            return
        op = raw[0]
        msg_type = None
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
            if opt == 12:  # hostname (in BOOTP requests)
                hostname = data.decode("utf-8", "ignore").strip()
                if hostname and op == 1:
                    result.observe(src_ip, name=hostname, protocol="DHCP")
            elif opt == 53 and length == 1:  # DHCP message type
                msg_type = data[0]
        # OFFER (2) / ACK (5) come *from* a DHCP server — track the source.
        if msg_type in (2, 5):
            result.observe_dhcp_server(src_ip)
    except Exception:
        pass


def _handle_conversation(pkt: Any, result: PassiveResult) -> None:
    if pkt.haslayer(scapy.IP):
        try:
            result.observe_conversation(pkt[scapy.IP].src, pkt[scapy.IP].dst)
        except Exception:
            pass


def _handle_vlan(pkt: Any, result: PassiveResult) -> None:
    if pkt.haslayer(scapy.Dot1Q):
        try:
            result.observe_vlan(int(pkt[scapy.Dot1Q].vlan))
        except Exception:
            pass


# Passive OS fingerprint from the SYN packet's IP-TTL + TCP window size.
_OSFP_TABLE = [
    (64, 64240, "Linux"), (64, 65535, "Linux/Android"),
    (128, 65535, "Windows"), (128, 8192, "Windows"),
    (255, 4128, "Cisco/Network gear"), (64, 5840, "Linux (older)"),
]


def _handle_osfp(pkt: Any, result: PassiveResult) -> None:
    if not (pkt.haslayer(scapy.IP) and pkt.haslayer(scapy.TCP)):
        return
    try:
        tcp = pkt[scapy.TCP]
        if tcp.flags & 0x02 and not (tcp.flags & 0x10):  # SYN, not SYN/ACK
            ttl = int(pkt[scapy.IP].ttl)
            win = int(tcp.window)
            # Round TTL up to the nearest common initial value.
            init_ttl = 64 if ttl <= 64 else 128 if ttl <= 128 else 255
            guess = next((os_ for t, w, os_ in _OSFP_TABLE
                          if t == init_ttl and w == win), None)
            if not guess:
                guess = {64: "Linux/Unix", 128: "Windows",
                         255: "Network gear"}.get(init_ttl)
            if guess:
                result.observe_osfp(pkt[scapy.IP].src, guess)
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
          stage_cb=None, capture_pcap: bool = False) -> PassiveResult:
    """Capture for duration_s seconds, harvesting passive observations.

    With capture_pcap=True, raw frames are retained so the caller can write a
    .pcap for offline Wireshark analysis (see write_pcap)."""
    result = PassiveResult()
    result.capture_pcap = capture_pcap
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
            _handle_conversation(pkt, result)
            _handle_vlan(pkt, result)
            _handle_osfp(pkt, result)
            if capture_pcap:
                result.pcap.append(pkt)
        except Exception:
            pass

    try:
        kwargs = {"iface": interface} if interface else {}
        # Broader filter so we also see TCP SYNs (OS fingerprint) + conversations.
        scapy.sniff(prn=handle, timeout=duration_s, store=False, **kwargs)
    except Exception:
        pass
    return result


def write_pcap(result: PassiveResult, path: str) -> Optional[str]:
    """Write captured frames to a .pcap. Returns the path, or None if empty."""
    if not _HAS_SCAPY or not getattr(result, "pcap", None):
        return None
    try:
        scapy.wrpcap(path, result.pcap)
        return path
    except Exception:
        return None
