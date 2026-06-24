"""
Layer-2 neighbor discovery — passive LLDP + CDP listener.

Switches and APs periodically announce themselves via LLDP (IEEE 802.1AB) and
CDP (Cisco). Listening for those frames — sending nothing — reveals the *switch
name, the exact port a link is plugged into, the native VLAN, and the switch's
management IP*. That is what turns the topology from a star into a real wiring
diagram.

Privileged + optional: needs scapy + root/Administrator (announcements are
infrequent, so a 30–60 s listen is typical). Degrades to an empty list.
"""

from __future__ import annotations

import struct
import time
from typing import Any, Dict, List, Optional, Tuple

from .primitives import is_windows, is_root

try:
    import scapy.all as scapy  # type: ignore
    _HAS_SCAPY = True
except Exception:
    _HAS_SCAPY = False

_LLDP_MULTICAST = {"01:80:c2:00:00:0e", "01:80:c2:00:00:03", "01:80:c2:00:00:00"}
_CDP_MULTICAST = "01:00:0c:cc:cc:cc"


def available() -> Tuple[bool, str]:
    if not _HAS_SCAPY:
        return False, "scapy not installed (pip install scapy)"
    if not is_root():
        return False, "LLDP/CDP capture requires root/Administrator"
    return True, ""


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


# ── LLDP ──────────────────────────────────────────────────────────────────────

def parse_lldp(payload: bytes) -> Dict[str, Any]:
    """Parse an LLDPDU (the bytes after the 0x88cc ethertype)."""
    out: Dict[str, Any] = {"protocol": "LLDP"}
    i = 0
    n = len(payload)
    while i + 2 <= n:
        header = struct.unpack("!H", payload[i:i + 2])[0]
        ttype = header >> 9
        tlen = header & 0x1FF
        i += 2
        val = payload[i:i + tlen]
        i += tlen
        if ttype == 0:  # end
            break
        if ttype == 1 and len(val) > 1:      # Chassis ID
            out["chassis_id"] = _decode_id(val)
        elif ttype == 2 and len(val) > 1:    # Port ID
            out["port_id"] = _decode_id(val)
        elif ttype == 4:                     # Port description
            out["port_desc"] = val.decode("utf-8", "ignore").strip("\x00")
        elif ttype == 5:                     # System name
            out["system_name"] = val.decode("utf-8", "ignore").strip("\x00")
        elif ttype == 6:                     # System description
            out["system_desc"] = val.decode("utf-8", "ignore").strip("\x00")[:200]
        elif ttype == 8 and len(val) >= 7:   # Management address
            addr_len = val[0]
            addr_subtype = val[1]
            addr = val[2:1 + addr_len]
            if addr_subtype == 1 and len(addr) == 4:  # IPv4
                out["mgmt_addr"] = ".".join(str(x) for x in addr)
        elif ttype == 127 and len(val) >= 4:  # Org-specific (802.1 → VLAN)
            oui_b = val[:3]
            subtype = val[3]
            if oui_b == b"\x00\x80\xc2" and subtype == 1 and len(val) >= 6:
                out["vlan"] = struct.unpack("!H", val[4:6])[0]
    return out


def _decode_id(val: bytes) -> str:
    subtype = val[0]
    body = val[1:]
    # MAC address subtypes (4 for chassis, 3 for port)
    if subtype in (4, 3) and len(body) == 6:
        return _mac(body)
    txt = body.decode("utf-8", "ignore").strip("\x00")
    return txt or _mac(body) if len(body) == 6 else txt


# ── CDP ───────────────────────────────────────────────────────────────────────

def parse_cdp(payload: bytes) -> Dict[str, Any]:
    """Parse a CDP payload (after the SNAP header: version/ttl/checksum + TLVs)."""
    out: Dict[str, Any] = {"protocol": "CDP"}
    if len(payload) < 4:
        return out
    i = 4  # skip version(1) ttl(1) checksum(2)
    n = len(payload)
    while i + 4 <= n:
        ttype, tlen = struct.unpack("!HH", payload[i:i + 4])
        if tlen < 4 or i + tlen > n:
            break
        val = payload[i + 4:i + tlen]
        if ttype == 0x0001:
            out["system_name"] = val.decode("utf-8", "ignore").strip("\x00")
        elif ttype == 0x0003:
            out["port_id"] = val.decode("utf-8", "ignore").strip("\x00")
        elif ttype == 0x0006:
            out["platform"] = val.decode("utf-8", "ignore").strip("\x00")[:120]
        elif ttype == 0x0005:
            out["software"] = val.decode("utf-8", "ignore").strip("\x00")[:120]
        elif ttype == 0x000a and len(val) >= 2:
            out["vlan"] = struct.unpack("!H", val[:2])[0]
        elif ttype == 0x0002 and len(val) >= 9:  # Addresses
            try:
                count = struct.unpack("!I", val[:4])[0]
                off = 4
                for _ in range(min(count, 4)):
                    # proto_type(1) proto_len(1) proto(var) addr_len(2) addr
                    plen = val[off + 1]
                    off += 2 + plen
                    alen = struct.unpack("!H", val[off:off + 2])[0]
                    off += 2
                    if alen == 4:
                        out["mgmt_addr"] = ".".join(str(x) for x in val[off:off + 4])
                    off += alen
            except Exception:
                pass
        i += tlen
    return out


def _parse_frame(raw: bytes) -> Optional[Dict[str, Any]]:
    if len(raw) < 15:
        return None
    dst = _mac(raw[0:6])
    src = _mac(raw[6:12])
    ethertype = struct.unpack("!H", raw[12:14])[0]
    if ethertype == 0x88CC:
        info = parse_lldp(raw[14:])
    elif dst == _CDP_MULTICAST:
        # 802.3: len field, then LLC AA AA 03, OUI 00 00 0c, PID 20 00
        idx = raw.find(b"\xaa\xaa\x03\x00\x00\x0c\x20\x00", 14)
        if idx < 0:
            return None
        info = parse_cdp(raw[idx + 8:])
    else:
        return None
    info["source_mac"] = src
    return info if len(info) > 2 else None


def listen(duration_s: float = 35.0, interface: Optional[str] = None,
           stage_cb=None) -> List[Dict[str, Any]]:
    """Capture LLDP/CDP for duration_s seconds. Returns deduped neighbors."""
    ok, _ = available()
    if not ok:
        return []
    if stage_cb:
        stage_cb(f"LLDP/CDP listen: {duration_s:.0f}s")

    found: Dict[str, Dict[str, Any]] = {}

    def handle(pkt: Any) -> None:
        try:
            info = _parse_frame(bytes(pkt))
            if info:
                key = info.get("chassis_id") or info.get("system_name") or info["source_mac"]
                found[key] = {**found.get(key, {}), **info,
                              "last_seen": time.time()}
        except Exception:
            pass

    try:
        kwargs = {"iface": interface} if interface else {}
        bpf = "ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc"
        scapy.sniff(prn=handle, timeout=duration_s, store=False, filter=bpf, **kwargs)
    except Exception:
        # Some platforms reject the BPF for SNAP; retry filterless.
        try:
            scapy.sniff(prn=handle, timeout=min(duration_s, 20), store=False,
                        **({"iface": interface} if interface else {}))
        except Exception:
            pass

    for v in found.values():
        v.pop("last_seen", None)
    return list(found.values())
