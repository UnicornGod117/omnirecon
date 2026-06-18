"""
MAC → vendor lookup backed by the IEEE OUI database (oui.txt).

The file is parsed lazily on first lookup and cached. Refresh it with
`python update_oui.py`. If oui.txt is missing, lookups return None
rather than failing.
"""

from __future__ import annotations

import os
import re
from typing import Dict, Optional

_OUI_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "oui.txt",
)

_TABLE: Optional[Dict[str, str]] = None
_LINE = re.compile(r"^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$")


def _load() -> Dict[str, str]:
    global _TABLE
    if _TABLE is not None:
        return _TABLE
    table: Dict[str, str] = {}
    try:
        with open(_OUI_FILE, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = _LINE.match(line.strip())
                if m:
                    prefix = m.group(1).replace("-", "").lower()
                    table[prefix] = m.group(2).strip()
    except OSError:
        pass
    _TABLE = table
    return table


def _normalize(mac: str) -> str:
    return re.sub(r"[^0-9a-fA-F]", "", mac or "").lower()


def mac_to_oui(mac: Optional[str]) -> Optional[str]:
    """Normalized OUI prefix 'AA-BB-CC' for a MAC, or None."""
    if not mac:
        return None
    norm = _normalize(mac)
    if len(norm) < 6:
        return None
    h = norm[:6].upper()
    return f"{h[0:2]}-{h[2:4]}-{h[4:6]}"


def lookup(mac: Optional[str]) -> Optional[str]:
    """Return the vendor for a MAC address, or None if unknown/unavailable."""
    if not mac:
        return None
    norm = _normalize(mac)
    if len(norm) < 6:
        return None
    return _load().get(norm[:6])


# ── Device-type classification by vendor ──────────────────────────────────────

_DEVICE_TYPES: list = [
    (["Apple"],                                          "Apple Device",    "🍎"),
    (["Raspberry Pi"],                                   "Raspberry Pi",    "🥧"),
    (["Samsung Electronics", "LG Electronics", "Motorola", "OnePlus",
      "Xiaomi", "Huawei", "Nokia", "Sony Mobile"],       "Mobile Device",   "📱"),
    (["ASRock", "Gigabyte", "ASUS", "MSI", "Intel Corporate", "Dell",
      "HP Inc", "Hewlett", "Lenovo", "Acer", "Toshiba", "Sony", "Aopen",
      "Shuttle", "AMPAK"],                               "PC / Laptop",     "💻"),
    (["Ubiquiti", "Cisco", "Netgear", "TP-Link", "Mikrotik", "Ruckus",
      "Aruba", "D-Link", "Zyxel", "Juniper", "Palo Alto", "Fortinet",
      "FRITZ", "AVM", "Synology", "QNAP", "Western Digital", "Drobo"],
                                                         "Network / NAS",   "🌐"),
    (["VMware", "Virtual", "Xen", "QEMU", "Parallels", "Microsoft Hyper",
      "Oracle VirtualBox", "Proxmox"],                   "Virtual Machine", "📦"),
    (["Amazon", "Google", "Espressif", "Nordic Semi", "Tuya", "Shenzhen",
      "HiSilicon", "Realtek Semi", "Azurewave", "Ring"], "IoT / Smart",     "🔌"),
    (["Canon", "Epson", "HP", "Lexmark", "Ricoh", "Xerox", "Brother",
      "Kyocera", "Konica", "Zebra", "Intermec"],         "Printer",         "🖨"),
    (["APC", "Eaton", "Vertiv", "Schneider"],            "UPS / Power",     "🔋"),
    (["Hikvision", "Dahua", "Axis", "Hanwha", "Vivotek"], "IP Camera",      "📷"),
]


def guess_device_type(vendor: Optional[str]) -> tuple:
    """Return (label, icon) for a vendor string."""
    if not vendor:
        return ("Unknown", "❓")
    v = vendor.lower()
    for kws, label, icon in _DEVICE_TYPES:
        if any(kw.lower() in v for kw in kws):
            return (label, icon)
    return ("Unknown", "❓")
