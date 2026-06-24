"""
Bluetooth / BLE discovery — an entire device class the IP scan can't see.

Phones, wearables, headphones, beacons, keyboards, and a lot of IoT speak
Bluetooth, not IP. A quick scan rounds out the asset picture next to the
Wi-Fi/Ethernet inventory.

Best-effort and tool-gated:
  - Linux:   `bluetoothctl` (timed scan) — needs BlueZ + a powered adapter
  - macOS:   `system_profiler SPBluetoothDataType` (paired/connected devices)
  - Windows: not supported via CLI → empty with a note
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from . import oui
from .primitives import is_linux, is_macos, is_windows, safe_run, which

_MAC_RE = re.compile(r"([0-9A-F]{2}(?::[0-9A-F]{2}){5})", re.I)


def available() -> Tuple[bool, str]:
    if is_linux():
        if which("bluetoothctl"):
            return True, ""
        return False, "bluetoothctl not found (install BlueZ)"
    if is_macos():
        return True, ""
    return False, "Bluetooth scan not supported on this platform"


def _scan_linux(duration_s: float) -> List[Dict[str, Any]]:
    devices: Dict[str, Dict[str, Any]] = {}
    # Timed discovery; --timeout returns control after the scan window.
    safe_run(["bluetoothctl", "--timeout", str(int(duration_s)), "scan", "on"],
             timeout=int(duration_s) + 10)
    res = safe_run(["bluetoothctl", "devices"], timeout=10)
    for line in (res.get("stdout") or "").splitlines():
        m = re.match(r"Device\s+([0-9A-F:]{17})\s+(.*)", line.strip(), re.I)
        if m:
            mac = m.group(1).lower()
            name = m.group(2).strip()
            devices[mac] = {"address": mac,
                            "name": None if name == mac.upper() else name,
                            "vendor": oui.lookup(mac)}
    return list(devices.values())


def _scan_macos() -> List[Dict[str, Any]]:
    res = safe_run(["system_profiler", "SPBluetoothDataType"], timeout=20)
    devices: List[Dict[str, Any]] = []
    out = res.get("stdout") or ""
    # Blocks look like:  "DeviceName:\n    Address: aa-bb-...\n    ..."
    blocks = re.split(r"\n(?=\s{4}\S.*:\n)", out)
    for blk in blocks:
        addr = re.search(r"Address:\s*([0-9A-Fa-f:\-]{17})", blk)
        name_m = re.match(r"\s*(.+?):", blk)
        if addr:
            devices.append({
                "address": addr.group(1).lower().replace("-", ":"),
                "name": name_m.group(1).strip() if name_m else None,
                "connected": "Connected: Yes" in blk,
            })
    return devices


def scan(duration_s: float = 8.0, stage_cb=None) -> Dict[str, Any]:
    ok, why = available()
    if not ok:
        return {"available": False, "reason": why, "devices": []}
    if stage_cb:
        stage_cb(f"Bluetooth scan ({duration_s:.0f}s)")
    try:
        if is_linux():
            devs = _scan_linux(duration_s)
        elif is_macos():
            devs = _scan_macos()
        else:
            devs = []
    except Exception as e:
        return {"available": True, "reason": repr(e), "devices": []}
    return {"available": True, "devices": devs, "count": len(devs)}
