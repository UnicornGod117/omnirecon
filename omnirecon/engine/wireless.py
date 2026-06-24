"""
Wireless survey + RF analysis.

Surveys *all* nearby access points (not just the one we're associated with) and
derives operational intelligence from the scan: per-channel utilization, a
best-channel recommendation, rogue-AP / evil-twin detection against the network
we're connected to, and weak-security / WPS findings.

Collection is best-effort and unprivileged where possible:
  - Linux:   `nmcli dev wifi` (no root) → enriched by `iw dev <if> scan` (root)
  - macOS:   `airport -s`
  - Windows: `netsh wlan show networks mode=bssid`

A missing tool or radio just yields an empty survey — never an error that
aborts a scan. Pairs with netinfo.get_wifi_info() (the *connected* link).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from . import oui
from .netinfo import _band_from_freq, _dbm_to_pct, _pct_to_dbm, _signal_label
from .primitives import is_linux, is_macos, is_windows, is_root, safe_run, which

# Non-overlapping 2.4 GHz channels — the only sane choices.
_CLEAN_24 = (1, 6, 11)

_WEAK_SEC_RE = re.compile(r"\b(open|wep|wpa(?!2|3))\b", re.I)


def _norm_security(s: Optional[str]) -> Optional[str]:
    if not s:
        return None
    s = s.strip()
    return s or None


def _ap_finalize(ap: Dict[str, Any], connected_bssid: Optional[str]) -> Dict[str, Any]:
    if ap.get("signal_dbm") is None and ap.get("signal_pct") is not None:
        ap["signal_dbm"] = _pct_to_dbm(ap["signal_pct"])
    if ap.get("signal_pct") is None and ap.get("signal_dbm") is not None:
        ap["signal_pct"] = _dbm_to_pct(ap["signal_dbm"])
    if ap.get("band") is None:
        ap["band"] = _band_from_freq(ap.get("frequency_mhz"))
    ap["signal_quality"] = _signal_label(ap.get("signal_dbm"))
    if ap.get("bssid"):
        ap["bssid"] = ap["bssid"].lower()
        ap["vendor"] = oui.lookup(ap["bssid"])
    ap["connected"] = bool(connected_bssid and ap.get("bssid") == connected_bssid)
    return ap


# ── Platform collectors ───────────────────────────────────────────────────────

def _survey_linux() -> List[Dict[str, Any]]:
    aps: Dict[str, Dict[str, Any]] = {}
    if which("nmcli"):
        nm = safe_run(["nmcli", "-t", "-f",
                       "BSSID,SSID,CHAN,FREQ,SIGNAL,SECURITY", "device", "wifi"],
                      timeout=12)
        for line in (nm.get("stdout") or "").splitlines():
            parts = [p.replace("\\:", ":") for p in re.split(r"(?<!\\):", line)]
            if len(parts) < 6:
                continue
            bssid = (parts[0] or "").lower()
            if not re.match(r"^[0-9a-f:]{17}$", bssid):
                continue
            fm = re.search(r"(\d+)", parts[3])
            aps[bssid] = {
                "bssid": bssid, "ssid": parts[1] or None,
                "channel": int(parts[2]) if parts[2].isdigit() else None,
                "frequency_mhz": int(fm.group(1)) if fm else None,
                "signal_pct": int(parts[4]) if parts[4].isdigit() else None,
                "security": _norm_security(parts[5]) or "Open",
                "wps": None,
            }
    # `iw scan` (root) adds RSSI in dBm and WPS presence.
    if is_root() and which("iw"):
        dev = safe_run(["iw", "dev"], timeout=6)
        iface = None
        for line in (dev.get("stdout") or "").splitlines():
            m = re.search(r"^\s*Interface\s+(\S+)", line)
            if m:
                iface = m.group(1)
                break
        if iface:
            sc = safe_run(["iw", "dev", iface, "scan"], timeout=20)
            cur = None
            for line in (sc.get("stdout") or "").splitlines():
                bm = re.match(r"BSS ([0-9a-f:]{17})", line.strip(), re.I)
                if bm:
                    cur = bm.group(1).lower()
                    aps.setdefault(cur, {"bssid": cur})
                    continue
                if not cur:
                    continue
                sm = re.search(r"signal:\s*(-?[\d.]+)\s*dBm", line)
                if sm:
                    aps[cur]["signal_dbm"] = int(float(sm.group(1)))
                if "WPS:" in line or "WPS version" in line:
                    aps[cur]["wps"] = True
                ssm = re.search(r"^\s*SSID:\s*(.+)", line)
                if ssm and not aps[cur].get("ssid"):
                    aps[cur]["ssid"] = ssm.group(1).strip()
    return list(aps.values())


def _survey_windows() -> List[Dict[str, Any]]:
    raw = safe_run(["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=15)
    aps: List[Dict[str, Any]] = []
    ssid = None
    auth = None
    cur: Optional[Dict[str, Any]] = None
    for line in (raw.get("stdout") or "").splitlines():
        s = line.strip()
        m = re.match(r"SSID\s+\d+\s*:\s*(.*)", s)
        if m:
            ssid = m.group(1).strip() or None
            continue
        m = re.match(r"Authentication\s*:\s*(.+)", s)
        if m:
            auth = m.group(1).strip()
            continue
        m = re.match(r"BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})", s)
        if m:
            cur = {"bssid": m.group(1).lower(), "ssid": ssid,
                   "security": auth, "wps": None}
            aps.append(cur)
            continue
        if cur is not None:
            m = re.match(r"Signal\s*:\s*(\d+)%", s)
            if m:
                cur["signal_pct"] = int(m.group(1))
            m = re.match(r"Channel\s*:\s*(\d+)", s)
            if m:
                cur["channel"] = int(m.group(1))
    return aps


def _survey_macos() -> List[Dict[str, Any]]:
    airport = ("/System/Library/PrivateFrameworks/Apple80211.framework/"
               "Versions/Current/Resources/airport")
    raw = safe_run([airport, "-s"], timeout=12)
    aps: List[Dict[str, Any]] = []
    lines = (raw.get("stdout") or "").splitlines()
    for line in lines[1:]:  # skip header row
        m = re.search(r"^(.*?)\s+([0-9a-fA-F:]{17})\s+(-?\d+)\s+(\d+)", line.strip())
        if m:
            aps.append({
                "ssid": m.group(1).strip() or None,
                "bssid": m.group(2).lower(),
                "signal_dbm": int(m.group(3)),
                "channel": int(m.group(4)),
                "security": line.strip().split()[-1] if line.strip() else None,
                "wps": None,
            })
    return aps


def survey(connected_bssid: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return nearby APs (deduped by BSSID), strongest first."""
    try:
        if is_windows():
            aps = _survey_windows()
        elif is_macos():
            aps = _survey_macos()
        elif is_linux():
            aps = _survey_linux()
        else:
            aps = []
    except Exception:
        aps = []
    cb = (connected_bssid or "").lower() or None
    aps = [_ap_finalize(a, cb) for a in aps if a.get("bssid")]
    aps.sort(key=lambda a: (a.get("signal_dbm") if a.get("signal_dbm") is not None else -999),
             reverse=True)
    return aps


# ── Analysis (pure) ───────────────────────────────────────────────────────────

def _finding(severity, ip, title, detail, rec):
    return {"severity": severity, "category": "Wireless", "ip": ip,
            "title": title, "detail": detail, "recommendation": rec}


def analyze(aps: List[Dict[str, Any]],
            connected: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Channel load, best-channel pick, rogue-AP + WPS/weak-sec findings."""
    connected = connected or {}
    conn_ssid = connected.get("ssid")
    conn_bssid = (connected.get("bssid") or "").lower() or None

    # Channel utilization (count of APs per channel, split by band).
    chan_load: Dict[str, Dict[int, int]] = {"2.4 GHz": {}, "5 GHz": {}, "6 GHz": {}}
    for a in aps:
        band = a.get("band")
        ch = a.get("channel")
        if band in chan_load and ch:
            chan_load[band][ch] = chan_load[band].get(ch, 0) + 1

    # Best 2.4 GHz channel among the non-overlapping set (least loaded).
    load24 = chan_load["2.4 GHz"]
    best_24 = min(_CLEAN_24, key=lambda c: load24.get(c, 0)) if load24 else None

    findings: List[Dict[str, Any]] = []
    rogue: List[Dict[str, Any]] = []

    # Evil-twin: our SSID broadcast by a BSSID that isn't the one we joined.
    if conn_ssid:
        for a in aps:
            if a.get("ssid") == conn_ssid and a.get("bssid") and a["bssid"] != conn_bssid:
                rogue.append(a)
        if rogue:
            bsss = ", ".join(a["bssid"] for a in rogue)
            findings.append(_finding(
                "high", None, "Possible evil-twin / rogue AP",
                f'SSID "{conn_ssid}" is also advertised by unexpected BSSID(s): {bsss}.',
                "Verify these are your own APs; investigate any you don't recognise."))

    # WPS-enabled and weak/open security across visible APs.
    wps_aps = [a for a in aps if a.get("wps")]
    if wps_aps:
        findings.append(_finding(
            "medium", None, "WPS enabled on nearby AP(s)",
            f"{len(wps_aps)} AP(s) advertise WPS, which is brute-forceable (Pixie-Dust).",
            "Disable WPS on your access points."))
    for a in aps:
        sec = a.get("security") or ""
        if a.get("ssid") == conn_ssid and _WEAK_SEC_RE.search(sec):
            findings.append(_finding(
                "high", None, "Weak Wi-Fi security on your network",
                f'Your SSID "{conn_ssid}" uses {sec}.',
                "Use WPA2-AES at minimum; prefer WPA3."))
            break

    return {
        "ap_count": len(aps),
        "channel_load": {b: dict(sorted(v.items())) for b, v in chan_load.items() if v},
        "recommended_channel_24ghz": best_24,
        "rogue_aps": rogue,
        "findings": findings,
    }
