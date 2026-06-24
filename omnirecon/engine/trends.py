"""
Trends over time — topology time-lapse + Wi-Fi signal trend.

Pure functions over a chronologically ordered list of prior scans (oldest first,
newest last). They turn history into change-intelligence:

  - topology_timeline(): which hosts appeared / left / stayed, with a per-host
    presence record — so a front-end can animate the map and highlight new nodes.
  - signal_trend(): the RSSI series for the connected uplink, with the delta vs
    the baseline ("your uplink degraded 12 dB this week").

Stateless and I/O-free. Callers (monitor store, one-time outdir history, legacy
load_history) supply the snapshots; this module just analyzes them.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def snapshot_from_report(report: Dict[str, Any]) -> Dict[str, Any]:
    """Extract a compact time-lapse snapshot from a full report dict."""
    hosts = (report.get("discovery") or {}).get("hosts", [])
    wifi = report.get("wifi") or {}
    sys_ = report.get("system") or {}
    return {
        "stamp": sys_.get("timestamp_local") or report.get("stamp") or "",
        "host_ips": sorted(h.get("ip") for h in hosts if h.get("ip")),
        "signal_dbm": wifi.get("signal_dbm"),
        "ssid": wifi.get("ssid"),
        "bssid": wifi.get("bssid"),
    }


def topology_timeline(snapshots: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Per-host presence across snapshots + what changed in the latest scan."""
    snaps = [s for s in snapshots if s]
    if not snaps:
        return {"snapshots": [], "nodes": [], "added_last": [], "removed_last": []}
    stamps = [s.get("stamp", "") for s in snaps]
    total = len(snaps)
    seen: Dict[str, List[int]] = {}
    for idx, s in enumerate(snaps):
        for ip in s.get("host_ips", []):
            seen.setdefault(ip, []).append(idx)

    last_idx = total - 1
    prev_ips = set(snaps[last_idx - 1].get("host_ips", [])) if total > 1 else set()
    last_ips = set(snaps[last_idx].get("host_ips", []))

    nodes = []
    for ip, idxs in sorted(seen.items()):
        present_now = last_idx in idxs
        if len(idxs) == 1 and idxs[0] == last_idx:
            status = "new"
        elif not present_now:
            status = "left"
        elif len(idxs) == total:
            status = "stable"
        else:
            status = "intermittent"
        nodes.append({
            "ip": ip, "first_seen": stamps[idxs[0]], "last_seen": stamps[idxs[-1]],
            "count": len(idxs), "runs": total,
            "frequency": round(len(idxs) / total, 2),
            "present_now": present_now, "status": status,
        })
    return {
        "snapshots": stamps,
        "nodes": nodes,
        "added_last": sorted(last_ips - prev_ips) if total > 1 else sorted(last_ips),
        "removed_last": sorted(prev_ips - last_ips) if total > 1 else [],
    }


def signal_trend(snapshots: List[Dict[str, Any]]) -> Dict[str, Any]:
    """RSSI series for the uplink + delta vs the earliest sample."""
    series = [{"stamp": s.get("stamp", ""), "signal_dbm": s.get("signal_dbm")}
              for s in snapshots if s and s.get("signal_dbm") is not None]
    if len(series) < 2:
        return {"series": series, "samples": len(series),
                "delta_db": None, "trend": "insufficient data"}
    first = series[0]["signal_dbm"]
    last = series[-1]["signal_dbm"]
    delta = last - first
    trend = ("degraded" if delta <= -5 else
             "improved" if delta >= 5 else "stable")
    return {
        "series": series, "samples": len(series),
        "baseline_dbm": first, "latest_dbm": last,
        "delta_db": delta, "trend": trend,
    }


def from_reports(reports: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Convenience: build both trends from a list of full reports (oldest first)."""
    snaps = [snapshot_from_report(r) for r in reports]
    return {
        "topology_timeline": topology_timeline(snaps),
        "signal_trend": signal_trend(snaps),
        "scan_count": len(snaps),
    }
