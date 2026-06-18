"""
Posture scoring for monitor mode.

Computes a 0–100 security posture from the latest scan across four dimensions:
Asset Inventory, Trust Coverage, Cert Health, and Management Exposure. Operates
on a Store; lives apart from store.py so scoring can evolve without touching the
persistence/diff core.
"""

from __future__ import annotations

import datetime as dt
import json
from typing import Any, Dict, Optional

from .store import MGMT_PORTS, Store


def compute(store: Store, scan_id: Optional[int] = None) -> Dict[str, Any]:
    conn = store.conn
    if scan_id is None:
        scan_id = store.latest_scan_id()
        if scan_id is None:
            return {"error": "No scans recorded yet."}

    snaps = conn.execute(
        "SELECT * FROM asset_snapshots WHERE scan_id = ?", (scan_id,)
    ).fetchall()
    if not snaps:
        return {"error": "No host data for this scan."}

    total = len(snaps)
    non_self = [s for s in snaps if not s["is_self"]]

    named = sum(1 for s in snaps if s["device_name"])
    inventory_score = int(100 * named / total) if total else 0

    all_assets = conn.execute("SELECT status FROM assets").fetchall()
    trusted_count = sum(1 for a in all_assets if a["status"] == "trusted")
    trust_score = int(100 * trusted_count / len(all_assets)) if all_assets else 0

    all_certs = conn.execute(
        "SELECT not_after FROM certs WHERE scan_id = ?", (scan_id,)
    ).fetchall()
    cert_score: Optional[int]
    if all_certs:
        threshold = (dt.datetime.now() + dt.timedelta(days=30)).isoformat()
        healthy = sum(1 for c in all_certs if c["not_after"] and c["not_after"] > threshold)
        cert_score = int(100 * healthy / len(all_certs))
    else:
        cert_score = None

    exposed_mgmt = 0
    for s in non_self:
        ports = set(json.loads(s["open_ports"] or "[]"))
        exposed_mgmt += len(ports & MGMT_PORTS)
    mgmt_score = max(0, 100 - exposed_mgmt * 10)

    if cert_score is not None:
        overall = int(inventory_score * 0.25 + trust_score * 0.30
                      + cert_score * 0.25 + mgmt_score * 0.20)
        dimensions = {
            "Asset Inventory": inventory_score, "Trust Coverage": trust_score,
            "Cert Health": cert_score, "Mgmt Exposure": mgmt_score,
        }
        note = ""
    else:
        overall = int(inventory_score * 0.35 + trust_score * 0.40 + mgmt_score * 0.25)
        dimensions = {
            "Asset Inventory": inventory_score, "Trust Coverage": trust_score,
            "Mgmt Exposure": mgmt_score,
        }
        note = "Cert Health excluded — no TLS data in this scan."

    return {"overall": overall, "dimensions": dimensions,
            "hosts_assessed": total, "note": note}
