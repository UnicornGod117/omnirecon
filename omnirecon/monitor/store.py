#!/usr/bin/env python3
"""
store.py — OmniRecon monitor-mode persistence + diff engine.

Records each scan into SQLite, maintains MAC-keyed asset identity, and computes
severity-rated deltas between consecutive scans. This module is the ONLY place
the main program persists scan data; one-time mode never touches it unless the
user opts in via `--save`.

Stdlib only (sqlite3, json, datetime).
"""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    stamp       TEXT NOT NULL UNIQUE,
    scanned_at  TEXT NOT NULL,
    json_path   TEXT,
    host_count  INTEGER,
    subnets     TEXT,
    source      TEXT NOT NULL DEFAULT 'monitor'
);

CREATE TABLE IF NOT EXISTS assets (
    mac         TEXT PRIMARY KEY,
    ip          TEXT,
    device_name TEXT,
    device_type TEXT,
    vendor      TEXT,
    status      TEXT NOT NULL DEFAULT 'unverified',
    first_seen  TEXT,
    last_seen   TEXT,
    seen_count  INTEGER NOT NULL DEFAULT 0,
    notes       TEXT
);

CREATE TABLE IF NOT EXISTS asset_snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    mac         TEXT,
    ip          TEXT NOT NULL,
    open_ports  TEXT,
    device_name TEXT,
    vendor      TEXT,
    is_self     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS certs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL REFERENCES scans(id),
    ip              TEXT NOT NULL,
    port            INTEGER,
    subject         TEXT,
    issuer          TEXT,
    not_after       TEXT,
    is_self_signed  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS deltas (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER NOT NULL REFERENCES scans(id),
    delta_type   TEXT NOT NULL,
    severity     TEXT NOT NULL,
    mac          TEXT,
    ip           TEXT,
    detail       TEXT,
    acknowledged INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_snapshots_scan ON asset_snapshots(scan_id);
CREATE INDEX IF NOT EXISTS idx_snapshots_mac  ON asset_snapshots(mac);
CREATE INDEX IF NOT EXISTS idx_deltas_scan    ON deltas(scan_id);
CREATE INDEX IF NOT EXISTS idx_deltas_acked   ON deltas(acknowledged);
"""

MGMT_PORTS: frozenset = frozenset({22, 23, 3389, 5900, 5901, 8443, 10000})


def _asset_key(host: Dict[str, Any]) -> str:
    mac = (host.get("mac") or "").strip().lower()
    return mac if mac else f"ip:{host['ip']}"


def _iso_now() -> str:
    return dt.datetime.now().isoformat()


class Store:
    def __init__(self, db_path: str) -> None:
        self._path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self) -> None:
        """Additive migrations for DBs created by an earlier schema version."""
        cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(scans)")}
        if "source" not in cols:
            self._conn.execute(
                "ALTER TABLE scans ADD COLUMN source TEXT NOT NULL DEFAULT 'monitor'"
            )

    @property
    def conn(self) -> sqlite3.Connection:
        return self._conn

    def close(self) -> None:
        self._conn.close()

    # ── Record a scan ─────────────────────────────────────────────────────────

    def record_scan(self, stamp: str, json_path: str, report: Dict[str, Any],
                    source: str = "monitor") -> int:
        scanned_at = report.get("system", {}).get("timestamp_local", _iso_now())
        discovery = report.get("discovery", {})
        hosts = discovery.get("hosts", [])
        subnets = json.dumps(discovery.get("subnets", []))

        cur = self._conn.execute(
            "INSERT OR IGNORE INTO scans (stamp, scanned_at, json_path, host_count, subnets, source) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (stamp, scanned_at, json_path, len(hosts), subnets, source),
        )
        self._conn.commit()

        row = self._conn.execute("SELECT id FROM scans WHERE stamp = ?", (stamp,)).fetchone()
        scan_id: int = cur.lastrowid or row["id"]

        for host in hosts:
            self._upsert_asset(host, scanned_at)
            self._insert_snapshot(scan_id, host)
            self._insert_certs(scan_id, host, report)

        self._conn.commit()
        return scan_id

    def _upsert_asset(self, host: Dict[str, Any], scanned_at: str) -> None:
        key = _asset_key(host)
        existing = self._conn.execute(
            "SELECT seen_count FROM assets WHERE mac = ?", (key,)
        ).fetchone()

        if existing:
            self._conn.execute(
                "UPDATE assets SET ip=?, device_name=?, device_type=?, vendor=?, "
                "last_seen=?, seen_count=seen_count+1 WHERE mac=?",
                (host.get("ip"), host.get("device_name"), host.get("device_type"),
                 host.get("vendor"), scanned_at, key),
            )
        else:
            initial_status = "trusted" if host.get("is_self") else "unverified"
            self._conn.execute(
                "INSERT INTO assets "
                "(mac, ip, device_name, device_type, vendor, status, first_seen, last_seen, seen_count) "
                "VALUES (?,?,?,?,?,?,?,?,1)",
                (key, host.get("ip"), host.get("device_name"), host.get("device_type"),
                 host.get("vendor"), initial_status, scanned_at, scanned_at),
            )

    def _insert_snapshot(self, scan_id: int, host: Dict[str, Any]) -> None:
        raw_mac = (host.get("mac") or "").strip().lower()
        mac = raw_mac or None
        self._conn.execute(
            "INSERT INTO asset_snapshots "
            "(scan_id, mac, ip, open_ports, device_name, vendor, is_self) "
            "VALUES (?,?,?,?,?,?,?)",
            (scan_id, mac, host["ip"],
             json.dumps(host.get("open_ports") or []),
             host.get("device_name"), host.get("vendor"),
             1 if host.get("is_self") else 0),
        )

    def _insert_certs(self, scan_id: int, host: Dict[str, Any],
                      report: Dict[str, Any]) -> None:
        ip = host["ip"]
        sources: List[Tuple[int, Dict]] = []

        for port_str, hint in (host.get("service_hints") or {}).items():
            tls = hint.get("tls") if isinstance(hint, dict) else None
            if tls and isinstance(tls, dict):
                try:
                    sources.append((int(port_str), tls))
                except (ValueError, TypeError):
                    pass

        pentest_host = (report.get("pentest") or {}).get(ip) or {}
        for port_str, audit in (pentest_host.get("tls_audit") or {}).items():
            cert = audit.get("cert") if isinstance(audit, dict) else None
            if cert and isinstance(cert, dict):
                try:
                    sources.append((int(port_str), cert))
                except (ValueError, TypeError):
                    pass

        for port, cert in sources:
            subject = str(cert.get("subject") or cert.get("common_name") or "")[:200]
            issuer = str(cert.get("issuer") or "")[:200]
            not_after = str(cert.get("not_after") or cert.get("expires") or "")[:50]
            self_signed = 1 if (subject and issuer and subject == issuer) else 0
            self._conn.execute(
                "INSERT INTO certs (scan_id, ip, port, subject, issuer, not_after, is_self_signed) "
                "VALUES (?,?,?,?,?,?,?)",
                (scan_id, ip, port, subject, issuer, not_after, self_signed),
            )

    # ── Diff engine ───────────────────────────────────────────────────────────

    def compute_and_store_deltas(self, scan_id: int) -> List[Dict[str, Any]]:
        prev = self._conn.execute(
            "SELECT id FROM scans WHERE id < ? ORDER BY id DESC LIMIT 1", (scan_id,)
        ).fetchone()
        if not prev:
            return []

        prev_id = prev["id"]

        def _load_snaps(sid: int) -> Dict[str, Any]:
            rows = self._conn.execute(
                "SELECT * FROM asset_snapshots WHERE scan_id = ?", (sid,)
            ).fetchall()
            by_key: Dict[str, Any] = {}
            for r in rows:
                k = r["mac"] or f"ip:{r['ip']}"
                by_key[k] = r
            return by_key

        curr_map = _load_snaps(scan_id)
        prev_map = _load_snaps(prev_id)

        deltas: List[Dict[str, Any]] = []

        for key, snap in curr_map.items():
            if key in prev_map:
                continue
            asset = self._conn.execute(
                "SELECT status FROM assets WHERE mac = ?", (key,)
            ).fetchone()
            severity = "info" if (asset and asset["status"] == "trusted") else "high"
            deltas.append({
                "delta_type": "new_device", "severity": severity,
                "mac": snap["mac"], "ip": snap["ip"],
                "detail": {
                    "device_name": snap["device_name"],
                    "vendor": snap["vendor"],
                    "open_ports": json.loads(snap["open_ports"] or "[]"),
                },
            })

        for key, prev_snap in prev_map.items():
            if prev_snap["is_self"]:
                continue
            curr_snap = curr_map.get(key)
            if curr_snap is None:
                deltas.append({
                    "delta_type": "gone_device", "severity": "low",
                    "mac": prev_snap["mac"], "ip": prev_snap["ip"],
                    "detail": {"device_name": prev_snap["device_name"]},
                })
                continue

            if curr_snap["ip"] != prev_snap["ip"]:
                deltas.append({
                    "delta_type": "ip_changed", "severity": "info",
                    "mac": curr_snap["mac"], "ip": curr_snap["ip"],
                    "detail": {"old_ip": prev_snap["ip"], "new_ip": curr_snap["ip"]},
                })

            curr_ports = set(json.loads(curr_snap["open_ports"] or "[]"))
            prev_ports = set(json.loads(prev_snap["open_ports"] or "[]"))
            for p in sorted(curr_ports - prev_ports):
                sev = "medium" if p in MGMT_PORTS else "low"
                deltas.append({
                    "delta_type": "port_added", "severity": sev,
                    "mac": curr_snap["mac"], "ip": curr_snap["ip"],
                    "detail": {"port": p},
                })
            for p in sorted(prev_ports - curr_ports):
                deltas.append({
                    "delta_type": "port_removed", "severity": "info",
                    "mac": curr_snap["mac"], "ip": curr_snap["ip"],
                    "detail": {"port": p},
                })

        now = dt.datetime.now()
        for cert in self._conn.execute(
            "SELECT * FROM certs WHERE scan_id = ?", (scan_id,)
        ).fetchall():
            if not cert["not_after"]:
                continue
            try:
                expiry = dt.datetime.fromisoformat(
                    cert["not_after"].replace("Z", "+00:00")
                ).replace(tzinfo=None)
            except (ValueError, AttributeError):
                continue
            days_left = (expiry - now).days
            if days_left < 0:
                deltas.append({
                    "delta_type": "cert_expired", "severity": "high",
                    "mac": None, "ip": cert["ip"],
                    "detail": {"port": cert["port"], "subject": cert["subject"],
                               "expired_days_ago": abs(days_left)},
                })
            elif days_left <= 30:
                deltas.append({
                    "delta_type": "cert_expiring", "severity": "medium",
                    "mac": None, "ip": cert["ip"],
                    "detail": {"port": cert["port"], "subject": cert["subject"],
                               "days_left": days_left},
                })

        for d in deltas:
            self._conn.execute(
                "INSERT INTO deltas (scan_id, delta_type, severity, mac, ip, detail) "
                "VALUES (?,?,?,?,?,?)",
                (scan_id, d["delta_type"], d["severity"],
                 d.get("mac"), d.get("ip"), json.dumps(d.get("detail", {}))),
            )
        self._conn.commit()
        return deltas

    # ── Query API ─────────────────────────────────────────────────────────────

    def latest_scan_id(self) -> Optional[int]:
        row = self._conn.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        return row["id"] if row else None

    def get_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            """
            SELECT s.id, s.stamp, s.scanned_at, s.host_count, s.subnets, s.source,
                   COUNT(d.id)                                            AS delta_count,
                   SUM(CASE WHEN d.severity='high'   THEN 1 ELSE 0 END)  AS high_count,
                   SUM(CASE WHEN d.severity='medium' THEN 1 ELSE 0 END)  AS med_count
            FROM   scans s
            LEFT JOIN deltas d ON d.scan_id = s.id
            GROUP  BY s.id
            ORDER  BY s.id DESC
            LIMIT  ?
            """,
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_deltas(self, scan_id: Optional[int] = None,
                   unacked_only: bool = False) -> List[Dict[str, Any]]:
        if scan_id is None:
            scan_id = self.latest_scan_id()
            if scan_id is None:
                return []

        q = "SELECT * FROM deltas WHERE scan_id = ?"
        params: list = [scan_id]
        if unacked_only:
            q += " AND acknowledged = 0"
        q += (" ORDER BY CASE severity "
              "WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END")
        rows = self._conn.execute(q, params).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["detail"] = json.loads(d.get("detail") or "{}")
            result.append(d)
        return result

    def get_scan_id_for_stamp(self, stamp: str) -> Optional[int]:
        row = self._conn.execute(
            "SELECT id FROM scans WHERE stamp = ?", (stamp,)
        ).fetchone()
        return row["id"] if row else None

    def ack(self, mac_or_ip: str) -> int:
        cur = self._conn.execute(
            "UPDATE assets SET status='trusted' WHERE mac IN (?, ?)",
            (mac_or_ip.lower(), f"ip:{mac_or_ip}"),
        )
        self._conn.commit()
        return cur.rowcount

    def ack_all(self) -> int:
        cur = self._conn.execute(
            "UPDATE assets SET status='trusted' WHERE status='unverified'"
        )
        self._conn.commit()
        return cur.rowcount

    def ignore_asset(self, mac_or_ip: str, reason: str = "") -> int:
        cur = self._conn.execute(
            "UPDATE assets SET status='ignored', notes=? WHERE mac IN (?, ?)",
            (reason, mac_or_ip.lower(), f"ip:{mac_or_ip}"),
        )
        self._conn.commit()
        return cur.rowcount

    def get_certs(self, expiring_within_days: int = 90) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            """
            SELECT c.ip, c.port, c.subject, c.issuer, c.not_after, c.is_self_signed,
                   s.stamp, s.scanned_at
            FROM   certs c
            JOIN   scans s ON s.id = c.scan_id
            WHERE  s.id = (SELECT MAX(id) FROM scans)
            ORDER  BY c.not_after ASC NULLS LAST
            """
        ).fetchall()
        return [dict(r) for r in rows]

    def get_assets(self) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM assets "
            "ORDER BY CASE status WHEN 'unverified' THEN 0 WHEN 'trusted' THEN 1 ELSE 2 END, "
            "last_seen DESC"
        ).fetchall()
        return [dict(r) for r in rows]
