#!/usr/bin/env python3
"""
web/app.py — OmniRecon web UI entry point.

Run:  python web/app.py
      python -m web
      Opens http://127.0.0.1:5000 in the browser automatically.
"""

import datetime as dt
import json
import os
import sys
import threading
import webbrowser
from typing import Any, Dict, List, Optional

# Ensure the project root is on sys.path so omnirecon.* packages resolve
# regardless of where this file is invoked from.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from flask import (
    Flask, Response, flash, jsonify, redirect,
    render_template, request, url_for,
)

# ── Bootstrap ─────────────────────────────────────────────────────────────────

_DB     = os.path.join(_PROJECT_ROOT, "reports", "omnirecon.db")
_OUTDIR = os.path.join(_PROJECT_ROOT, "reports")

app = Flask(__name__)
app.secret_key = os.urandom(24)

from omnirecon.monitor import Store as _Store, score as _score  # noqa: E402
from web import jobs as _jobs  # noqa: E402


# ── Store helper ──────────────────────────────────────────────────────────────

def _get_store():
    try:
        os.makedirs(_OUTDIR, exist_ok=True)
        return _Store(_DB)
    except Exception:
        return None


# ── Delta summary helper ──────────────────────────────────────────────────────

def _summarise_delta(d: dict) -> str:
    dtype  = d.get("delta_type", "")
    detail = d.get("detail") or {}
    ip     = d.get("ip") or "?"
    name   = detail.get("device_name") or d.get("mac") or ip

    if dtype == "new_device":
        return f"New device: {ip} {name}"
    if dtype == "gone_device":
        return f"Device gone: {ip} {name}"
    if dtype == "ip_changed":
        return f"IP changed: {d.get('mac')} → {detail.get('new_ip')}"
    if dtype == "port_added":
        return f"Port opened on {ip}: :{detail.get('port')}"
    if dtype == "port_removed":
        return f"Port closed on {ip}: :{detail.get('port')}"
    if dtype == "cert_expiring":
        return f"Cert expiring: {ip}:{detail.get('port')} ({detail.get('days_left')}d)"
    if dtype == "cert_expired":
        return f"Cert EXPIRED: {ip}:{detail.get('port')}"
    return f"{dtype}: {ip}"


def _enrich_deltas(deltas: List[dict]) -> List[dict]:
    for d in deltas:
        d["summary"] = _summarise_delta(d)
    return deltas


def _cert_days_left(not_after: Optional[str]) -> Optional[int]:
    if not not_after:
        return None
    try:
        expiry = dt.datetime.fromisoformat(
            not_after.replace("Z", "+00:00")
        ).replace(tzinfo=None)
        return (expiry - dt.datetime.now()).days
    except (ValueError, AttributeError):
        return None


# ── Pages ─────────────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    store = _get_store()
    stats: Dict[str, Any] = {
        "total_assets":   0,
        "unverified":     0,
        "high_findings":  0,
        "certs_expiring": 0,
        "total_scans":    0,
    }
    history: List[dict] = []
    deltas:  List[dict] = []
    score:   dict = {}

    if store:
        try:
            assets = store.get_assets()
            stats["total_assets"] = len(assets)
            stats["unverified"]   = sum(1 for a in assets if a["status"] == "unverified")

            history = store.get_history(limit=10)
            stats["total_scans"] = len(store.get_history(limit=9999))

            raw_deltas = store.get_deltas()
            stats["high_findings"] = sum(1 for d in raw_deltas if d["severity"] == "high")
            deltas = _enrich_deltas(raw_deltas[:10])

            certs = store.get_certs(expiring_within_days=30)
            stats["certs_expiring"] = len(certs)

            score = _score.compute(store)
        finally:
            store.close()

    return render_template(
        "dashboard.html",
        active="dashboard",
        stats=stats,
        history=history,
        deltas=deltas,
        score=score,
    )


@app.route("/scan")
def scan_page():
    token = request.args.get("token")
    return render_template("scan.html", active="scan", token=token)


@app.route("/assets")
def assets_page():
    f = request.args.get("filter", "all")
    store = _get_store()
    assets: List[dict] = []
    if store:
        try:
            all_assets = store.get_assets()
            assets = all_assets if f == "all" else [a for a in all_assets if a["status"] == f]
        finally:
            store.close()
    return render_template("assets.html", active="assets", assets=assets, filter=f)


@app.route("/history")
def history_page():
    store = _get_store()
    scans: List[dict] = []
    if store:
        try:
            raw = store.get_history(limit=50)
            for s in raw:
                s["deltas"] = _enrich_deltas(store.get_deltas(scan_id=s["id"]))
            scans = raw
        finally:
            store.close()
    return render_template("history.html", active="history", scans=scans)


def _latest_report() -> Optional[Dict[str, Any]]:
    """Load the JSON of the most recent recorded scan, if any."""
    store = _get_store()
    if not store:
        return None
    try:
        row = store.conn.execute(
            "SELECT json_path FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
    except Exception:
        return None
    finally:
        store.close()
    if not row or not row["json_path"] or not os.path.exists(row["json_path"]):
        return None
    try:
        with open(row["json_path"], "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


@app.route("/findings")
def findings_page():
    report = _latest_report()
    hygiene = (report or {}).get("hygiene") or {}
    return render_template(
        "findings.html", active="findings",
        summary=hygiene.get("summary") or {},
        findings=hygiene.get("findings") or [],
        by_host=hygiene.get("by_host") or {},
        have_report=report is not None,
    )


@app.route("/reports")
def reports_page():
    files: List[dict] = []
    try:
        for name in sorted(os.listdir(_OUTDIR), reverse=True):
            path = os.path.join(_OUTDIR, name)
            if not os.path.isfile(path):
                continue
            ext = name.rsplit(".", 1)[-1].lower()
            if ext not in ("html", "json", "csv", "md"):
                continue
            files.append({
                "name": name, "ext": ext,
                "size": os.path.getsize(path),
                "mtime": dt.datetime.fromtimestamp(
                    os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M"),
            })
    except OSError:
        pass
    return render_template("reports.html", active="reports", files=files)


@app.route("/reports/<path:name>")
def report_download(name: str):
    # Path-safe: only serve plain files directly inside the reports dir.
    safe = os.path.normpath(os.path.join(_OUTDIR, name))
    if not safe.startswith(_OUTDIR) or not os.path.isfile(safe):
        return ("Not found", 404)
    inline = safe.rsplit(".", 1)[-1].lower() in ("html", "json")
    with open(safe, "rb") as f:
        data = f.read()
    mime = {"html": "text/html", "json": "application/json",
            "csv": "text/csv", "md": "text/markdown"}.get(
        safe.rsplit(".", 1)[-1].lower(), "application/octet-stream")
    disp = "inline" if inline else "attachment"
    return Response(data, mimetype=mime,
                    headers={"Content-Disposition": f'{disp}; filename="{os.path.basename(safe)}"'})


@app.route("/certs")
def certs_page():
    store = _get_store()
    certs: List[dict] = []
    if store:
        try:
            raw = store.get_certs(expiring_within_days=3650)
            for c in raw:
                c["days_left"] = _cert_days_left(c.get("not_after"))
            certs = raw
        finally:
            store.close()
    return render_template("certs.html", active="certs", certs=certs)


# ── API ───────────────────────────────────────────────────────────────────────

@app.route("/api/scan/start", methods=["POST"])
def api_scan_start():
    config = request.get_json(force=True) or {}
    outdir = os.path.join(_PROJECT_ROOT, config.get("outdir") or "reports")
    outdir = os.path.normpath(outdir)

    # Safety: must be inside project root
    if not outdir.startswith(_PROJECT_ROOT):
        return jsonify({"error": "Invalid output directory."}), 400

    try:
        os.makedirs(outdir, exist_ok=True)
        token = _jobs.start(config, _DB, outdir)
        return jsonify({"token": token})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/<token>/stream")
def api_scan_stream(token: str):
    def generate():
        for line in _jobs.stream(token):
            yield f"data: {line}\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/scan/<token>/status")
def api_scan_status(token: str):
    return jsonify(_jobs.status(token))


@app.route("/api/assets/<path:key>/ack", methods=["POST"])
def api_asset_ack(key: str):
    store = _get_store()
    if not store:
        return jsonify({"error": "DB unavailable"}), 503
    try:
        n = store.ack(key)
        return jsonify({"updated": n})
    finally:
        store.close()


@app.route("/api/assets/<path:key>/ignore", methods=["POST"])
def api_asset_ignore(key: str):
    store = _get_store()
    if not store:
        return jsonify({"error": "DB unavailable"}), 503
    try:
        n = store.ignore_asset(key)
        return jsonify({"updated": n})
    finally:
        store.close()


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    url = "http://127.0.0.1:5000"
    print(f"\n  OmniRecon Web UI")
    print(f"  Listening on {url}")
    print(f"  DB: {_DB}")
    print(f"  Press Ctrl+C to quit.\n")
    threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)


if __name__ == "__main__":
    main()
