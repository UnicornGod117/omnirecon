"""
alerts.py — monitor-mode alerting.

After a monitored scan computes deltas, this dispatches the ones that matter to
configured channels. Channels are progressively configurable; everything is
opt-in via a small JSON config and degrades to "do nothing" when absent.

Channels:
  • log      — always-on append to reports/alerts.log (one JSON line per alert)
  • webhook  — POST JSON to any URL (Slack/Discord/Teams/ntfy via one code path)
  • desktop  — OS toast (plyer if present, else notify-send / osascript)

Config (reports/alerts.json, .omnirecon/alerts.json, or $OMNIRECON_ALERTS):

    {
      "enabled": true,
      "min_severity": "medium",
      "log": true,
      "desktop": false,
      "webhooks": [
        { "url": "https://hooks.slack.com/services/…", "style": "slack" }
      ]
    }

Stdlib only (urllib for the webhook) so monitor stays dependency-light.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
from typing import Any, Dict, List, Optional

_SEV_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}

DEFAULT_CONFIG_FILES = [
    os.path.join("reports", "alerts.json"),
    os.path.join(".omnirecon", "alerts.json"),
]


# ── Config ────────────────────────────────────────────────────────────────────

def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    """Load the alert config, or {} if none is found / it is disabled."""
    candidates: List[str] = []
    env = os.environ.get("OMNIRECON_ALERTS")
    if path:
        candidates.append(path)
    elif env:
        candidates.append(env)
    else:
        candidates.extend(DEFAULT_CONFIG_FILES)
    for cand in candidates:
        if cand and os.path.exists(cand):
            try:
                with open(cand, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                if isinstance(cfg, dict):
                    return cfg
            except (OSError, ValueError):
                continue
    return {}


# ── Formatting ────────────────────────────────────────────────────────────────

def _delta_phrase(d: Dict[str, Any]) -> str:
    detail = d.get("detail") or {}
    ip = d.get("ip") or "?"
    t = d.get("delta_type")
    if t == "new_device":
        return f"New device {ip} ({detail.get('vendor') or detail.get('device_name') or 'unknown'})"
    if t == "gone_device":
        return f"Device gone {ip}"
    if t == "port_added":
        return f"Port opened {ip}:{detail.get('port')}"
    if t == "port_removed":
        return f"Port closed {ip}:{detail.get('port')}"
    if t == "ip_changed":
        return f"IP changed {detail.get('old_ip')} → {detail.get('new_ip')}"
    if t == "cert_expiring":
        return f"Cert expiring {ip}:{detail.get('port')} ({detail.get('days_left')}d)"
    if t == "cert_expired":
        return f"Cert EXPIRED {ip}:{detail.get('port')}"
    return f"{t} {ip}"


def summarize(deltas: List[Dict[str, Any]]) -> str:
    by_sev: Dict[str, int] = {}
    for d in deltas:
        by_sev[d["severity"]] = by_sev.get(d["severity"], 0) + 1
    head = ", ".join(f"{n} {sev}" for sev, n in
                     sorted(by_sev.items(), key=lambda kv: -_SEV_RANK.get(kv[0], 0)))
    lines = [_delta_phrase(d) for d in deltas[:10]]
    if len(deltas) > 10:
        lines.append(f"…and {len(deltas) - 10} more")
    return f"OmniRecon: {len(deltas)} change(s) — {head}\n" + "\n".join(lines)


# ── Channels ──────────────────────────────────────────────────────────────────

def _write_log(deltas: List[Dict[str, Any]], stamp: str, outdir: str) -> None:
    path = os.path.join(outdir, "alerts.log")
    os.makedirs(outdir, exist_ok=True)
    ts = dt.datetime.now().isoformat()
    with open(path, "a", encoding="utf-8") as f:
        for d in deltas:
            f.write(json.dumps({"ts": ts, "scan": stamp, "severity": d["severity"],
                                "type": d["delta_type"], "ip": d.get("ip"),
                                "detail": d.get("detail")}, ensure_ascii=False) + "\n")


def _post_webhook(hook: Dict[str, Any], deltas: List[Dict[str, Any]],
                  stamp: str) -> Optional[str]:
    import urllib.request
    url = hook.get("url")
    if not url:
        return "no url"
    text = summarize(deltas)
    style = (hook.get("style") or "json").lower()
    if style in ("slack", "discord", "teams", "mattermost"):
        payload: Dict[str, Any] = {"text": text}
    elif style == "ntfy":
        payload = {"_raw": text}  # ntfy takes a plain body
    else:
        payload = {"source": "omnirecon", "scan": stamp,
                   "summary": text, "count": len(deltas), "deltas": deltas}
    try:
        if payload.get("_raw") is not None:
            data = payload["_raw"].encode("utf-8")
            req = urllib.request.Request(url, data=data, method="POST",
                                         headers={"Content-Type": "text/plain"})
        else:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=data, method="POST",
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=8) as resp:  # noqa: S310
            return None if 200 <= resp.status < 300 else f"HTTP {resp.status}"
    except Exception as e:  # noqa: BLE001
        return str(e)


def _desktop_notify(title: str, message: str) -> Optional[str]:
    try:
        from plyer import notification  # type: ignore
        notification.notify(title=title, message=message[:240], timeout=10)
        return None
    except Exception:
        pass
    # Native fallbacks
    try:
        import shutil
        if shutil.which("notify-send"):
            subprocess.run(["notify-send", title, message[:240]], timeout=8)
            return None
        if shutil.which("osascript"):
            script = f'display notification {json.dumps(message[:240])} with title {json.dumps(title)}'
            subprocess.run(["osascript", "-e", script], timeout=8)
            return None
    except Exception as e:  # noqa: BLE001
        return str(e)
    return "no desktop notifier available"


# ── Dispatch ──────────────────────────────────────────────────────────────────

def dispatch(deltas: List[Dict[str, Any]], stamp: str, outdir: str,
             config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Send qualifying deltas to all configured channels. Returns a summary."""
    cfg = config if config is not None else load_config()
    if not cfg or not cfg.get("enabled", True):
        return {"dispatched": False, "reason": "no config / disabled"}

    min_sev = _SEV_RANK.get(str(cfg.get("min_severity", "medium")).lower(), 2)
    matched = [d for d in deltas if _SEV_RANK.get(d["severity"], 0) >= min_sev]
    if not matched:
        return {"dispatched": False, "matched": 0, "reason": "nothing above threshold"}

    channels: List[str] = []
    errors: List[str] = []

    if cfg.get("log", True):
        try:
            _write_log(matched, stamp, outdir)
            channels.append("log")
        except Exception as e:  # noqa: BLE001
            errors.append(f"log: {e}")

    for hook in (cfg.get("webhooks") or ([cfg["webhook"]] if cfg.get("webhook") else [])):
        err = _post_webhook(hook, matched, stamp)
        if err:
            errors.append(f"webhook: {err}")
        else:
            channels.append("webhook")

    if cfg.get("desktop"):
        err = _desktop_notify("OmniRecon", summarize(matched))
        if err:
            errors.append(f"desktop: {err}")
        else:
            channels.append("desktop")

    return {"dispatched": bool(channels), "matched": len(matched),
            "channels": channels, "errors": errors}
