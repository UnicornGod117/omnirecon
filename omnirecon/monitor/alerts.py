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


def _send_email(cfg: Dict[str, Any], subject: str, body: str) -> Optional[str]:
    """Send a plain-text email via SMTP. Returns an error string or None."""
    import smtplib
    from email.message import EmailMessage
    host = cfg.get("smtp_host")
    to = cfg.get("to")
    if not host or not to:
        return "email channel missing smtp_host/to"
    recipients = to if isinstance(to, list) else [to]
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg.get("from") or cfg.get("username") or "omnirecon@localhost"
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)
    try:
        port = int(cfg.get("smtp_port", 587))
        with smtplib.SMTP(host, port, timeout=15) as s:
            if cfg.get("use_tls", True):
                s.starttls()
            if cfg.get("username"):
                s.login(cfg["username"], cfg.get("password", ""))
            s.send_message(msg)
        return None
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

def _route(processed: List, channel: str, min_sev: int) -> List[Dict[str, Any]]:
    """Deltas that should go to `channel`. Rule-routed deltas (explicit channel
    set) bypass the severity threshold; default-routed deltas (channels=None)
    must clear min_severity and not be restricted away from this channel."""
    out: List[Dict[str, Any]] = []
    for delta, chans in processed:
        if chans is None:
            if _SEV_RANK.get(delta["severity"], 0) >= min_sev:
                out.append(delta)
        elif channel in chans:
            out.append(delta)
    return out


def dispatch(deltas: List[Dict[str, Any]], stamp: str, outdir: str,
             config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Send qualifying deltas to configured channels, honouring any rule policy.

    Flow: load config → apply rules (suppress / re-rate / route) → per-channel
    threshold + dispatch. With no rules file, behaviour is the classic
    min_severity broadcast to every configured channel.
    """
    cfg = config if config is not None else load_config()
    if not cfg or not cfg.get("enabled", True):
        return {"dispatched": False, "reason": "no config / disabled"}

    # Apply the rule engine (no-op when there is no rules file).
    rules_applied = 0
    try:
        from . import rules as rules_mod
        rule_list = rules_mod.load(cfg.get("rules_file"))
        if rule_list:
            processed = rules_mod.evaluate(deltas, rule_list)
            rules_applied = len(rule_list)
        else:
            processed = [(d, None) for d in deltas]
    except ValueError as e:
        return {"dispatched": False, "reason": f"rules error: {e}"}

    if not processed:
        return {"dispatched": False, "matched": 0, "reason": "all suppressed by rules"}

    min_sev = _SEV_RANK.get(str(cfg.get("min_severity", "medium")).lower(), 2)
    channels: List[str] = []
    errors: List[str] = []

    # log
    if cfg.get("log", True):
        log_deltas = _route(processed, "log", min_sev)
        if log_deltas:
            try:
                _write_log(log_deltas, stamp, outdir)
                channels.append("log")
            except Exception as e:  # noqa: BLE001
                errors.append(f"log: {e}")

    # webhook
    webhook_deltas = _route(processed, "webhook", min_sev)
    if webhook_deltas:
        for hook in (cfg.get("webhooks") or ([cfg["webhook"]] if cfg.get("webhook") else [])):
            err = _post_webhook(hook, webhook_deltas, stamp)
            if err:
                errors.append(f"webhook: {err}")
            elif "webhook" not in channels:
                channels.append("webhook")

    # desktop
    if cfg.get("desktop"):
        desk_deltas = _route(processed, "desktop", min_sev)
        if desk_deltas:
            err = _desktop_notify("OmniRecon", summarize(desk_deltas))
            if err:
                errors.append(f"desktop: {err}")
            else:
                channels.append("desktop")

    # email
    if cfg.get("email"):
        email_deltas = _route(processed, "email", min_sev)
        if email_deltas:
            err = _send_email(cfg["email"], f"OmniRecon: {len(email_deltas)} change(s)",
                              summarize(email_deltas))
            if err:
                errors.append(f"email: {err}")
            else:
                channels.append("email")

    matched = len({id(d) for d, _ in processed
                   if _ is not None or _SEV_RANK.get(d["severity"], 0) >= min_sev})
    return {"dispatched": bool(channels), "matched": matched,
            "channels": channels, "errors": errors, "rules_applied": rules_applied}
