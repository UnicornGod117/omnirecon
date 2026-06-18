"""
Rule engine — declarative alert policies over computed deltas.

After a monitored scan diffs against the baseline, the rule engine lets a user
decide *what they care about* without writing code. Each rule matches some
deltas and then suppresses them, re-rates their severity, and/or routes them to
specific alert channels.

Rules live in a YAML file (PyYAML if installed) or a JSON file — whichever is
found first among:
    1. the path passed to load()
    2. $OMNIRECON_RULES
    3. .omnirecon/rules.yaml          5. .omnirecon/rules.json
    4. reports/rules.yaml             6. reports/rules.json

Rule shape (see examples/rules.yaml):

    rules:
      - name: "New device on network"
        trigger: new_device          # see TRIGGER_MAP; or a raw delta_type, or '*'
        severity: high               # optional: override the delta's severity
        alert: [log, webhook]        # optional: restrict to these channels
      - name: "Ignore guest VLAN"
        trigger: new_device
        match: { subnet: "192.168.10.0/24" }
        action: suppress             # drop matching deltas entirely
      - name: "Cert expiring soon"
        trigger: cert_expiry
        threshold_days: 30           # only fire when days_left <= 30
        alert: [webhook]

The first rule that matches a delta wins. Deltas that match no rule pass through
unchanged (default behaviour preserved). Stdlib-only unless YAML is used.
"""

from __future__ import annotations

import ipaddress
import json
import os
from typing import Any, Dict, List, Optional, Set, Tuple

# Friendly trigger names → the delta_type(s) the store actually emits.
TRIGGER_MAP: Dict[str, Set[str]] = {
    "new_device": {"new_device"},
    "device_gone": {"gone_device"},
    "gone_device": {"gone_device"},
    "new_service": {"port_added"},
    "service_added": {"port_added"},
    "service_removed": {"port_removed"},
    "port_added": {"port_added"},
    "port_removed": {"port_removed"},
    "ip_changed": {"ip_changed"},
    "cert_expiry": {"cert_expiring", "cert_expired"},
    "cert_expiring": {"cert_expiring"},
    "cert_expired": {"cert_expired"},
}

_KNOWN_CHANNELS = {"log", "webhook", "desktop", "email"}

DEFAULT_RULE_FILES = [
    os.path.join(".omnirecon", "rules.yaml"),
    os.path.join("reports", "rules.yaml"),
    os.path.join(".omnirecon", "rules.yml"),
    os.path.join(".omnirecon", "rules.json"),
    os.path.join("reports", "rules.json"),
]


# ── Loading ───────────────────────────────────────────────────────────────────

def _parse(text: str, is_yaml: bool) -> Any:
    if is_yaml:
        try:
            import yaml  # type: ignore
        except ImportError:
            # Fall back to JSON — works for the strict-JSON subset of YAML.
            return json.loads(text)
        return yaml.safe_load(text)
    return json.loads(text)


def load(path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return the list of rule dicts, or [] if no rules file is found."""
    candidates: List[str] = []
    if path:
        candidates.append(path)
    elif os.environ.get("OMNIRECON_RULES"):
        candidates.append(os.environ["OMNIRECON_RULES"])
    else:
        candidates.extend(DEFAULT_RULE_FILES)
    for cand in candidates:
        if not cand or not os.path.exists(cand):
            continue
        try:
            with open(cand, "r", encoding="utf-8") as f:
                text = f.read()
            data = _parse(text, cand.endswith((".yaml", ".yml")))
        except (OSError, ValueError) as exc:  # includes yaml.YAMLError (subclass)
            raise ValueError(f"failed to parse rules file {cand}: {exc}") from exc
        if isinstance(data, dict):
            rules = data.get("rules", [])
        elif isinstance(data, list):
            rules = data
        else:
            rules = []
        return [r for r in rules if isinstance(r, dict)]
    return []


# ── Matching ──────────────────────────────────────────────────────────────────

def _triggers_for(rule: Dict[str, Any]) -> Optional[Set[str]]:
    trig = rule.get("trigger")
    if not trig or trig in ("*", "any", "all"):
        return None  # matches every delta_type
    if isinstance(trig, list):
        out: Set[str] = set()
        for t in trig:
            out |= TRIGGER_MAP.get(str(t), {str(t)})
        return out
    return TRIGGER_MAP.get(str(trig), {str(trig)})


def _role_of(detail: Dict[str, Any]) -> str:
    return str(detail.get("role") or detail.get("asset_role") or "").strip().lower()


def _match_clause(match: Dict[str, Any], delta: Dict[str, Any]) -> bool:
    detail = delta.get("detail") or {}
    ip = delta.get("ip") or detail.get("new_ip") or detail.get("ip")

    if "subnet" in match and ip:
        try:
            if ipaddress.ip_address(ip) not in ipaddress.ip_network(str(match["subnet"]), strict=False):
                return False
        except ValueError:
            return False
    if "ip" in match and str(match["ip"]) != str(ip):
        return False
    if "port" in match:
        want = match["port"]
        ports = set(detail.get("open_ports") or [])
        if detail.get("port") is not None:
            ports.add(detail.get("port"))
        if want not in ports:
            return False
    if "vendor" in match:
        if str(match["vendor"]).lower() not in str(detail.get("vendor") or "").lower():
            return False
    if "asset_role" in match:
        want = str(match["asset_role"]).strip().lower()
        role = _role_of(detail)
        if want.startswith("!"):
            if role == want[1:]:
                return False
        elif role != want:
            return False
    return True


def matches(rule: Dict[str, Any], delta: Dict[str, Any]) -> bool:
    triggers = _triggers_for(rule)
    if triggers is not None and delta.get("delta_type") not in triggers:
        return False
    # Cert-expiry threshold: only fire when within N days (expired always fires).
    if "threshold_days" in rule and delta.get("delta_type") == "cert_expiring":
        days = (delta.get("detail") or {}).get("days_left")
        try:
            if days is not None and int(days) > int(rule["threshold_days"]):
                return False
        except (TypeError, ValueError):
            pass
    match = rule.get("match")
    if isinstance(match, dict) and not _match_clause(match, delta):
        return False
    return True


# ── Evaluation ────────────────────────────────────────────────────────────────

def evaluate(deltas: List[Dict[str, Any]],
             rules: List[Dict[str, Any]]) -> List[Tuple[Dict[str, Any], Optional[Set[str]]]]:
    """Apply rules to deltas. Returns [(delta, channels)] where channels is a set
    of channel names the delta is restricted to, or None for 'all configured'.
    Suppressed deltas are dropped from the result. The first matching rule wins;
    unmatched deltas pass through as (delta, None)."""
    out: List[Tuple[Dict[str, Any], Optional[Set[str]]]] = []
    for delta in deltas:
        rule = next((r for r in rules if matches(r, delta)), None)
        if rule is None:
            out.append((delta, None))
            continue
        if str(rule.get("action", "alert")).lower() == "suppress":
            continue
        d2 = dict(delta)
        if rule.get("severity"):
            d2["severity"] = str(rule["severity"]).lower()
        d2["rule"] = rule.get("name")
        alert = rule.get("alert")
        channels = ({str(c).strip().lower() for c in alert}
                    if isinstance(alert, list) else None)
        out.append((d2, channels))
    return out
