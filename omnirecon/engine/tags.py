"""
Asset tags — optional user annotations that make reports read like an audit.

A small, stdlib-first loader for a tags file that maps a device (by IP or MAC)
to a role, owner, and free-form label. The engine reads it and stamps each
discovered host with host['tags'] so reporters and the exposure mapper can use
the role (e.g. flag SSH exposed on a non-server).

File format (JSON always; YAML if PyYAML happens to be installed):

    {
      "192.168.1.10": { "role": "fileserver", "owner": "infra", "label": "NAS" },
      "aa:bb:cc:dd:ee:ff": { "role": "printer", "owner": "office" }
    }

Keys may be an IP or a MAC (case-insensitive). Missing file → no tags, no error.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

# Default search locations, first hit wins. Kept alongside other report artifacts.
DEFAULT_TAG_FILES = [
    os.path.join("reports", "asset_tags.json"),
    os.path.join("reports", "asset_tags.yaml"),
    os.path.join(".omnirecon", "tags.json"),
]


def _normalize_key(key: str) -> str:
    return (key or "").strip().lower()


def load_tags(path: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """Load the tags map. Returns {} if no file is found or it is unreadable."""
    candidates: List[str] = [path] if path else list(DEFAULT_TAG_FILES)
    for cand in candidates:
        if not cand or not os.path.exists(cand):
            continue
        try:
            with open(cand, "r", encoding="utf-8") as f:
                raw = f.read()
        except OSError:
            continue
        data = _parse(raw, cand)
        if isinstance(data, dict):
            return {_normalize_key(k): v for k, v in data.items()
                    if isinstance(v, dict)}
    return {}


def _parse(raw: str, path: str) -> Any:
    if path.lower().endswith((".yaml", ".yml")):
        try:
            import yaml  # type: ignore
            return yaml.safe_load(raw)
        except Exception:
            return None
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return None


def apply_tags(hosts: List[Dict[str, Any]],
               tags: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Stamp each host with its tags (matched by IP first, then MAC)."""
    if not tags:
        return hosts
    for h in hosts:
        ip = _normalize_key(h.get("ip", ""))
        mac = _normalize_key(h.get("mac", "") or "")
        tag = tags.get(ip) or (tags.get(mac) if mac else None)
        if tag:
            h["tags"] = tag
            if tag.get("role"):
                h["role"] = tag["role"]
    return hosts
