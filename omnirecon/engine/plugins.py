"""
Plugin system — user-droppable checks that extend the brain without touching it.

A plugin is a small Python file that defines one or more `Plugin` subclasses.
Two kinds exist, mirroring the architecture's two seams:

  • AnalysisPlugin — pure, read-only over the normalized report. Returns extra
    findings. Runs inside the engine on every scan (free, no network I/O), so it
    is safe for monitor mode. MUST NOT perform I/O.

  • ActivePlugin   — probes a host over the network. Runs in ONE-TIME mode only
    (it is aggression, and one-time owns aggression). If `requires_authorization`
    is set, it is skipped unless the caller passed authorized=True — the same
    consent gate the pentest suite uses.

Plugins are discovered from, in order:
  1. directories in $OMNIRECON_PLUGINS (os.pathsep-separated)
  2. ./plugins
  3. ./.omnirecon/plugins
  4. the repo's bundled plugins/ directory

Each `.py` file whose name does not start with `_` is imported; every concrete
`AnalysisPlugin` / `ActivePlugin` subclass found in it is instantiated. A module
may also expose a ready instance as `PLUGIN` (or a list as `PLUGINS`).

Nothing here imports monitor/onetime/web. Loading is opt-in (engine only loads
plugins when EngineOptions.plugins is set), so the "hygiene does no I/O" contract
holds for default scans.
"""

from __future__ import annotations

import importlib.util
import os
import traceback
from typing import Any, Callable, Dict, List, Optional

StageCb = Optional[Callable[[str], None]]


# ── Base classes ──────────────────────────────────────────────────────────────

class Plugin:
    """Base for all plugins. Subclasses set `name` and `kind`."""
    name: str = "unnamed"
    kind: str = "analysis"          # "analysis" | "active"
    description: str = ""


class AnalysisPlugin(Plugin):
    """Pure, read-only analysis over the whole report. No network/disk I/O."""
    kind = "analysis"

    def analyze(self, report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Return a list of findings (use `finding()` to build them)."""
        return []


class ActivePlugin(Plugin):
    """Active per-host probe. One-time mode only."""
    kind = "active"
    requires_authorization: bool = False

    def applies(self, host: Dict[str, Any]) -> bool:
        """Whether this plugin wants to run against `host`."""
        return bool(host.get("open_ports"))

    def run(self, host: Dict[str, Any]) -> Dict[str, Any]:
        """Probe the host. Return a JSON-able result dict (stored per host)."""
        return {}

    def findings(self, host: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Optionally turn a result into report findings."""
        return []


def finding(severity: str, category: str, ip: Optional[str], title: str,
            detail: str, recommendation: str = "") -> Dict[str, Any]:
    """Build a finding in the schema hygiene/report expect."""
    return {"severity": severity, "category": category, "ip": ip,
            "title": title, "detail": detail, "recommendation": recommendation}


# ── Discovery / loading ───────────────────────────────────────────────────────

_VALID_SEV = {"high", "medium", "low", "info"}


def default_dirs() -> List[str]:
    dirs: List[str] = []
    env = os.environ.get("OMNIRECON_PLUGINS")
    if env:
        dirs.extend(p for p in env.split(os.pathsep) if p.strip())
    dirs.append(os.path.join(os.getcwd(), "plugins"))
    dirs.append(os.path.join(os.getcwd(), ".omnirecon", "plugins"))
    # repo-bundled plugins/ (…/omnirecon/engine/plugins.py → repo root)
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    dirs.append(os.path.join(repo_root, "plugins"))
    # De-dup, preserve order.
    seen: set = set()
    out: List[str] = []
    for d in dirs:
        ad = os.path.abspath(d)
        if ad not in seen:
            seen.add(ad)
            out.append(ad)
    return out


def _instances_from_module(mod: Any) -> List[Plugin]:
    found: List[Plugin] = []
    explicit = getattr(mod, "PLUGINS", None) or (
        [mod.PLUGIN] if getattr(mod, "PLUGIN", None) else [])
    for obj in explicit:
        if isinstance(obj, Plugin):
            found.append(obj)
    for attr in vars(mod).values():
        if (isinstance(attr, type) and issubclass(attr, Plugin)
                and attr not in (Plugin, AnalysisPlugin, ActivePlugin)):
            try:
                found.append(attr())
            except Exception:
                continue
    # De-dup by (name, kind).
    uniq: Dict[Any, Plugin] = {}
    for p in found:
        uniq.setdefault((getattr(p, "name", ""), getattr(p, "kind", "")), p)
    return list(uniq.values())


def load(dirs: Optional[List[str]] = None,
         names: Optional[List[str]] = None) -> List[Plugin]:
    """Import every plugin file under `dirs` and return instantiated plugins.

    `names` (if given) filters to those plugin names. Import errors are swallowed
    per-file so one broken plugin never breaks a scan.
    """
    search = dirs if dirs is not None else default_dirs()
    plugins: List[Plugin] = []
    for d in search:
        if not os.path.isdir(d):
            continue
        for entry in sorted(os.listdir(d)):
            if not entry.endswith(".py") or entry.startswith("_"):
                continue
            path = os.path.join(d, entry)
            mod_name = f"omnirecon_plugin_{os.path.splitext(entry)[0]}"
            try:
                spec = importlib.util.spec_from_file_location(mod_name, path)
                if not spec or not spec.loader:
                    continue
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
            except Exception:
                # A misbehaving plugin must not abort the scan.
                continue
            plugins.extend(_instances_from_module(mod))
    if names:
        wanted = {n.strip() for n in names if n.strip()}
        plugins = [p for p in plugins if p.name in wanted]
    return plugins


def list_plugins(dirs: Optional[List[str]] = None) -> List[Dict[str, str]]:
    """Metadata for every discoverable plugin (for `--list-plugins` / web UI)."""
    out: List[Dict[str, str]] = []
    for p in load(dirs):
        out.append({"name": p.name, "kind": p.kind,
                    "description": getattr(p, "description", ""),
                    "requires_authorization": str(
                        bool(getattr(p, "requires_authorization", False))).lower()})
    return out


# ── Execution ─────────────────────────────────────────────────────────────────

def _clean_findings(raw: Any, plugin_name: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not isinstance(raw, list):
        return out
    for f in raw:
        if not isinstance(f, dict):
            continue
        sev = str(f.get("severity", "info")).lower()
        if sev not in _VALID_SEV:
            sev = "info"
        out.append({
            "severity": sev,
            "category": str(f.get("category") or f"Plugin: {plugin_name}"),
            "ip": f.get("ip"),
            "title": str(f.get("title") or "Plugin finding"),
            "detail": str(f.get("detail") or ""),
            "recommendation": str(f.get("recommendation") or ""),
            "plugin": plugin_name,
        })
    return out


def run_analysis(report: Dict[str, Any], dirs: Optional[List[str]] = None,
                 names: Optional[List[str]] = None,
                 stage_cb: StageCb = None) -> List[Dict[str, Any]]:
    """Run every analysis plugin over the report; return merged findings."""
    findings: List[Dict[str, Any]] = []
    for p in load(dirs, names):
        if not isinstance(p, AnalysisPlugin):
            continue
        if stage_cb:
            stage_cb(f"plugin: {p.name}")
        try:
            findings.extend(_clean_findings(p.analyze(report), p.name))
        except Exception:
            continue
    return findings


def run_active(hosts: List[Dict[str, Any]], authorized: bool = False,
               dirs: Optional[List[str]] = None, names: Optional[List[str]] = None,
               stage_cb: StageCb = None) -> Dict[str, Any]:
    """Run active plugins against each host.

    Returns {"results": {plugin_name: {ip: result}}, "findings": [...],
             "skipped": [names needing authorization]}.
    """
    results: Dict[str, Dict[str, Any]] = {}
    findings: List[Dict[str, Any]] = []
    skipped: List[str] = []
    targets = [h for h in hosts if not h.get("is_self")]
    for p in load(dirs, names):
        if not isinstance(p, ActivePlugin):
            continue
        if getattr(p, "requires_authorization", False) and not authorized:
            skipped.append(p.name)
            continue
        for host in targets:
            try:
                if not p.applies(host):
                    continue
            except Exception:
                continue
            ip = host.get("ip")
            if stage_cb:
                stage_cb(f"plugin: {p.name} {ip}")
            try:
                res = p.run(host)
            except Exception:
                res = {"error": "plugin raised"}
            if res:
                results.setdefault(p.name, {})[ip] = res
                try:
                    findings.extend(_clean_findings(p.findings(host, res), p.name))
                except Exception:
                    pass
    return {"results": results, "findings": findings, "skipped": skipped}
