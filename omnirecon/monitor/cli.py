#!/usr/bin/env python3
"""
monitor/cli.py — secondary CLI for monitor (over-time) mode.

The browser is the primary front door; this CLI exists for automation and
scheduled monitor scans. Subcommands:

  scan                  Run a scan, record it, and compute deltas
  history               Show scan history
  diff [--scan STAMP]   Deltas from the latest (or named) scan
  compare S1 S2         Compare two scans side by side
  ack <mac|ip> | --all  Mark device(s) trusted
  ignore <mac|ip>       Mark a device ignored
  certs [--days N]      Certificate expiry inventory
  assets                Asset table with trust status
  score                 Baseline security posture

DB defaults to ./reports/omnirecon.db (override with --db).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from typing import List

from ..engine import DEFAULT_PORTS, EngineOptions
from . import score as score_mod
from .scan import run_monitored_scan
from .store import Store

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_DEFAULT_DB = os.path.join(_ROOT, "reports", "omnirecon.db")
_DEFAULT_OUT = os.path.join(_ROOT, "reports")


# ── Formatting helpers ────────────────────────────────────────────────────────

def _bar(score: int, width: int = 20) -> str:
    filled = max(0, min(width, round(score / 100 * width)))
    return "█" * filled + "░" * (width - filled)


_SEV_LABEL = {"high": "[HIGH]  ", "medium": "[MED]   ",
              "low": "[LOW]   ", "info": "[INFO]  "}


def _sev(s: str) -> str:
    return _SEV_LABEL.get(s, f"[{s[:4].upper()}]  ")


def _days_label(not_after: str) -> str:
    if not not_after:
        return "unknown"
    try:
        expiry = dt.datetime.fromisoformat(not_after.replace("Z", "+00:00")).replace(tzinfo=None)
        days = (expiry - dt.datetime.now()).days
        return f"EXPIRED {abs(days)}d ago" if days < 0 else f"{days}d remaining"
    except (ValueError, AttributeError):
        return not_after[:10]


def _delta_line(d: dict) -> str:
    dtype = d["delta_type"]
    detail = d.get("detail") or {}
    ip = d.get("ip") or "?"
    mac = d.get("mac") or ""
    name = detail.get("device_name") or mac or ip

    if dtype == "new_device":
        parts = [f"New device:   {ip}"]
        if name != ip:
            parts.append(name)
        if detail.get("vendor"):
            parts.append(detail["vendor"])
        if detail.get("open_ports"):
            parts.append(f"ports={detail['open_ports']}")
        return "  ".join(parts)
    if dtype == "gone_device":
        return f"Device gone:  {ip}  {name}"
    if dtype == "ip_changed":
        return f"IP changed:   {mac}  {detail.get('old_ip')} → {detail.get('new_ip')}"
    if dtype == "port_added":
        return f"Port opened:  {ip}  :{detail.get('port')}"
    if dtype == "port_removed":
        return f"Port closed:  {ip}  :{detail.get('port')}"
    if dtype == "cert_expiring":
        return (f"Cert expiring: {ip}:{detail.get('port')}  "
                f"{detail.get('subject', '')}  ({detail.get('days_left')} days)")
    if dtype == "cert_expired":
        return f"Cert EXPIRED:  {ip}:{detail.get('port')}  {detail.get('subject', '')}"
    return f"{dtype}: {ip}  {json.dumps(detail)}"


# ── Subcommands ───────────────────────────────────────────────────────────────

def cmd_scan(args) -> None:
    subnets: List[str] = []
    if args.subnet:
        subnets = [s.strip() for s in args.subnet.split(",") if s.strip()]
    opts = EngineOptions(
        subnets=subnets,
        discover=True,
        probe_ports=not args.no_ports,
        ports=DEFAULT_PORTS,
        discovery_mode=args.discovery_mode,
        arp_prime=args.arp_prime,
        ipv6=args.ipv6,
        ttl_os=args.ttl_os,
        service_hints=args.service_hints,
        snmp=args.snmp,
        zeroconf=args.zeroconf,
        ssdp=args.ssdp,
        cve=args.cve,
        cve_min_score=args.cve_min_score,
        topology=args.topology,
        tags_file=getattr(args, "tags_file", None),
    )

    def stage(name: str) -> None:
        print(f"  [{name}]")

    print("\n  Running monitored scan…\n")
    result = run_monitored_scan(opts, args.db, _DEFAULT_OUT, stage_cb=stage)
    print(f"\n  Scan {result['stamp']} recorded "
          f"({result['host_count']} host(s), {result['delta_count']} change(s)).")
    print(f"  Report: {result['json_path']}\n")
    if result["deltas"]:
        for d in result["deltas"]:
            print(f"  {_sev(d['severity'])} {_delta_line(d)}")
        print()
    alert = result.get("alerts") or {}
    if alert.get("dispatched"):
        print(f"  Alerts: {alert['matched']} sent via {', '.join(alert.get('channels', []))}.")
        for err in alert.get("errors", []):
            print(f"    ⚠ {err}")
        print()


def cmd_history(store, args) -> None:
    rows = store.get_history(limit=getattr(args, "limit", 20))
    if not rows:
        print("\n  No scans recorded yet. Run: omnirecon monitor scan\n")
        return
    hdr = f"  {'STAMP':<22}  {'SCANNED AT':<20}  {'HOSTS':>5}  {'CHANGES':>7}  {'HIGH':>4}  {'MED':>4}"
    print(f"\n{hdr}\n  {'─'*70}")
    for r in rows:
        ts = (r["scanned_at"] or "")[:19].replace("T", " ")
        print(f"  {r['stamp']:<22}  {ts:<20}  {r['host_count'] or 0:>5}  "
              f"{r['delta_count'] or 0:>7}  {r['high_count'] or 0:>4}  {r['med_count'] or 0:>4}")
    print()


def cmd_diff(store, args) -> None:
    scan_id = None
    if getattr(args, "scan", None):
        scan_id = store.get_scan_id_for_stamp(args.scan)
        if scan_id is None:
            print(f"\n  Stamp '{args.scan}' not found.\n")
            sys.exit(1)
    deltas = store.get_deltas(scan_id=scan_id)
    if not deltas:
        print("\n  No changes detected in this scan.\n")
        return
    print(f"\n  {len(deltas)} change(s) detected:\n")
    for d in deltas:
        print(f"  {_sev(d['severity'])} {_delta_line(d)}")
    print()


def cmd_compare(store, args) -> None:
    id1 = store.get_scan_id_for_stamp(args.stamp1)
    id2 = store.get_scan_id_for_stamp(args.stamp2)
    missing = [s for s, i in ((args.stamp1, id1), (args.stamp2, id2)) if i is None]
    if missing:
        print(f"\n  Unknown stamp(s): {', '.join(missing)}\n")
        sys.exit(1)
    for stamp, sid in ((args.stamp1, id1), (args.stamp2, id2)):
        deltas = store.get_deltas(scan_id=sid)
        print(f"\n  Scan {stamp}  ({len(deltas)} change(s))\n  {'─'*60}")
        for d in deltas:
            print(f"  {_sev(d['severity'])} {_delta_line(d)}")
        if not deltas:
            print("  (no changes)")
    print()


def cmd_ack(store, args) -> None:
    if getattr(args, "all", False):
        print(f"\n  Marked {store.ack_all()} device(s) as trusted.\n")
        return
    if not args.target:
        print("\n  Usage: omnirecon monitor ack <mac-or-ip>  |  --all\n")
        sys.exit(1)
    n = store.ack(args.target)
    print(f"\n  '{args.target}' → trusted.\n" if n
          else f"\n  No device matching '{args.target}'.\n")


def cmd_ignore(store, args) -> None:
    n = store.ignore_asset(args.target, reason=getattr(args, "reason", ""))
    print(f"\n  '{args.target}' → ignored.\n" if n
          else f"\n  No device matching '{args.target}'.\n")


def cmd_certs(store, args) -> None:
    certs = store.get_certs(expiring_within_days=getattr(args, "days", 90))
    if not certs:
        print("\n  No certificates recorded. Scan with --service-hints to collect them.\n")
        return
    print(f"\n  {'HOST':<22}  {'PORT':>5}  {'SUBJECT':<34}  {'STATUS':<22}  ISSUER\n  {'─'*100}")
    for c in certs:
        flag = " ⚠ self-signed" if c["is_self_signed"] else ""
        print(f"  {c['ip']:<22}  {c['port'] or '':>5}  {(c['subject'] or '')[:33]:<34}  "
              f"{_days_label(c['not_after']):<22}  {(c['issuer'] or '')[:27]}{flag}")
    print()


def cmd_assets(store, args) -> None:
    assets = store.get_assets()
    if not assets:
        print("\n  No assets recorded yet.\n")
        return
    disp = {"trusted": "✓ trusted", "ignored": "– ignored", "unverified": "? unverified"}
    print(f"\n  {'STATUS':<13}  {'IP':<16}  {'IDENTITY KEY':<22}  {'NAME':<24}  {'VENDOR':<18}  {'SEEN':>4}\n  {'─'*105}")
    for a in assets:
        print(f"  {disp.get(a['status'], a['status']):<13}  {a['ip'] or '':<16}  "
              f"{(a['mac'] or '')[:21]:<22}  {(a['device_name'] or '')[:23]:<24}  "
              f"{(a['vendor'] or '')[:17]:<18}  {a['seen_count']:>4}")
    print()


def cmd_alerts(args) -> None:
    from . import alerts as alerts_mod
    cfg = alerts_mod.load_config(getattr(args, "config", None))
    if not cfg:
        print("\n  No alert config found.\n"
              "  Create reports/alerts.json (or set $OMNIRECON_ALERTS). Example:\n"
              '    {"enabled": true, "min_severity": "medium",\n'
              '     "webhooks": [{"url": "https://hooks.slack.com/...", "style": "slack"}],\n'
              '     "desktop": true}\n')
        return
    enabled = cfg.get("enabled", True)
    hooks = cfg.get("webhooks") or ([cfg["webhook"]] if cfg.get("webhook") else [])
    print(f"\n  Alerts: {'enabled' if enabled else 'disabled'}  "
          f"min_severity={cfg.get('min_severity', 'medium')}")
    print(f"  Channels: log={cfg.get('log', True)}  desktop={bool(cfg.get('desktop'))}  "
          f"webhooks={len(hooks)}")
    if getattr(args, "test", False):
        sample = [{"delta_type": "new_device", "severity": "high", "ip": "192.0.2.1",
                   "detail": {"vendor": "Test Vendor"}}]
        res = alerts_mod.dispatch(sample, "TEST", _DEFAULT_OUT, cfg)
        print(f"\n  Test dispatch → {res}\n")
    else:
        print()


def cmd_score(store, args) -> None:
    result = score_mod.compute(store)
    if "error" in result:
        print(f"\n  {result['error']}\n")
        return
    print(f"\n  Network Security Posture\n  {'─'*46}")
    for name, sc in result["dimensions"].items():
        print(f"  {name:<24}  {sc:>3}%  {_bar(sc)}")
    print(f"  {'─'*46}\n  Overall Score: {result['overall']}/100  {_bar(result['overall'])}")
    if result.get("note"):
        print(f"\n  Note: {result['note']}")
    print(f"  Hosts assessed: {result.get('hosts_assessed', 0)}\n")


# ── Entry point ───────────────────────────────────────────────────────────────

def build_parser(sub) -> None:
    """Attach monitor subcommands to a parent subparser (the top-level CLI)."""
    p = sub.add_parser("scan", help="Run a scan, record it, and compute deltas")
    p.add_argument("--subnet", metavar="CIDR")
    p.add_argument("--no-ports", action="store_true")
    p.add_argument("--discovery-mode", default="auto",
                   choices=["auto", "arp", "icmp", "udp", "tcp", "combined"])
    p.add_argument("--arp-prime", action="store_true")
    p.add_argument("--ipv6", action="store_true")
    p.add_argument("--ttl-os", action="store_true")
    p.add_argument("--service-hints", action="store_true")
    p.add_argument("--snmp", action="store_true")
    p.add_argument("--zeroconf", action="store_true")
    p.add_argument("--ssdp", action="store_true")
    p.add_argument("--cve", action="store_true")
    p.add_argument("--cve-min-score", type=float, default=6.0)
    p.add_argument("--topology", action="store_true")
    p.add_argument("--tags-file", metavar="PATH", default=None)
    p.set_defaults(func=cmd_scan, needs_store=False)

    p = sub.add_parser("history", help="Show scan history")
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=cmd_history, needs_store=True)

    p = sub.add_parser("diff", help="Deltas from latest (or named) scan")
    p.add_argument("--scan", metavar="STAMP", default=None)
    p.set_defaults(func=cmd_diff, needs_store=True)

    p = sub.add_parser("compare", help="Compare two scans")
    p.add_argument("stamp1")
    p.add_argument("stamp2")
    p.set_defaults(func=cmd_compare, needs_store=True)

    p = sub.add_parser("ack", help="Mark a device trusted")
    p.add_argument("target", nargs="?", metavar="mac-or-ip")
    p.add_argument("--all", action="store_true")
    p.set_defaults(func=cmd_ack, needs_store=True)

    p = sub.add_parser("ignore", help="Mark a device ignored")
    p.add_argument("target", metavar="mac-or-ip")
    p.add_argument("--reason", default="")
    p.set_defaults(func=cmd_ignore, needs_store=True)

    p = sub.add_parser("certs", help="Certificate expiry inventory")
    p.add_argument("--days", type=int, default=90)
    p.set_defaults(func=cmd_certs, needs_store=True)

    sub.add_parser("assets", help="Asset table").set_defaults(func=cmd_assets, needs_store=True)
    sub.add_parser("score", help="Baseline posture score").set_defaults(func=cmd_score, needs_store=True)

    p = sub.add_parser("alerts", help="Show alert config (optionally send a test)")
    p.add_argument("--config", metavar="PATH", default=None)
    p.add_argument("--test", action="store_true", help="send a sample alert")
    p.set_defaults(func=cmd_alerts, needs_store=False)


def dispatch(args) -> None:
    """Run a monitor subcommand. Opens a Store only if the command needs one."""
    args.db = getattr(args, "db", None) or _DEFAULT_DB
    if not getattr(args, "needs_store", False):
        args.func(args)
        return

    db_path = os.path.abspath(args.db)
    if not os.path.exists(db_path):
        print(f"\n  Database not found: {db_path}\n  Run: omnirecon monitor scan\n")
        sys.exit(1)
    store = Store(db_path)
    try:
        args.func(store, args)
    finally:
        store.close()


def main() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except Exception:
            pass
    ap = argparse.ArgumentParser(prog="omnirecon monitor",
                                 description="OmniRecon monitor-mode CLI")
    ap.add_argument("--db", default=_DEFAULT_DB, metavar="PATH")
    sub = ap.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True
    build_parser(sub)
    args = ap.parse_args()
    dispatch(args)


if __name__ == "__main__":
    main()
