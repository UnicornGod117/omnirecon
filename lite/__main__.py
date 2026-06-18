"""
Entry point for `python -m lite` or `python lite/`.

Falls back to a plain CLI mode if textual is not installed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List


def _cli_fallback(args: argparse.Namespace) -> None:
    """Non-TUI fallback: runs the scan and prints results to stdout."""
    from .scanner import (
        DEFAULT_PORTS,
        get_local_ipv4_networks,
        run_scan,
        write_reports,
    )

    err = sys.stderr if args.json else sys.stdout

    print("OmniRecon Lite — CLI mode (install textual for the TUI)", file=err)
    print(file=err)

    subnets: List[str] = []
    if args.subnet:
        subnets = [s.strip() for s in args.subnet.split(",") if s.strip()]

    if not args.no_discover and not subnets:
        nets = get_local_ipv4_networks()
        subnets = [n["cidr"] for n in nets if n.get("cidr")]
        print(f"Auto-detected networks: {', '.join(subnets) or 'none'}", file=err)
    print(file=err)

    stages_seen: List[str] = []

    def stage_cb(name: str) -> None:
        print(f"  [{name}]", file=err)
        stages_seen.append(name)

    last_pct = [-1]

    def progress_cb(done: int, total: int) -> None:
        pct = int(done / max(1, total) * 100)
        if pct != last_pct[0]:
            last_pct[0] = pct
            bar = "█" * (pct // 4) + "░" * (25 - pct // 4)
            print(f"\r  [{bar}] {pct:3d}%", end="", flush=True, file=err)
            if done >= total:
                print(file=err)

    config: Dict[str, Any] = {
        "discover":      not args.no_discover,
        "probe_ports":   not args.no_ports,
        "service_hints": args.service_hints,
        "subnets":       subnets,
        "workers":       args.workers,
        "progress_cb":   progress_cb,
    }

    report = run_scan(config, stage_cb=stage_cb)
    print(file=err)

    # Summary
    hosts = report.get("discovery", {}).get("hosts", [])
    pub   = report.get("public_ip", {}).get("public_ip")
    gw    = report.get("routes", {}).get("default_gateway")
    print(f"  Gateway  : {gw}", file=err)
    print(f"  Public IP: {pub}", file=err)
    print(f"  Hosts    : {len(hosts)}", file=err)
    print(file=err)

    if hosts and not args.json:
        print("  {:<16} {:<24} {:<20} {:<14} {}".format(
            "IP", "Hostname", "Vendor", "Type", "Open Ports"))
        print("  " + "─" * 96)
        for h in hosts:
            ports = ", ".join(map(str, h.get("open_ports", []))) or "—"
            print("  {:<16} {:<24} {:<20} {:<14} {}".format(
                h["ip"],
                (h.get("hostname") or "—")[:23],
                (h.get("vendor") or "—")[:19],
                (h.get("device_type") or "—")[:13],
                ports,
            ))
            if h.get("service_hint"):
                print(f"  {'':<16} ↳ {h['service_hint']}")
        print()

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    elif not args.no_save:
        outdir = args.outdir or os.path.join(os.getcwd(), "reports")
        from .scanner import write_reports
        html_path, json_path = write_reports(report, outdir)
        print(f"  HTML → {html_path}", file=err)
        print(f"  JSON → {json_path}", file=err)


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="python -m lite",
        description="OmniRecon Lite — lightweight network recon",
    )
    p.add_argument("--subnet", metavar="CIDR",
                   help="subnet(s) to scan, comma-separated (default: auto-detect)")
    p.add_argument("--no-discover",  action="store_true",
                   help="skip host discovery")
    p.add_argument("--no-ports",     action="store_true",
                   help="skip port scan")
    p.add_argument("--service-hints", action="store_true",
                   help="grab a basic service banner per host")
    p.add_argument("--no-save",      action="store_true",
                   help="do not write report files")
    p.add_argument("--json",         action="store_true",
                   help="print raw JSON to stdout (implies --no-save)")
    p.add_argument("--workers",      type=int, default=128,
                   help="thread concurrency (default: 128)")
    p.add_argument("--outdir",       metavar="DIR", default=None,
                   help="output directory (default: ./reports)")
    p.add_argument("--no-tui",       action="store_true",
                   help="run headless CLI even if textual is installed")
    return p.parse_args()


def main() -> None:
    # Box/bar glyphs (█ ░ ↳) break on a cp1252 console when piped — force UTF-8.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except Exception:
            pass

    args = _parse_args()

    if args.no_tui or args.json:
        _cli_fallback(args)
        return

    try:
        from .tui import OmniReconLite
        OmniReconLite().run()
    except ImportError as e:
        print(f"textual not available ({e}) — falling back to CLI mode")
        print()
        _cli_fallback(args)


if __name__ == "__main__":
    main()
