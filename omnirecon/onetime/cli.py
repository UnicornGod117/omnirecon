#!/usr/bin/env python3
"""
onetime/cli.py — secondary CLI for one-time (right-now) mode.

The browser is the primary front door; this exists for automation. It is
stateless by default. Pentest requires --i-have-authorization. --save records
the run into the monitor store (the one sanctioned bridge).
"""

from __future__ import annotations

import os
import sys
from typing import List

from ..engine import DEFAULT_PORTS, EngineOptions
from ..engine.primitives import now_stamp
from .pentest import ALL_MODULES
from .scan import run_onetime_scan

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_DEFAULT_OUT = os.path.join(_ROOT, "reports")
_DEFAULT_DB = os.path.join(_ROOT, "reports", "omnirecon.db")


def build_parser(p) -> None:
    """Configure the `scan` (one-time) parser of the top-level CLI."""
    p.add_argument("--subnet", metavar="CIDR", help="CIDR(s), comma-separated (default: auto)")
    p.add_argument("--no-discover", action="store_true", help="skip host discovery")
    p.add_argument("--no-ports", action="store_true", help="skip port scan")
    # Discovery
    p.add_argument("--discovery-mode", default="auto",
                   choices=["auto", "arp", "icmp", "udp", "tcp", "combined"])
    p.add_argument("--arp-prime", action="store_true", help="prime ARP cache before sweep")
    p.add_argument("--ipv6", action="store_true", help="include IPv6 NDP neighbors")
    p.add_argument("--udp-probe", action="store_true", help="UDP unreachable probe (needs root)")
    p.add_argument("--ttl-os", action="store_true", help="guess OS from TTL")
    p.add_argument("--allow-non-private", action="store_true", help="permit non-RFC1918 targets")
    p.add_argument("--max-hosts", type=int, default=512, help="max hosts per subnet")
    # Services / enrichment
    p.add_argument("--service-hints", action="store_true", help="banners + TLS + HTTP titles")
    p.add_argument("--snmp", action="store_true", help="SNMP sysName/sysDescr probe")
    p.add_argument("--snmp-communities", default="public,private")
    p.add_argument("--zeroconf", action="store_true", help="Zeroconf/mDNS browse")
    p.add_argument("--ssdp", action="store_true", help="SSDP/UPnP discovery")
    p.add_argument("--passive", action="store_true", help="passive sniff (needs root + scapy)")
    p.add_argument("--passive-duration", type=float, default=20.0)
    p.add_argument("--pcap", action="store_true",
                   help="write a .pcap of the passive capture (with --passive)")
    # Wireless / RF
    p.add_argument("--wireless-survey", action="store_true",
                   help="survey nearby APs (channels, rogue/evil-twin, WPS)")
    p.add_argument("--bluetooth", action="store_true",
                   help="scan nearby Bluetooth/BLE devices")
    p.add_argument("--bluetooth-duration", type=float, default=8.0)
    # Layer-2 / path / link
    p.add_argument("--lldp", action="store_true",
                   help="passive LLDP/CDP switch discovery (needs root + scapy)")
    p.add_argument("--lldp-duration", type=float, default=35.0)
    p.add_argument("--traceroute", action="store_true",
                   help="map the L3 path to gateway + internet (double-NAT check)")
    p.add_argument("--link-quality", action="store_true",
                   help="latency/jitter/loss to gateway + internet")
    p.add_argument("--wan-exposure", action="store_true",
                   help="enumerate UPnP IGD port-forwards on the router")
    # Intelligence
    p.add_argument("--cve", action="store_true", help="correlate CVEs (NVD + CISA KEV)")
    p.add_argument("--cve-min-score", type=float, default=6.0)
    p.add_argument("--lifecycle", action="store_true",
                   help="flag end-of-life software versions (endoflife.date)")
    p.add_argument("--topology", action="store_true", help="build topology map")
    p.add_argument("--extintel", action="store_true",
                   help="external intel: Shodan/Censys/VirusTotal (needs API keys)")
    p.add_argument("--extintel-config", metavar="PATH", default=None,
                   help="external-intel keys file (default: reports/extintel.json)")
    # Plugins
    p.add_argument("--plugins", action="store_true",
                   help="run user plugins (analysis + active)")
    p.add_argument("--plugin", action="append", metavar="NAME", default=None,
                   help="restrict to a named plugin (repeatable)")
    p.add_argument("--plugin-dir", action="append", metavar="DIR", default=None,
                   help="extra plugin search directory (repeatable)")
    p.add_argument("--list-plugins", action="store_true",
                   help="list discoverable plugins and exit")
    # Pentest
    p.add_argument("--pentest", nargs="?", const="all", metavar="MODULES",
                   help=f"run pentest suite ({', '.join(ALL_MODULES)}, or 'all')")
    p.add_argument("--i-have-authorization", action="store_true",
                   help="required consent flag for pentest")
    p.add_argument("--save", action="store_true",
                   help="record this run into the monitor store (seed a baseline)")
    p.add_argument("--export", metavar="FORMATS", default="",
                   help="extra formats, comma-separated: csv,md,pdf,mermaid,dot,graphml")
    p.add_argument("--tags-file", metavar="PATH", default=None,
                   help="asset tags file (role/owner annotations)")
    p.add_argument("--outdir", default=_DEFAULT_OUT, metavar="DIR")
    p.set_defaults(func=cmd_scan)


def cmd_scan(args) -> None:
    if getattr(args, "list_plugins", False):
        from ..engine import plugins as plugins_mod
        found = plugins_mod.list_plugins(getattr(args, "plugin_dir", None))
        if not found:
            print("\n  No plugins found. Drop *.py into ./plugins or set "
                  "$OMNIRECON_PLUGINS.\n")
            return
        print("\n  Discoverable plugins:\n")
        for p in found:
            auth = "  [needs authorization]" if p["requires_authorization"] == "true" else ""
            print(f"    {p['name']:<22} {p['kind']:<9} {p['description']}{auth}")
        print()
        return

    subnets: List[str] = []
    if getattr(args, "subnet", None):
        subnets = [s.strip() for s in args.subnet.split(",") if s.strip()]

    pentest = args.pentest is not None
    if pentest and not args.i_have_authorization:
        print("\n  Refusing pentest without --i-have-authorization.\n")
        sys.exit(2)

    opts = EngineOptions(
        subnets=subnets,
        discover=not args.no_discover,
        probe_ports=not args.no_ports,
        ports=DEFAULT_PORTS,
        discovery_mode=args.discovery_mode,
        arp_prime=args.arp_prime,
        ipv6=args.ipv6,
        udp_probe=args.udp_probe,
        ttl_os=args.ttl_os,
        allow_non_private=args.allow_non_private,
        max_per_subnet=args.max_hosts,
        service_hints=args.service_hints or pentest,
        snmp=args.snmp,
        snmp_communities=args.snmp_communities,
        zeroconf=args.zeroconf,
        ssdp=args.ssdp,
        passive=args.passive,
        passive_duration=args.passive_duration,
        pcap=args.pcap,
        pcap_path=(os.path.join(args.outdir, f"capture_{now_stamp()}.pcap")
                   if args.pcap else None),
        wireless_survey=args.wireless_survey,
        bluetooth=args.bluetooth,
        bluetooth_duration=args.bluetooth_duration,
        lldp=args.lldp,
        lldp_duration=args.lldp_duration,
        traceroute=args.traceroute,
        link_quality=args.link_quality,
        wan_exposure=args.wan_exposure,
        cve=args.cve,
        cve_min_score=args.cve_min_score,
        lifecycle=args.lifecycle,
        topology=args.topology,
        tags_file=args.tags_file,
        extintel=args.extintel,
        extintel_config=args.extintel_config,
        plugins=args.plugins,
        plugin_dirs=args.plugin_dir,
        plugin_names=args.plugin,
    )

    def stage(name: str) -> None:
        print(f"  [{name}]")

    export = [f.strip() for f in (args.export or "").split(",") if f.strip()]

    print("\n  Running one-time scan…\n")
    result = run_onetime_scan(
        opts, args.outdir,
        pentest=pentest,
        pentest_modules=[m.strip() for m in (args.pentest or "all").split(",")],
        authorized=args.i_have_authorization,
        save=args.save,
        db_path=_DEFAULT_DB if args.save else None,
        export=export,
        stage_cb=stage,
    )

    hyg = (result.get("report") or {}).get("hygiene", {}).get("summary", {})
    print(f"\n  {result['host_count']} host(s) scanned.")
    if hyg:
        print(f"  Posture: {hyg.get('grade','—')} ({hyg.get('score','—')}/100), "
              f"{hyg.get('total', 0)} finding(s).")
    print(f"  HTML → {result['html_path']}")
    print(f"  JSON → {result['json_path']}")
    for fmt, path in (result.get("exports") or {}).items():
        print(f"  {fmt.upper()} → {path}")
    if result.get("saved"):
        print(f"  Saved to monitor store as {result['stamp']}.")
    print()


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(prog="omnirecon scan",
                                 description="OmniRecon one-time scan")
    build_parser(ap)
    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
