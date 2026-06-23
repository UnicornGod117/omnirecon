"""
run_engine — the single entry point into the brain.

Given EngineOptions and optional callbacks, it runs the shared pipeline and
returns a normalized report dict. Mode- and interface-agnostic: it never
persists, never runs pentest, and never imports monitor/onetime/web.

Pipeline: host facts → (arp-prime) → (zeroconf / ssdp / passive) → discovery
(mode-driven) → ttl-os tagging → port scan → service hints → passive merge →
CVE correlation → topology → public IP.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from . import (
    discovery, enrichment, hygiene, intel, netinfo, passive as passive_mod,
    ports, ssdp as ssdp_mod, tags as tags_mod, topology, zeroconf_disc,
)
from .primitives import check_privileges, guess_os_from_ttl

StageCb = Optional[Callable[[str], None]]
ProgressCb = Optional[Callable[[int, int], None]]


@dataclass
class EngineOptions:
    # Targets
    subnets: List[str] = field(default_factory=list)   # empty → auto-detect
    allow_non_private: bool = False
    max_per_subnet: int = 512
    workers: int = 256
    enrich_timeout: float = 5.0
    # Discovery
    discover: bool = True
    discovery_mode: str = "auto"          # auto|arp|icmp|udp|tcp|combined
    arp_prime: bool = False
    ipv6: bool = False
    udp_probe: bool = False
    ttl_os: bool = False
    # Ports & services
    probe_ports: bool = True
    ports: Optional[List[int]] = None
    service_hints: bool = False
    # Enrichment add-ons
    snmp: bool = False
    snmp_communities: str = "public,private"
    zeroconf: bool = False
    ssdp: bool = False
    # Passive
    passive: bool = False
    passive_duration: float = 20.0
    passive_interface: Optional[str] = None
    # Intelligence
    cve: bool = False
    cve_min_score: float = 6.0
    cve_results_per_query: int = 10
    cve_kev: bool = True
    topology: bool = False
    # Analysis
    hygiene: bool = True                  # derived findings + exposure (free)
    tags_file: Optional[str] = None       # asset tags (None → default search paths)
    plugins: bool = False                 # run user analysis plugins (folded into hygiene)
    plugin_dirs: Optional[List[str]] = None  # override plugin search dirs
    plugin_names: Optional[List[str]] = None  # restrict to named plugins
    # External intelligence (opt-in, network I/O — like CVE correlation)
    extintel: bool = False                # Shodan/Censys/VirusTotal enrichment
    extintel_config: Optional[str] = None  # path to keys config (None → default search)


def _merge_passive(hosts: List[Dict[str, Any]], passive_hosts: List[Dict[str, Any]],
                   self_ips: set) -> List[Dict[str, Any]]:
    from . import oui
    existing = {h["ip"]: h for h in hosts}
    for obs in passive_hosts:
        ip = obs["ip"]
        if ip in existing:
            h = existing[ip]
            if not h.get("mac") and obs.get("mac"):
                h["mac"] = obs["mac"]
                h["vendor"] = oui.lookup(obs["mac"])
                h["device_type"], h["device_icon"] = oui.guess_device_type(h["vendor"])
            if not h.get("device_name") and obs.get("names"):
                h["device_name"] = obs["names"][0]
            h.setdefault("passive_protocols", [])
            h["passive_protocols"] = sorted(set(h["passive_protocols"]) | set(obs.get("protocols", [])))
            h.setdefault("passive_services", [])
            h["passive_services"] = sorted(set(h["passive_services"]) | set(obs.get("services", [])))
        else:
            vendor = oui.lookup(obs.get("mac"))
            dtype, dicon = oui.guess_device_type(vendor)
            hosts.append({
                "ip": ip, "is_self": ip in self_ips,
                "device_name": obs["names"][0] if obs.get("names") else None,
                "device_type": dtype, "device_icon": dicon, "reverse_dns": None,
                "mac": obs.get("mac"), "vendor": vendor, "open_ports": [],
                "service_hints": {}, "passive_only": True,
                "passive_protocols": obs.get("protocols", []),
                "passive_services": obs.get("services", []),
            })
            existing[ip] = hosts[-1]
    return hosts


def run_engine(opts: EngineOptions, stage_cb: StageCb = None,
               progress_cb: ProgressCb = None) -> Dict[str, Any]:
    def stage(name: str) -> None:
        if stage_cb:
            stage_cb(name)

    report: Dict[str, Any] = {}

    stage("Host facts")
    report["system"] = netinfo.get_system_info()
    report["identity"] = netinfo.get_identity_info()
    report["privileges"] = check_privileges()
    report["interfaces"] = netinfo.get_interfaces()
    report["routes"] = netinfo.get_routes_and_gateway()
    report["wifi"] = netinfo.get_wifi_info()
    report["dns_servers"] = netinfo.get_dns_servers()
    report["neighbors"] = netinfo.get_neighbor_table(include_ipv6=opts.ipv6)
    report["listening_ports"] = netinfo.get_listening_ports()
    report["active_connections"] = netinfo.get_active_connections()
    local_nets = netinfo.get_local_ipv4_networks()
    report["local_networks"] = local_nets
    self_ips = netinfo.get_local_ipv4_addresses()

    discovery_block: Dict[str, Any] = {"performed": False, "subnets": [], "hosts": [],
                                       "mode": opts.discovery_mode}

    if opts.discover:
        subnets = opts.subnets or [n["cidr"] for n in local_nets if n.get("cidr")]
        discovery_block["performed"] = True
        discovery_block["subnets"] = subnets

        # Effective mode: udp_probe upgrades 'auto' to 'combined'.
        eff_mode = opts.discovery_mode
        if opts.udp_probe and eff_mode in ("auto",):
            eff_mode = "combined"

        if opts.arp_prime:
            for cidr in subnets:
                stage(f"ARP prime {cidr}")
                discovery.arp_prime_subnet(cidr, opts.max_per_subnet, opts.workers)

        zeroconf_map: Dict[str, Any] = {}
        if opts.zeroconf:
            stage("Zeroconf / mDNS browse")
            zeroconf_map = zeroconf_disc.discover()

        if opts.ssdp:
            stage("SSDP / UPnP discovery")
            report["ssdp"] = ssdp_mod.discover()

        passive_result = None
        if opts.passive:
            ok, why = passive_mod.available()
            if ok:
                stage(f"Passive sniff ({opts.passive_duration:.0f}s)")
                passive_result = passive_mod.sniff(opts.passive_duration,
                                                   opts.passive_interface, stage_cb)
            else:
                stage(f"Passive sniff skipped — {why}")

        snmp_comms = ([c.strip() for c in opts.snmp_communities.split(",") if c.strip()]
                      if opts.snmp else None)

        hosts, ttl_map = discovery.discover_hosts(
            subnets, max_per_subnet=opts.max_per_subnet, workers=opts.workers,
            discovery_mode=eff_mode, allow_non_private=opts.allow_non_private,
            ttl_os=opts.ttl_os, zeroconf_map=zeroconf_map, snmp_communities=snmp_comms,
            enrich_timeout=opts.enrich_timeout, progress_cb=progress_cb, stage_cb=stage_cb,
        )

        if opts.ttl_os:
            for h in hosts:
                ttl = ttl_map.get(h["ip"])
                if ttl is not None:
                    h["ttl"] = ttl
                    h["os_guess"] = guess_os_from_ttl(ttl)

        if opts.probe_ports and hosts:
            stage(f"Port scanning {len(hosts)} host(s)")
            hosts = ports.scan_ports(hosts, ports=opts.ports, workers=opts.workers,
                                     progress_cb=progress_cb)

        if opts.service_hints and hosts:
            stage("Gathering service hints")
            hosts = enrichment.enrich_hosts(hosts, progress_cb=progress_cb)

        if passive_result is not None:
            stage("Merging passive observations")
            hosts = _merge_passive(hosts, passive_result.to_list(), self_ips)

        asset_tags = tags_mod.load_tags(opts.tags_file)
        if asset_tags:
            stage("Applying asset tags")
            hosts = tags_mod.apply_tags(hosts, asset_tags)

        discovery_block["hosts"] = hosts

    report["discovery"] = discovery_block
    hosts = discovery_block["hosts"]

    if opts.cve and hosts:
        stage("Correlating CVEs (NVD + CISA KEV)")
        report["intel"] = intel.correlate(
            hosts, min_score=opts.cve_min_score,
            results_per_query=opts.cve_results_per_query, use_kev=opts.cve_kev,
        )

    if opts.topology and hosts:
        stage("Building topology")
        report["topology"] = topology.build(
            hosts, report.get("routes", {}),
            wifi=report.get("wifi"), neighbors=report.get("neighbors"))

    stage("Public IP")
    report["public_ip"] = netinfo.get_public_ip()

    if opts.hygiene:
        stage("Analyzing hygiene & exposure")
        report["hygiene"] = hygiene.analyze(report)

    # External intelligence (opt-in network I/O against public IPs).
    if opts.extintel and hosts:
        stage("Querying external intel (Shodan / Censys / VirusTotal)")
        from . import extintel
        ext = extintel.enrich(report, config_path=opts.extintel_config, stage_cb=stage_cb)
        if ext.get("by_ip"):
            report["external_intel"] = ext
            if opts.hygiene and ext.get("findings"):
                hygiene.fold_in_findings(report, ext["findings"])

    # Analysis plugins (pure, read-only) — folded into hygiene so they grade.
    if opts.plugins:
        from . import plugins as plugins_mod
        pl = plugins_mod.run_analysis(report, dirs=opts.plugin_dirs,
                                      names=opts.plugin_names, stage_cb=stage_cb)
        if pl:
            report["plugin_findings"] = pl
            if opts.hygiene:
                hygiene.fold_in_findings(report, pl)

    return report
