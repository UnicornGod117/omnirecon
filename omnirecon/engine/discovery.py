"""
Host discovery — turn subnets into live, identified hosts.

A mode-driven async liveness sweep (arp / icmp / udp / tcp / combined / auto)
finds responders; ARP-state is a free liveness signal. Responders are then
enriched with MAC + vendor + device-type, reverse-DNS, NetBIOS / mDNS names,
optional SNMP, and Zeroconf data. Self addresses are tagged is_self.

Ported from the legacy engine's discovery pipeline.
"""

from __future__ import annotations

import asyncio
import concurrent.futures as cf
import ipaddress
import itertools
import socket
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from . import oui, snmp as snmp_mod
from .enrichment import mdns_name_system, netbios_name
from .netinfo import (
    arp_lookup, build_neighbor_maps, get_local_ipv4_addresses,
    get_local_ipv4_networks, get_neighbor_table,
)
from .primitives import (
    ip_sort_key, is_private_or_lan_ip, is_windows, ping_with_ttl,
    resolve_reverse, udp_probe_alive,
)

ProgressCb = Optional[Callable[[int, int], None]]

# TCP ports used as liveness signals in tcp/combined modes.
_TCP_ALIVE_PORTS = [445, 3389, 135, 139, 5985, 22, 80, 443, 631, 9100,
                    8080, 8443, 23, 53, 21, 25, 110, 143, 8006, 5900]

_ARP_ALIVE_STATES = frozenset({
    "REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT", "DYNAMIC", "STATIC",
})


# ── ARP priming ───────────────────────────────────────────────────────────────

def arp_prime_subnet(cidr: str, max_hosts: int = 512, workers: int = 256) -> None:
    """Poke every host with a tiny UDP datagram to populate the ARP cache."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return
    hosts = list(itertools.islice(net.hosts(), max_hosts))

    def _poke(ip: str) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(0.05)
                s.sendto(b"", (ip, 9))
        except Exception:
            pass

    with cf.ThreadPoolExecutor(max_workers=min(workers, 256)) as ex:
        list(ex.map(_poke, (str(h) for h in hosts)))
    time.sleep(1.0)


# ── Async liveness ────────────────────────────────────────────────────────────

async def _async_tcp_connect(ip: str, port: int, timeout: float) -> bool:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _check_one(ip: str, mode: str, tcp_ports: List[int], ip_state: Dict[str, str],
                     sem: asyncio.Semaphore, alive_set: Set[str],
                     ttl_map: Dict[str, Optional[int]]) -> None:
    async with sem:
        alive = False
        ttl: Optional[int] = None
        loop = asyncio.get_running_loop()

        if ip_state.get(ip, "").upper() in _ARP_ALIVE_STATES:
            alive = True

        if not alive:
            if mode == "arp":
                pass
            elif mode == "icmp":
                alive, ttl = await loop.run_in_executor(None, ping_with_ttl, ip, 1)
            elif mode == "udp":
                alive = await loop.run_in_executor(None, udp_probe_alive, ip, 33434, 0.8)
                if not alive:
                    alive, ttl = await loop.run_in_executor(None, ping_with_ttl, ip, 1)
            elif mode == "combined":
                tcp_tasks = [asyncio.create_task(_async_tcp_connect(ip, p, 0.4)) for p in tcp_ports]
                icmp_fut = loop.run_in_executor(None, ping_with_ttl, ip, 1)
                udp_fut = loop.run_in_executor(None, udp_probe_alive, ip, 33434, 0.6)
                tcp_results = await asyncio.gather(*tcp_tasks, return_exceptions=True)
                icmp_alive, ttl = await icmp_fut
                udp_alive = await udp_fut
                alive = any(r is True for r in tcp_results) or icmp_alive or udp_alive
            else:  # tcp
                tasks = [asyncio.create_task(_async_tcp_connect(ip, p, 0.35)) for p in tcp_ports]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                alive = any(r is True for r in results)
                if not alive and ip in ip_state:
                    tasks2 = [asyncio.create_task(_async_tcp_connect(ip, p, 0.8)) for p in tcp_ports]
                    r2 = await asyncio.gather(*tasks2, return_exceptions=True)
                    alive = any(r is True for r in r2)

        if alive:
            alive_set.add(ip)
            if ttl is not None:
                ttl_map[ip] = ttl


def _liveness_sweep(host_strs: List[str], mode: str, tcp_ports: List[int],
                    ip_state: Dict[str, str], max_concurrent: int,
                    progress_cb: ProgressCb = None) -> Tuple[Set[str], Dict[str, Optional[int]]]:
    alive_set: Set[str] = set()
    ttl_map: Dict[str, Optional[int]] = {}
    total = len(host_strs)
    done = [0]

    async def _run():
        sem = asyncio.Semaphore(max_concurrent)

        async def _tracked(ip: str):
            await _check_one(ip, mode, tcp_ports, ip_state, sem, alive_set, ttl_map)
            done[0] += 1
            if progress_cb:
                progress_cb(done[0], total)

        await asyncio.gather(*[_tracked(ip) for ip in host_strs])

    if host_strs:
        asyncio.run(_run())
    return alive_set, ttl_map


# ── Per-host identity enrichment ──────────────────────────────────────────────

def _enrich_one(ip: str, ip_mac: Dict[str, str], zeroconf_map: Dict[str, Dict[str, Any]],
                snmp_communities: Optional[List[str]], enrich_timeout: float) -> Dict[str, Any]:
    mac = ip_mac.get(ip)
    vendor = oui.lookup(mac)
    dtype, dicon = oui.guess_device_type(vendor)
    rdns = resolve_reverse(ip, timeout=min(enrich_timeout, 1.5))

    nb = md = None
    snmp_data: Optional[Dict[str, str]] = None
    with cf.ThreadPoolExecutor(max_workers=3) as ex:
        nb_fut = ex.submit(netbios_name, ip, min(enrich_timeout, 3.0))
        md_fut = ex.submit(mdns_name_system, ip, min(enrich_timeout, 2.0))
        snmp_fut = (ex.submit(snmp_mod.probe, ip, snmp_communities, min(enrich_timeout, 1.5))
                    if snmp_communities else None)
        try:
            nb = nb_fut.result(timeout=min(enrich_timeout, 3.5))
        except Exception:
            pass
        try:
            md = md_fut.result(timeout=min(enrich_timeout, 2.5))
        except Exception:
            pass
        if snmp_fut:
            try:
                snmp_data = snmp_fut.result(timeout=min(enrich_timeout, 4.0))
            except Exception:
                pass

    zc = zeroconf_map.get(ip, {})
    zc_names = zc.get("names", []) or []
    snmp_name = (snmp_data or {}).get("sysName")
    device_name = ((nb or "").strip() or (snmp_name or "").strip() or (md or "").strip()
                   or (rdns or "").strip() or (zc_names[0].strip() if zc_names else "")) or None

    return {
        "ip": ip, "is_self": False, "device_name": device_name,
        "device_type": dtype, "device_icon": dicon, "reverse_dns": rdns,
        "netbios": nb, "mdns": md, "zeroconf_names": zc_names,
        "zeroconf_services": zc.get("services", []) or [],
        "mac": mac, "vendor": vendor, "snmp": snmp_data,
        "open_ports": [], "service_hints": {},
    }


def _build_self_hosts(local_nets: List[Dict[str, Any]], ip_mac: Dict[str, str]) -> List[Dict[str, Any]]:
    seen: Set[str] = set()
    selfs: List[Dict[str, Any]] = []
    hostname = socket.gethostname()
    for n in local_nets:
        ip = n["ip"]
        if ip in seen:
            continue
        seen.add(ip)
        mac = ip_mac.get(ip)
        vendor = oui.lookup(mac)
        dtype, dicon = oui.guess_device_type(vendor)
        selfs.append({
            "ip": ip, "is_self": True, "device_name": hostname,
            "device_type": dtype, "device_icon": dicon, "reverse_dns": resolve_reverse(ip),
            "netbios": None, "mdns": None, "zeroconf_names": [], "zeroconf_services": [],
            "mac": mac, "vendor": vendor, "snmp": None, "interface": n["interface"],
            "open_ports": [], "service_hints": {},
        })
    return selfs


# ── Orchestrator ──────────────────────────────────────────────────────────────

def discover_hosts(
    subnets: List[str],
    max_per_subnet: int = 512,
    workers: int = 256,
    discovery_mode: str = "auto",
    allow_non_private: bool = False,
    ttl_os: bool = False,
    zeroconf_map: Optional[Dict[str, Dict[str, Any]]] = None,
    snmp_communities: Optional[List[str]] = None,
    enrich_timeout: float = 5.0,
    progress_cb: ProgressCb = None,
    stage_cb: Optional[Callable[[str], None]] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Optional[int]]]:
    """Returns (hosts, ttl_map). Self hosts are included and tagged is_self."""
    zeroconf_map = zeroconf_map or {}

    nb = get_neighbor_table(include_ipv6=False)
    ip_mac, ip_state = build_neighbor_maps(nb)
    local_nets = get_local_ipv4_networks()
    self_hosts = _build_self_hosts(local_nets, ip_mac)
    self_ips = get_local_ipv4_addresses()

    eff_mode = discovery_mode
    if eff_mode == "auto":
        eff_mode = "tcp" if is_windows() else "icmp"

    all_alive: Set[str] = set()
    all_ttl: Dict[str, Optional[int]] = {}

    for cidr in subnets:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except Exception:
            continue
        host_strs = [
            str(h) for h in itertools.islice(net.hosts(), max_per_subnet)
            if str(h) not in self_ips and (allow_non_private or is_private_or_lan_ip(str(h)))
        ]
        if stage_cb:
            stage_cb(f"Liveness ({eff_mode}) {cidr} — {len(host_strs)} candidates")
        alive, ttl_map = _liveness_sweep(host_strs, eff_mode, _TCP_ALIVE_PORTS,
                                         ip_state, workers, progress_cb)
        all_alive.update(alive)
        all_ttl.update(ttl_map)

    unique_alive = sorted(all_alive, key=ip_sort_key)
    enriched: List[Dict[str, Any]] = []
    if unique_alive:
        if stage_cb:
            stage_cb(f"Enriching {len(unique_alive)} host(s)")
        done = [0]

        def _track(ip: str) -> Dict[str, Any]:
            r = _enrich_one(ip, ip_mac, zeroconf_map, snmp_communities, enrich_timeout)
            done[0] += 1
            if progress_cb:
                progress_cb(done[0], len(unique_alive))
            return r

        with cf.ThreadPoolExecutor(max_workers=min(32, max(4, len(unique_alive)))) as ex:
            enriched = list(ex.map(_track, unique_alive))

    # Merge self + discovered, dedupe by IP.
    all_hosts: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for h in self_hosts + enriched:
        if h["ip"] not in seen:
            seen.add(h["ip"])
            all_hosts.append(h)

    return sorted(all_hosts, key=lambda h: ip_sort_key(h["ip"])), all_ttl
