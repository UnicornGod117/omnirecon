#!/usr/bin/env python3
"""
omnirecon.py  v6.0
====================
Extensive local network diagnostics — active, passive, historical,
vulnerability-aware, and penetration-testing capable.

New in v6.0 over v5.0:
  - ADD: Full penetration testing module (--pentest) with modular test suite:
         ssh-defaults, ftp-anon, http-vulns, tls-audit, smb-enum, headers
  - ADD: Dual-gate consent system — pentest requires explicit typed consent
         AND --i-have-authorization flag. All pentest actions audit-logged.
  - ADD: CISA Known Exploited Vulnerabilities (KEV) catalog integration
         (--cve-kev) — flags CVEs that are actively being exploited in the wild
  - ADD: CVE impact classification: RCE / PrivEsc / InfoDisc / DoS / Auth
  - ADD: CVSS minimum score filter (--cve-min-score, default 6.0)
  - ADD: Increased CVE results per NVD query (--cve-results-per-query, default 20)
  - ADD: TLS/SSL deep audit: protocol versions, weak ciphers, cert chain,
         expired/soon-expiring certs, POODLE/BEAST/RC4 flagging
  - ADD: HTTP security headers audit: HSTS, CSP, X-Frame-Options, etc.
  - ADD: Anonymous FTP login test
  - ADD: SMB null session / guest share enumeration (Windows/Samba)
  - ADD: Default credential checks for SSH and HTTP basic auth
  - ADD: Structured JSONL audit log (--audit-log, default: omnirecon_audit.jsonl)
  - ADD: --pentest-modules to choose which pentest modules to run
  - ADD: New Security tab in HTML report with colour-coded severity, KEV badges,
         impact categories, and pentest findings
  - IMPROVE: CVE table now shows KEV badge, impact icon, and CVSS colour
  - FIX:  All v5 bug fixes retained

⚠  LEGAL WARNING: Penetration testing features must ONLY be used against
   networks and systems you own or have explicit written authorisation to test.
   Unauthorised use may violate the Computer Fraud and Abuse Act (US), Computer
   Misuse Act (UK), or equivalent laws in your jurisdiction.
   This tool logs all pentest actions with timestamps.

Required:   pip install psutil requests
Optional:   pip install scapy puresnmp zeroconf paramiko
            Windows scapy also needs: https://npcap.com (free, tick WinPcap mode)
            paramiko needed for SSH credential checks:  pip install paramiko
"""

# ── stdlib ────────────────────────────────────────────────────────────────────
import argparse
import asyncio
import concurrent.futures as cf
import datetime as dt
import hashlib
import html
import ipaddress
import itertools
import json
import math
import os
import platform
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import textwrap
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

__version__ = "6.0"

# ── third-party required ──────────────────────────────────────────────────────
import psutil
import requests

# urllib3 InsecureRequestWarning is intentionally NOT suppressed globally.
# verify=False is only used for LAN device probing; external API calls use verify=True.

# ── optional packages ─────────────────────────────────────────────────────────
try:
    import scapy.all as scapy
    _HAS_SCAPY = True
except ImportError:
    _HAS_SCAPY = False

try:
    import puresnmp
    _HAS_PURESNMP = True
except ImportError:
    _HAS_PURESNMP = False

try:
    from zeroconf import Zeroconf, ServiceBrowser
    _HAS_ZEROCONF = True
except ImportError:
    _HAS_ZEROCONF = False

try:
    import paramiko
    _HAS_PARAMIKO = True
except ImportError:
    _HAS_PARAMIKO = False


# ══════════════════════════════════════════════════════════════════════════════
# Help topics
# ══════════════════════════════════════════════════════════════════════════════

HELP_TOPICS: Dict[str, str] = {
    "discover": """
  --discover
  ----------
  Active host discovery sweep over local subnet(s).
  Combines: ARP evidence + asyncio TCP connects + optional UDP probing.
  Your own IPs are always included, flagged [YOU].
  See also: --passive for zero-probe passive-only mode.

  After active discovery, any passive-only hosts are pinged to trigger ARP
  exchange, which reveals their MAC addresses automatically.
""",
    "passive": """
  --passive
  ---------
  Passive listening mode using scapy packet capture.
  Requires: pip install scapy  (+ Npcap on Windows from https://npcap.com)

  What it captures without sending a single probe:
    ARP broadcasts   — who-has / is-at (IP + MAC of every talking device)
    mDNS (port 5353) — Bonjour/Avahi hostname advertisements
    NetBIOS NS (137) — Windows computer name announcements
    SSDP (port 1900) — UPnP device advertisements (smart TVs, routers, etc.)
    DHCP (67/68)     — hostname claims in DHCP requests
    LLMNR (5355)     — Windows link-local name resolution broadcasts

  Passive results are merged with active discovery results if both are run.
  When merged, passive-discovered hosts are pinged to populate MAC addresses.

  --passive-duration N  (default: 30)
    Seconds to listen passively. Longer = more devices caught.
    Recommended: 30s normal, 120-300s for extended soak.

  --passive-extended
    Runs an extended passive-only soak for --passive-duration seconds,
    then outputs a report without any active probing.
    Great for stealth audits or networks where active scanning is restricted.
""",
    "discovery-mode": """
  --discovery-mode {auto|tcp|icmp|arp|udp|combined}
  --------------------------------------------------
  Controls liveness method for active discovery.

  auto      TCP on Windows, ICMP elsewhere (default).
  tcp       Async TCP connects to alive-ports. Best for Windows-heavy LANs.
  icmp      Classic ping sweep.
  arp       ARP/NDP table only — zero probes, passive.
  udp       UDP probe: send packet to closed port, ICMP unreachable = alive.
            Finds hosts that block TCP and ICMP entirely.
  combined  All methods simultaneously — most thorough, slowest.
            ARP + TCP + ICMP + UDP all run concurrently per host.
""",
    "alive-ports": """
  --alive-ports PORT,PORT,...
  ---------------------------
  TCP ports tried in TCP discovery mode.
  Default: 445,3389,135,139,5985,22,80,443,631,9100,8080,8443,23,53,21

  Port ordering matters: highest-yield ports are tried first in parallel.
  Any single open port marks the host as alive.
""",
    "subnet": """
  --subnet CIDR  (repeatable)
  ---------------------------
  Manual subnet override. Default: auto from interface owning default route,
  excluding virtual adapters (Docker, Hyper-V, WSL, VPN, tun*, virbr*).

  Example (multiple subnets):
    python omnirecon.py --discover --subnet 192.168.1.0/24 \\
      --subnet 10.0.0.0/24 --i-have-authorization

  Note: ARP, mDNS, and NetBIOS broadcast-based discovery does NOT cross
  routers. To scan a remote subnet, use --subnet explicitly and ensure
  your host has a route to that subnet.
""",
    "udp-probe": """
  --udp-probe
  -----------
  Enable UDP-based host existence detection alongside TCP/ICMP.

  Technique: send a UDP datagram to a port very unlikely to be open
  (default: 33434, traceroute range). If the host exists and the port is
  closed, it returns ICMP "port unreachable", proving the host is there.

  Why it helps: some devices block all TCP connects and all ICMP echo,
  but still generate ICMP unreachable for closed UDP ports.
  Common on: some printers, VoIP gear, embedded systems.

  Requires raw socket access (root/Administrator). Silently skipped if
  privileges are insufficient. In v5, the ICMP response parser correctly
  handles variable-length IP headers (non-standard IP option sets).
""",
    "ttl-os": """
  --ttl-os
  --------
  Infer the OS from the IP TTL of ping responses.

    TTL 60–65  → Linux / macOS / Android / iOS  (initial TTL 64)
    TTL 125–130→ Windows                          (initial TTL 128)
    TTL 252–255→ Cisco IOS / FreeBSD              (initial TTL 255)
    TTL 250–251→ Cisco (some versions)
    TTL 30–32  → Low-TTL network gear
    Other      → Unknown (TTL printed)

  This is a heuristic — not 100% accurate (VPNs and hops alter TTL),
  but it's a useful free signal when combined with vendor fingerprinting.
  Adds an "OS Hint" column to the HTML table.
""",
    "ssdp": """
  --ssdp
  ------
  Send SSDP M-SEARCH multicast to 239.255.255.250:1900.
  No scapy required — pure Python socket.

  Discovers UPnP-capable devices: smart TVs, routers, NAS boxes,
  streaming sticks, smart speakers, printers, IP cameras.
  Returns device descriptions including manufacturer, model, and
  a URL to fetch full UPnP XML metadata.

  --ssdp-timeout N  (default: 5)
    Seconds to wait for SSDP responses. Increase on slow/busy networks.
""",
    "probe-ports": """
  --probe-ports
  -------------
  After discovering live hosts, run a TCP port scan against each.

  --ports PORT,PORT,...
    Ports to scan. Default:
      21,22,23,25,53,80,110,143,443,445,3389,5357,5900,8006,8080,8443

  --service-hints
    After finding open ports, attempt service fingerprinting:
      SSH  — grab version banner (port 22)
      FTP  — grab version banner (port 21)
      HTTP — fetch headers, status code, page title (ports 80, 8080, 8008, etc.)
      HTTPS— same as HTTP over TLS (ports 443, 8443, 4443)
      TLS  — extract certificate CN, SAN, expiry

  Service data from --service-hints feeds --cve-check for CVE correlation.
  Running --probe-ports significantly increases scan time.
""",
    "cve-check": """
  --cve-check
  -----------
  Cross-reference discovered service banners against the NVD (National
  Vulnerability Database) to flag known CVEs.

  How it works:
    1. Collects service strings: SSH banners, HTTP Server headers,
       TLS CN values, SNMP sysDescr.
    2. Queries NVD 2.0 API (https://nvd.nist.gov) per unique service string.
    3. Caches results in --outdir/cve_cache.json to avoid re-querying.
    4. Flags hosts with known CVEs in the HTML report.

  NVD rate limits: 5 requests/30s without API key.
  The tool respects this automatically (6.2s delay between queries).

  ⚠ CVE matching is keyword-based (heuristic). Results may include false
  positives. Always cross-reference with the NVD website before acting.

  --nvd-api-key KEY
    Optional NVD API key for higher rate limits (50 req/30s).
    Register free at: https://nvd.nist.gov/developers/request-an-api-key

  Output: "CVEs" column in host table with CVE IDs and severity scores.
  Requires --probe-ports and --service-hints to have service data to check.
""",
    "topology": """
  --topology
  ----------
  Render an interactive network topology graph in the HTML report
  using vis.js (loaded from CDN — requires internet when opening the HTML).

  The graph shows:
    - Your machine (centre, diamond, blue)
    - Gateway (star shape, gold)
    - All discovered hosts (nodes coloured by device type)
    - Edges connecting each host to the gateway
    - Node labels: device icon + name + IP

  Hover over a node for IP, MAC, and vendor info.
  The graph is physics-simulated and draggable/scrollable.

  v5 FIX: The vis.js script tag no longer uses async loading, which
  previously caused a race condition that made the topology blank.
  The initialiser also retries until vis.js is ready.

  --no-topology
    Suppress the topology tab entirely (useful when offline or when
    the vis.js CDN is blocked).
""",
    "history": """
  History tracking (automatic)
  -----------------------------
  On every run, the tool loads all previous network_report_*.json files
  from --outdir and builds a per-host timeline:

    first_seen   — timestamp of the earliest report where this IP appeared
    last_seen    — timestamp of the most recent report
    seen_count   — how many reports this IP has appeared in
    total_runs   — total number of historical reports found
    frequency    — fraction of runs this IP appeared in (0.0–1.0)

  These appear as tooltips on host rows in the HTML table,
  and as a "Frequency" column showing the appearance rate as a bar.

  Interpretation:
    ≥ 80% frequency → Permanent infrastructure (servers, routers, printers)
    20–80%          → Semi-permanent (desktops, NAS)
    < 20%           → Ephemeral (phones, laptops, guest devices)
""",
    "workers": """
  --workers N  (default: 256)
  ---------------------------
  Max concurrent async TCP/UDP coroutines during liveness sweep.
  asyncio handles this efficiently — 256-512 is fine on most LANs.

  For larger networks (e.g. /20 or /16), consider reducing workers AND
  adding a scan delay to avoid triggering IDS or causing packet loss:
    --workers 64 --scan-delay 5

  --enrich-workers N  (default: workers//4, min 8)
    Separate thread pool for enrichment (reverse DNS, NetBIOS, SNMP).
    Lower than liveness workers since enrichment ops block longer.
""",
    "rate-limit": """
  --scan-delay MS  (default: 0)
  -----------------------------
  Millisecond delay injected between liveness probes. Useful on larger
  networks or when you want to avoid triggering IDS/IPS alerts.

  Examples:
    --scan-delay 0    No delay (default, fast LAN scanning)
    --scan-delay 10   10ms between probes (~100 hosts/sec sustained)
    --scan-delay 50   50ms between probes (~20 hosts/sec)
    --scan-delay 200  200ms — conservative, near-silent on most IDS

  --randomize-scan
    Randomise the order hosts are probed. Breaks sequential scan
    signatures. Recommended alongside --scan-delay for large networks.

  Note: On a typical /24 (254 hosts), --scan-delay 0 with 256 workers
  completes in 1–5 seconds. A /16 (65534 hosts) without rate limiting
  could saturate a network. Use --max-hosts to cap the scan depth.
""",
    "snmp": """
  --snmp
  ------
  SNMP v1/v2c GET on discovered hosts.
  Requires: pip install puresnmp

  Fetches: sysName, sysDescr, sysLocation, sysContact.
  Tries community strings from --snmp-communities (default: public,private).

  --snmp-communities STRING,STRING,...
    Comma-separated list of community strings to try. Example:
      --snmp-communities public,private,community,readonly

  Extremely useful on routers, switches, printers, NAS, and UPS devices.
  sysDescr often reveals firmware version, useful for CVE correlation.
""",
    "zeroconf": """
  --zeroconf
  ----------
  Browse mDNS/Zeroconf service types to discover device names and services.
  Requires: pip install zeroconf

  Listens for advertised services including:
    _http._tcp, _https._tcp, _ssh._tcp, _smb._tcp, _printer._tcp,
    _ipp._tcp, _airplay._tcp, _googlecast._tcp, _homekit._tcp,
    _raop._tcp (AirPlay audio), _matter._tcp (smart home)

  Results are merged into host enrichment — zeroconf names fill in
  device names where NetBIOS/mDNS resolution otherwise fails.

  --zeroconf-timeout N  (default: 3)
    Seconds to browse. Increase to 5–10 on networks with many Bonjour devices.
""",
    "arp-prime": """
  --arp-prime
  -----------
  Send lightweight UDP datagrams to every host in the subnet before
  the main sweep. This forces your OS to perform ARP lookups, populating
  the kernel ARP cache.

  Effect: the subsequent liveness sweep has pre-cached MAC addresses,
  improving MAC discovery rate significantly without active TCP/ICMP probing.

  This is a very low-noise operation — each host receives one tiny UDP
  packet on port 9 (discard). Most firewalls drop these silently.
  The tool then waits 1 second for the ARP cache to settle.

  Most useful when combined with --discovery-mode arp:
    python omnirecon.py --discover --arp-prime --discovery-mode arp
""",
    "ipv6": """
  --ipv6
  ------
  Include IPv6 NDP (Neighbor Discovery Protocol) table entries in results.

  On Linux, reads: ip -6 neigh show
  On macOS, reads: ndp -a
  On Windows, reads: netsh interface ipv6 show neighbors

  IPv6 addresses from the NDP table appear in the neighbor data but are
  NOT actively scanned (active IPv6 sweep is not supported in v5).
  Passive sniffing will still pick up IPv6 hosts if they send traffic.

  Note: Link-local addresses (fe80::/10) are included but are only
  meaningful on the local segment. Global IPv6 addresses (2000::/3)
  cross routers and indicate routable connectivity.
""",
    "oui-file": """
  --oui-file PATH
  ---------------
  Path to a local IEEE OUI (Organizationally Unique Identifier) file.
  Used to look up hardware vendor names from MAC address prefixes.

  Without this file, vendor lookup is skipped and device type inference
  relies only on other heuristics (hostname patterns, etc.).

  Where to get the OUI file:
    https://standards-oui.ieee.org/oui/oui.txt
    (Download ~4MB text file, update periodically)

  The file is parsed in multiple formats:
    "AA-BB-CC  (hex)  Vendor Name"     (IEEE standard format)
    "AA:BB:CC,Vendor Name"              (CSV format)
    "AABBCC Vendor Name"                (compact hex format)
""",
    "authorization": """
  --i-have-authorization
  ----------------------
  Bypass the interactive authorization prompt for active scanning.
  Use in scripts and automated pipelines.

  Passive-only mode (--passive-extended) does not probe hosts and
  therefore does NOT require this flag.

  The authorization record is embedded in the report JSON and HTML,
  including the timestamp, subnets scanned, and any note provided.

  --authorization-note TEXT
    Freeform note embedded in the report (e.g. "Pen test ticket #1234").

  --non-interactive
    Never prompt for input. If authorization is required but not given
    via --i-have-authorization, the tool exits with an error.
    Use for CI pipelines and scheduled scans.

  ⚠ You are responsible for ensuring you have authorization to scan
    the target network. Unauthorised scanning is illegal in many
    jurisdictions.
""",
    "output": """
  --outdir PATH  (default: current directory)
  -------------------------------------------
  Output directory for all report files:
    network_report_YYYYMMDD_HHMMSS.html   Human-readable report
    network_report_YYYYMMDD_HHMMSS.json   Full raw dump
    cve_cache.json                         CVE lookup cache (if --cve-check)

  HTML report features:
    Tabs: Hosts · Passive · SSDP/UPnP · Topology · CVEs · System · Raw
    Sortable/filterable host table with colour-coded change diff
    Interactive vis.js topology graph
    Export to CSV button

  History diffing compares against the most recent .json in --outdir.
""",
    "progress": """
  --progress / --no-progress
  --------------------------
  --progress    (default) Show live progress bars with ETA during sweeps.
  --no-progress Disable all progress output. Useful for:
                  - Piping output to files/logs
                  - Non-interactive (daemon) mode
                  - CI environments with basic terminals

  Progress output goes to stdout via carriage-return (\\r) line overwriting.
  It does not appear in the final report.
""",
    "pentest": """
  --pentest
  ---------
  Enable the penetration testing module. Runs configurable active security
  checks against each discovered live host.

  ⚠  DUAL CONSENT REQUIRED:
     1. Pass --i-have-authorization  (standard scan gate)
     2. Interactively type the consent phrase when prompted

  ⚠  LEGAL: Only use against systems you own or have explicit WRITTEN
     authorisation to test. Unauthorised use is a criminal offence.

  All pentest actions are written to an audit log (see --audit-log).

  --pentest-modules MODULE,MODULE,...
    Comma-separated list of modules to run. Default: all
    Available modules:
      tls-audit      TLS/SSL protocol, cipher, and cert-chain audit
      headers        HTTP security-headers audit (HSTS, CSP, X-Frame, etc.)
      ftp-anon       Test anonymous FTP login
      ssh-defaults   Try default SSH credentials (needs pip install paramiko)
      http-vulns     Basic HTTP vulnerability checks (dir traversal probes,
                     common sensitive paths, open redirect)
      smb-enum       SMB null session / guest share enumeration

  --pentest-credentials FILE
    File with one user:pass per line for credential tests.
    Built-in minimal default list used if omitted.

  --pentest-timeout N  (default: 3.0)
    Per-connection timeout for pentest probes in seconds.

  Example (full security scan):
    python omnirecon.py --discover --probe-ports --service-hints \\
      --cve-check --cve-kev --pentest \\
      --i-have-authorization
""",
    "cve-kev": """
  --cve-kev
  ---------
  Cross-reference found CVEs against the CISA Known Exploited Vulnerabilities
  (KEV) catalog. CVEs in the KEV catalog are being actively weaponised by
  real threat actors — these should be your top remediation priority.

  KEV catalog source (downloaded fresh each run):
    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

  KEV-matched CVEs receive a 🔴 KEV badge and are sorted to the top of the
  Security tab in the HTML report.

  --cve-min-score N  (default: 6.0)
    Filter out CVEs with CVSS base score below N.
    Use --cve-min-score 0.0 to see all findings including informational.

  --cve-results-per-query N  (default: 20)
    Number of CVE results fetched per NVD service string query (max 2000).
""",
}



def show_topic_help(topic: str) -> None:
    t = topic.strip().lower().lstrip("-")
    if t in HELP_TOPICS:
        print(f"\n{'─'*70}\n  Help: --{t}\n{'─'*70}")
        print(HELP_TOPICS[t])
        print(f"{'─'*70}\n")
        sys.exit(0)
    avail = "\n    ".join(f"--{k}" for k in sorted(HELP_TOPICS))
    print(f"\nUnknown topic: '{topic}'\nAvailable topics:\n    {avail}\n")
    sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
# Platform / privilege helpers
# ══════════════════════════════════════════════════════════════════════════════

def is_windows() -> bool: return platform.system().lower().startswith("win")
def is_macos()   -> bool: return platform.system().lower() == "darwin"
def is_linux()   -> bool: return platform.system().lower() == "linux"


def is_root() -> bool:
    if is_windows():
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def check_privileges() -> Dict[str, Any]:
    elevated = is_root()
    warnings = []
    if not elevated:
        base = ("Not running as root/admin. "
                "Raw socket features (UDP probing, scapy sniffing, full ICMP) "
                "require elevated privileges.")
        if is_linux():
            warnings.append(base + " Try: sudo python omnirecon.py ...")
        elif is_macos():
            warnings.append(base + " Try: sudo python omnirecon.py ...")
        elif is_windows():
            warnings.append(
                "Not running as Administrator. "
                "Scapy passive sniffing and UDP probing require 'Run as Administrator'.")
    return {"elevated": elevated, "warnings": warnings}


# ══════════════════════════════════════════════════════════════════════════════
# General utilities
# ══════════════════════════════════════════════════════════════════════════════

def now_stamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def safe_run(cmd: List[str], timeout: int = 10) -> Dict[str, Any]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"cmd": cmd, "returncode": p.returncode,
                "stdout": p.stdout.strip(), "stderr": p.stderr.strip()}
    except Exception as e:
        return {"cmd": cmd, "error": repr(e)}


def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def is_private_or_lan_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback or addr.is_link_local or addr.is_private:
            return True
        if addr.version == 4 and addr in ipaddress.ip_network("100.64.0.0/10"):
            return True
    except Exception:
        pass
    return False


def html_escape(s: Any) -> str:
    return html.escape(str(s), quote=True)


def _fmt_elapsed(secs: float) -> str:
    if secs < 60: return f"{secs:.1f}s"
    m, s = divmod(int(secs), 60)
    return f"{m}m {s:02d}s"


def _fmt_uptime(secs: int) -> str:
    d, rem = divmod(secs, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    parts = []
    if d: parts.append(f"{d}d")
    if h: parts.append(f"{h}h")
    if m: parts.append(f"{m}m")
    return " ".join(parts) or "<1m"


def _short_ts(iso: str) -> str:
    return iso[:16].replace("T", " ") if iso else "—"


# ══════════════════════════════════════════════════════════════════════════════
# Progress / ETA
# ══════════════════════════════════════════════════════════════════════════════

class ProgressETA:
    def __init__(self, total: int, label: str, enabled: bool = True):
        self.total = max(0, int(total))
        self.label = label
        self.enabled = enabled
        self._lock = threading.Lock()
        self._start = time.perf_counter()
        self._last_t = self._start
        self._done = 0
        self._ema: Optional[float] = None

    def incr(self, n: int = 1) -> None:
        if not self.enabled: return
        now = time.perf_counter()
        with self._lock:
            self._done += n
            dt_ = now - self._last_t
            if dt_ > 0:
                inst = n / dt_
                self._ema = inst if self._ema is None else 0.15 * inst + 0.85 * self._ema
            self._last_t = now

    def snapshot(self) -> Tuple[int, int, float, Optional[float]]:
        with self._lock:
            return self._done, self.total, time.perf_counter() - self._start, self._ema

    @staticmethod
    def _fmts(secs: Optional[float]) -> str:
        if secs is None or not math.isfinite(secs) or secs < 0: return "?"
        s = int(secs)
        h, r = divmod(s, 3600); m, sec = divmod(r, 60)
        if h: return f"{h}h{m:02d}m{sec:02d}s"
        if m: return f"{m}m{sec:02d}s"
        return f"{sec}s"

    def render(self, extra: str = "") -> None:
        if not self.enabled: return
        done, total, elapsed, rate = self.snapshot()
        pct = done / total * 100 if total else 100
        eta = (max(0, total - done) / rate) if (rate and total) else None
        line = (f"{self.label}: {done}/{total} ({pct:5.1f}%)"
                f"  elapsed={self._fmts(elapsed)}  eta={self._fmts(eta)}")
        if extra: line += f"  | {extra}"
        sys.stdout.write("\r" + line + "   ")
        sys.stdout.flush()

    def finish(self, extra: str = "") -> None:
        if not self.enabled: return
        self.render(extra=extra)
        sys.stdout.write("\n")
        sys.stdout.flush()


# ══════════════════════════════════════════════════════════════════════════════
# Authorization gate
# ══════════════════════════════════════════════════════════════════════════════

def _non_private_subnets(subnets: List[str]) -> List[str]:
    bad = []
    for s in subnets:
        try:
            net = ipaddress.ip_network(s, strict=False)
            if (net.is_private or net.is_link_local or net.is_loopback or
                    (net.version == 4 and
                     net.overlaps(ipaddress.ip_network("100.64.0.0/10")))):
                continue
            bad.append(str(net))
        except Exception:
            bad.append(s)
    return bad


def require_authorization_or_abort(args: argparse.Namespace,
                                   subnets: List[str],
                                   scope: str) -> Dict[str, Any]:
    flagged = _non_private_subnets(subnets)
    record: Dict[str, Any] = {
        "attested": bool(args.i_have_authorization),
        "note": args.authorization_note or "",
        "timestamp_local": dt.datetime.now().isoformat(),
        "scope": scope, "subnets": list(subnets),
        "flagged_non_lan_subnets": flagged,
        "operator_prompted": False,
    }
    if record["attested"]:
        return record
    if args.non_interactive:
        raise SystemExit(
            "Refusing: active scanning requires --i-have-authorization "
            "with --non-interactive.")
    record["operator_prompted"] = True
    print("\n=== Authorization required ===")
    print("Active discovery / port probing requires explicit authorization.")
    if flagged:
        print("\n⚠  Non-LAN subnets detected (possible public IP space):")
        for s in flagged: print(f"     {s}")
    ans = input("\nType 'YES' to confirm you have authorization: ").strip()
    if ans != "YES":
        raise SystemExit("Aborted.")
    record["attested"] = True
    return record


# ══════════════════════════════════════════════════════════════════════════════
# OUI / vendor / device-type
# ══════════════════════════════════════════════════════════════════════════════

_DEVICE_TYPES: List[Tuple[List[str], str, str]] = [
    (["Apple"],                                          "Apple Device",    "🍎"),
    (["Raspberry Pi"],                                   "Raspberry Pi",    "🥧"),
    (["Samsung Electronics", "LG Electronics",
      "Motorola", "OnePlus", "Xiaomi", "Huawei",
      "Nokia", "Sony Mobile"],                          "Mobile Device",   "📱"),
    (["ASRock","Gigabyte","ASUS","MSI","Intel Corporate",
      "Dell","HP Inc","Hewlett","Lenovo","Acer",
      "Toshiba","Sony","Aopen","Shuttle"],               "PC / Laptop",     "💻"),
    (["Ubiquiti","Cisco","Netgear","TP-Link","Mikrotik",
      "Ruckus","Aruba","D-Link","Zyxel","Juniper",
      "Palo Alto","Fortinet","FRITZ","AVM",
      "Synology","QNAP","Western Digital",
      "Drobo"],                                         "Network / NAS",   "🌐"),
    (["VMware","Virtual","Xen","QEMU","Parallels",
      "Microsoft Hyper","Oracle VirtualBox",
      "Proxmox"],                                       "Virtual Machine", "📦"),
    (["Amazon","Google","Espressif","Nordic Semi",
      "Tuya","Shenzhen","HiSilicon","Realtek Semi",
      "Azurewave"],                                     "IoT / Smart",     "🔌"),
    (["Canon","Epson","HP","Lexmark","Ricoh",
      "Xerox","Brother","Kyocera","Konica",
      "Zebra","Intermec"],                              "Printer",         "🖨"),
    (["APC","Eaton","Vertiv","Schneider"],               "UPS / Power",     "🔋"),
    (["Hikvision","Dahua","Axis","Hanwha",
      "Vivotek"],                                       "IP Camera",       "📷"),
]


def guess_device_type(vendor: Optional[str]) -> Tuple[str, str]:
    if not vendor: return ("Unknown", "❓")
    v = vendor.lower()
    for kws, label, icon in _DEVICE_TYPES:
        if any(kw.lower() in v for kw in kws):
            return (label, icon)
    return ("Unknown", "❓")


def load_oui_map(path: str) -> Dict[str, str]:
    m: Dict[str, str] = {}
    if not path or not os.path.exists(path):
        return m

    def norm(x: str) -> Optional[str]:
        x = x.strip().upper().replace(":", "-")
        if re.match(r"^[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}$", x): return x
        if re.match(r"^[0-9A-F]{6}$", x):
            return f"{x[0:2]}-{x[2:4]}-{x[4:6]}"
        return None

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"): continue
            mi = re.match(
                r"^([0-9A-F]{2}[-:][0-9A-F]{2}[-:][0-9A-F]{2})\s+\(hex\)\s+(.+)$",
                line, re.I)
            if mi:
                oui = norm(mi.group(1))
                if oui: m[oui] = mi.group(2).strip()
                continue
            if "," in line:
                pts = line.split(",", 1)
                oui = norm(pts[0])
                if oui: m[oui] = pts[1].strip()
                continue
            toks = line.split()
            if toks:
                oui = norm(toks[0])
                if oui and len(toks) > 1: m[oui] = " ".join(toks[1:])
    return m


def mac_to_oui(mac: Optional[str]) -> Optional[str]:
    if not mac: return None
    mac = mac.strip().upper().replace(":", "-")
    if re.match(r"^[0-9A-F]{2}(-[0-9A-F]{2}){5}$", mac):
        return "-".join(mac.split("-")[:3])
    return None


# ══════════════════════════════════════════════════════════════════════════════
# PASSIVE SNIFFING ENGINE  (scapy)
# ══════════════════════════════════════════════════════════════════════════════

class PassiveSniffResult:
    """Accumulates passive observations from packet capture."""
    def __init__(self):
        self._lock = threading.Lock()
        # ip → {mac, names: set, services: set, protocols: set}
        self.hosts: Dict[str, Dict[str, Any]] = {}
        self.packet_counts: Dict[str, int] = {}

    def _ensure(self, ip: str) -> Dict[str, Any]:
        if ip not in self.hosts:
            self.hosts[ip] = {
                "ip": ip, "mac": None,
                "names": set(), "services": set(), "protocols": set(),
            }
        return self.hosts[ip]

    def observe(self, ip: str, mac: Optional[str] = None,
                name: Optional[str] = None, service: Optional[str] = None,
                protocol: Optional[str] = None) -> None:
        if not ip or not is_private_or_lan_ip(ip): return
        with self._lock:
            h = self._ensure(ip)
            if mac and not h["mac"]: h["mac"] = mac.lower()
            if name and len(name) > 1: h["names"].add(name.strip("."))
            if service: h["services"].add(service)
            if protocol: h["protocols"].add(protocol)
            self.packet_counts[ip] = self.packet_counts.get(ip, 0) + 1

    def to_list(self) -> List[Dict[str, Any]]:
        with self._lock:
            out = []
            for ip, h in self.hosts.items():
                out.append({
                    "ip": ip,
                    "mac": h["mac"],
                    "names": sorted(h["names"]),
                    "services": sorted(h["services"]),
                    "protocols": sorted(h["protocols"]),
                    "packet_count": self.packet_counts.get(ip, 0),
                })
            return sorted(out, key=lambda x: _ip_sort_key_str(x["ip"]))

    def merge_into_hosts(self,
                         hosts: List[Dict[str, Any]],
                         oui_map: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Merge passive observations into an existing host list.
        Adds new hosts for IPs not already present.
        """
        existing = {h["ip"]: h for h in hosts}
        for obs in self.to_list():
            ip = obs["ip"]
            if ip in existing:
                h = existing[ip]
                # Fill in missing MAC
                if not h.get("mac") and obs["mac"]:
                    h["mac"] = obs["mac"]
                    oui = mac_to_oui(obs["mac"])
                    h["oui"] = oui
                    h["vendor"] = oui_map.get(oui) if oui else None
                    h["device_type"], h["device_icon"] = guess_device_type(h["vendor"])
                # Supplement names
                if not h.get("device_name") and obs["names"]:
                    h["device_name"] = obs["names"][0]
                h.setdefault("passive_protocols", [])
                h["passive_protocols"] = sorted(
                    set(h["passive_protocols"]) | set(obs["protocols"]))
                h.setdefault("passive_services", [])
                h["passive_services"] = sorted(
                    set(h["passive_services"]) | set(obs["services"]))
            else:
                # New host discovered purely passively
                mac = obs["mac"]
                oui = mac_to_oui(mac)
                vendor = oui_map.get(oui) if oui else None
                dtype, dicon = guess_device_type(vendor)
                existing[ip] = {
                    "ip": ip, "is_self": False,
                    "device_name": obs["names"][0] if obs["names"] else None,
                    "device_type": dtype,
                    "device_icon": dicon,
                    "reverse_dns": None, "netbios": None, "mdns": None,
                    "zeroconf_names": [], "zeroconf_services": [],
                    "mac": mac, "oui": oui, "vendor": vendor,
                    "snmp": None,
                    "passive_only": True,
                    "passive_protocols": sorted(obs["protocols"]),
                    "passive_services": sorted(obs["services"]),
                    "open_ports": [],
                }
        return sorted(existing.values(), key=lambda h: _ip_sort_key_str(h["ip"]))


def _ip_sort_key_str(ip: str) -> Tuple:
    try: return tuple(int(p) for p in ip.split("."))
    except Exception: return (999, 999, 999, 999)


def passive_sniff(duration_s: float,
                  interface: Optional[str] = None,
                  progress: bool = True) -> PassiveSniffResult:
    """
    Capture packets passively for duration_s seconds.
    Harvests: ARP, mDNS, NetBIOS NS, SSDP, DHCP, LLMNR.
    Returns a PassiveSniffResult with everything observed.
    """
    result = PassiveSniffResult()

    if not _HAS_SCAPY:
        print("  ✗ Passive sniffing requires scapy: pip install scapy")
        if is_windows():
            print("    Windows also needs Npcap from https://npcap.com")
        return result

    if not is_root():
        print("  ✗ Passive sniffing requires root/Administrator privileges.")
        return result

    if progress:
        print(f"  Passive sniff: listening for {duration_s:.0f}s "
              f"on {'default interface' if not interface else interface} …")

    stop_event = threading.Event()
    progress_thread = None

    if progress:
        def _show_progress():
            start = time.time()
            while not stop_event.wait(1.0):
                elapsed = time.time() - start
                pct = min(elapsed / duration_s * 100, 100)
                total_packets = sum(result.packet_counts.values())
                hosts_seen = len(result.hosts)
                sys.stdout.write(
                    f"\r  Passive: {elapsed:.0f}/{duration_s:.0f}s "
                    f"({pct:.0f}%)  hosts={hosts_seen}  packets={total_packets}   ")
                sys.stdout.flush()
        progress_thread = threading.Thread(target=_show_progress, daemon=True)
        progress_thread.start()

    def handle_packet(pkt: Any) -> None:
        try:
            _handle_arp(pkt, result)
            _handle_mdns(pkt, result)
            _handle_netbios_ns(pkt, result)
            _handle_ssdp_passive(pkt, result)
            _handle_dhcp(pkt, result)
            _handle_llmnr(pkt, result)
        except Exception:
            pass

    try:
        iface_kwarg = {"iface": interface} if interface else {}
        scapy.sniff(
            prn=handle_packet,
            timeout=duration_s,
            store=False,
            filter="arp or udp or (ip and icmp)",
            **iface_kwarg
        )
    except Exception as e:
        if progress:
            sys.stdout.write(f"\r  Passive sniff error: {e}                    \n")
    finally:
        stop_event.set()
        if progress_thread:
            progress_thread.join(timeout=2)
        if progress:
            total = sum(result.packet_counts.values())
            print(f"\r  Passive done: {len(result.hosts)} hosts, "
                  f"{total} relevant packets in {duration_s:.0f}s          ")

    return result


def ping_passive_hosts_for_mac(passive_result: PassiveSniffResult,
                                 timeout_s: float = 0.5,
                                 max_workers: int = 64,
                                 progress: bool = True) -> None:
    """
    Ping passive-only hosts that have no MAC address yet.
    Pinging triggers an ARP exchange, which the OS records in the ARP cache.
    After pinging, re-read the ARP/NDP table to fill in MACs.

    v5 addition: passive sniffing sometimes sees IP-only traffic where
    the source MAC is not available. A quick ping forces ARP exchange,
    letting us capture the MAC address reliably.
    """
    targets = [
        obs for obs in passive_result.to_list()
        if not obs.get("mac") and obs.get("ip")
    ]
    if not targets:
        return

    if progress:
        print(f"  Passive-ping: pinging {len(targets)} host(s) "
              f"to trigger ARP/MAC discovery …")

    def _ping_once(ip: str) -> None:
        try:
            if is_windows():
                subprocess.run(["ping", "-n", "1", "-w", "500", ip],
                               capture_output=True, timeout=2)
            else:
                subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                               capture_output=True, timeout=2)
        except Exception:
            pass

    with cf.ThreadPoolExecutor(max_workers=min(max_workers, len(targets))) as ex:
        list(ex.map(_ping_once, (t["ip"] for t in targets)))

    # Brief pause for ARP cache to settle, then re-read neighbor table
    time.sleep(0.5)
    nb = get_neighbor_table(include_ipv6=False)
    ip_mac, _ = build_neighbor_maps(nb)

    # Inject discovered MACs back into the passive result
    with passive_result._lock:
        for ip, mac in ip_mac.items():
            if ip in passive_result.hosts and not passive_result.hosts[ip]["mac"]:
                passive_result.hosts[ip]["mac"] = mac.lower()

    if progress:
        filled = sum(1 for obs in passive_result.to_list() if obs.get("mac"))
        print(f"  Passive-ping complete: {filled}/{len(passive_result.hosts)} "
              f"hosts now have MAC addresses.")


def _handle_arp(pkt: Any, result: PassiveSniffResult) -> None:
    if not pkt.haslayer(scapy.ARP): return
    arp = pkt[scapy.ARP]
    # who-has (op=1): sender is definitely alive
    if arp.op == 1:
        result.observe(arp.psrc, mac=arp.hwsrc, protocol="ARP")
    # is-at (op=2): both sender and target are known
    elif arp.op == 2:
        result.observe(arp.psrc, mac=arp.hwsrc, protocol="ARP")
        if arp.pdst and arp.pdst != "0.0.0.0":
            result.observe(arp.pdst, mac=arp.hwdst, protocol="ARP")


def _decode_dns_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Minimal DNS name decoder for mDNS/LLMNR parsing."""
    labels = []
    visited = set()
    while offset < len(data):
        if offset in visited: break
        visited.add(offset)
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data): break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            name, _ = _decode_dns_name(data, ptr)
            labels.append(name)
            offset += 2
            break
        offset += 1
        if offset + length > len(data): break
        labels.append(data[offset:offset + length].decode("utf-8", errors="ignore"))
        offset += length
    return ".".join(labels), offset


def _handle_mdns(pkt: Any, result: PassiveSniffResult) -> None:
    """Parse mDNS (UDP 5353) for hostname advertisements."""
    if not (pkt.haslayer(scapy.UDP) and pkt[scapy.UDP].dport == 5353):
        return
    if not pkt.haslayer(scapy.IP): return

    src_ip = pkt[scapy.IP].src
    try:
        raw = bytes(pkt[scapy.UDP].payload)
        if len(raw) < 12: return
        an_count = struct.unpack("!H", raw[6:8])[0]
        if an_count == 0: return

        offset = 12
        # Skip questions (qd_count)
        qd_count = struct.unpack("!H", raw[4:6])[0]
        for _ in range(qd_count):
            _, offset = _decode_dns_name(raw, offset)
            offset += 4  # type + class

        for _ in range(an_count):
            if offset >= len(raw): break
            name, offset = _decode_dns_name(raw, offset)
            if offset + 10 > len(raw): break
            rtype, _, _, rdlen = struct.unpack("!HHIH", raw[offset:offset + 10])
            offset += 10
            rdata_end = offset + rdlen

            # A record (type 1) → IP → hostname mapping
            if rtype == 1 and rdlen == 4:
                ip = ".".join(str(b) for b in raw[offset:offset + 4])
                if is_private_or_lan_ip(ip):
                    hostname = name.rstrip(".")
                    result.observe(ip, name=hostname, protocol="mDNS")
                    result.observe(src_ip, protocol="mDNS")

            # PTR record (type 12) → service advertisement
            elif rtype == 12:
                ptr_name, _ = _decode_dns_name(raw, offset)
                service_label = name.rstrip(".")
                result.observe(src_ip, service=service_label, protocol="mDNS")

            offset = rdata_end
    except Exception:
        pass


def _handle_netbios_ns(pkt: Any, result: PassiveSniffResult) -> None:
    """Parse NetBIOS Name Service (UDP 137) registration/announcement packets."""
    if not (pkt.haslayer(scapy.UDP) and pkt[scapy.UDP].dport in (137, 138)):
        return
    if not pkt.haslayer(scapy.IP): return
    src_ip = pkt[scapy.IP].src
    try:
        raw = bytes(pkt[scapy.UDP].payload)
        if len(raw) < 12: return
        # NetBIOS name is in the question/answer section — find readable name
        # It's encoded: 32 chars, each char = 2 bytes A-P encoded
        for match in re.finditer(rb"([A-Z]{32})", raw):
            encoded = match.group(1)
            try:
                decoded = "".join(
                    chr(((encoded[i] - 65) << 4) | (encoded[i + 1] - 65))
                    for i in range(0, 32, 2)
                ).rstrip("\x00").strip()
                if decoded and len(decoded) >= 1 and decoded.isprintable():
                    result.observe(src_ip, name=decoded, protocol="NetBIOS-NS")
                    break
            except Exception:
                pass
    except Exception:
        pass


def _handle_ssdp_passive(pkt: Any, result: PassiveSniffResult) -> None:
    """Passively capture SSDP announcements (NOTIFY packets on 1900)."""
    if not (pkt.haslayer(scapy.UDP) and pkt[scapy.UDP].dport == 1900):
        return
    if not pkt.haslayer(scapy.IP): return
    src_ip = pkt[scapy.IP].src
    try:
        raw = bytes(pkt[scapy.UDP].payload).decode("utf-8", errors="ignore")
        if "NOTIFY" not in raw and "HTTP/1.1" not in raw: return

        # Extract server / USN header as service hint
        server_m = re.search(r"SERVER:\s*(.+)", raw, re.I)
        usn_m = re.search(r"USN:\s*(.+)", raw, re.I)
        nt_m = re.search(r"^NT:\s*(.+)", raw, re.I | re.M)

        service = None
        if nt_m: service = nt_m.group(1).strip()
        if server_m:
            result.observe(src_ip, name=server_m.group(1).strip()[:80],
                           service=service or "SSDP", protocol="SSDP")
        else:
            result.observe(src_ip, service=service or "SSDP", protocol="SSDP")
    except Exception:
        pass


def _handle_dhcp(pkt: Any, result: PassiveSniffResult) -> None:
    """Extract DHCP hostname options (option 12) from DHCP requests."""
    if not pkt.haslayer(scapy.IP): return
    if not (pkt.haslayer(scapy.UDP) and pkt[scapy.UDP].dport in (67, 68)):
        return
    src_ip = pkt[scapy.IP].src
    try:
        raw = bytes(pkt[scapy.UDP].payload)
        if len(raw) < 240: return
        if raw[:4] != b"\x01\x01\x06\x00": return  # BOOTP request magic
        # Skip to options (byte 236 onward, after magic cookie at 236)
        if raw[236:240] != b"\x63\x82\x53\x63": return
        i = 240
        while i < len(raw) - 1:
            opt = raw[i]; i += 1
            if opt == 255: break
            if opt == 0: continue
            if i >= len(raw): break
            length = raw[i]; i += 1
            if i + length > len(raw): break
            data = raw[i:i + length]; i += length
            if opt == 12:  # Hostname
                hostname = data.decode("utf-8", errors="ignore").strip()
                if hostname:
                    result.observe(src_ip, name=hostname, protocol="DHCP")
    except Exception:
        pass


def _handle_llmnr(pkt: Any, result: PassiveSniffResult) -> None:
    """LLMNR (UDP 5355) — Windows link-local name resolution."""
    if not (pkt.haslayer(scapy.UDP) and pkt[scapy.UDP].dport == 5355):
        return
    if not pkt.haslayer(scapy.IP): return
    src_ip = pkt[scapy.IP].src
    try:
        raw = bytes(pkt[scapy.UDP].payload)
        if len(raw) < 12: return
        qd_count = struct.unpack("!H", raw[4:6])[0]
        offset = 12
        for _ in range(qd_count):
            name, offset = _decode_dns_name(raw, offset)
            offset += 4
            if name:
                result.observe(src_ip, protocol="LLMNR")
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# SSDP / UPnP active discovery  (pure socket, no scapy)
# ══════════════════════════════════════════════════════════════════════════════

_SSDP_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 3\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
)


def ssdp_discover(timeout_s: float = 5.0,
                  max_responses: int = 128) -> List[Dict[str, Any]]:
    """
    Send SSDP M-SEARCH multicast and collect responses.
    Returns list of discovered device dicts (ip, server, location, usn, st).
    """
    results: List[Dict[str, Any]] = []
    seen_ips: Set[str] = set()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                             socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
        sock.settimeout(timeout_s)
        sock.sendto(_SSDP_MSEARCH.encode(), ("239.255.255.250", 1900))

        deadline = time.time() + timeout_s
        while time.time() < deadline and len(results) < max_responses:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                if not is_private_or_lan_ip(ip): continue
                resp = data.decode("utf-8", errors="ignore")
                entry: Dict[str, Any] = {"ip": ip, "server": None,
                                          "location": None, "usn": None, "st": None}
                for line in resp.splitlines():
                    k, _, v = line.partition(":")
                    k = k.strip().lower()
                    v = v.strip()
                    if k == "server": entry["server"] = v
                    elif k == "location": entry["location"] = v
                    elif k == "usn": entry["usn"] = v
                    elif k == "st": entry["st"] = v

                # Fetch UPnP device description if location available
                if entry["location"] and ip not in seen_ips:
                    desc = _fetch_upnp_description(entry["location"])
                    if desc: entry.update(desc)

                if ip not in seen_ips:
                    seen_ips.add(ip)
                    results.append(entry)
            except socket.timeout:
                break
            except Exception:
                continue
    except Exception:
        pass
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
    return results


def _fetch_upnp_description(url: str, timeout: float = 3.0) -> Dict[str, Any]:
    """Fetch and parse a UPnP device description XML."""
    out: Dict[str, Any] = {}
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": f"OmniRecon/{__version__}"})
        if r.status_code != 200: return out
        txt = r.text
        for tag in ("friendlyName", "manufacturer", "modelName",
                    "modelNumber", "serialNumber"):
            m = re.search(rf"<{tag}>([^<]{{0,200}})</{tag}>", txt, re.I)
            if m: out[tag] = m.group(1).strip()
    except Exception:
        pass
    return out


# ══════════════════════════════════════════════════════════════════════════════
# UDP host-existence probe  (ICMP port-unreachable technique)
# ══════════════════════════════════════════════════════════════════════════════

def udp_probe_alive(ip: str, port: int = 33434, timeout: float = 0.8) -> bool:
    """
    Send a UDP datagram to a port unlikely to be open.
    If host exists and port is closed → ICMP port-unreachable → True.
    Requires raw socket (root/admin). Returns False if insufficient privilege.

    v5: Parses the outer IP header length field dynamically to correctly
    locate the ICMP header even when IP options are present.
    """
    if not is_root(): return False
    recv_sock: Optional[socket.socket] = None
    send_sock: Optional[socket.socket] = None
    try:
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                  socket.IPPROTO_ICMP)
        recv_sock.settimeout(timeout)
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        send_sock.settimeout(timeout)
        send_sock.sendto(b"\x00" * 8, (ip, port))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = recv_sock.recvfrom(1024)
                if addr[0] != ip:
                    continue
                if len(data) < 1:
                    continue
                # Parse IP header length from IHL field (lower nibble of first byte)
                ip_hdr_len = (data[0] & 0x0F) * 4
                if len(data) < ip_hdr_len + 1:
                    continue
                icmp_type = data[ip_hdr_len]
                # ICMP type 3 = Destination Unreachable (host is alive, port closed)
                if icmp_type == 3:
                    return True
            except socket.timeout:
                break
        return False
    except PermissionError:
        return False
    except Exception:
        return False
    finally:
        for s in (recv_sock, send_sock):
            if s:
                try: s.close()
                except Exception: pass


# ══════════════════════════════════════════════════════════════════════════════
# TTL-based OS fingerprinting
# ══════════════════════════════════════════════════════════════════════════════

_TTL_OS_MAP: List[Tuple[range, str]] = [
    (range(60, 66),   "Linux / macOS / Android"),
    (range(125, 130), "Windows"),
    (range(252, 256), "Cisco / Network gear / FreeBSD"),
    (range(250, 252), "Cisco (some)"),
    (range(30, 33),   "Network gear (low TTL)"),
]


def guess_os_from_ttl(ttl: Optional[int]) -> str:
    if ttl is None: return ""
    for rng, label in _TTL_OS_MAP:
        if ttl in rng: return label
    return f"Unknown (TTL {ttl})"


def ping_with_ttl(ip: str, timeout_s: int = 1) -> Tuple[bool, Optional[int]]:
    """
    Ping and extract the TTL from the response.
    Returns (alive, ttl).  ttl is None if not parseable.
    """
    if is_windows():
        cmd = ["ping", "-n", "1", "-w", str(timeout_s * 1000), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]
    res = safe_run(cmd, timeout=timeout_s + 2)
    alive = res.get("returncode", 1) == 0
    ttl: Optional[int] = None
    if alive:
        out = res.get("stdout", "")
        # Windows: "TTL=128", Linux: "ttl=64"
        m = re.search(r"\bttl=(\d+)\b", out, re.I)
        if m:
            try: ttl = int(m.group(1))
            except Exception: pass
    return alive, ttl


def ping_one(ip: str, timeout_s: int = 1) -> bool:
    alive, _ = ping_with_ttl(ip, timeout_s)
    return alive


# ══════════════════════════════════════════════════════════════════════════════
# Name resolution
# ══════════════════════════════════════════════════════════════════════════════

def resolve_reverse(ip: str, timeout: float = 1.5) -> Optional[str]:
    """Resolve reverse DNS without mutating the global socket timeout."""
    def _lookup() -> Optional[str]:
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            return name
        except Exception:
            return None
    try:
        with cf.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(_lookup)
            return fut.result(timeout=timeout)
    except Exception:
        return None


def netbios_name(ip: str, timeout_s: float = 3.0) -> Optional[str]:
    if not is_private_or_lan_ip(ip): return None
    try:
        if is_windows():
            with cf.ThreadPoolExecutor(max_workers=1) as ex:
                res = ex.submit(safe_run, ["nbtstat", "-A", ip],
                                int(timeout_s)).result(timeout=timeout_s + 0.5)
            for line in res.get("stdout", "").splitlines():
                m = re.search(r"^\s*([A-Z0-9\-_]+)\s+<00>\s+UNIQUE", line, re.I)
                if m: return m.group(1)
        elif which("nmblookup"):
            with cf.ThreadPoolExecutor(max_workers=1) as ex:
                res = ex.submit(safe_run, ["nmblookup", "-A", ip],
                                int(timeout_s)).result(timeout=timeout_s + 0.5)
            for line in res.get("stdout", "").splitlines():
                m = re.search(
                    r"^\s*([A-Z0-9\-_]+)\s+<00>\s+-\s+.*<ACTIVE>", line, re.I)
                if m: return m.group(1)
    except Exception:
        pass
    return None


def mdns_name_system(ip: str, timeout_s: float = 2.0) -> Optional[str]:
    if not (is_private_or_lan_ip(ip) and is_linux() and which("avahi-resolve-address")):
        return None
    try:
        with cf.ThreadPoolExecutor(max_workers=1) as ex:
            res = ex.submit(safe_run, ["avahi-resolve-address", ip],
                            int(timeout_s)).result(timeout=timeout_s + 0.5)
        out = res.get("stdout", "")
        if res.get("returncode") == 0 and out:
            parts = out.split()
            if len(parts) >= 2: return parts[1].strip()
    except Exception:
        pass
    return None


# ══════════════════════════════════════════════════════════════════════════════
# SNMP probing
# ══════════════════════════════════════════════════════════════════════════════

_SNMP_OIDS = {
    "sysDescr":    "1.3.6.1.2.1.1.1.0",
    "sysName":     "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "sysContact":  "1.3.6.1.2.1.1.4.0",
}


def snmp_probe(ip: str, communities: List[str],
               timeout_s: float = 1.5) -> Optional[Dict[str, str]]:
    if not _HAS_PURESNMP: return None
    for community in communities:
        try:
            results: Dict[str, str] = {}
            for name, oid in _SNMP_OIDS.items():
                try:
                    val = puresnmp.get(ip, community, oid,
                                       port=161, timeout=timeout_s)
                    if val is not None: results[name] = str(val).strip()
                except Exception:
                    pass
            if results: return results
        except Exception:
            continue
    return None


# ══════════════════════════════════════════════════════════════════════════════
# Zeroconf
# ══════════════════════════════════════════════════════════════════════════════

def zeroconf_passive_map(timeout_s: float = 3.0) -> Dict[str, Dict[str, Any]]:
    if not _HAS_ZEROCONF: return {}
    service_types = [
        "_http._tcp.local.", "_https._tcp.local.", "_workstation._tcp.local.",
        "_ssh._tcp.local.", "_smb._tcp.local.", "_printer._tcp.local.",
        "_ipp._tcp.local.", "_airplay._tcp.local.", "_googlecast._tcp.local.",
        "_raop._tcp.local.", "_apple-mobdev2._tcp.local.", "_homekit._tcp.local.",
        "_matter._tcp.local.",
    ]
    zc = Zeroconf()
    results: Dict[str, Dict[str, Any]] = {}

    def add(ip: str, name: Optional[str], stype: str) -> None:
        if not ip or not is_private_or_lan_ip(ip): return
        if ip not in results:
            results[ip] = {"names": set(), "services": set()}
        if name: results[ip]["names"].add(name)
        results[ip]["services"].add(stype)

    class Listener:
        def add_service(self, zeroconf, stype, name):
            try:
                info = zeroconf.get_service_info(stype, name, timeout=500)
                if not info: return
                addrs = getattr(info, "parsed_addresses", lambda: [])()
                for ip in addrs:
                    add(ip, getattr(info, "server", None), stype)
            except Exception: pass
        def update_service(self, *a): pass
        def remove_service(self, *a): pass

    try:
        for st in service_types:
            ServiceBrowser(zc, st, Listener())
        time.sleep(max(0.5, float(timeout_s)))
    finally:
        try: zc.close()
        except Exception: pass

    return {ip: {"names": sorted(d["names"]), "services": sorted(d["services"])}
            for ip, d in results.items()}


# ══════════════════════════════════════════════════════════════════════════════
# Service fingerprinting  (SSH, HTTP title, TLS, UPnP)
# ══════════════════════════════════════════════════════════════════════════════

def grab_ssh_banner(ip: str, port: int, timeout: float = 1.0) -> Optional[str]:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(256)
        txt = data.decode("utf-8", errors="ignore").strip()
        return txt if txt.startswith("SSH-") else None
    except Exception:
        return None


def _extract_title(html: str) -> Optional[str]:
    m = re.search(r"<title[^>]*>([^<]{1,250})</title>", html, re.I | re.S)
    if m: return re.sub(r"\s+", " ", m.group(1)).strip()
    return None


def grab_http_headers(ip: str, port: int, use_tls: bool,
                      timeout: float = 2.5) -> Dict[str, Any]:
    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{ip}:{port}/"
    out: Dict[str, Any] = {"url": url}
    try:
        r = requests.get(url, timeout=timeout,
                         headers={"User-Agent": f"OmniRecon/{__version__}"},
                         verify=False, allow_redirects=True)
        out["status_code"] = r.status_code
        keep = {"server", "via", "x-powered-by", "www-authenticate",
                "content-type", "location"}
        out["headers"] = {k: v for k, v in r.headers.items()
                          if k.lower() in keep}
        ct = r.headers.get("content-type", "")
        if "html" in ct.lower() or not ct:
            title = _extract_title(r.text[:12288])
            if title: out["title"] = title
    except Exception as e:
        out["error"] = repr(e)
    return out


def grab_tls_subject(ip: str, port: int, timeout: float = 2.0) -> Optional[Dict]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=None) as ssock:
                # With CERT_NONE, getpeercert() always returns {} — use binary form
                raw = ssock.getpeercert(binary_form=True)
                if not raw:
                    return None
                try:
                    from cryptography import x509
                    cert_obj = x509.load_der_x509_certificate(raw)
                    subj = [(a.oid._name, a.value) for a in cert_obj.subject]
                    try:
                        from cryptography.x509 import SubjectAlternativeName, DNSName
                        san_ext = cert_obj.extensions.get_extension_for_class(
                            SubjectAlternativeName)
                        san = [("DNS", n.value) for n in
                               san_ext.value.get_values_for_type(DNSName)]
                    except Exception:
                        san = []
                    try:
                        exp = cert_obj.not_valid_after_utc.strftime(
                            "%b %d %H:%M:%S %Y GMT")
                    except AttributeError:
                        exp = cert_obj.not_valid_after.strftime(  # type: ignore[attr-defined]
                            "%b %d %H:%M:%S %Y GMT")
                    return {"subject": subj[:24], "subjectAltName": san[:24],
                            "notAfter": exp}
                except ImportError:
                    return {"subject": [], "subjectAltName": [], "notAfter": "",
                            "note": "install cryptography package for full cert details"}
    except Exception:
        return None


def service_hints(ip: str, open_ports: List[int],
                  timeout: float = 2.5) -> Dict[str, Any]:
    hints: Dict[str, Any] = {}
    for p in open_ports:
        if p == 22:
            b = grab_ssh_banner(ip, p, timeout=1.0)
            if b: hints.setdefault("ssh", {})[str(p)] = {"banner": b}
        if p in (21,):
            # FTP banner
            try:
                with socket.create_connection((ip, p), timeout=1.5) as s:
                    s.settimeout(1.5)
                    data = s.recv(256)
                banner = data.decode("utf-8", errors="ignore").strip()
                if banner:
                    hints.setdefault("ftp", {})[str(p)] = {"banner": banner[:120]}
            except Exception:
                pass
        if p in (80, 8080, 8006, 8008, 8888):
            hints.setdefault("http", {})[str(p)] = grab_http_headers(
                ip, p, False, timeout)
        if p in (443, 8443, 4443):
            hints.setdefault("https", {})[str(p)] = grab_http_headers(
                ip, p, True, timeout)
            subj = grab_tls_subject(ip, p, timeout)
            if subj: hints.setdefault("tls", {})[str(p)] = subj
    return hints


# ══════════════════════════════════════════════════════════════════════════════
# CVE cross-reference  (NVD 2.0 API with local cache)
# ══════════════════════════════════════════════════════════════════════════════

_NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_RATE_DELAY_NO_KEY = 6.2   # seconds between requests (5 req/30s)
_NVD_RATE_DELAY_WITH_KEY = 0.7  # seconds between requests (50 req/30s)

# ── CVE Impact classification keywords ───────────────────────────────────────
_IMPACT_PATTERNS: List[Tuple[str, str, str]] = [
    # (pattern, label, icon)  — checked in order, first match wins
    (r"remote code exec|rce|arbitrary code|unauthenticated.*exec|execute arbitrary",
     "Remote Code Execution", "🔴"),
    (r"privilege esc|elevat.*privilege|local privilege|gain.*root|become.*admin",
     "Privilege Escalation",  "🟠"),
    (r"denial.of.service|dos\b|crash|infinite loop|resource exhaust|memory leak",
     "Denial of Service",     "🟢"),
    (r"authentication bypass|bypass.*auth|skip.*auth|unauthenticated access",
     "Authentication Bypass", "🟠"),
    (r"sql injection|sqli|os command inject|command inject|ldap inject|xpath inject",
     "Injection",             "🔴"),
    (r"cross.site script|xss\b|reflected.*script|stored.*script",
     "XSS",                   "🟡"),
    (r"information disclos|sensitive.*data|credential.*expos|password.*expos|"
     r"path traversal|directory traversal|file read",
     "Information Disclosure","🟡"),
    (r"buffer overflow|heap overflow|stack overflow|memory corruption|use.after.free",
     "Memory Corruption",     "🔴"),
    (r"man.in.the.middle|mitm|ssl strip|certificate.*forg|weak.*cipher|"
     r"downgrade.*attack|poodle|beast\b|heartbleed",
     "Cryptographic Weakness","🟠"),
]


def classify_cve_impact(description: str) -> Tuple[str, str]:
    """Return (impact_label, impact_icon) for a CVE description."""
    d = description.lower()
    for pat, label, icon in _IMPACT_PATTERNS:
        if re.search(pat, d):
            return label, icon
    return "Other", "⚪"


_CVE_CACHE_TTL_SECONDS = 7 * 86400  # 7 days


def load_cve_cache(cache_path: str) -> Dict[str, Any]:
    if not os.path.exists(cache_path):
        return {}
    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        cutoff = time.time() - _CVE_CACHE_TTL_SECONDS
        out: Dict[str, Any] = {}
        for k, v in raw.items():
            if isinstance(v, dict) and "ts" in v:
                if v["ts"] >= cutoff:
                    out[k] = v["data"]
            else:
                out[k] = v  # Legacy entries without timestamp
        return out
    except Exception:
        return {}


def save_cve_cache(cache_path: str, cache: Dict[str, Any]) -> None:
    try:
        now = time.time()
        stamped = {k: {"data": v, "ts": now} for k, v in cache.items()}
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(stamped, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def _extract_service_strings(hosts: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
    """
    Build a mapping from service_string → set of IPs that expose it.
    Service strings come from: SSH banners, HTTP Server headers, TLS CN,
    SNMP sysDescr.
    """
    svc_to_ips: Dict[str, Set[str]] = {}

    def add(svc: str, ip: str) -> None:
        # Normalise: strip version noise to a canonical keyword
        svc = svc.strip()
        if not svc or len(svc) < 3: return
        svc_to_ips.setdefault(svc, set()).add(ip)

    for h in hosts:
        ip = h.get("ip", "")
        # SSH banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        for pmap in (h.get("service_hints") or {}).get("ssh", {}).values():
            banner = pmap.get("banner", "")
            if banner:
                # Extract product + version: "OpenSSH_8.9p1"
                m = re.search(r"SSH-\d+\.\d+-(\S+)", banner)
                if m: add(m.group(1), ip)

        # HTTP Server header: "Apache/2.4.51 (Ubuntu)"
        for proto in ("http", "https"):
            for pmap in (h.get("service_hints") or {}).get(proto, {}).values():
                srv = (pmap.get("headers") or {}).get("server") or \
                      (pmap.get("headers") or {}).get("Server", "")
                if srv: add(srv[:100], ip)

        # SNMP sysDescr
        snmp = h.get("snmp") or {}
        desc = snmp.get("sysDescr", "")
        if desc: add(desc[:120], ip)

        # TLS CN
        for pmap in (h.get("service_hints") or {}).get("tls", {}).values():
            subj = dict(pmap.get("subject") or [])
            cn = subj.get("commonName", "")
            if cn: add(cn[:80], ip)

    return svc_to_ips


def query_nvd(keyword: str, api_key: Optional[str],
              rate_delay: float,
              results_per_page: int = 20) -> List[Dict[str, Any]]:
    """Query NVD 2.0 API for CVEs matching keyword. Returns list of CVE dicts."""
    headers: Dict[str, str] = {"User-Agent": "OmniRecon/6.0"}
    if api_key:
        headers["apiKey"] = api_key
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": min(max(1, results_per_page), 2000),
        "startIndex": 0,
    }
    try:
        r = requests.get(_NVD_API_BASE, params=params, headers=headers,
                         timeout=15)
        if r.status_code == 403:
            return []
        if r.status_code != 200:
            return []
        data = r.json()
        cves = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            # CVSS score (prefer v3.1, fall back to v2)
            score = None
            severity = None
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                mlist = metrics.get(key, [])
                if mlist:
                    cvss = mlist[0].get("cvssData", {})
                    score = cvss.get("baseScore")
                    severity = cvss.get("baseSeverity") or mlist[0].get("baseSeverity")
                    break
            # Description
            desc_list = cve.get("descriptions", [])
            desc = next((d["value"] for d in desc_list if d.get("lang") == "en"), "")
            impact_label, impact_icon = classify_cve_impact(desc)
            cves.append({
                "id": cve_id,
                "score": score,
                "severity": severity,
                "description": desc[:300],
                "published": cve.get("published", "")[:10],
                "impact": impact_label,
                "impact_icon": impact_icon,
                "kev": False,  # filled in later by KEV cross-reference
            })
        time.sleep(rate_delay)
        return cves
    except Exception:
        time.sleep(rate_delay)
        return []


def fetch_cisa_kev() -> Set[str]:
    """
    Download the CISA Known Exploited Vulnerabilities catalog.
    Returns a set of CVE IDs that are actively exploited.
    """
    url = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
    try:
        r = requests.get(url, timeout=20, headers={"User-Agent": "OmniRecon/6.0"})
        r.raise_for_status()
        data = r.json()
        return {v["cveID"] for v in data.get("vulnerabilities", []) if v.get("cveID")}
    except Exception:
        return set()


def check_cves(hosts: List[Dict[str, Any]],
               cache_path: str,
               api_key: Optional[str] = None,
               progress: bool = True,
               min_score: float = 6.0,
               use_kev: bool = False,
               results_per_query: int = 20) -> Dict[str, List[Dict[str, Any]]]:
    """
    Cross-reference service strings against NVD CVE database.
    Returns dict: ip → list of CVE records.
    Respects NVD rate limits. Uses local cache to skip re-queries.
    Filters by min_score. Optionally cross-references CISA KEV catalog.
    """
    rate_delay = _NVD_RATE_DELAY_WITH_KEY if api_key else _NVD_RATE_DELAY_NO_KEY
    cache = load_cve_cache(cache_path)

    # Fetch CISA KEV catalog if requested
    kev_ids: Set[str] = set()
    if use_kev:
        if progress:
            print("\n  Fetching CISA Known Exploited Vulnerabilities catalog …")
        kev_ids = fetch_cisa_kev()
        if progress:
            print(f"  KEV catalog: {len(kev_ids)} actively-exploited CVEs loaded.")

    svc_to_ips = _extract_service_strings(hosts)
    if not svc_to_ips:
        return {}

    if progress:
        print(f"\n  CVE check: {len(svc_to_ips)} unique service string(s) to query …")
        if min_score > 0:
            print(f"  CVSS minimum score filter: ≥ {min_score}")

    ip_cves: Dict[str, List[Dict]] = {}

    for svc_str, ips in svc_to_ips.items():
        cache_key = hashlib.md5(
            f"{svc_str}|rpp={results_per_query}".encode(),
            usedforsecurity=False).hexdigest()
        if cache_key in cache:
            cve_list = cache[cache_key]
        else:
            if progress:
                print(f"    Querying NVD: {svc_str[:70]} …")
            cve_list = query_nvd(svc_str, api_key, rate_delay,
                                 results_per_page=results_per_query)
            cache[cache_key] = cve_list
            save_cve_cache(cache_path, cache)

        # Apply CVSS minimum score filter
        if min_score > 0:
            cve_list = [c for c in cve_list
                        if c.get("score") is not None and
                        float(c.get("score", 0)) >= min_score]

        # Mark KEV entries
        for cve in cve_list:
            cve["kev"] = cve["id"] in kev_ids

        # De-duplicate informational (score=None or score<4) findings
        # Only keep informational if nothing else is available for that IP
        high_cves = [c for c in cve_list if (c.get("score") or 0) >= 4.0]
        info_cves = [c for c in cve_list if (c.get("score") or 0) < 4.0]
        filtered = high_cves if high_cves else info_cves[:3]  # max 3 info findings

        for ip in ips:
            if filtered:
                existing = ip_cves.setdefault(ip, [])
                seen_ids = {c["id"] for c in existing}
                for cve in filtered:
                    if cve["id"] not in seen_ids:
                        existing.append(cve)
                        seen_ids.add(cve["id"])

    # Sort each IP's CVE list: KEV first, then by score desc
    for ip in ip_cves:
        ip_cves[ip].sort(
            key=lambda c: (not c.get("kev", False),
                           -(c.get("score") or 0)))

    if progress:
        flagged = sum(1 for v in ip_cves.values() if v)
        kev_flagged = sum(
            1 for cves in ip_cves.values()
            for c in cves if c.get("kev"))
        print(f"  CVE check complete: {flagged} host(s) with CVEs"
              + (f", {kev_flagged} KEV match(es)" if kev_ids else "") + "\n")

    return ip_cves


# ══════════════════════════════════════════════════════════════════════════════
# PENETRATION TESTING MODULE  (v6.0)
# ══════════════════════════════════════════════════════════════════════════════
#
# ⚠  LEGAL WARNING: Only use against systems you own or have explicit
#    written authorisation to test. All actions are audit-logged.
#
# ══════════════════════════════════════════════════════════════════════════════

_PENTEST_CONSENT_PHRASE = "I HAVE AUTHORISATION TO TEST THIS NETWORK"

# Default credential list (intentionally minimal — add your own via --pentest-credentials)
_DEFAULT_CREDS: List[Tuple[str, str]] = [
    ("admin",    "admin"),
    ("admin",    "password"),
    ("admin",    ""),
    ("root",     "root"),
    ("root",     ""),
    ("root",     "toor"),
    ("user",     "user"),
    ("guest",    "guest"),
    ("guest",    ""),
    ("test",     "test"),
    ("pi",       "raspberry"),
    ("ubnt",     "ubnt"),
    ("support",  "support"),
    ("service",  "service"),
    ("cisco",    "cisco"),
    ("enable",   "enable"),
    ("admin",    "1234"),
    ("admin",    "12345"),
    ("admin",    "123456"),
]

# TLS weak protocols / ciphers
_WEAK_TLS_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
_WEAK_CIPHER_PATTERNS = re.compile(
    r"NULL|EXPORT|RC4|DES(?!-EDE)|ANON|ADH|AECDH|3DES|RC2|IDEA|SEED|eNULL|aNULL",
    re.I,
)

# HTTP sensitive paths to probe
_HTTP_SENSITIVE_PATHS = [
    "/.git/HEAD", "/.env", "/wp-config.php", "/config.php",
    "/etc/passwd", "/phpinfo.php", "/admin/", "/administrator/",
    "/backup/", "/db/", "/.htaccess", "/web.config",
    "/server-status", "/server-info", "/.DS_Store",
    "/crossdomain.xml", "/robots.txt", "/sitemap.xml",
    "/api/v1/users", "/api/users", "/actuator", "/actuator/env",
    "/actuator/health", "/metrics", "/_cat/indices",  # ElasticSearch
    "/console",  # JBoss / Wildfly admin console
    "/manager/html",  # Tomcat manager
    "/phpmyadmin/", "/pma/", "/myadmin/",
]

# HTTP security headers to check
_SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS not set — susceptible to downgrade attacks",
    "Content-Security-Policy":   "No CSP — XSS mitigation missing",
    "X-Frame-Options":           "Clickjacking protection missing",
    "X-Content-Type-Options":    "MIME-sniffing protection missing",
    "Referrer-Policy":           "Referrer-Policy not set",
    "Permissions-Policy":        "Permissions-Policy not set",
    "X-XSS-Protection":          "Legacy XSS filter header missing (informational)",
}


# ── Audit logging ─────────────────────────────────────────────────────────────

_audit_log_path: Optional[str] = None
_audit_lock = threading.Lock()


def init_audit_log(path: str) -> None:
    global _audit_log_path
    _audit_log_path = path
    # Write header entry
    _audit_write({
        "event": "audit_start",
        "tool": "OmniRecon v6.0",
        "pid": os.getpid(),
        "user": os.environ.get("USER") or os.environ.get("USERNAME") or "unknown",
    })


def _audit_write(record: Dict[str, Any]) -> None:
    if not _audit_log_path:
        return
    record["timestamp"] = dt.datetime.now().isoformat()
    with _audit_lock:
        try:
            with open(_audit_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception:
            pass


def audit_pentest_action(module: str, target_ip: str,
                         action: str, result: str,
                         extra: Optional[Dict] = None) -> None:
    rec: Dict[str, Any] = {
        "event":     "pentest_action",
        "module":    module,
        "target":    target_ip,
        "action":    action,
        "result":    result,
    }
    if extra:
        rec.update(extra)
    _audit_write(rec)


# ── Pentest consent gate ──────────────────────────────────────────────────────

def pentest_consent_gate(args: argparse.Namespace,
                         targets: List[str]) -> Dict[str, Any]:
    """
    Require dual consent for penetration testing:
      1. --i-have-authorization flag must be set
      2. Operator must interactively type the consent phrase
    Returns a consent record embedded in the report.
    """
    record: Dict[str, Any] = {
        "consented": False,
        "timestamp": dt.datetime.now().isoformat(),
        "targets":   targets,
        "phrase_matched": False,
        "auth_flag_set":  bool(args.i_have_authorization),
    }

    if not args.i_have_authorization:
        raise SystemExit(
            "\n⚠  Pentest requires --i-have-authorization flag.\n"
            "   This confirms you have authorisation to test the target network.")

    if args.non_interactive:
        raise SystemExit(
            "\n⚠  Pentest cannot run in --non-interactive mode.\n"
            "   Explicit interactive consent is required.")

    print("\n" + "═" * 70)
    print("  ⚠  PENETRATION TESTING CONSENT REQUIRED")
    print("═" * 70)
    print("""
  You are about to run active penetration testing probes against:
""")
    for t in targets[:10]:
        print(f"    • {t}")
    if len(targets) > 10:
        print(f"    … and {len(targets)-10} more host(s)")
    print("""
  This includes:
    • Attempting default/common credentials on services
    • Probing web paths for sensitive files
    • Testing TLS/SSL for weak protocols and ciphers
    • Testing FTP for anonymous access
    • Enumerating SMB shares via null/guest sessions

  ⚠  ONLY proceed if you OWN these systems or have EXPLICIT WRITTEN
     AUTHORISATION to conduct security testing against them.

  All actions will be logged to the audit log file.
""")
    print(f'  Type exactly: {_PENTEST_CONSENT_PHRASE}')
    try:
        ans = input("\n  Your input: ").strip()
    except (EOFError, KeyboardInterrupt):
        raise SystemExit("\n  Aborted.")

    if ans != _PENTEST_CONSENT_PHRASE:
        raise SystemExit(
            f"\n  Consent phrase did not match. Pentest aborted.\n"
            f"  Expected: {_PENTEST_CONSENT_PHRASE}\n"
            f"  Got:      {ans!r}\n")

    record["consented"] = True
    record["phrase_matched"] = True
    _audit_write({
        "event":   "pentest_consent_granted",
        "targets": targets,
        "phrase":  ans,
    })
    print("\n  ✓ Consent granted. Starting penetration tests …\n")
    return record


# ── TLS / SSL audit ──────────────────────────────────────────────────────────

_TLS_WEAK_PROTOCOLS = [
    ("SSLv2",   ssl.PROTOCOL_TLS_CLIENT),
    ("SSLv3",   ssl.PROTOCOL_TLS_CLIENT),
    ("TLSv1",   ssl.PROTOCOL_TLS_CLIENT),
    ("TLSv1.1", ssl.PROTOCOL_TLS_CLIENT),
]


def _tls_probe_protocol(ip: str, port: int,
                        protocol_name: str,
                        timeout: float = 3.0) -> bool:
    """Try to connect with a specific minimum TLS protocol."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        if protocol_name == "SSLv2":
            try: ctx.options |= ssl.OP_NO_SSLv3
            except AttributeError: pass
        elif protocol_name == "SSLv3":
            try:
                ctx.minimum_version = ssl.TLSVersion.SSLv3  # type: ignore
            except AttributeError:
                return False  # not supported on this Python build
        elif protocol_name == "TLSv1":
            try:
                ctx.maximum_version = ssl.TLSVersion.TLSv1  # type: ignore
                ctx.minimum_version = ssl.TLSVersion.TLSv1  # type: ignore
            except AttributeError:
                return False
        elif protocol_name == "TLSv1.1":
            try:
                ctx.maximum_version = ssl.TLSVersion.TLSv1_1  # type: ignore
                ctx.minimum_version = ssl.TLSVersion.TLSv1_1  # type: ignore
            except AttributeError:
                return False

        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                return ssock.version() is not None
    except Exception:
        return False


def _get_cert_info(ip: str, port: int,
                   timeout: float = 3.0) -> Dict[str, Any]:
    """Retrieve TLS certificate details."""
    result: Dict[str, Any] = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cert_bin = ssock.getpeercert(binary_form=True)
                result["protocol"] = ssock.version()
                result["cipher"] = ssock.cipher()
                if cert:
                    not_after = cert.get("notAfter", "")
                    not_before = cert.get("notBefore", "")
                    result["not_after"]  = not_after
                    result["not_before"] = not_before
                    result["issuer"]     = dict(
                        x for rdn in cert.get("issuer", []) for x in rdn)
                    result["subject"]    = dict(
                        x for rdn in cert.get("subject", []) for x in rdn)
                    # Check self-signed
                    result["self_signed"] = (
                        result.get("issuer") == result.get("subject"))
                    # Days until expiry
                    if not_after:
                        try:
                            exp = dt.datetime.strptime(
                                not_after, "%b %d %H:%M:%S %Y %Z").replace(
                                    tzinfo=dt.timezone.utc)
                            days_left = (exp - dt.datetime.now(dt.timezone.utc)).days
                            result["days_until_expiry"] = days_left
                        except Exception:
                            pass
    except Exception as e:
        result["error"] = repr(e)
    return result


def audit_tls(ip: str, port: int,
              timeout: float = 3.0) -> Dict[str, Any]:
    """
    Full TLS/SSL audit for a given host:port.
    Returns structured findings with severity ratings.
    """
    findings: List[Dict[str, Any]] = []
    summary: Dict[str, Any] = {"ip": ip, "port": port, "findings": findings}

    cert_info = _get_cert_info(ip, port, timeout)
    summary["cert"] = cert_info
    audit_pentest_action("tls-audit", ip, f"tls_connect:{port}",
                         "ok" if not cert_info.get("error") else "error",
                         {"port": port})

    if cert_info.get("error"):
        return summary

    # Protocol version check
    for proto_name in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        supported = _tls_probe_protocol(ip, port, proto_name, timeout)
        if supported:
            sev = "CRITICAL" if proto_name in ("SSLv2", "SSLv3") else "HIGH"
            findings.append({
                "check": f"Weak protocol: {proto_name}",
                "severity": sev,
                "detail": (f"{proto_name} is supported. "
                           f"This protocol is deprecated and cryptographically weak."),
                "remediation": f"Disable {proto_name} on the server.",
            })
            audit_pentest_action("tls-audit", ip,
                                 f"weak_protocol:{proto_name}:{port}",
                                 "VULNERABLE")

    # Cipher suite check
    cipher = cert_info.get("cipher")
    if cipher:
        cipher_str = cipher[0] if isinstance(cipher, (list, tuple)) else str(cipher)
        if _WEAK_CIPHER_PATTERNS.search(cipher_str):
            findings.append({
                "check": "Weak cipher in use",
                "severity": "HIGH",
                "detail": f"Negotiated cipher: {cipher_str}",
                "remediation": "Configure server to only allow strong AEAD ciphers "
                               "(AES-GCM, ChaCha20-Poly1305).",
            })
            audit_pentest_action("tls-audit", ip,
                                 f"weak_cipher:{port}", "VULNERABLE",
                                 {"cipher": cipher_str})

    # Certificate expiry
    days = cert_info.get("days_until_expiry")
    if days is not None:
        if days < 0:
            findings.append({
                "check": "Certificate EXPIRED",
                "severity": "CRITICAL",
                "detail": f"Certificate expired {abs(days)} day(s) ago.",
                "remediation": "Renew the TLS certificate immediately.",
            })
        elif days <= 30:
            findings.append({
                "check": f"Certificate expiring soon ({days} days)",
                "severity": "HIGH",
                "detail": f"Certificate expires in {days} day(s).",
                "remediation": "Renew the TLS certificate before expiry.",
            })

    # Self-signed cert
    if cert_info.get("self_signed"):
        findings.append({
            "check": "Self-signed certificate",
            "severity": "MEDIUM",
            "detail": "Issuer == Subject — certificate is self-signed. "
                      "Clients cannot verify authenticity.",
            "remediation": "Replace with a certificate signed by a trusted CA.",
        })

    # BEAST (TLS 1.0 CBC)
    tls1_supported = any(
        f["check"] == "Weak protocol: TLSv1" for f in findings)
    if tls1_supported:
        findings.append({
            "check": "Potential BEAST attack surface (TLS 1.0 + CBC)",
            "severity": "MEDIUM",
            "detail": "TLS 1.0 with CBC ciphers is theoretically vulnerable "
                      "to the BEAST attack. Modern clients mitigate this.",
            "remediation": "Disable TLS 1.0 and use TLS 1.2+ exclusively.",
        })

    return summary


# ── HTTP security headers audit ───────────────────────────────────────────────

def audit_http_headers(ip: str, port: int,
                       use_https: bool = False,
                       timeout: float = 3.0) -> Dict[str, Any]:
    """Audit HTTP response headers for security best-practices."""
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{ip}:{port}/"
    result: Dict[str, Any] = {"url": url, "findings": []}
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                         headers={"User-Agent": "OmniRecon/6.0"},
                         allow_redirects=True)
        result["status_code"] = r.status_code
        headers_lower = {k.lower(): v for k, v in r.headers.items()}

        for header, description in _SECURITY_HEADERS.items():
            if header.lower() not in headers_lower:
                sev = "MEDIUM"
                if header == "Strict-Transport-Security" and use_https:
                    sev = "HIGH"
                elif header in ("Content-Security-Policy", "X-Frame-Options"):
                    sev = "MEDIUM"
                else:
                    sev = "INFO"
                result["findings"].append({
                    "check":       f"Missing header: {header}",
                    "severity":    sev,
                    "detail":      description,
                    "remediation": f"Add '{header}' response header on the server.",
                })

        # Check for information disclosure headers
        for bad_hdr in ("server", "x-powered-by", "x-aspnet-version",
                        "x-aspnetmvc-version"):
            val = headers_lower.get(bad_hdr)
            if val:
                result["findings"].append({
                    "check":    f"Version disclosure: {bad_hdr}",
                    "severity": "INFO",
                    "detail":   f"{bad_hdr}: {val[:120]}",
                    "remediation": f"Remove or redact the '{bad_hdr}' header.",
                })

        audit_pentest_action("headers", ip, f"headers_audit:{port}", "done",
                             {"findings": len(result["findings"])})
    except Exception as e:
        result["error"] = repr(e)
    return result


# ── HTTP vulnerability probes ─────────────────────────────────────────────────

def probe_http_vulns(ip: str, port: int,
                     use_https: bool = False,
                     timeout: float = 3.0) -> Dict[str, Any]:
    """Probe common sensitive HTTP paths and basic vulnerability patterns."""
    scheme = "https" if use_https else "http"
    base = f"{scheme}://{ip}:{port}"
    findings: List[Dict[str, Any]] = []
    result: Dict[str, Any] = {"base_url": base, "findings": findings}
    _ua = {"User-Agent": f"OmniRecon/{__version__}"}

    def _probe_path(path: str) -> Optional[Dict[str, Any]]:
        url = base + path
        try:
            r = requests.get(url, timeout=timeout, verify=False,
                             headers=_ua, allow_redirects=False)
            if r.status_code in (200, 301, 302, 307, 308):
                sev = "HIGH" if r.status_code == 200 else "MEDIUM"
                snippet = r.text[:200].replace("\n", " ").strip() if r.status_code == 200 else ""
                audit_pentest_action("http-vulns", ip,
                                     f"sensitive_path:{path}:{port}",
                                     f"HTTP_{r.status_code}")
                return {
                    "check":    f"Accessible path: {path}",
                    "severity": sev,
                    "detail":   f"HTTP {r.status_code} — {url}"
                                + (f" — content snippet: {snippet[:100]!r}" if snippet else ""),
                    "remediation": f"Restrict access to {path} or remove the resource.",
                }
        except Exception:
            pass
        return None

    with cf.ThreadPoolExecutor(max_workers=10) as ex:
        for finding in ex.map(_probe_path, _HTTP_SENSITIVE_PATHS):
            if finding:
                findings.append(finding)

    # Basic open-redirect check
    redirect_url = base + "/?url=https://evil.example.com"
    try:
        r2 = requests.get(redirect_url, timeout=timeout, verify=False,
                          headers=_ua, allow_redirects=False)
        loc = r2.headers.get("Location", "")
        if "evil.example.com" in loc:
            findings.append({
                "check":    "Open redirect detected",
                "severity": "MEDIUM",
                "detail":   f"GET /?url= parameter reflects in Location header: {loc!r}",
                "remediation": "Validate and whitelist redirect destinations.",
            })
            audit_pentest_action("http-vulns", ip,
                                 f"open_redirect:{port}", "VULNERABLE")
    except Exception:
        pass

    return result


# ── FTP anonymous login check ─────────────────────────────────────────────────

def check_ftp_anonymous(ip: str, port: int = 21,
                        timeout: float = 3.0) -> Dict[str, Any]:
    """Test whether FTP allows anonymous login."""
    result: Dict[str, Any] = {"ip": ip, "port": port, "anonymous_allowed": False,
                               "banner": None, "findings": []}
    try:
        import ftplib
        ftp = ftplib.FTP()
        ftp.connect(ip, port, timeout=timeout)
        result["banner"] = ftp.getwelcome()[:200]
        ftp.login("anonymous", "omnirecon@example.com")
        result["anonymous_allowed"] = True
        # Try listing root
        files: List[str] = []
        try:
            ftp.retrlines("LIST", files.append)
        except Exception:
            pass
        ftp.quit()
        result["findings"].append({
            "check":    "Anonymous FTP login allowed",
            "severity": "HIGH",
            "detail":   f"FTP on {ip}:{port} accepts anonymous credentials. "
                        f"Directory listing returned {len(files)} item(s).",
            "remediation": "Disable anonymous FTP access unless explicitly required. "
                           "If needed, restrict to read-only in a chroot jail.",
        })
        audit_pentest_action("ftp-anon", ip, f"ftp_anon:{port}",
                             "VULNERABLE",
                             {"files_listed": len(files)})
    except Exception as e:
        err = repr(e)
        if "anonymous" in err.lower() or "530" in err:
            pass  # denied — expected
        result["error"] = err[:100]
        audit_pentest_action("ftp-anon", ip, f"ftp_anon:{port}", "denied")
    return result


# ── SSH default credentials ───────────────────────────────────────────────────

def check_ssh_defaults(ip: str, port: int = 22,
                       creds: Optional[List[Tuple[str, str]]] = None,
                       timeout: float = 3.0) -> Dict[str, Any]:
    """Attempt a list of default credentials against an SSH service."""
    result: Dict[str, Any] = {
        "ip": ip, "port": port,
        "vulnerable": False, "working_creds": [],
        "findings": [],
    }
    if not _HAS_PARAMIKO:
        result["error"] = "paramiko not installed — pip install paramiko"
        return result

    cred_list = creds or _DEFAULT_CREDS
    for username, password in cred_list:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.WarningPolicy())
            client.connect(ip, port=port, username=username,
                           password=password, timeout=timeout,
                           banner_timeout=timeout,
                           auth_timeout=timeout,
                           look_for_keys=False,
                           allow_agent=False)
            client.close()
            result["vulnerable"] = True
            result["working_creds"].append(
                {"username": username, "password": password})
            audit_pentest_action("ssh-defaults", ip,
                                 f"ssh_cred:{port}",
                                 "CREDENTIAL_FOUND",
                                 {"user": username})
        except paramiko.AuthenticationException:
            audit_pentest_action("ssh-defaults", ip,
                                 f"ssh_cred:{port}:{username}",
                                 "auth_denied")
        except Exception:
            break  # Host refusing connections — stop trying

    if result["vulnerable"]:
        cred_summary = ", ".join(
            f"{c['username']}:****"
            for c in result["working_creds"])
        result["findings"].append({
            "check":    "Default SSH credentials accepted",
            "severity": "CRITICAL",
            "detail":   f"SSH on {ip}:{port} accepted: {cred_summary}",
            "remediation": "Change default passwords immediately. "
                           "Enforce key-based authentication and disable "
                           "password login in sshd_config.",
        })
    return result


# ── SMB null/guest session enumeration ────────────────────────────────────────

def check_smb_enum(ip: str, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Attempt SMB null session and guest share enumeration via system tools.
    Uses 'smbclient' (Linux/macOS) or 'net view' (Windows).
    """
    result: Dict[str, Any] = {
        "ip": ip, "null_session": False,
        "shares": [], "findings": [],
    }
    audit_pentest_action("smb-enum", ip, "smb_enum", "attempting")

    if is_windows():
        raw = safe_run(["net", "view", f"\\\\{ip}", "/all"], timeout=timeout + 2)
        stdout = raw.get("stdout", "") or ""
        if stdout and "Share name" in stdout:
            result["null_session"] = True
            for line in stdout.splitlines():
                line = line.strip()
                if line and not line.startswith("Share") and not line.startswith("-"):
                    result["shares"].append(line.split()[0])
    else:
        # Try smbclient -N (no password / null session)
        cmd = ["smbclient", "-L", f"//{ip}/", "-N",
               "--timeout", str(int(timeout + 2))]
        raw = safe_run(cmd, timeout=timeout + 5)
        stdout = raw.get("stdout", "") or ""
        stderr = raw.get("stderr", "") or ""
        combined = stdout + stderr
        if "Sharename" in combined or "IPC$" in combined:
            result["null_session"] = True
            for line in combined.splitlines():
                m = re.match(r"\s+(\S+)\s+(Disk|Print|IPC)", line)
                if m:
                    result["shares"].append(m.group(1))

    if result["null_session"]:
        result["findings"].append({
            "check":    "SMB null/anonymous session allowed",
            "severity": "HIGH",
            "detail":   (f"SMB on {ip} accepts null session. "
                         f"Shares enumerated: {result['shares'] or ['(none listed)']!r}"),
            "remediation": "Disable null session access: set "
                           "RestrictAnonymous=2 (Windows) or "
                           "'restrict anonymous = 2' in smb.conf.",
        })
        audit_pentest_action("smb-enum", ip, "smb_null_session",
                             "VULNERABLE",
                             {"shares": result["shares"]})
    else:
        audit_pentest_action("smb-enum", ip, "smb_null_session", "denied")

    return result


# ── Master pentest runner ─────────────────────────────────────────────────────

def load_pentest_credentials(path: Optional[str]) -> List[Tuple[str, str]]:
    if not path:
        return _DEFAULT_CREDS
    creds = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" in line:
                    u, p = line.split(":", 1)
                    creds.append((u.strip(), p.strip()))
    except Exception as e:
        print(f"  ⚠  Could not load credentials file: {e}")
    return creds or _DEFAULT_CREDS


def _pentest_one_host(
    h: Dict[str, Any],
    run_modules: Set[str],
    creds: List[Tuple[str, str]],
    timeout: float,
    progress: bool,
) -> Tuple[str, Dict[str, Any]]:
    """Run all pentest modules for a single host. Returns (ip, host_results)."""
    ip = h.get("ip", "")
    open_ports: List[int] = h.get("open_ports", [])
    host_results: Dict[str, Any] = {"ip": ip, "modules": {}, "all_findings": []}

    if progress:
        print(f"    [{ip}] Running pentest …")

    if "tls-audit" in run_modules:
        for port in [p for p in open_ports if p in (443, 8443, 4443, 8080)]:
            res = audit_tls(ip, port, timeout=timeout)
            host_results["modules"][f"tls:{port}"] = res
            host_results["all_findings"].extend(res.get("findings", []))

    if "headers" in run_modules:
        for port in [p for p in open_ports if p in (80, 8080, 8008, 8888)]:
            res = audit_http_headers(ip, port, use_https=False, timeout=timeout)
            host_results["modules"][f"headers:{port}"] = res
            host_results["all_findings"].extend(res.get("findings", []))
        for port in [p for p in open_ports if p in (443, 8443, 4443)]:
            res = audit_http_headers(ip, port, use_https=True, timeout=timeout)
            host_results["modules"][f"headers_https:{port}"] = res
            host_results["all_findings"].extend(res.get("findings", []))

    if "http-vulns" in run_modules:
        for port in [p for p in open_ports if p in (80, 8080, 8008, 8888)]:
            res = probe_http_vulns(ip, port, use_https=False, timeout=timeout)
            host_results["modules"][f"http_vulns:{port}"] = res
            host_results["all_findings"].extend(res.get("findings", []))
        for port in [p for p in open_ports if p in (443, 8443, 4443)]:
            res = probe_http_vulns(ip, port, use_https=True, timeout=timeout)
            host_results["modules"][f"https_vulns:{port}"] = res
            host_results["all_findings"].extend(res.get("findings", []))

    if "ftp-anon" in run_modules:
        for port in [p for p in open_ports if p == 21]:
            res = check_ftp_anonymous(ip, port, timeout=timeout)
            host_results["modules"][f"ftp_anon:{port}"] = res
            host_results["all_findings"].extend(res.get("findings", []))

    if "ssh-defaults" in run_modules:
        for port in [p for p in open_ports if p == 22]:
            res = check_ssh_defaults(ip, port, creds=creds, timeout=timeout)
            host_results["modules"][f"ssh_defaults:{port}"] = res
            host_results["all_findings"].extend(res.get("findings", []))

    if "smb-enum" in run_modules:
        if any(p in open_ports for p in (139, 445)):
            res = check_smb_enum(ip, timeout=timeout)
            host_results["modules"]["smb_enum"] = res
            host_results["all_findings"].extend(res.get("findings", []))

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3, "Other": 4}
    host_results["all_findings"].sort(
        key=lambda f: sev_order.get(f.get("severity", "Other"), 4))

    return ip, host_results


def run_pentest(hosts: List[Dict[str, Any]],
                modules: List[str],
                creds: List[Tuple[str, str]],
                timeout: float = 3.0,
                progress: bool = True) -> Dict[str, Any]:
    """
    Run the selected pentest modules against all discovered hosts in parallel.
    Returns a dict keyed by IP with all findings.
    """
    pentest_results: Dict[str, Any] = {}

    all_modules = {"tls-audit", "headers", "ftp-anon",
                   "ssh-defaults", "http-vulns", "smb-enum"}
    run_modules = set(modules) if "all" not in modules else all_modules
    unknown = run_modules - all_modules
    if unknown:
        print(f"  ⚠  Unknown pentest modules ignored: {unknown}")
    run_modules &= all_modules

    print(f"  Pentest modules active: {', '.join(sorted(run_modules))}")

    valid_hosts = [h for h in hosts if h.get("ip")]
    max_workers = min(len(valid_hosts), 8) if valid_hosts else 1
    with cf.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [
            ex.submit(_pentest_one_host, h, run_modules, creds, timeout, progress)
            for h in valid_hosts
        ]
        for fut in cf.as_completed(futures):
            try:
                ip, host_results = fut.result()
                pentest_results[ip] = host_results
            except Exception:
                pass

    total_findings = sum(
        len(v.get("all_findings", [])) for v in pentest_results.values())
    critical = sum(
        1 for v in pentest_results.values()
        for f in v.get("all_findings", [])
        if f.get("severity") == "CRITICAL")
    high = sum(
        1 for v in pentest_results.values()
        for f in v.get("all_findings", [])
        if f.get("severity") == "HIGH")

    if progress:
        print(f"\n  Pentest complete: {total_findings} finding(s) "
              f"({critical} CRITICAL, {high} HIGH)\n")

    _audit_write({
        "event":           "pentest_complete",
        "hosts_tested":    len(pentest_results),
        "total_findings":  total_findings,
        "critical":        critical,
        "high":            high,
    })

    return pentest_results


# ══════════════════════════════════════════════════════════════════════════════
# Historical trending
# ══════════════════════════════════════════════════════════════════════════════

def load_history(outdir: str,
                 current_stamp: str) -> Dict[str, Any]:
    """
    Load all previous network_report_*.json files in outdir.
    Returns:
      {
        "total_runs": N,
        "run_timestamps": [...],
        "per_ip": {
          ip: {
            "first_seen": ISO,
            "last_seen": ISO,
            "seen_count": N,
            "frequency": 0.0–1.0,
          }
        }
      }
    """
    history: Dict[str, Any] = {
        "total_runs": 0,
        "run_timestamps": [],
        "per_ip": {},
    }

    try:
        files = sorted([
            f for f in os.listdir(outdir)
            if f.startswith("network_report_") and f.endswith(".json")
            and f != f"network_report_{current_stamp}.json"
        ])
    except Exception:
        return history

    history["total_runs"] = len(files)

    for fname in files:
        try:
            with open(os.path.join(outdir, fname), "r", encoding="utf-8") as f:
                data = json.load(f)
            ts = data.get("system", {}).get("timestamp_local", "")
            history["run_timestamps"].append(ts)
            hosts = data.get("discovery", {}).get("hosts", [])
            for h in hosts:
                ip = h.get("ip")
                if not ip: continue
                rec = history["per_ip"].setdefault(ip, {
                    "first_seen": ts, "last_seen": ts, "seen_count": 0})
                rec["seen_count"] += 1
                if ts and (not rec["first_seen"] or ts < rec["first_seen"]):
                    rec["first_seen"] = ts
                if ts and ts > rec["last_seen"]:
                    rec["last_seen"] = ts
        except Exception:
            continue

    total = history["total_runs"]
    for ip, rec in history["per_ip"].items():
        rec["frequency"] = rec["seen_count"] / total if total > 0 else 0.0

    return history


# ══════════════════════════════════════════════════════════════════════════════
# Data collection
# ══════════════════════════════════════════════════════════════════════════════

def get_system_info() -> Dict[str, Any]:
    return {
        "timestamp_local": dt.datetime.now().isoformat(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "python": sys.version,
        "boot_time": dt.datetime.fromtimestamp(psutil.boot_time(), tz=dt.timezone.utc).isoformat(),
        "uptime_seconds": int(time.time() - psutil.boot_time()),
    }


def get_identity_info() -> Dict[str, Any]:
    return {"hostname": socket.gethostname(), "fqdn": socket.getfqdn()}


def get_public_ip() -> Dict[str, Any]:
    out: Dict[str, Any] = {"public_ip": None, "service": None, "error": None}
    for name, url in [("ipify", "https://api.ipify.org?format=json"),
                      ("ifconfig.co", "https://ifconfig.co/json")]:
        try:
            r = requests.get(url, timeout=5, headers={"User-Agent": f"OmniRecon/{__version__}"})
            r.raise_for_status()
            data = r.json()
            ip = data.get("ip") or data.get("ip_addr")
            if ip:
                out["public_ip"] = ip
                out["service"] = name
                return out
        except Exception as e:
            out["error"] = f"{name}: {e!r}"
    return out


def get_interfaces() -> Dict[str, Any]:
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    out: Dict[str, Any] = {}
    for ifname, addr_list in addrs.items():
        st = stats.get(ifname)
        out[ifname] = {
            "stats": {
                "isup": getattr(st, "isup", None),
                "speed_mbps": getattr(st, "speed", None),
                "mtu": getattr(st, "mtu", None),
            },
            "addresses": [
                {"family": str(a.family), "address": a.address,
                 "netmask": a.netmask, "broadcast": a.broadcast}
                for a in addr_list
            ]
        }
    return out


def get_routes_and_gateway() -> Dict[str, Any]:
    out: Dict[str, Any] = {"default_gateway": None, "default_iface": None, "raw": None}
    if is_windows():
        raw = safe_run(["route", "print", "-4"], timeout=10)
        out["raw"] = raw
        for line in (raw.get("stdout") or "").splitlines():
            if line.strip().startswith("0.0.0.0"):
                parts = re.split(r"\s+", line.strip())
                if len(parts) >= 3:
                    out["default_gateway"] = parts[2]
                    if len(parts) > 3: out["default_iface"] = parts[3]
                break
    elif is_linux() and which("ip"):
        raw = safe_run(["ip", "route"], timeout=10)
        out["raw"] = raw
        for line in (raw.get("stdout") or "").splitlines():
            if line.startswith("default "):
                m = re.search(r"\bvia\s+(\S+)", line)
                if m: out["default_gateway"] = m.group(1)
                m2 = re.search(r"\bdev\s+(\S+)", line)
                if m2: out["default_iface"] = m2.group(1)
                break
    elif is_macos():
        raw = safe_run(["route", "-n", "get", "default"], timeout=10)
        out["raw"] = raw
        for line in (raw.get("stdout") or "").splitlines():
            if "gateway:" in line:
                out["default_gateway"] = line.split("gateway:")[-1].strip()
            if "interface:" in line:
                out["default_iface"] = line.split("interface:")[-1].strip()
    return out


def get_dns_config() -> Dict[str, Any]:
    out: Dict[str, Any] = {"dns_servers": [], "raw": None}
    try:
        if is_windows():
            raw = safe_run(["ipconfig", "/all"], timeout=12)
            out["raw"] = raw
            dns, capture = [], False
            for line in (raw.get("stdout") or "").splitlines():
                if "DNS Servers" in line:
                    capture = True
                    ip = line.split(":")[-1].strip()
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip): dns.append(ip)
                    continue
                if capture:
                    cont = line.strip()
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", cont): dns.append(cont)
                    elif not cont or ":" in cont: capture = False
            out["dns_servers"] = sorted(set(dns))
        elif is_macos():
            raw = safe_run(["scutil", "--dns"], timeout=12)
            out["raw"] = raw
            out["dns_servers"] = sorted(set(re.findall(
                r"nameserver\[\d+\]\s*:\s*(\d+\.\d+\.\d+\.\d+)",
                raw.get("stdout") or "")))
        else:
            raw = safe_run(["cat", "/etc/resolv.conf"], timeout=6)
            out["raw"] = raw
            dns = []
            for line in (raw.get("stdout") or "").splitlines():
                if line.strip().startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2: dns.append(parts[1])
            out["dns_servers"] = sorted(set(dns))
    except Exception as e:
        out["raw"] = {"error": repr(e)}
    return out


def get_listening_ports() -> List[Dict[str, Any]]:
    out = []
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status == psutil.CONN_LISTEN:
                out.append({"local_ip": getattr(c.laddr, "ip", None),
                             "local_port": getattr(c.laddr, "port", None),
                             "pid": c.pid})
    except Exception as e:
        out.append({"error": repr(e)})
    return out


def get_active_connections(limit: int = 200) -> List[Dict[str, Any]]:
    rows = []
    try:
        for c in psutil.net_connections(kind="inet")[:limit]:
            rows.append({
                "status": c.status,
                "local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                "remote": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                "pid": c.pid,
            })
    except Exception as e:
        rows.append({"error": repr(e)})
    return rows


def get_neighbor_table(include_ipv6: bool = False) -> Dict[str, Any]:
    out: Dict[str, Any] = {"neighbors": [], "raw": []}
    if is_linux() and which("ip"):
        raw4 = safe_run(["ip", "neigh", "show"], timeout=8)
        out["raw"].append(raw4)
        for line in (raw4.get("stdout") or "").splitlines():
            m = re.search(
                r"^(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)"
                r"\s+(?:lladdr\s+([0-9a-f:]{17})\s+)?(\S+)",
                line.strip(), re.I)
            if m:
                out["neighbors"].append({
                    "ip": m.group(1), "version": 4, "interface": m.group(2),
                    "mac": m.group(3).lower() if m.group(3) else None,
                    "state": m.group(4)})
    else:
        raw4 = safe_run(["arp", "-a"], timeout=8)
        out["raw"].append(raw4)
        for line in (raw4.get("stdout") or "").splitlines():
            line = line.strip()
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]{17})\s+(\S+)",
                          line, re.I)
            if m:
                out["neighbors"].append({
                    "ip": m.group(1), "version": 4,
                    "mac": m.group(2).lower().replace("-", ":"),
                    "state": m.group(3), "interface": None})
                continue
            m2 = re.search(
                r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{17}|<incomplete>)\s+on\s+(\S+)",
                line, re.I)
            if m2:
                out["neighbors"].append({
                    "ip": m2.group(1), "version": 4,
                    "mac": None if m2.group(2) == "<incomplete>" else m2.group(2).lower(),
                    "state": None, "interface": m2.group(3)})

    if include_ipv6:
        if is_linux() and which("ip"):
            raw6 = safe_run(["ip", "-6", "neigh", "show"], timeout=8)
            out["raw"].append(raw6)
            for line in (raw6.get("stdout") or "").splitlines():
                m = re.search(
                    r"^([0-9a-f:]+)\s+dev\s+(\S+)"
                    r"\s+(?:lladdr\s+([0-9a-f:]{17})\s+)?(\S+)",
                    line.strip(), re.I)
                if m and ":" in m.group(1):
                    out["neighbors"].append({
                        "ip": m.group(1), "version": 6, "interface": m.group(2),
                        "mac": m.group(3).lower() if m.group(3) else None,
                        "state": m.group(4)})
        elif is_windows():
            raw6 = safe_run(["netsh", "interface", "ipv6", "show", "neighbors"],
                            timeout=10)
            out["raw"].append(raw6)
            for line in (raw6.get("stdout") or "").splitlines():
                m = re.search(r"([0-9a-f:]{4,})\s+([0-9a-f-]{17}|)\s+(\S+)",
                              line.strip(), re.I)
                if m and ":" in m.group(1) and len(m.group(1)) > 6:
                    mac = m.group(2).lower().replace("-", ":") if m.group(2) else None
                    out["neighbors"].append({
                        "ip": m.group(1), "version": 6, "mac": mac,
                        "state": m.group(3), "interface": None})
        elif is_macos() and which("ndp"):
            raw6 = safe_run(["ndp", "-a"], timeout=8)
            out["raw"].append(raw6)
            for line in (raw6.get("stdout") or "").splitlines():
                m = re.search(
                    r"([0-9a-f:]+%?\S*)\s+([0-9a-f:]{17}|<incomplete>)\s+(\S+)",
                    line.strip(), re.I)
                if m and ":" in m.group(1):
                    mac_raw = m.group(2)
                    out["neighbors"].append({
                        "ip": m.group(1).split("%")[0], "version": 6,
                        "mac": None if mac_raw == "<incomplete>" else mac_raw.lower(),
                        "state": m.group(3), "interface": None})
    return out


def build_neighbor_maps(nb: Dict[str, Any]) -> Tuple[Dict[str, str], Dict[str, str]]:
    ip_mac: Dict[str, str] = {}
    ip_state: Dict[str, str] = {}
    for n in nb.get("neighbors", []):
        ip = n.get("ip")
        if ip:
            if n.get("mac"): ip_mac[ip] = n["mac"]
            ip_state[ip] = (n.get("state") or "").upper()
    return ip_mac, ip_state


# ══════════════════════════════════════════════════════════════════════════════
# Smart subnet selection
# ══════════════════════════════════════════════════════════════════════════════

_VIRTUAL_RE = re.compile(
    r"(hyper.?v|vethernet|vmnet|vmware|docker|virbr|br-|vboxnet"
    r"|tun|tap|wsl|tailscale|utun|awdl|llw|bridge|dummy|lo$)",
    re.I)


def is_virtual_interface(name: str) -> bool:
    return bool(_VIRTUAL_RE.search(name))


def get_local_ipv4_networks(default_iface: Optional[str] = None,
                             exclude_virtual: bool = True) -> List[Dict[str, Any]]:
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    nets = []
    for ifname, addr_list in addrs.items():
        if exclude_virtual and is_virtual_interface(ifname): continue
        st = stats.get(ifname)
        isup = getattr(st, "isup", False)
        for a in addr_list:
            if str(a.family) not in ("AddressFamily.AF_INET", "2"): continue
            ip, mask = a.address, a.netmask
            if not ip or not mask: continue
            try:
                prefix = sum(bin(int(o)).count("1") for o in mask.split("."))
                cidr = f"{ip}/{prefix}"
                net = ipaddress.ip_network(cidr, strict=False)
                if net.is_loopback or net.is_link_local or net.prefixlen >= 32:
                    continue
                nets.append({
                    "interface": ifname, "ip": ip, "netmask": mask,
                    "cidr": str(net), "num_addresses": net.num_addresses,
                    "is_default_iface": (ifname == default_iface), "isup": isup,
                })
            except Exception:
                pass
    seen: Set[str] = set()
    unique = []
    for n in nets:
        if n["cidr"] not in seen:
            seen.add(n["cidr"])
            unique.append(n)
    unique.sort(key=lambda n: (
        0 if n["is_default_iface"] else 1,
        0 if n["isup"] else 1,
        n["num_addresses"]))
    return unique


def connectivity_checks(gw: Optional[str]) -> Dict[str, Any]:
    targets = []
    if gw: targets.append(("default_gateway", gw))
    targets += [("google_dns", "8.8.8.8"), ("cloudflare_dns", "1.1.1.1")]
    results: Dict[str, Any] = {"ping": [], "http": []}
    for name, ip in targets:
        alive, ttl = ping_with_ttl(ip, timeout_s=1)
        results["ping"].append({"target": name, "ip": ip,
                                "reachable": alive, "ttl": ttl})
    for name, url in [("https_google", "https://www.google.com/generate_204"),
                      ("https_cloudflare", "https://1.1.1.1/cdn-cgi/trace")]:
        try:
            r = requests.get(url, timeout=5, headers={"User-Agent": f"OmniRecon/{__version__}"})
            results["http"].append({"target": name, "url": url,
                                    "status_code": r.status_code,
                                    "ok": 200 <= r.status_code < 400})
        except Exception as e:
            results["http"].append({"target": name, "url": url,
                                    "error": repr(e), "ok": False})
    return results


# ══════════════════════════════════════════════════════════════════════════════
# ARP priming
# ══════════════════════════════════════════════════════════════════════════════

def arp_prime_subnet(cidr: str, max_hosts: int, workers: int,
                     progress: bool = True) -> None:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return
    hosts = list(itertools.islice(net.hosts(), max_hosts))
    prog = ProgressETA(total=len(hosts), label=f"ARP prime {cidr}", enabled=progress)

    def _poke(ip: str) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(0.05)
                s.sendto(b"", (ip, 9))
        except Exception:
            pass
        prog.incr(1)

    with cf.ThreadPoolExecutor(max_workers=min(workers, 256)) as ex:
        list(ex.map(_poke, (str(h) for h in hosts)))
    prog.finish()
    time.sleep(1.0)


# ══════════════════════════════════════════════════════════════════════════════
# Async liveness engine
# ══════════════════════════════════════════════════════════════════════════════

async def _async_tcp_connect(ip: str, port: int, timeout: float) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout)
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass
        return True
    except Exception:
        return False


_ARP_ALIVE_STATES = frozenset({
    "REACHABLE", "STALE", "DELAY", "PROBE",
    "PERMANENT", "DYNAMIC", "STATIC"
})


async def _check_one(ip: str,
                     mode: str,
                     tcp_ports: List[int],
                     ip_state: Dict[str, str],
                     enable_udp: bool,
                     enable_ttl: bool,
                     sem: asyncio.Semaphore,
                     alive_set: Set[str],
                     ttl_map: Dict[str, Optional[int]],
                     prog: ProgressETA,
                     last_render: List[float]) -> None:
    async with sem:
        alive = False
        ttl: Optional[int] = None

        # ARP/NDP is always a free liveness signal
        if ip_state.get(ip, "").upper() in _ARP_ALIVE_STATES:
            alive = True

        if not alive:
            if mode == "arp":
                pass
            elif mode == "icmp":
                loop = asyncio.get_running_loop()
                alive, ttl = await loop.run_in_executor(
                    None, ping_with_ttl, ip, 1)
            elif mode == "udp":
                loop = asyncio.get_running_loop()
                alive = await loop.run_in_executor(
                    None, udp_probe_alive, ip, 33434, 0.8)
                if not alive:
                    alive = await loop.run_in_executor(None, ping_one, ip, 1)
            elif mode == "combined":
                loop = asyncio.get_running_loop()
                # Run TCP, ICMP, UDP concurrently
                tcp_tasks = [asyncio.create_task(
                    _async_tcp_connect(ip, p, 0.4)) for p in tcp_ports]
                icmp_fut = loop.run_in_executor(None, ping_with_ttl, ip, 1)
                udp_fut  = loop.run_in_executor(
                    None, udp_probe_alive, ip, 33434, 0.6)
                tcp_results = await asyncio.gather(*tcp_tasks,
                                                    return_exceptions=True)
                icmp_alive, ttl = await icmp_fut
                udp_alive = await udp_fut
                alive = (any(r is True for r in tcp_results) or
                         icmp_alive or udp_alive)
            else:
                # tcp (default)
                tasks = [asyncio.create_task(
                    _async_tcp_connect(ip, p, 0.35)) for p in tcp_ports]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                alive = any(r is True for r in results)
                # near-miss retry
                if not alive and ip in ip_state:
                    tasks2 = [asyncio.create_task(
                        _async_tcp_connect(ip, p, 0.8)) for p in tcp_ports]
                    r2 = await asyncio.gather(*tasks2, return_exceptions=True)
                    alive = any(r is True for r in r2)

        if alive:
            alive_set.add(ip)
            if enable_ttl and ttl is not None:
                ttl_map[ip] = ttl

        prog.incr(1)
        now = time.perf_counter()
        if now - last_render[0] >= 0.12:
            prog.render(extra=f"alive={len(alive_set)}")
            last_render[0] = now


def run_liveness_sweep(host_strs: List[str],
                       mode: str,
                       tcp_ports: List[int],
                       ip_state: Dict[str, str],
                       max_concurrent: int,
                       label: str,
                       enable_udp: bool,
                       enable_ttl: bool,
                       progress_enabled: bool,
                       scan_delay_ms: float = 0.0,
                       randomize: bool = False) -> Tuple[Set[str], Dict[str, Optional[int]]]:
    alive_set: Set[str] = set()
    ttl_map: Dict[str, Optional[int]] = {}

    hosts_to_scan = list(host_strs)
    if randomize:
        import random
        random.shuffle(hosts_to_scan)

    prog = ProgressETA(total=len(hosts_to_scan), label=label, enabled=progress_enabled)
    last_render = [time.perf_counter()]

    async def _run():
        sem = asyncio.Semaphore(max_concurrent)
        delay = scan_delay_ms / 1000.0

        async def _check_with_delay(ip: str) -> None:
            if delay > 0:
                await asyncio.sleep(delay)
            await _check_one(ip, mode, tcp_ports, ip_state, enable_udp,
                             enable_ttl, sem, alive_set, ttl_map, prog, last_render)

        await asyncio.gather(*[_check_with_delay(ip) for ip in hosts_to_scan])

    asyncio.run(_run())
    prog.finish(extra=f"alive={len(alive_set)}")
    return alive_set, ttl_map


# ══════════════════════════════════════════════════════════════════════════════
# Async port scanner
# ══════════════════════════════════════════════════════════════════════════════

async def _async_port_scan_all(hosts: List[Dict[str, Any]],
                                ports: List[int],
                                timeout: float,
                                semaphore: asyncio.Semaphore,
                                prog: ProgressETA,
                                last_render: List[float]) -> Dict[str, List[int]]:
    results: Dict[str, List[int]] = {}

    async def scan_one(h: Dict[str, Any]) -> None:
        async with semaphore:
            ip = h["ip"]
            # Smart port ordering: try high-yield ports first
            open_ports = []
            tasks = {p: asyncio.create_task(
                _async_tcp_connect(ip, p, timeout)) for p in ports}
            r = await asyncio.gather(*tasks.values(), return_exceptions=True)
            open_ports = [p for p, ok in zip(tasks.keys(), r) if ok is True]
            results[ip] = sorted(open_ports)
            prog.incr(1)
            now = time.perf_counter()
            if now - last_render[0] >= 0.12:
                prog.render()
                last_render[0] = now

    await asyncio.gather(*[scan_one(h) for h in hosts])
    return results


def port_probe_hosts(hosts: List[Dict[str, Any]],
                     ports: List[int],
                     max_concurrent: int,
                     include_service_hints: bool = False,
                     progress: bool = True) -> List[Dict[str, Any]]:
    prog = ProgressETA(total=len(hosts), label="Port probe", enabled=progress)
    last_render = [time.perf_counter()]
    port_results: Dict[str, List[int]] = {}

    async def _run():
        sem = asyncio.Semaphore(max_concurrent)
        port_results.update(
            await _async_port_scan_all(hosts, ports, timeout=0.6,
                                       semaphore=sem, prog=prog,
                                       last_render=last_render))

    asyncio.run(_run())
    prog.finish()

    enriched = []
    for h in hosts:
        hh = dict(h)
        hh["open_ports"] = port_results.get(h["ip"], [])
        if include_service_hints and hh["open_ports"]:
            hh["service_hints"] = service_hints(h["ip"], hh["open_ports"])
        enriched.append(hh)
    return enriched


# ══════════════════════════════════════════════════════════════════════════════
# Host enrichment
# ══════════════════════════════════════════════════════════════════════════════

def _enrich_one(ip: str,
                ip_mac: Dict[str, str],
                oui_map: Dict[str, str],
                zeroconf_map: Dict[str, Dict[str, Any]],
                snmp_communities: Optional[List[str]],
                enrich_timeout: float) -> Dict[str, Any]:
    mac = ip_mac.get(ip)
    oui = mac_to_oui(mac)
    vendor = oui_map.get(oui) if oui else None
    dtype, dicon = guess_device_type(vendor)

    rdns = resolve_reverse(ip, timeout=min(enrich_timeout, 1.5))

    nb: Optional[str] = None
    md: Optional[str] = None
    snmp_data: Optional[Dict[str, str]] = None

    with cf.ThreadPoolExecutor(max_workers=3) as ex:
        nb_fut = ex.submit(netbios_name, ip, min(enrich_timeout, 3.0))
        md_fut = ex.submit(mdns_name_system, ip, min(enrich_timeout, 2.0))
        snmp_fut = (ex.submit(snmp_probe, ip, snmp_communities, min(enrich_timeout, 1.5))
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
    zc_svc   = zc.get("services", []) or []

    snmp_name = (snmp_data or {}).get("sysName")
    device_name = (
        (nb or "").strip() or
        (snmp_name or "").strip() or
        (md or "").strip() or
        (rdns or "").strip() or
        (zc_names[0].strip() if zc_names else "")
    ) or None

    return {
        "ip": ip, "is_self": False,
        "device_name": device_name,
        "device_type": dtype,
        "device_icon": dicon,
        "reverse_dns": rdns,
        "netbios": nb, "mdns": md,
        "zeroconf_names": zc_names,
        "zeroconf_services": zc_svc,
        "mac": mac, "oui": oui, "vendor": vendor,
        "snmp": snmp_data,
        "passive_protocols": [],
        "passive_services": [],
    }


def build_self_hosts(local_nets: List[Dict[str, Any]],
                     ip_mac: Dict[str, str],
                     oui_map: Dict[str, str]) -> List[Dict[str, Any]]:
    seen: Set[str] = set()
    selfs = []
    hostname = socket.gethostname()
    for n in local_nets:
        ip = n["ip"]
        if ip in seen: continue
        seen.add(ip)
        mac = ip_mac.get(ip)
        oui = mac_to_oui(mac)
        vendor = oui_map.get(oui) if oui else None
        dtype, dicon = guess_device_type(vendor)
        selfs.append({
            "ip": ip, "is_self": True,
            "device_name": hostname, "device_type": dtype, "device_icon": dicon,
            "reverse_dns": resolve_reverse(ip),
            "netbios": None, "mdns": None,
            "zeroconf_names": [], "zeroconf_services": [],
            "mac": mac, "oui": oui, "vendor": vendor,
            "snmp": None, "interface": n["interface"],
            "passive_protocols": [], "passive_services": [],
        })
    return selfs


# ══════════════════════════════════════════════════════════════════════════════
# Full discovery orchestrator
# ══════════════════════════════════════════════════════════════════════════════

def discover_hosts(
        subnets: List[str],
        max_hosts_per_subnet: int,
        liveness_workers: int,
        enrich_workers: int,
        ip_mac: Optional[Dict[str, str]] = None,
        ip_state: Optional[Dict[str, str]] = None,
        oui_map: Optional[Dict[str, str]] = None,
        zeroconf_map: Optional[Dict[str, Dict[str, Any]]] = None,
        self_hosts: Optional[List[Dict[str, Any]]] = None,
        allow_non_private: bool = False,
        discovery_mode: str = "auto",
        tcp_alive_ports: Optional[List[int]] = None,
        enable_udp_probe: bool = False,
        enable_ttl_os: bool = False,
        snmp_communities: Optional[List[str]] = None,
        enrich_timeout: float = 5.0,
        progress: bool = True,
        scan_delay_ms: float = 0.0,
        randomize_scan: bool = False,
) -> Tuple[List[Dict[str, Any]], Dict[str, Optional[int]]]:
    """Returns (hosts, ttl_map)."""
    ip_mac   = ip_mac   or {}
    ip_state = ip_state or {}
    oui_map  = oui_map  or {}
    zeroconf_map = zeroconf_map or {}
    self_ips: Set[str] = {h["ip"] for h in (self_hosts or [])}
    tcp_alive_ports = tcp_alive_ports or [
        445, 3389, 135, 139, 5985, 22, 80, 443, 631, 9100,
        8080, 8443, 23, 53, 21, 25, 110, 143, 8006, 5900]

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
            str(h) for h in itertools.islice(net.hosts(), max_hosts_per_subnet)
            if str(h) not in self_ips and
            (allow_non_private or is_private_or_lan_ip(str(h)))
        ]
        alive, ttl_map = run_liveness_sweep(
            host_strs=host_strs,
            mode=eff_mode,
            tcp_ports=tcp_alive_ports,
            ip_state=ip_state,
            max_concurrent=liveness_workers,
            label=f"Liveness {cidr}",
            enable_udp=enable_udp_probe,
            enable_ttl=enable_ttl_os,
            progress_enabled=progress,
            scan_delay_ms=scan_delay_ms,
            randomize=randomize_scan,
        )
        all_alive.update(alive)
        all_ttl.update(ttl_map)

    unique_alive = sorted(all_alive)
    enriched: List[Dict[str, Any]] = []

    if unique_alive:
        prog2 = ProgressETA(total=len(unique_alive), label="Enrichment",
                            enabled=progress)
        last_render = [time.perf_counter()]

        def enrich_track(ip: str) -> Dict[str, Any]:
            r = _enrich_one(ip, ip_mac, oui_map, zeroconf_map,
                             snmp_communities, enrich_timeout)
            prog2.incr(1)
            if time.perf_counter() - last_render[0] >= 0.15:
                prog2.render()
                last_render[0] = time.perf_counter()
            return r

        with cf.ThreadPoolExecutor(max_workers=enrich_workers) as ex:
            enriched = list(ex.map(enrich_track, unique_alive))
        prog2.finish()

    all_hosts: List[Dict[str, Any]] = []
    all_ips: Set[str] = set()
    for h in (self_hosts or []):
        if h["ip"] not in all_ips:
            all_ips.add(h["ip"]); all_hosts.append(h)
    for h in enriched:
        if h["ip"] not in all_ips:
            all_ips.add(h["ip"]); all_hosts.append(h)

    return (sorted(all_hosts, key=lambda h: _ip_sort_key_str(h["ip"])),
            all_ttl)


# ══════════════════════════════════════════════════════════════════════════════
# Diff / change detection
# ══════════════════════════════════════════════════════════════════════════════

def find_latest_report(outdir: str, current_stamp: str) -> Optional[str]:
    try:
        files = sorted([
            f for f in os.listdir(outdir)
            if f.startswith("network_report_") and f.endswith(".json")
            and f != f"network_report_{current_stamp}.json"
        ], reverse=True)
        return os.path.join(outdir, files[0]) if files else None
    except Exception:
        return None


def compute_diff(current_hosts: List[Dict[str, Any]],
                 prev_path: str) -> Dict[str, Any]:
    diff: Dict[str, Any] = {
        "previous_report": prev_path,
        "new_ips": [], "gone_ips": [], "changed_ports": {},
        "compared_at": dt.datetime.now().isoformat(),
    }
    try:
        with open(prev_path, "r", encoding="utf-8") as f:
            prev = json.load(f)
        prev_hosts = prev.get("discovery", {}).get("hosts", [])
        if not prev_hosts:
            diff["note"] = "Previous report has no discovery data."
            return diff
        prev_map = {h["ip"]: h for h in prev_hosts}
        curr_map = {h["ip"]: h for h in current_hosts}
        diff["new_ips"]  = [ip for ip in curr_map if ip not in prev_map]
        diff["gone_ips"] = [ip for ip in prev_map if ip not in curr_map]
        for ip in curr_map:
            if ip not in prev_map: continue
            cp = set(curr_map[ip].get("open_ports") or [])
            pp = set(prev_map[ip].get("open_ports") or [])
            if cp != pp:
                diff["changed_ports"][ip] = {
                    "old": sorted(pp), "new": sorted(cp),
                    "added": sorted(cp - pp), "removed": sorted(pp - cp),
                }
    except Exception as e:
        diff["error"] = repr(e)
    return diff


# ══════════════════════════════════════════════════════════════════════════════
# Console summary
# ══════════════════════════════════════════════════════════════════════════════

def print_discovery_console(hosts: List[Dict[str, Any]],
                            diff: Optional[Dict[str, Any]] = None,
                            ttl_map: Optional[Dict[str, Optional[int]]] = None,
                            show_hints: bool = False) -> None:
    if not hosts:
        print("\n  No hosts found.\n"); return
    new_ips  = set((diff or {}).get("new_ips", []))
    gone_ips = set((diff or {}).get("gone_ips", []))
    changed  = (diff or {}).get("changed_ports", {})
    ttl_map  = ttl_map or {}

    total = len(hosts)
    active_hosts = [h for h in hosts if not h.get("passive_only")]
    passive_hosts = [h for h in hosts if h.get("passive_only")]

    print(f"\n  ┌─ Discovered Hosts ({total} total | "
          f"{len(active_hosts)} active | {len(passive_hosts)} passive-only) "
          f"{'─'*20}")

    col_ip    = 17
    col_t     = 3
    col_name  = 26
    col_os    = 24
    col_mac   = 19
    col_vend  = 21

    hdr = (f"  │ {'IP':<{col_ip}} {'T':<{col_t}} {'Name':<{col_name}} "
           f"{'OS Hint':<{col_os}} {'MAC':<{col_mac}} {'Vendor':<{col_vend}} Ports")
    sep = "  │ " + "─" * (len(hdr) - 6)
    print(hdr)
    print(sep)

    for h in hosts:
        ip   = h.get("ip", "")
        icon = h.get("device_icon", "")
        flags = ""
        if h.get("is_self"):      flags += " [YOU]"
        if ip in new_ips:         flags += " [NEW]"
        if ip in changed:         flags += " [CHG]"
        if h.get("passive_only"): flags += " [PSV]"

        name = ((h.get("device_name") or "") + flags)[:col_name]
        ttl  = ttl_map.get(ip)
        os_hint = guess_os_from_ttl(ttl)[:col_os - 1] if ttl else ""
        mac  = (h.get("mac") or "")[:col_mac - 1]
        vend = (h.get("vendor") or "")[:col_vend - 1]
        ports = ",".join(map(str, h.get("open_ports", [])))[:28]
        print(f"  │ {ip:<{col_ip}} {icon:<{col_t}} {name:<{col_name}} "
              f"{os_hint:<{col_os}} {mac:<{col_mac}} {vend:<{col_vend}} {ports}")

    print(f"  └{'─'*(len(hdr)-4)}")

    if gone_ips:
        print(f"\n  ⚠  Gone since last scan: {', '.join(sorted(gone_ips))}")
    if diff and diff.get("previous_report"):
        prev = os.path.basename(diff["previous_report"])
        print(f"\n  Diff vs {prev}:")
        print(f"    ✚ New: {len(new_ips)}  ✖ Gone: {len(gone_ips)}"
              f"  ↕ Port changes: {len(changed)}")
    print()


# ══════════════════════════════════════════════════════════════════════════════
# HTML REPORT  v5 — topology + history + CVE + passive + OS hints
# ══════════════════════════════════════════════════════════════════════════════

_CSS = """
:root{
  --bg:#f0f4f8;--card:#fff;--border:#dde3ec;
  --accent:#3b82f6;--green:#10b981;--amber:#f59e0b;--red:#ef4444;
  --purple:#8b5cf6;--text:#1e293b;--muted:#64748b;
  --row-new:#f0fdf4;--row-gone:#fef2f2;--row-chg:#fffbeb;--row-self:#eff6ff;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,
  Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);
  font-size:14px;line-height:1.55;padding:0}
.page{max-width:1400px;margin:0 auto;padding:24px 28px}
h1{font-size:1.65rem;font-weight:800;letter-spacing:-.02em}
h2{font-size:1.05rem;font-weight:700;margin-bottom:12px}
.subtitle{color:var(--muted);font-size:0.85rem;margin-top:3px}
.topbar{background:linear-gradient(135deg,#1e3a5f 0%,#2563eb 100%);
  color:#fff;padding:20px 28px 18px;margin-bottom:24px}
.topbar h1{color:#fff}
.topbar .subtitle{color:#93c5fd}
.topbar-row{display:flex;justify-content:space-between;align-items:flex-start;
  flex-wrap:wrap;gap:12px}
.badge{background:rgba(255,255,255,.18);border:1px solid rgba(255,255,255,.35);
  color:#fff;border-radius:20px;padding:3px 12px;font-size:0.78rem;
  font-weight:600;white-space:nowrap;backdrop-filter:blur(4px)}
.badge.green{background:rgba(16,185,129,.25);border-color:rgba(16,185,129,.5)}
.warn-box{background:#fef9c3;border:1px solid #fde047;border-radius:8px;
  padding:10px 14px;margin-bottom:14px;font-size:0.85rem;color:#713f12}

/* Tabs */
.tabs{display:flex;gap:0;border-bottom:2px solid var(--border);
  margin-bottom:20px;flex-wrap:wrap}
.tab{padding:9px 18px;cursor:pointer;font-weight:600;font-size:0.85rem;
  color:var(--muted);border-bottom:3px solid transparent;margin-bottom:-2px;
  transition:color .15s,border-color .15s}
.tab:hover{color:var(--text)}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab-content{display:none}.tab-content.active{display:block}

/* Stats */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));
  gap:12px;margin-bottom:22px}
.stat-card{background:var(--card);border:1px solid var(--border);
  border-radius:12px;padding:14px 12px;text-align:center;
  box-shadow:0 1px 3px rgba(0,0,0,.05)}
.stat-card .val{font-size:1.85rem;font-weight:800;color:var(--accent);
  line-height:1.1}
.stat-card .lbl{font-size:0.74rem;color:var(--muted);margin-top:3px;
  font-weight:500}
.stat-card.green .val{color:var(--green)}
.stat-card.amber .val{color:var(--amber)}
.stat-card.red   .val{color:var(--red)}
.stat-card.purple .val{color:var(--purple)}

/* Section cards */
.section{background:var(--card);border:1px solid var(--border);
  border-radius:12px;padding:18px 22px;margin-bottom:18px;
  box-shadow:0 1px 3px rgba(0,0,0,.04)}

/* Host table */
.tbl-wrap{overflow-x:auto}
.host-table{width:100%;border-collapse:collapse;min-width:800px;font-size:0.84rem}
.host-table th{background:#f1f5f9;color:var(--muted);font-weight:700;
  font-size:0.73rem;text-transform:uppercase;letter-spacing:.05em;
  padding:7px 10px;border-bottom:2px solid var(--border);
  text-align:left;white-space:nowrap;position:sticky;top:0;z-index:1}
.host-table td{padding:8px 10px;border-bottom:1px solid #f1f5f9;
  vertical-align:middle}
.host-table tr:hover td{background:#f8fafc}
.row-self td{background:var(--row-self);border-left:3px solid #93c5fd}
.row-new  td{background:var(--row-new) ;border-left:3px solid var(--green)}
.row-gone td{background:var(--row-gone);border-left:3px solid var(--red);
  opacity:.8}
.row-chg  td{background:var(--row-chg) ;border-left:3px solid var(--amber)}
.row-passive td{border-left:3px solid var(--purple)}

.ip-cell{font-family:ui-monospace,monospace;font-weight:700;
  color:var(--accent);font-size:0.88rem}
.mac-cell{font-family:ui-monospace,monospace;font-size:0.78rem;color:var(--muted)}
.port-chip{display:inline-block;background:#e0f2fe;color:#0369a1;
  border-radius:4px;padding:1px 5px;font-size:0.74rem;
  font-family:ui-monospace,monospace;margin:1px 2px 1px 0}
.port-chip.added{background:#dcfce7;color:#166534}
.port-chip.removed{background:#fee2e2;color:#991b1b;
  text-decoration:line-through}
.you-badge{background:var(--accent);color:#fff;border-radius:4px;
  padding:0 5px;font-size:0.7rem;font-weight:700;vertical-align:middle;
  margin-left:4px}
.new-badge{background:var(--green);color:#fff;border-radius:4px;
  padding:0 5px;font-size:0.7rem;font-weight:700;vertical-align:middle;
  margin-left:4px}
.psv-badge{background:var(--purple);color:#fff;border-radius:4px;
  padding:0 5px;font-size:0.7rem;font-weight:700;vertical-align:middle;
  margin-left:4px}
.cve-chip{display:inline-block;border-radius:4px;padding:1px 6px;
  font-size:0.72rem;font-weight:700;margin:1px 2px 1px 0;cursor:default}
.cve-critical{background:#fef2f2;color:#991b1b;border:1px solid #fca5a5}
.cve-high    {background:#fff7ed;color:#c2410c;border:1px solid #fdba74}
.cve-medium  {background:#fefce8;color:#854d0e;border:1px solid #fde047}
.cve-low     {background:#f0fdf4;color:#166534;border:1px solid #86efac}
.cve-none    {background:#f8fafc;color:var(--muted);border:1px solid var(--border)}

/* History bar */
.hist-bar-wrap{width:60px;height:10px;background:#e2e8f0;border-radius:5px;
  display:inline-block;vertical-align:middle;overflow:hidden}
.hist-bar{height:100%;background:var(--accent);border-radius:5px;
  transition:width .3s}

/* Hint row */
.hint-row td{background:#fafafa;font-size:0.80rem;color:var(--muted);
  padding:3px 10px 7px 26px;border-bottom:1px solid #f1f5f9}
.hint-row code{background:#f1f5f9;padding:1px 4px;border-radius:3px;
  font-family:ui-monospace,monospace;font-size:0.78rem}

/* Info table */
.info-table{width:100%;border-collapse:collapse}
.info-table tr:nth-child(even) td{background:#f8fafc}
.info-table td{padding:6px 10px;border-bottom:1px solid #f1f5f9}
.info-table td:first-child{font-weight:600;color:var(--muted);
  font-size:0.8rem;width:200px;white-space:nowrap}

/* Connectivity */
.conn-ok  {color:var(--green);font-weight:700}
.conn-fail{color:var(--red)  ;font-weight:700}

/* Topology */
#topology-container{width:100%;height:520px;border:1px solid var(--border);
  border-radius:8px;background:#f8fafc;overflow:hidden}

/* SSDP / passive table */
.small-table{width:100%;border-collapse:collapse;font-size:0.82rem}
.small-table th{background:#f1f5f9;padding:6px 10px;text-align:left;
  font-weight:600;color:var(--muted);font-size:0.74rem;text-transform:uppercase;
  letter-spacing:.05em}
.small-table td{padding:6px 10px;border-bottom:1px solid #f1f5f9}

/* Diff legend */
.diff-legend{display:flex;gap:16px;margin-bottom:12px;
  font-size:0.81rem;flex-wrap:wrap}
.dl-item{display:flex;align-items:center;gap:6px}
.dl-swatch{width:14px;height:14px;border-radius:3px;display:inline-block}

/* Buttons */
.btn{background:var(--accent);color:#fff;border:none;border-radius:6px;
  padding:7px 14px;cursor:pointer;font-size:0.82rem;font-weight:600;
  transition:background .15s}
.btn:hover{background:#2563eb}
.btn-row{display:flex;justify-content:flex-end;gap:8px;margin-bottom:10px}

/* Collapsible raw */
details{margin-top:10px}
details>summary{cursor:pointer;font-weight:600;color:var(--muted);
  font-size:0.83rem;user-select:none;padding:7px 12px;background:#f1f5f9;
  border:1px solid var(--border);border-radius:6px}
details[open]>summary{border-radius:6px 6px 0 0}
details pre{background:#1e293b;color:#e2e8f0;padding:14px;overflow:auto;
  font-size:0.78rem;line-height:1.5;border-radius:0 0 6px 6px;
  border:1px solid var(--border);border-top:none;max-height:380px}
.empty{color:var(--muted);font-style:italic;padding:10px 0}
.icon-cell{font-size:1.1rem;text-align:center;width:32px}
"""

_JS = """
// Tab switching
function switchTab(id) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.getElementById('tab-' + id).classList.add('active');
  document.getElementById('content-' + id).classList.add('active');
}

// CSV export
function exportCSV() {
  const tbl = document.getElementById('host-table');
  if (!tbl) return;
  const rows = [];
  const hdrs = [];
  tbl.querySelectorAll('thead th').forEach(th =>
    hdrs.push('"' + th.innerText.replace(/"/g,'""') + '"'));
  rows.push(hdrs.join(','));
  tbl.querySelectorAll('tbody tr.data-row').forEach(tr => {
    const cols = [];
    tr.querySelectorAll('td').forEach(td =>
      cols.push('"' + (td.dataset.val || td.innerText).replace(/"/g,'""') + '"'));
    rows.push(cols.join(','));
  });
  const blob = new Blob([rows.join('\\n')], {type:'text/csv'});
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
  a.download = 'network_hosts.csv'; a.click();
}

// Table search/filter
function filterTable(q) {
  q = q.toLowerCase();
  document.querySelectorAll('#host-table tbody tr').forEach(tr => {
    tr.style.display = (!q || tr.innerText.toLowerCase().includes(q)) ? '' : 'none';
  });
}
"""


def _stat_card(val: str, lbl: str, cls: str = "") -> str:
    return (f'<div class="stat-card {cls}">'
            f'<div class="val">{html_escape(val)}</div>'
            f'<div class="lbl">{html_escape(lbl)}</div></div>')


def _port_chips_html(open_ports: List[int],
                     added: Optional[List[int]] = None,
                     removed: Optional[List[int]] = None) -> str:
    added   = set(added   or [])
    removed = set(removed or [])
    all_p   = sorted(set(open_ports or []) | removed)
    if not all_p: return '<span style="color:#94a3b8">—</span>'
    chips = []
    for p in all_p:
        if p in removed:
            chips.append(f'<span class="port-chip removed">{p}</span>')
        elif p in added:
            chips.append(f'<span class="port-chip added">{p}</span>')
        else:
            chips.append(f'<span class="port-chip">{p}</span>')
    return "".join(chips)


def _cve_chips(cves: List[Dict[str, Any]]) -> str:
    if not cves: return '<span style="color:#94a3b8">—</span>'
    chips = []
    for cve in cves[:5]:
        cid   = html_escape(cve.get("id", "?"))
        score = cve.get("score")
        sev   = (cve.get("severity") or "").upper()
        desc  = html_escape(cve.get("description", "")[:120])
        impact_icon = cve.get("impact_icon", "")
        is_kev = cve.get("kev", False)
        css = ("cve-critical" if sev == "CRITICAL" else
               "cve-high"     if sev == "HIGH"     else
               "cve-medium"   if sev == "MEDIUM"   else
               "cve-low"      if sev == "LOW"       else "cve-none")
        score_str = f" {score}" if score else ""
        kev_badge = (' <span style="background:#dc2626;color:#fff;border-radius:3px;'
                     'padding:0 3px;font-size:0.65rem;font-weight:900">KEV</span>'
                     if is_kev else "")
        chips.append(f'<span class="cve-chip {css}" title="{desc}">'
                     f'{impact_icon} {cid}{score_str}{kev_badge}</span>')
    if len(cves) > 5:
        chips.append(f'<span class="cve-none cve-chip">+{len(cves)-5} more</span>')
    return "".join(chips)


def _history_bar(ip: str, history: Dict[str, Any]) -> str:
    rec = history.get("per_ip", {}).get(ip, {})
    freq = rec.get("frequency", 0)
    seen = rec.get("seen_count", 0)
    total = history.get("total_runs", 0)
    if total == 0: return '<span style="color:#94a3b8;font-size:.78rem">—</span>'
    pct = int(freq * 100)
    tip = (f"Seen {seen}/{total} scans | "
           f"First: {_short_ts(rec.get('first_seen',''))} | "
           f"Last: {_short_ts(rec.get('last_seen',''))}")
    bar = int(freq * 60)
    return (f'<span title="{html_escape(tip)}" style="white-space:nowrap">'
            f'<span class="hist-bar-wrap">'
            f'<span class="hist-bar" style="width:{bar}px"></span>'
            f'</span> <span style="font-size:.75rem;color:var(--muted)">'
            f'{pct}%</span></span>')


def _build_topology_js(hosts: List[Dict[str, Any]],
                       gateway_ip: Optional[str],
                       self_ips: Set[str]) -> str:
    """Build vis.js nodes + edges JSON for the topology tab."""
    nodes = []
    edges = []
    added_ips: Set[str] = set()

    # Gateway node
    if gateway_ip:
        nodes.append({
            "id": "gw",
            "label": f"Gateway\n{gateway_ip}",
            "shape": "star",
            "color": {"background": "#fbbf24", "border": "#d97706"},
            "font": {"size": 12, "color": "#1e293b"},
            "size": 28,
        })
        added_ips.add(gateway_ip)

    color_map = {
        "Apple Device":    "#3b82f6",
        "PC / Laptop":     "#6366f1",
        "Network / NAS":   "#10b981",
        "Printer":         "#f59e0b",
        "Mobile Device":   "#ec4899",
        "IoT / Smart":     "#8b5cf6",
        "Virtual Machine": "#64748b",
        "UPS / Power":     "#14b8a6",
        "IP Camera":       "#ef4444",
        "Raspberry Pi":    "#e11d48",
        "Unknown":         "#94a3b8",
    }

    for h in hosts:
        ip   = h.get("ip", "")
        name = h.get("device_name") or ip
        dtype = h.get("device_type", "Unknown")
        dicon = h.get("device_icon", "")
        is_self = h.get("is_self", False)
        mac  = h.get("mac") or ""
        vendor = h.get("vendor") or ""

        tooltip = f"{ip}\\n{vendor or dtype}\\n{mac}"

        if is_self:
            shape = "diamond"
            bg = "#2563eb"
            border = "#1d4ed8"
            sz = 30
        else:
            shape = "ellipse"
            bg = color_map.get(dtype, "#94a3b8")
            border = bg
            sz = 22

        label = f"{dicon} {name[:18]}\\n{ip}"
        nodes.append({
            "id": ip, "label": label, "title": tooltip,
            "shape": shape,
            "color": {"background": bg, "border": border,
                      "highlight": {"background": bg, "border": "#1e293b"}},
            "font": {"size": 11, "color": "#fff" if not is_self else "#fff"},
            "size": sz,
        })
        added_ips.add(ip)

        # Edge to gateway
        edge_to = "gw" if gateway_ip else None
        if edge_to:
            edges.append({"from": ip, "to": edge_to,
                          "color": {"color": "#dde3ec"},
                          "width": 1.5})

    return json.dumps({"nodes": nodes, "edges": edges}, ensure_ascii=False)


def render_html(report: Dict[str, Any],
                scan_elapsed: Optional[float] = None,
                diff: Optional[Dict[str, Any]] = None,
                passive_result: Optional[List[Dict[str, Any]]] = None,
                ssdp_devices: Optional[List[Dict[str, Any]]] = None,
                cve_map: Optional[Dict[str, List[Dict]]] = None,
                history: Optional[Dict[str, Any]] = None,
                ttl_map: Optional[Dict[str, Optional[int]]] = None) -> str:

    sysinfo = report.get("system", {})
    ident   = report.get("identity", {})
    pub     = report.get("public_ip", {})
    routes  = report.get("routes", {})
    gw      = routes.get("default_gateway")
    dns_cfg = report.get("dns", {})
    disc    = report.get("discovery", {})
    hosts   = disc.get("hosts", [])
    auth    = report.get("authorization", {}) or {}
    conn    = report.get("connectivity", {})
    priv    = report.get("privileges", {})
    pentest_results = report.get("pentest", {}) or {}

    cve_map   = cve_map   or {}
    ttl_map   = ttl_map   or {}
    history   = history   or {"total_runs": 0, "per_ip": {}}
    self_ips  = {h["ip"] for h in hosts if h.get("is_self")}

    subnets       = disc.get("subnets", [])
    elapsed_str   = _fmt_elapsed(scan_elapsed) if scan_elapsed else "—"
    uptime_str    = _fmt_uptime(sysinfo.get("uptime_seconds", 0))
    remote_hosts  = [h for h in hosts if not h.get("is_self")]
    new_ips       = set((diff or {}).get("new_ips", []))
    gone_ips      = set((diff or {}).get("gone_ips", []))
    changed_ports = (diff or {}).get("changed_ports", {})
    has_diff      = bool(diff and (new_ips or gone_ips or changed_ports))
    has_ports     = any(h.get("open_ports") for h in hosts)
    has_snmp      = any(h.get("snmp") for h in hosts)
    has_cve       = bool(cve_map)
    has_ttl       = bool(ttl_map)
    has_history   = history.get("total_runs", 0) > 0
    has_pentest   = bool(pentest_results)
    total_cves    = sum(len(v) for v in cve_map.values())
    passive_count = len(passive_result or [])
    ssdp_count    = len(ssdp_devices or [])

    # ── Privilege warnings ───────────────────────────────────────────────────
    priv_html = "".join(
        f'<div class="warn-box">⚠ <b>Privilege warning:</b> {html_escape(w)}</div>'
        for w in (priv.get("warnings") or []))

    # ── Stat cards ───────────────────────────────────────────────────────────
    stats = (
        '<div class="stats-grid">'
        + _stat_card(str(len(remote_hosts)), "Hosts Found", "green")
        + _stat_card(str(passive_count), "Passive-Only Hosts", "purple")
        + _stat_card(str(len(new_ips)), "New Since Last Scan",
                     "green" if new_ips else "")
        + _stat_card(str(len(gone_ips)), "Hosts Gone",
                     "red" if gone_ips else "")
        + _stat_card(str(total_cves), "Potential CVEs",
                     "red" if total_cves else "")
        + _stat_card(str(len(subnets)), "Subnets Scanned")
        + _stat_card(elapsed_str, "Scan Duration", "amber")
        + _stat_card(uptime_str, "System Uptime")
        + '</div>'
    )

    # ── Auth note ────────────────────────────────────────────────────────────
    auth_html = ""
    if auth.get("attested"):
        note = auth.get("note") or ""
        auth_html = (
            f'<p style="color:var(--green);font-weight:600;margin-bottom:5px">'
            f'✓ Authorization attested</p>'
            f'<p style="color:var(--muted);font-size:.83rem">'
            f'Scope: {html_escape(auth.get("scope",""))} '
            + (f'· Note: {html_escape(note)} ' if note else "")
            + f'· {html_escape(auth.get("timestamp_local",""))[:19]}</p>'
        )

    # ── Diff legend ──────────────────────────────────────────────────────────
    diff_legend = ""
    if has_diff:
        prev_name = os.path.basename(diff.get("previous_report", ""))
        diff_legend = (
            f'<p style="font-size:.82rem;color:var(--muted);margin-bottom:8px">'
            f'Compared to: <b>{html_escape(prev_name)}</b></p>'
            '<div class="diff-legend">'
            '<div class="dl-item"><span class="dl-swatch" style="background:#bbf7d0"></span>New</div>'
            '<div class="dl-item"><span class="dl-swatch" style="background:#fecaca"></span>Gone</div>'
            '<div class="dl-item"><span class="dl-swatch" style="background:#fde68a"></span>Port changes</div>'
            '<div class="dl-item"><span class="dl-swatch" style="background:#bfdbfe"></span>This machine</div>'
            '<div class="dl-item"><span class="dl-swatch" style="background:#e9d5ff"></span>Passive-only</div>'
            '</div>'
        )

    # ── Discovery meta ───────────────────────────────────────────────────────
    if disc.get("performed"):
        mode = str(disc.get("discovery_mode") or "?").upper()
        disc_meta = (
            f'<p style="color:var(--muted);font-size:.82rem;margin-bottom:10px">'
            f'Mode: <b>{html_escape(mode)}</b> · '
            f'Subnets: <b>{html_escape(", ".join(subnets))}</b> · '
            f'Duration: <b>{elapsed_str}</b>'
            + (' · SNMP: on' if disc.get("snmp_enabled") else '')
            + (' · TTL OS: on' if disc.get("ttl_os_enabled") else '')
            + (' · UDP probe: on' if disc.get("udp_probe_enabled") else '')
            + '</p>'
        )
    else:
        disc_meta = ('<p class="empty" style="margin-bottom:10px">'
                     'Discovery not run. Use <code>--discover</code>.</p>')

    # ── Host table rows ──────────────────────────────────────────────────────
    def row_class(h: Dict[str, Any]) -> str:
        ip = h.get("ip", "")
        if h.get("is_self"):           return "row-self"
        if ip in new_ips:              return "row-new"
        if ip in gone_ips:             return "row-gone"
        if ip in changed_ports:        return "row-chg"
        if h.get("passive_only"):      return "row-passive"
        return ""

    def name_cell(h: Dict[str, Any]) -> str:
        name = h.get("device_name") or ""
        bits = [html_escape(name)] if name else ['<span style="color:#94a3b8">—</span>']
        if h.get("is_self"):      bits.append('<span class="you-badge">YOU</span>')
        if h.get("ip") in new_ips: bits.append('<span class="new-badge">NEW</span>')
        if h.get("passive_only"): bits.append('<span class="psv-badge">PASSIVE</span>')
        return " ".join(bits)

    def addl_names(h: Dict[str, Any]) -> str:
        bits = []
        if h.get("netbios"): bits.append(f"NetBIOS: {html_escape(h['netbios'])}")
        if h.get("mdns"):    bits.append(f"mDNS: {html_escape(h['mdns'])}")
        for svc in (h.get("zeroconf_services") or [])[:2]:
            bits.append(html_escape(svc.replace("._tcp.local.", "").replace("_", "")))
        for svc in (h.get("passive_services") or [])[:2]:
            bits.append(f'<span style="color:var(--purple)">{html_escape(svc[:30])}</span>')
        return ' <span style="color:#e2e8f0">·</span> '.join(bits) if bits else ""

    def snmp_cell(h: Dict[str, Any]) -> str:
        s = h.get("snmp")
        if not s: return '<span style="color:#94a3b8">—</span>'
        parts = []
        if s.get("sysName"): parts.append(html_escape(s["sysName"]))
        if s.get("sysDescr"):
            parts.append(f'<span style="color:var(--muted);font-size:.77rem">'
                         f'{html_escape(s["sysDescr"][:80])}</span>')
        return "<br>".join(parts) or '<span style="color:#94a3b8">—</span>'

    def hint_row_html(h: Dict[str, Any]) -> str:
        hints = h.get("service_hints", {})
        if not hints: return ""
        lines = []
        for proto, pmap in hints.items():
            for p, info in (pmap or {}).items():
                if proto == "ssh":
                    b = html_escape((info.get("banner") or "")[:90])
                    lines.append(f"<b>SSH:{p}</b> <code>{b}</code>")
                elif proto in ("http", "https"):
                    sc = info.get("status_code", "?")
                    hdrs = info.get("headers") or {}
                    srv = html_escape(hdrs.get("server") or hdrs.get("Server") or "")
                    title = html_escape(info.get("title") or "")
                    parts = [f"<b>{proto.upper()}:{p}</b> — status {sc}"]
                    if title: parts.append(f"<em>{title}</em>")
                    if srv:   parts.append(f"server: <code>{srv}</code>")
                    lines.append("  ".join(parts))
                elif proto == "tls":
                    subj = dict(info.get("subject") or [])
                    cn   = html_escape(subj.get("commonName",""))
                    exp  = html_escape(info.get("notAfter",""))
                    sans = [v for k,v in (info.get("subjectAltName") or [])
                            if k=="DNS"][:3]
                    bits = [f"<b>TLS:{p}</b>"]
                    if cn: bits.append(f"CN=<code>{cn}</code>")
                    if exp: bits.append(f"exp:{exp[:10]}")
                    if sans: bits.append("SAN:"+", ".join(html_escape(s) for s in sans))
                    lines.append(" — ".join(bits))
                elif proto == "ftp":
                    b = html_escape((info.get("banner") or "")[:80])
                    lines.append(f"<b>FTP:{p}</b> <code>{b}</code>")
        if not lines: return ""
        rc = row_class(h)
        total_cols = (7 + (1 if has_ports else 0) + (1 if has_snmp else 0)
                      + (1 if has_cve else 0) + (1 if has_ttl else 0)
                      + (1 if has_history else 0))
        return (f'<tr class="hint-row {rc}"><td colspan="{total_cols}">'
                + " &nbsp;|&nbsp; ".join(lines) + '</td></tr>')

    rows_html = []
    for h in hosts:
        ip = h.get("ip", "")
        rc = row_class(h)
        rdns   = html_escape(h.get("reverse_dns") or "")
        mac_v  = html_escape(h.get("mac") or "")
        vend_v = html_escape(h.get("vendor") or "")
        dtype  = html_escape(h.get("device_type") or "Unknown")
        dicon  = html_escape(h.get("device_icon") or "❓")
        addl   = addl_names(h)
        chg    = changed_ports.get(ip, {})
        ttl    = ttl_map.get(ip)
        os_h   = html_escape(guess_os_from_ttl(ttl)) if ttl else ""
        cves   = cve_map.get(ip, [])

        port_td   = (f'<td data-val="{",".join(map(str,h.get("open_ports") or []))}">'
                     f'{_port_chips_html(h.get("open_ports") or [], chg.get("added"), chg.get("removed"))}'
                     f'</td>') if has_ports else ""
        snmp_td   = f"<td>{snmp_cell(h)}</td>" if has_snmp else ""
        cve_td    = f'<td data-val="{html_escape(",".join(c["id"] for c in cves))}">{_cve_chips(cves)}</td>' if has_cve else ""
        ttl_td    = f'<td data-val="{os_h}">{os_h or "<span style=\'color:#94a3b8\'>—</span>"}</td>' if has_ttl else ""
        hist_td   = f"<td>{_history_bar(ip, history)}</td>" if has_history else ""

        rows_html.append(
            f'<tr class="{rc} data-row">'
            f'<td class="icon-cell" data-val="{dicon}" title="{dtype}">{dicon}</td>'
            f'<td class="ip-cell" data-val="{ip}">{ip}</td>'
            f'<td data-val="{html_escape(h.get("device_name") or "")}">{name_cell(h)}</td>'
            f'<td data-val="{rdns}">{rdns or "<span style=\"color:#94a3b8\">—</span>"}</td>'
            f'<td class="mac-cell" data-val="{mac_v}">{mac_v or "<span style=\"color:#94a3b8\">—</span>"}</td>'
            f'<td data-val="{vend_v}">{vend_v or "<span style=\"color:#94a3b8\">—</span>"}</td>'
            f'<td data-val="{html_escape(addl)}" style="font-size:.8rem;color:var(--muted)">{addl}</td>'
            f'{snmp_td}{port_td}{ttl_td}{cve_td}{hist_td}'
            f'</tr>'
        )
        hr = hint_row_html(h)
        if hr: rows_html.append(hr)

    # Gone ghost rows
    for ip in sorted(gone_ips):
        rows_html.append(
            f'<tr class="row-gone data-row">'
            f'<td class="icon-cell" data-val="❌">❌</td>'
            f'<td class="ip-cell" data-val="{ip}">{ip}</td>'
            f'<td colspan="20" style="color:var(--red);font-style:italic">'
            f'Not found in this scan</td></tr>'
        )

    port_th  = "<th>Open Ports</th>"  if has_ports  else ""
    snmp_th  = "<th>SNMP Info</th>"   if has_snmp   else ""
    cve_th   = "<th>CVEs</th>"        if has_cve    else ""
    ttl_th   = "<th>OS Hint</th>"     if has_ttl    else ""
    hist_th  = "<th>Frequency</th>"   if has_history else ""

    host_table = (
        f'<div class="tbl-wrap">'
        f'<table class="host-table" id="host-table">'
        f'<thead><tr>'
        f'<th style="width:36px">Type</th>'
        f'<th>IP Address</th><th>Device Name</th><th>Reverse DNS</th>'
        f'<th>MAC</th><th>Vendor</th><th>Additional Names</th>'
        f'{snmp_th}{port_th}{ttl_th}{cve_th}{hist_th}'
        f'</tr></thead>'
        f'<tbody>{"".join(rows_html)}</tbody>'
        f'</table></div>'
    ) if hosts else '<p class="empty">No discovery performed.</p>'

    # ── System summary ───────────────────────────────────────────────────────
    sysinfo_rows = [
        ("Hostname",          ident.get("hostname","—")),
        ("FQDN",              ident.get("fqdn","—")),
        ("OS",                sysinfo.get("platform","—")),
        ("Boot time",         sysinfo.get("boot_time","—")),
        ("Uptime",            uptime_str),
        ("Default gateway",   gw or "—"),
        ("Public IP",         f'{pub.get("public_ip") or "—"} (via {pub.get("service") or "?"})'),
        ("DNS servers",       ", ".join(dns_cfg.get("dns_servers",[])  ) or "—"),
        ("Elevated privs",    "✓ Yes" if priv.get("elevated") else "✗ No"),
        ("Scan timestamp",    sysinfo.get("timestamp_local","—")),
        ("Scan duration",     elapsed_str),
        ("History runs",      str(history.get("total_runs",0))),
    ]
    sysinfo_html = '<table class="info-table">' + "".join(
        f'<tr><td>{html_escape(k)}</td><td>{html_escape(str(v))}</td></tr>'
        for k, v in sysinfo_rows
    ) + '</table>'

    # ── Connectivity ─────────────────────────────────────────────────────────
    conn_rows = []
    for item in conn.get("ping", []):
        ok = item.get("reachable", False)
        ttl_c = item.get("ttl")
        ttl_str = f" (TTL {ttl_c})" if ttl_c else ""
        cls = "conn-ok" if ok else "conn-fail"
        conn_rows.append(
            f'<tr><td>{html_escape(item.get("target",""))}</td>'
            f'<td><code>{html_escape(str(item.get("ip","")))}</code></td>'
            f'<td>PING</td>'
            f'<td class="{cls}">{"✓" if ok else "✗"}{html_escape(ttl_str)}</td></tr>')
    for item in conn.get("http", []):
        ok = item.get("ok", False)
        cls = "conn-ok" if ok else "conn-fail"
        conn_rows.append(
            f'<tr><td>{html_escape(item.get("target",""))}</td>'
            f'<td><code style="font-size:.77rem">{html_escape(str(item.get("url","")))}</code></td>'
            f'<td>HTTPS</td>'
            f'<td class="{cls}">{"✓ " + str(item.get("status_code","")) if ok else "✗"}</td></tr>')
    connectivity_html = (
        '<table class="info-table"><thead><tr style="background:#f1f5f9">'
        '<th style="padding:6px 10px">Target</th>'
        '<th style="padding:6px 10px">Address</th>'
        '<th style="padding:6px 10px">Type</th>'
        '<th style="padding:6px 10px">Result</th>'
        '</tr></thead><tbody>' + "".join(conn_rows) + '</tbody></table>'
    ) if conn_rows else '<p class="empty">Not tested.</p>'

    # ── Listening ports ──────────────────────────────────────────────────────
    listening = report.get("listening_ports", [])
    pg: Dict[int, List[str]] = {}
    for lp in listening:
        if isinstance(lp, dict) and "local_port" in lp:
            pg.setdefault(lp["local_port"], []).append(lp.get("local_ip") or "*")
    listening_html = (
        '<div style="margin-top:6px">'
        + "".join(f'<span class="port-chip" title="Bound: {html_escape(", ".join(ips))}">{p}</span>'
                  for p, ips in sorted(pg.items()))
        + '</div>'
    ) if pg else '<p class="empty">None detected (may need elevated privileges).</p>'

    # ── Passive summary tab ──────────────────────────────────────────────────
    passive_rows = ""
    for obs in (passive_result or []):
        ip = html_escape(obs.get("ip",""))
        mac = html_escape(obs.get("mac") or "—")
        names = html_escape(", ".join(obs.get("names", [])) or "—")
        protos = html_escape(", ".join(obs.get("protocols", [])))
        svcs   = html_escape(", ".join(obs.get("services", [])) or "—")
        pkts   = html_escape(str(obs.get("packet_count", 0)))
        passive_rows += (
            f'<tr><td class="ip-cell">{ip}</td>'
            f'<td class="mac-cell">{mac}</td>'
            f'<td>{names}</td><td>{protos}</td>'
            f'<td>{svcs}</td><td style="text-align:right">{pkts}</td></tr>')

    passive_tab = (
        '<table class="small-table"><thead><tr>'
        '<th>IP</th><th>MAC</th><th>Names</th>'
        '<th>Protocols</th><th>Services</th><th style="text-align:right">Packets</th>'
        '</tr></thead><tbody>' + passive_rows + '</tbody></table>'
    ) if passive_rows else '<p class="empty">No passive sniffing performed or no traffic captured.</p>'

    # ── SSDP tab ─────────────────────────────────────────────────────────────
    ssdp_rows = ""
    for d in (ssdp_devices or []):
        ip   = html_escape(d.get("ip",""))
        srv  = html_escape(d.get("server","") or "—")
        fn   = html_escape(d.get("friendlyName","") or "—")
        mfr  = html_escape(d.get("manufacturer","") or "—")
        model= html_escape(d.get("modelName","") or "—")
        st   = html_escape(d.get("st","") or "—")
        ssdp_rows += (
            f'<tr><td class="ip-cell">{ip}</td>'
            f'<td>{fn}</td><td>{mfr}</td><td>{model}</td>'
            f'<td style="font-size:.78rem">{srv}</td>'
            f'<td style="font-size:.78rem;color:var(--muted)">{st}</td></tr>')
    ssdp_tab = (
        '<table class="small-table"><thead><tr>'
        '<th>IP</th><th>Friendly Name</th><th>Manufacturer</th>'
        '<th>Model</th><th>Server</th><th>Service Type</th>'
        '</tr></thead><tbody>' + ssdp_rows + '</tbody></table>'
    ) if ssdp_rows else '<p class="empty">No SSDP discovery performed or no devices responded.</p>'

    # ── CVE tab ──────────────────────────────────────────────────────────────
    cve_tab_rows = ""
    for ip, cves in sorted(cve_map.items()):
        for cve in cves:
            cid   = html_escape(cve.get("id",""))
            score = html_escape(str(cve.get("score") or "—"))
            sev   = html_escape(cve.get("severity") or "—")
            pub_d = html_escape(cve.get("published","")[:10])
            desc  = html_escape(cve.get("description","")[:180])
            sev_u = (cve.get("severity") or "").upper()
            impact= html_escape(cve.get("impact","Other"))
            impact_icon = cve.get("impact_icon","")
            is_kev = cve.get("kev", False)
            css = ("cve-critical" if sev_u == "CRITICAL" else
                   "cve-high"     if sev_u == "HIGH"     else
                   "cve-medium"   if sev_u == "MEDIUM"   else
                   "cve-low"      if sev_u == "LOW"       else "cve-none")
            kev_badge = ('<span style="background:#dc2626;color:#fff;border-radius:3px;'
                         'padding:0 4px;font-size:0.65rem;font-weight:900;margin-left:4px">'
                         'KEV</span>' if is_kev else "")
            cve_tab_rows += (
                f'<tr>'
                f'<td class="ip-cell">{ip}</td>'
                f'<td><span class="cve-chip {css}">{cid}</span>{kev_badge}</td>'
                f'<td style="text-align:center">{score}</td>'
                f'<td><span class="cve-chip {css}">{sev}</span></td>'
                f'<td style="font-size:.82rem">{impact_icon} {impact}</td>'
                f'<td style="font-size:.78rem">{pub_d}</td>'
                f'<td style="font-size:.78rem">{desc}</td>'
                f'</tr>')
    cve_tab = (
        '<table class="small-table"><thead><tr>'
        '<th>IP</th><th>CVE ID</th><th style="text-align:center">Score</th>'
        '<th>Severity</th><th>Impact</th><th>Published</th><th>Description</th>'
        '</tr></thead><tbody>' + cve_tab_rows + '</tbody></table>'
        + '<p style="font-size:.78rem;color:var(--muted);margin-top:10px">'
        '⚠ CVE data is heuristic — cross-reference with NVD before acting. '
        'KEV = CISA Known Exploited Vulnerabilities (actively exploited in the wild). '
        'Matches are keyword-based and may include false positives.</p>'
    ) if cve_tab_rows else '<p class="empty">No CVE check performed. Use <code>--cve-check</code>.</p>'

    # ── Security / Pentest tab ────────────────────────────────────────────────
    sev_css = {
        "CRITICAL": "background:#fef2f2;color:#991b1b;border:1px solid #fca5a5",
        "HIGH":     "background:#fff7ed;color:#c2410c;border:1px solid #fdba74",
        "MEDIUM":   "background:#fefce8;color:#854d0e;border:1px solid #fde047",
        "INFO":     "background:#f0f9ff;color:#0369a1;border:1px solid #7dd3fc",
    }
    pentest_rows = ""
    for ip, presult in sorted(pentest_results.items()):
        findings = presult.get("all_findings", [])
        for f in findings:
            sev = f.get("severity", "INFO")
            fcheck = html_escape(f.get("check",""))
            fdetail = html_escape(f.get("detail","")[:250])
            frem = html_escape(f.get("remediation","")[:200])
            css_s = sev_css.get(sev, "background:#f8fafc")
            pentest_rows += (
                f'<tr>'
                f'<td class="ip-cell">{html_escape(ip)}</td>'
                f'<td><span style="border-radius:4px;padding:2px 7px;'
                f'font-size:.72rem;font-weight:700;{css_s}">{sev}</span></td>'
                f'<td style="font-weight:600;font-size:.83rem">{fcheck}</td>'
                f'<td style="font-size:.78rem">{fdetail}</td>'
                f'<td style="font-size:.78rem;color:var(--muted)">{frem}</td>'
                f'</tr>'
            )
    pentest_tab = (
        '<p style="color:var(--amber);font-size:.82rem;margin-bottom:10px">'
        '⚠ Penetration testing findings. Verify all results manually before acting. '
        'False positives are possible. All actions were logged to the audit log.</p>'
        '<table class="small-table"><thead><tr>'
        '<th>IP</th><th>Severity</th><th>Finding</th>'
        '<th>Detail</th><th>Remediation</th>'
        '</tr></thead><tbody>' + pentest_rows + '</tbody></table>'
    ) if pentest_rows else (
        '<p class="empty">No pentest performed or no findings. '
        'Use <code>--pentest</code> with <code>--probe-ports</code>.</p>'
    )

    # ── Topology ─────────────────────────────────────────────────────────────
    topo_data = _build_topology_js(hosts, gw, self_ips)
    topo_legend_items = []
    seen_types: Set[str] = set()
    color_map_js = {
        "Apple Device":"#3b82f6","PC / Laptop":"#6366f1","Network / NAS":"#10b981",
        "Printer":"#f59e0b","Mobile Device":"#ec4899","IoT / Smart":"#8b5cf6",
        "Virtual Machine":"#64748b","UPS / Power":"#14b8a6",
        "IP Camera":"#ef4444","Raspberry Pi":"#e11d48","Unknown":"#94a3b8",
    }
    for h in hosts:
        dt_ = h.get("device_type","Unknown")
        if dt_ not in seen_types:
            seen_types.add(dt_)
            col = color_map_js.get(dt_,"#94a3b8")
            icon = h.get("device_icon","❓")
            topo_legend_items.append(
                f'<span style="margin-right:14px;font-size:.82rem">'
                f'<span style="display:inline-block;width:12px;height:12px;'
                f'border-radius:50%;background:{col};vertical-align:middle;'
                f'margin-right:4px"></span>{icon} {html_escape(dt_)}</span>')

    topo_html = (
        f'<div id="topology-container"></div>'
        f'<p style="font-size:.78rem;color:var(--muted);margin-top:8px">'
        f'Drag nodes to rearrange. Scroll to zoom. '
        f'Requires internet connection to load vis.js from CDN.</p>'
        f'<div style="margin-top:8px">{"".join(topo_legend_items)}</div>'
        f'<script>'
        f'(function initTopologyWhenReady() {{'
        f'  if (typeof vis === "undefined") {{ setTimeout(initTopologyWhenReady, 50); return; }}'
        f'  var topoData = {topo_data};'
        f'  var container = document.getElementById("topology-container");'
        f'  if (!container) return;'
        f'  var options = {{'
        f'    physics: {{stabilization: {{iterations: 120}}, '
        f'      barnesHut: {{gravitationalConstant: -4000, springLength: 120}}}}, '
        f'    edges: {{smooth: {{type: "cubicBezier", roundness: 0.4}}}}, '
        f'    interaction: {{hover: true, tooltipDelay: 100}}, '
        f'    nodes: {{borderWidth: 2, shadow: true}}'
        f'  }};'
        f'  new vis.Network(container, '
        f'    {{nodes: new vis.DataSet(topoData.nodes), '
        f'     edges: new vis.DataSet(topoData.edges)}}, options);'
        f'}})();'
        f'</script>'
    )

    # ── Raw collapsibles ─────────────────────────────────────────────────────
    def raw_block(label: str, obj: Any) -> str:
        txt = json.dumps(obj, indent=2, ensure_ascii=False)
        return (f'<details><summary>▶ {html_escape(label)}</summary>'
                f'<pre>{html_escape(txt)}</pre></details>\n')

    raw_html = "".join([
        raw_block("Network Interfaces",          report.get("interfaces",{})),
        raw_block("Local IPv4 Networks",         report.get("local_ipv4_networks",[])),
        raw_block("Routing Table",               report.get("routes",{})),
        raw_block("DNS Configuration",           report.get("dns",{})),
        raw_block("ARP / NDP Neighbour Table",   report.get("neighbors",{})),
        raw_block("Active Connections (sampled)",report.get("active_connections",[])),
        raw_block("Zeroconf Map",                report.get("zeroconf_map",{})),
        raw_block("Change Diff",                 diff or {}),
        raw_block("CVE Map",                     cve_map),
        raw_block("Authorization Record",        auth),
    ])

    # ── Optional package status ───────────────────────────────────────────────
    pkg_lines = "\n".join([
        f"scapy:     {'✓ installed' if _HAS_SCAPY else '✗ not installed — pip install scapy'}",
        f"puresnmp:  {'✓ installed' if _HAS_PURESNMP else '✗ not installed — pip install puresnmp'}",
        f"zeroconf:  {'✓ installed' if _HAS_ZEROCONF else '✗ not installed — pip install zeroconf'}",
    ])

    ts = sysinfo.get("timestamp_local","")[:19].replace("T"," ")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Network Report v6 — {html_escape(ident.get("hostname",""))}</title>
<style>{_CSS}</style>
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.6/vis-network.min.js"
  integrity="sha512-LnMHsRFwHZ8emkHKKlKJ7ziFISJDLXBOmViVzIzJbNh9DVGKF7ySiOF9LjXSqnPDO5ux8pZ5YKIWnzheRzUw=="
  crossorigin="anonymous" referrerpolicy="no-referrer"></script>
</head>
<body>
<script>{_JS}</script>

<div class="topbar">
  <div class="topbar-row">
    <div>
      <h1>🌐 Network Diagnostic Report <span style="font-weight:400;font-size:1rem;opacity:.7">v6.0</span></h1>
      <div class="subtitle">
        Host: <b>{html_escape(ident.get("hostname",""))}</b> &nbsp;·&nbsp;
        Generated: {html_escape(ts)} &nbsp;·&nbsp;
        Gateway: {html_escape(gw or "—")}
      </div>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
      <span class="badge {'green' if auth.get('attested') else ''}">
        {'✓ Auth attested' if auth.get('attested') else 'Report only'}
      </span>
      <span class="badge {'green' if has_pentest else ''}">
        {'🔍 Pentest run' if has_pentest else '—no pentest'}
      </span>
      <span class="badge">{'✓ Elevated' if priv.get('elevated') else '✗ No root'}</span>
    </div>
  </div>
</div>

<div class="page">
{priv_html}
{stats}

<div class="tabs">
  <div class="tab active" id="tab-hosts" onclick="switchTab('hosts')">📡 Hosts</div>
  <div class="tab" id="tab-passive" onclick="switchTab('passive')">👁 Passive ({passive_count})</div>
  <div class="tab" id="tab-ssdp" onclick="switchTab('ssdp')">📺 SSDP/UPnP ({ssdp_count})</div>
  <div class="tab" id="tab-topology" onclick="switchTab('topology')">🗺 Topology</div>
  <div class="tab" id="tab-cve" onclick="switchTab('cve')">🔐 CVEs ({total_cves})</div>
  <div class="tab {'red' if has_pentest else ''}" id="tab-security" onclick="switchTab('security')">🛡 Security{(' (' + str(sum(len(v.get('all_findings',[])) for v in pentest_results.values())) + ')') if has_pentest else ''}</div>
  <div class="tab" id="tab-system" onclick="switchTab('system')">🖥 System</div>
  <div class="tab" id="tab-raw" onclick="switchTab('raw')">🗂 Raw</div>
</div>

<!-- HOSTS TAB -->
<div class="tab-content active" id="content-hosts">
  <div class="section">
    <h2>📡 Discovered Hosts</h2>
    {auth_html}
    {disc_meta}
    {diff_legend}
    <div class="btn-row">
      <input type="text" placeholder="🔍 Filter hosts…"
        oninput="filterTable(this.value)"
        style="padding:6px 12px;border:1px solid var(--border);border-radius:6px;
               font-size:.84rem;outline:none;width:220px">
      <button class="btn" onclick="exportCSV()">⬇ Export CSV</button>
    </div>
    {host_table}
  </div>
  <div class="section">
    <h2>🔒 Listening Ports on This Machine</h2>
    {listening_html}
  </div>
  <div class="section">
    <h2>🔗 Internet Connectivity</h2>
    {connectivity_html}
  </div>
</div>

<!-- PASSIVE TAB -->
<div class="tab-content" id="content-passive">
  <div class="section">
    <h2>👁 Passive Sniffing Results</h2>
    <p style="color:var(--muted);font-size:.83rem;margin-bottom:12px">
      Hosts observed purely through traffic analysis — no probes sent.
      Protocols: ARP, mDNS, NetBIOS-NS, SSDP, DHCP, LLMNR.
    </p>
    {passive_tab}
  </div>
</div>

<!-- SSDP TAB -->
<div class="tab-content" id="content-ssdp">
  <div class="section">
    <h2>📺 SSDP / UPnP Devices</h2>
    <p style="color:var(--muted);font-size:.83rem;margin-bottom:12px">
      Devices responding to SSDP M-SEARCH multicast. UPnP XML descriptions
      fetched where available.
    </p>
    {ssdp_tab}
  </div>
</div>

<!-- TOPOLOGY TAB -->
<div class="tab-content" id="content-topology">
  <div class="section">
    <h2>🗺 Network Topology</h2>
    {topo_html}
  </div>
</div>

<!-- CVE TAB -->
<div class="tab-content" id="content-cve">
  <div class="section">
    <h2>🔐 CVE Cross-Reference</h2>
    {cve_tab}
  </div>
</div>

<!-- SECURITY / PENTEST TAB -->
<div class="tab-content" id="content-security">
  <div class="section">
    <h2>🛡 Security Findings (Penetration Test)</h2>
    {pentest_tab}
  </div>
</div>

<!-- SYSTEM TAB -->
<div class="tab-content" id="content-system">
  <div class="section">
    <h2>🖥 System Summary</h2>
    {sysinfo_html}
    <details style="margin-top:12px">
      <summary>▶ Optional package status</summary>
      <pre>{html_escape(pkg_lines)}</pre>
    </details>
  </div>
</div>

<!-- RAW TAB -->
<div class="tab-content" id="content-raw">
  <div class="section">
    <h2>🗂 Raw Data</h2>
    <p style="color:var(--muted);font-size:.83rem;margin-bottom:10px">
      Full data dump in the companion <code>.json</code> file.
      Expand sections below for inline inspection.
    </p>
    {raw_html}
  </div>
</div>

</div><!-- .page -->
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════════════════
# Argument parser
# ══════════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="omnirecon.py",
        description=textwrap.dedent("""\
            OmniRecon v6.0 — Network diagnostics + security audit platform
            ──────────────────────────────────────────────────────────────────
            Active + passive + historical + vulnerability-aware + pentest.

            ── Quick start ──────────────────────────────────────
            Report only (no scanning):
              python omnirecon.py

            Active discovery (most common):
              python omnirecon.py --discover --i-have-authorization

            Full security scan (CVE + CISA KEV):
              python omnirecon.py --discover --probe-ports --service-hints \\
                --cve-check --cve-kev --i-have-authorization

            Full everything including pentest:
              python omnirecon.py --discover --passive --ssdp \\
                --probe-ports --service-hints --snmp --ttl-os --udp-probe \\
                --cve-check --cve-kev --pentest --topology \\
                --i-have-authorization

            Pentest specific modules only:
              python omnirecon.py --discover --probe-ports --service-hints \\
                --pentest --pentest-modules tls-audit,headers,ftp-anon \\
                --i-have-authorization

            Passive-only stealth audit (no probes sent):
              python omnirecon.py --passive-extended --passive-duration 120

            ── Help topics ──────────────────────────────────────
            python omnirecon.py --help-topic discover
            python omnirecon.py --help-topic pentest
            python omnirecon.py --help-topic cve-kev
            python omnirecon.py --help-topic cve-check
            python omnirecon.py --help-topic tls-audit
            python omnirecon.py --help-topic authorization

            All topics: """ + ", ".join(f"--{t}" for t in sorted(HELP_TOPICS))),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    ap.add_argument("--help-topic", metavar="TOPIC",
                    help="Detailed help for one option. "
                         "Run without TOPIC to see all available topics.")

    g_out = ap.add_argument_group("Output  (--help-topic output)")
    g_out.add_argument("--outdir", default=".",
                       help="Output directory. Default: current dir.")

    g_disc = ap.add_argument_group("Active Discovery  (--help-topic discover)")
    g_disc.add_argument("--discover", action="store_true",
                        help="Active host discovery sweep.")
    g_disc.add_argument("--discovery-mode", default="auto",
                        choices=["auto","tcp","icmp","arp","udp","combined"],
                        help="Liveness method. --help-topic discovery-mode")
    g_disc.add_argument("--alive-ports",
                        default="445,3389,135,139,5985,22,80,443,631,9100,"
                                "8080,8443,23,53,21,25,110,143,8006,5900",
                        help="TCP ports for TCP-mode liveness. --help-topic alive-ports")
    g_disc.add_argument("--subnet", action="append", default=[],
                        help="CIDR(s) to scan (repeatable). --help-topic subnet")
    g_disc.add_argument("--arp-prime", action="store_true",
                        help="Prime ARP cache before sweep.")
    g_disc.add_argument("--max-hosts", type=int, default=512,
                        help="Max IPs per subnet. Default: 512.")
    g_disc.add_argument("--allow-non-private", action="store_true",
                        help="Allow scanning non-RFC1918 ranges.")
    g_disc.add_argument("--ipv6", action="store_true",
                        help="Include IPv6 NDP table.")
    g_disc.add_argument("--udp-probe", action="store_true",
                        help="UDP existence probe. --help-topic udp-probe")
    g_disc.add_argument("--ttl-os", action="store_true",
                        help="TTL-based OS fingerprinting. --help-topic ttl-os")

    g_pass = ap.add_argument_group("Passive / SSDP  (--help-topic passive)")
    g_pass.add_argument("--passive", action="store_true",
                        help="Run passive sniffing alongside active discovery.")
    g_pass.add_argument("--passive-extended", action="store_true",
                        help="Passive-only mode (no active probing). --help-topic passive")
    g_pass.add_argument("--passive-duration", type=float, default=30.0,
                        help="Passive listening seconds. Default: 30.")
    g_pass.add_argument("--passive-interface", default=None,
                        help="Network interface for passive sniffing (default: auto).")
    g_pass.add_argument("--ssdp", action="store_true",
                        help="SSDP/UPnP active discovery. --help-topic ssdp")
    g_pass.add_argument("--ssdp-timeout", type=float, default=5.0,
                        help="Seconds to wait for SSDP responses. Default: 5.")

    g_perf = ap.add_argument_group("Performance  (--help-topic workers)")
    g_perf.add_argument("--workers", type=int, default=256,
                        help="Async liveness concurrency. Default: 256.")
    g_perf.add_argument("--enrich-workers", type=int, default=0,
                        help="Enrichment thread pool. Default: workers//4, min 8.")
    g_perf.add_argument("--enrich-timeout", type=float, default=5.0,
                        help="Per-enrichment-op timeout (s). Default: 5.")
    g_perf.add_argument("--active-limit", type=int, default=200,
                        help="Max active connections captured. Default: 200.")
    g_perf.add_argument("--scan-delay", type=float, default=0.0, metavar="MS",
                        help="Millisecond delay between liveness probes. "
                             "Reduces IDS triggering on large networks. "
                             "--help-topic rate-limit")
    g_perf.add_argument("--randomize-scan", action="store_true",
                        help="Randomise probe order. "
                             "Breaks sequential scan signatures. "
                             "--help-topic rate-limit")

    g_probe = ap.add_argument_group("Port probing  (--help-topic probe-ports)")
    g_probe.add_argument("--probe-ports", action="store_true",
                         help="TCP port-scan discovered hosts.")
    g_probe.add_argument("--ports",
                         default="21,22,23,25,53,80,110,143,443,445,3389,"
                                 "5357,5900,8006,8080,8443",
                         help="Ports to probe. --help-topic probe-ports")
    g_probe.add_argument("--service-hints", action="store_true",
                         help="Banner grab + header fetch on open ports.")

    g_enrich = ap.add_argument_group("Enrichment")
    g_enrich.add_argument("--snmp", action="store_true",
                           help="SNMP probe (needs puresnmp). --help-topic snmp")
    g_enrich.add_argument("--snmp-communities", default="public,private",
                           help="SNMP community strings. Default: public,private")
    g_enrich.add_argument("--zeroconf", action="store_true",
                           help="Passive Zeroconf browse (needs zeroconf).")
    g_enrich.add_argument("--zeroconf-timeout", type=float, default=3.0,
                           help="Zeroconf browse seconds. Default: 3.")
    g_enrich.add_argument("--oui-file", default="",
                           help="Local IEEE OUI file. --help-topic oui-file")

    g_intel = ap.add_argument_group("Threat Intelligence / CVE")
    g_intel.add_argument("--cve-check", action="store_true",
                          help="NVD CVE cross-reference. --help-topic cve-check")
    g_intel.add_argument("--nvd-api-key", default="",
                          help="NVD API key for higher rate limits.")
    g_intel.add_argument("--cve-kev", action="store_true",
                          help="Cross-ref CVEs with CISA KEV catalog. "
                               "--help-topic cve-kev")
    g_intel.add_argument("--cve-min-score", type=float, default=6.0,
                          metavar="N",
                          help="Only report CVEs with CVSS >= N. Default: 6.0. "
                               "Use 0.0 for all.")
    g_intel.add_argument("--cve-results-per-query", type=int, default=20,
                          metavar="N",
                          help="CVE results per NVD query. Default: 20.")
    g_intel.add_argument("--topology", action="store_true",
                          help="vis.js topology map in HTML. --help-topic topology")
    g_intel.add_argument("--no-topology", action="store_true",
                          help="Suppress topology tab (useful offline or when CDN blocked).")
    g_intel.add_argument("--no-diff", action="store_true",
                          help="Skip comparison against previous report.")

    g_pentest = ap.add_argument_group(
        "Penetration Testing  (--help-topic pentest)\n"
        "  ⚠  Only use against systems you own or have written authorisation to test.")
    g_pentest.add_argument("--pentest", action="store_true",
                            help="Enable pentest module. Requires --i-have-authorization "
                                 "AND interactive consent. --help-topic pentest")
    g_pentest.add_argument("--pentest-modules",
                            default="all",
                            help="Comma-separated pentest modules. Default: all. "
                                 "Options: tls-audit,headers,ftp-anon,"
                                 "ssh-defaults,http-vulns,smb-enum")
    g_pentest.add_argument("--pentest-credentials", default=None,
                            metavar="FILE",
                            help="File with user:pass credentials for credential tests.")
    g_pentest.add_argument("--pentest-timeout", type=float, default=3.0,
                            metavar="N",
                            help="Per-probe timeout in seconds. Default: 3.0")
    g_pentest.add_argument("--audit-log",
                            default=None,
                            metavar="FILE",
                            help="Path for JSONL audit log. "
                                 "Default: <outdir>/omnirecon_audit.jsonl")

    g_prog = ap.add_argument_group("Progress  (--help-topic progress)")
    g_prog.add_argument("--progress", dest="progress", action="store_true",
                        default=True, help="Live progress (default).")
    g_prog.add_argument("--no-progress", dest="progress",
                        action="store_false", help="Disable progress output.")

    g_auth = ap.add_argument_group("Authorization  (--help-topic authorization)")
    g_auth.add_argument("--i-have-authorization", action="store_true",
                        help="Skip interactive auth prompt.")
    g_auth.add_argument("--authorization-note", default="",
                        help="Note embedded in report.")
    g_auth.add_argument("--non-interactive", action="store_true",
                        help="Never prompt.")

    return ap


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    # Handle --help-topic before argparse
    for flag in ("--help-topic",):
        if flag in sys.argv:
            idx = sys.argv.index(flag)
            if idx + 1 < len(sys.argv):
                show_topic_help(sys.argv[idx + 1])
            else:
                print("Usage: --help-topic TOPIC"); sys.exit(1)
    for flag in ("-h", "--help"):
        if flag in sys.argv:
            idx = sys.argv.index(flag)
            if idx + 1 < len(sys.argv) and not sys.argv[idx+1].startswith("-"):
                show_topic_help(sys.argv[idx+1])

    ap = build_parser()
    args = ap.parse_args()
    if getattr(args, "help_topic", None):
        show_topic_help(args.help_topic)

    scan_start = time.perf_counter()
    stamp      = now_stamp()
    outdir     = os.path.abspath(args.outdir)
    os.makedirs(outdir, exist_ok=True)

    # ── Init audit log ────────────────────────────────────────────────────────
    audit_log_path = getattr(args, "audit_log", None) or \
        os.path.join(outdir, "omnirecon_audit.jsonl")
    init_audit_log(audit_log_path)
    _audit_write({"event": "scan_start", "stamp": stamp,
                  "argv": sys.argv[1:]})

    print(f"\n  {'─'*60}")
    print(f"  OmniRecon v6.0  ·  {stamp}")
    print(f"  Output: {outdir}")
    print(f"  Audit:  {audit_log_path}")
    print(f"  {'─'*60}\n")

    # Privilege check
    privinfo = check_privileges()
    report: Dict[str, Any] = {}
    report["privileges"] = privinfo
    for w in privinfo["warnings"]:
        print(f"  ⚠  {w}")
    if privinfo["warnings"]: print()

    # ── [1] Base data ─────────────────────────────────────────────────────────
    print("  [1/8] System info …")
    report["system"]   = get_system_info()
    report["identity"] = get_identity_info()
    report["public_ip"] = get_public_ip()
    report["interfaces"] = get_interfaces()

    print("  [2/8] Routes & DNS …")
    report["routes"] = get_routes_and_gateway()
    report["dns"]    = get_dns_config()
    default_iface    = report["routes"].get("default_iface")
    gw               = report["routes"].get("default_gateway")

    print("  [3/8] ARP / NDP …")
    report["neighbors"] = get_neighbor_table(include_ipv6=args.ipv6)
    ip_mac, ip_state = build_neighbor_maps(report["neighbors"])

    print("  [4/8] Connectivity …")
    report["connectivity"]     = connectivity_checks(gw)
    report["listening_ports"]  = get_listening_ports()
    report["active_connections"] = get_active_connections(limit=args.active_limit)

    local_nets = get_local_ipv4_networks(
        default_iface=default_iface,
        exclude_virtual=not args.allow_non_private)
    report["local_ipv4_networks"] = local_nets

    oui_map = load_oui_map(args.oui_file) if args.oui_file else {}

    # ── [5] Zeroconf ──────────────────────────────────────────────────────────
    zc_map: Dict[str, Dict[str, Any]] = {}
    if args.zeroconf:
        print("  [5/8] Zeroconf …")
        if not _HAS_ZEROCONF:
            print("        ✗ pip install zeroconf")
        else:
            zc_map = zeroconf_passive_map(timeout_s=args.zeroconf_timeout)
    else:
        print("  [5/8] Zeroconf: skipped")
    report["zeroconf_map"] = zc_map

    # ── [6] Passive sniffing ──────────────────────────────────────────────────
    passive_result_obj: Optional[PassiveSniffResult] = None
    passive_list: List[Dict[str, Any]] = []

    run_passive = args.passive or args.passive_extended
    if run_passive:
        print(f"\n  [6/8] Passive sniffing ({args.passive_duration:.0f}s) …")
        passive_result_obj = passive_sniff(
            duration_s=args.passive_duration,
            interface=args.passive_interface,
            progress=args.progress,
        )
        # v5: Ping passive-only hosts to trigger ARP exchange for MAC discovery
        if passive_result_obj and len(passive_result_obj.hosts) > 0:
            ping_passive_hosts_for_mac(
                passive_result_obj,
                max_workers=min(64, args.workers),
                progress=args.progress,
            )
        passive_list = passive_result_obj.to_list()
        report["passive_observations"] = passive_list
    else:
        print("  [6/8] Passive sniffing: skipped  (use --passive or --passive-extended)")
        report["passive_observations"] = []

    # ── SSDP ─────────────────────────────────────────────────────────────────
    ssdp_devices: List[Dict[str, Any]] = []
    if args.ssdp:
        print(f"\n  SSDP/UPnP discovery ({args.ssdp_timeout:.0f}s) …")
        ssdp_devices = ssdp_discover(timeout_s=args.ssdp_timeout)
        print(f"  SSDP: {len(ssdp_devices)} device(s) found.")
    report["ssdp_devices"] = ssdp_devices

    # Default auth record
    report["authorization"] = {
        "attested": False, "note": args.authorization_note or "",
        "timestamp_local": dt.datetime.now().isoformat(),
        "scope": "report-only", "subnets": [],
        "flagged_non_lan_subnets": [], "operator_prompted": False,
    }

    # ── [7] Active discovery ──────────────────────────────────────────────────
    disc_block: Dict[str, Any] = {
        "performed": False, "subnets": [], "hosts": [],
        "discovery_mode": None, "alive_ports": None,
        "snmp_enabled": False, "ttl_os_enabled": False,
        "udp_probe_enabled": False,
    }
    diff: Optional[Dict[str, Any]] = None
    ttl_map: Dict[str, Optional[int]] = {}
    hosts: List[Dict[str, Any]] = []

    if args.passive_extended and not args.discover:
        # Passive-only: build host list from passive observations
        print("\n  [7/8] Building host list from passive observations …")
        disc_block["performed"] = True
        disc_block["passive_only_mode"] = True
        if passive_result_obj:
            # Enrich passive hosts with reverse DNS etc.
            for obs in passive_list:
                ip = obs["ip"]
                mac = obs["mac"]
                oui = mac_to_oui(mac)
                vendor = oui_map.get(oui) if oui else None
                dtype, dicon = guess_device_type(vendor)
                rdns = resolve_reverse(ip)
                hosts.append({
                    "ip": ip, "is_self": False,
                    "device_name": obs["names"][0] if obs["names"] else rdns,
                    "device_type": dtype, "device_icon": dicon,
                    "reverse_dns": rdns,
                    "netbios": None, "mdns": None,
                    "zeroconf_names": [], "zeroconf_services": [],
                    "mac": mac, "oui": oui, "vendor": vendor, "snmp": None,
                    "passive_only": True,
                    "passive_protocols": obs["protocols"],
                    "passive_services": obs["services"],
                    "open_ports": [],
                })
        hosts = sorted(hosts, key=lambda h: _ip_sort_key_str(h["ip"]))
        disc_block["hosts"] = hosts
        disc_block["subnets"] = [n["cidr"] for n in local_nets]

    elif args.discover:
        print("\n  [7/8] Active host discovery …\n")
        disc_block["performed"] = True

        subnets = args.subnet if args.subnet else [
            n["cidr"] for n in local_nets if n.get("cidr")]
        disc_block["subnets"] = subnets

        scope = "discovery" + ("+probe-ports" if args.probe_ports else "")
        report["authorization"] = require_authorization_or_abort(
            args, subnets, scope)

        alive_ports = [
            int(p.strip()) for p in args.alive_ports.split(",")
            if p.strip().isdigit() and 1 <= int(p.strip()) <= 65535
        ] or [445, 3389, 135, 139, 5985, 22, 80, 443, 631, 9100]

        snmp_communities: Optional[List[str]] = None
        if args.snmp:
            if not _HAS_PURESNMP:
                print("  ⚠  --snmp: pip install puresnmp\n")
            else:
                snmp_communities = [c.strip() for c in args.snmp_communities.split(",") if c.strip()]
                disc_block["snmp_enabled"] = True

        disc_block["ttl_os_enabled"]    = args.ttl_os
        disc_block["udp_probe_enabled"] = args.udp_probe

        enrich_workers = args.enrich_workers or max(8, args.workers // 4)

        if args.arp_prime:
            print("  ARP priming …")
            for cidr in subnets:
                arp_prime_subnet(cidr, args.max_hosts,
                                 min(args.workers, 256), progress=args.progress)
            report["neighbors"] = get_neighbor_table(include_ipv6=args.ipv6)
            ip_mac, ip_state = build_neighbor_maps(report["neighbors"])

        self_hosts = build_self_hosts(local_nets, ip_mac, oui_map)

        hosts, ttl_map = discover_hosts(
            subnets=subnets,
            max_hosts_per_subnet=args.max_hosts,
            liveness_workers=args.workers,
            enrich_workers=enrich_workers,
            ip_mac=ip_mac, ip_state=ip_state,
            oui_map=oui_map, zeroconf_map=zc_map,
            self_hosts=self_hosts,
            allow_non_private=args.allow_non_private,
            discovery_mode=args.discovery_mode,
            tcp_alive_ports=alive_ports,
            enable_udp_probe=args.udp_probe,
            enable_ttl_os=args.ttl_os,
            snmp_communities=snmp_communities,
            enrich_timeout=args.enrich_timeout,
            progress=args.progress,
            scan_delay_ms=args.scan_delay,
            randomize_scan=args.randomize_scan,
        )
        disc_block["discovery_mode"] = args.discovery_mode
        disc_block["alive_ports"]    = alive_ports

        # Merge passive observations into active results
        if passive_result_obj and hosts:
            print("\n  Merging passive observations …")
            hosts = passive_result_obj.merge_into_hosts(hosts, oui_map)

        # Port probing
        if args.probe_ports and hosts:
            print()
            probe_ports = sorted(set(
                int(p.strip()) for p in args.ports.split(",")
                if p.strip().isdigit() and 1 <= int(p.strip()) <= 65535))
            hosts = port_probe_hosts(
                hosts, ports=probe_ports,
                max_concurrent=args.workers,
                include_service_hints=args.service_hints,
                progress=args.progress,
            )
            disc_block["probed_ports"]  = probe_ports
            disc_block["service_hints"] = args.service_hints

        disc_block["hosts"] = hosts

        # Diff
        if not args.no_diff:
            prev = find_latest_report(outdir, stamp)
            if prev:
                diff = compute_diff(hosts, prev)
                disc_block["diff"] = diff
            else:
                print("  Diff: no previous report — this run becomes the baseline.")
    else:
        print("  [7/8] Discovery: skipped  (use --discover or --passive-extended)")

    report["discovery"] = disc_block

    # ── CVE check ─────────────────────────────────────────────────────────────
    cve_map_result: Dict[str, List[Dict]] = {}
    if args.cve_check and hosts:
        print("\n  CVE cross-reference …")
        cve_cache_path = os.path.join(outdir, "cve_cache.json")
        cve_map_result = check_cves(
            hosts,
            cache_path=cve_cache_path,
            api_key=args.nvd_api_key or None,
            progress=args.progress,
            min_score=getattr(args, "cve_min_score", 6.0),
            use_kev=getattr(args, "cve_kev", False),
            results_per_query=getattr(args, "cve_results_per_query", 20),
        )
        report["cve_results"] = cve_map_result
    else:
        report["cve_results"] = {}

    # ── Pentest ───────────────────────────────────────────────────────────────
    pentest_results: Dict[str, Any] = {}
    pentest_consent_record: Optional[Dict[str, Any]] = None
    if getattr(args, "pentest", False) and hosts:
        pentest_hosts = [h for h in hosts if h.get("open_ports")]
        if not pentest_hosts:
            print("\n  ⚠  Pentest: no hosts with open ports found. "
                  "Run --probe-ports first.\n")
        else:
            target_ips = [h["ip"] for h in pentest_hosts]
            # Dual consent gate
            pentest_consent_record = pentest_consent_gate(args, target_ips)
            modules = [m.strip() for m in
                       getattr(args, "pentest_modules", "all").split(",")
                       if m.strip()]
            creds = load_pentest_credentials(
                getattr(args, "pentest_credentials", None))
            print(f"\n  Penetration testing {len(pentest_hosts)} host(s) …\n")
            pentest_results = run_pentest(
                pentest_hosts,
                modules=modules,
                creds=creds,
                timeout=getattr(args, "pentest_timeout", 3.0),
                progress=args.progress,
            )
    report["pentest"] = pentest_results
    report["pentest_consent"] = pentest_consent_record

    # ── History ───────────────────────────────────────────────────────────────
    print("  [8/8] Loading history & writing reports …")
    history = load_history(outdir, stamp)
    report["history"] = history

    # Console summary
    if hosts:
        print_discovery_console(hosts, diff=diff, ttl_map=ttl_map,
                                show_hints=getattr(args, "service_hints", False))

    # ── Write output ──────────────────────────────────────────────────────────
    scan_elapsed = time.perf_counter() - scan_start

    json_path = os.path.join(outdir, f"network_report_{stamp}.json")
    html_path = os.path.join(outdir, f"network_report_{stamp}.html")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(render_html(
            report,
            scan_elapsed=scan_elapsed,
            diff=diff,
            passive_result=passive_list,
            ssdp_devices=ssdp_devices,
            cve_map=cve_map_result,
            history=history,
            ttl_map=ttl_map,
        ))

    print(f"\n  {'─'*60}")
    print(f"  ✓ Done in {_fmt_elapsed(scan_elapsed)}")
    print(f"\n  Reports saved:")
    print(f"    HTML  →  {html_path}")
    print(f"    JSON  →  {json_path}")
    print(f"    Audit →  {audit_log_path}")
    print(f"  {'─'*60}")

    _audit_write({"event": "scan_complete",
                  "elapsed_seconds": round(scan_elapsed, 2),
                  "html_path": html_path,
                  "json_path": json_path})

    tips = []
    if not _HAS_SCAPY:
        tips.append("pip install scapy    (enables passive sniffing — also needs Npcap on Windows)")
    if not _HAS_PURESNMP:
        tips.append("pip install puresnmp (enables SNMP probing)")
    if not _HAS_ZEROCONF:
        tips.append("pip install zeroconf (enables mDNS/Bonjour browsing)")
    if not _HAS_PARAMIKO:
        tips.append("pip install paramiko (enables SSH credential checks in --pentest)")
    if tips:
        print("\n  Optional packages not installed:")
        for t in tips:
            print(f"    ↳ {t}")

    if not args.discover and not args.passive_extended:
        print("\n  Tip: Run with --discover --i-have-authorization to scan your network.")
    elif not args.probe_ports:
        print("\n  Tip: Add --probe-ports --service-hints for open port and service data.")
    elif not getattr(args, "cve_check", False):
        print("\n  Tip: Add --cve-check --cve-kev to check CVEs and CISA exploited vulns.")
    elif not getattr(args, "pentest", False):
        print("\n  Tip: Add --pentest for active security checks (TLS, headers, creds).")
    print()


if __name__ == "__main__":
    main()