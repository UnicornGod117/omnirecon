# OmniRecon — Legacy Scripts

These are the original monolithic Python scripts that OmniRecon was built on. They have been superseded by the structured package in the root of this repository but are kept here as **reference implementations** and because the web UI still uses `omnirecon.py` as its scan engine via subprocess.

---

## Files

### `omnirecon.py` — Full Scan Engine (V6.1)
The original 5,000+ line all-in-one scan engine. Still actively used: the web UI (`app.py`) invokes it as a subprocess via `omnirecon/scanner.py`.

Features: host discovery, port scanning, service fingerprinting, SNMP, CVE/NVD + CISA KEV lookup, passive sniffing (Scapy), Zeroconf/mDNS, SSDP/UPnP, topology map, full pentest module suite (TLS audit, HTTP headers, HTTP vulns, FTP anon, SSH default creds, SMB enumeration).

**v6.1 recon expansion** — to make the topology section genuinely action-packed:
- **Router/AP uplink** in the topology: SSID, BSSID, RSSI/quality, band/channel, PHY, security, tx/rx rate, BSS beacon/DTIM.
- **Wireless survey** (`--wireless-survey`): every nearby AP, channel utilization + best-channel pick, rogue/evil-twin detection, WPS/weak-security flags.
- **Layer-2 discovery** (`--lldp`): passive LLDP/CDP → switch name, port, VLAN, mgmt IP.
- **Path map** (`--traceroute`): hops to gateway + internet, double-NAT detection.
- **Link quality** (`--link-quality`): latency / jitter / loss to gateway + internet.
- **Anomaly detection** (always on): ARP-spoof/MITM (duplicate MAC, gateway-MAC sharing) + rogue DHCP.
- **WAN exposure** (`--wan-exposure`): UPnP IGD external IP + forwarded ports.
- **Router audit** (`--router-audit`): admin-interface detection, default-credential test (needs `--i-have-authorization`), firmware hint.
- **Bluetooth/BLE** (`--bluetooth`): nearby BT device scan.
- **Software lifecycle** (`--lifecycle`): service version → endoflife.date EOL flags.
- **Passive++**: conversation edges, 802.1Q VLANs, rogue-DHCP servers, passive OS fingerprint, **PCAP export** (`--pcap`).
- **Topology+**: subnet segments, per-AP grouping, critical-node/SPOF inference, communication edges, **graph exports** (`--graph-export` → `.mmd`/`.dot`/`.graphml`).
- **Trends over time** (automatic): topology time-lapse + Wi-Fi signal trend across prior `network_report_*.json` in the output dir.

### `omnirecon_lite.py` — Lightweight Diagnostic Script (V6.1)
The original single-file tool. Replaced by the `lite/` package in the repo root, which provides the same functionality as a proper Python package with a textual TUI and CLI fallback. v6.1 adds a lite subset (kept dependency-free): connected-AP Wi-Fi summary, a tidy ARP/NDP table, and a duplicate-MAC anomaly check.

### `commands.txt` — Quick-Reference Command Sheet
All CLI flags and example invocations for both legacy scripts, organized by tier (local-only → full pentest).

---

## Running the legacy scripts directly

If you want to run them standalone (e.g., without the web UI):

```bash
# Update the MAC vendor database first (run from repo root)
python update_oui.py

# Lightweight — no admin needed
python legacy/omnirecon_lite.py --discover --probe-ports --outdir reports

# Full engine — run from repo root so store.py is importable
python legacy/omnirecon.py --discover --probe-ports --service-hints --topology --outdir reports
```

> **Note:** Run from the **repo root**, not from inside `legacy/`, so that `store.py` and `oui.txt` are found correctly.

### Dependencies

```bash
# Lite only
pip install psutil requests

# Full engine
pip install psutil requests scapy puresnmp zeroconf paramiko
```

On Windows, Scapy requires [Npcap](https://npcap.com/) installed in WinPcap API-compatible mode for raw socket features (passive sniffing, ARP). The rest works without it.

---

## Why they're still here

- `omnirecon.py` is the active scan engine. The web UI's `omnirecon/scanner.py` calls it as a subprocess. Until the engine is fully migrated into the `omnirecon/` package, this file stays.
- `omnirecon_lite.py` serves as the reference spec for the `lite/` package.
- Neither file will be deleted — only eventually replaced by their structured equivalents.
