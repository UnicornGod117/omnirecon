# OmniRecon — Legacy Scripts

These are the original monolithic Python scripts that OmniRecon was built on. They have been superseded by the structured package in the root of this repository but are kept here as **reference implementations** and because the web UI still uses `omnirecon.py` as its scan engine via subprocess.

---

## Files

### `omnirecon.py` — Full Scan Engine (V6)
The original 5,000+ line all-in-one scan engine. Still actively used: the web UI (`app.py`) invokes it as a subprocess via `omnirecon/scanner.py`.

Features: host discovery, port scanning, service fingerprinting, SNMP, CVE/NVD + CISA KEV lookup, passive sniffing (Scapy), Zeroconf/mDNS, SSDP/UPnP, topology map, full pentest module suite (TLS audit, HTTP headers, HTTP vulns, FTP anon, SSH default creds, SMB enumeration).

### `omnirecon_lite.py` — Lightweight Diagnostic Script (V6)
The original 676-line single-file tool. Replaced by the `lite/` package in the repo root, which provides the same functionality as a proper Python package with a textual TUI and CLI fallback.

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
