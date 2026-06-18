# OmniRecon

A cross-platform network reconnaissance and monitoring platform. It is **two programs**, divided by *purpose*, not by feature — see [ARCHITECTURE.md](ARCHITECTURE.md) for the full design.

| | **Main** | **Lite** |
|---|---|---|
| What | Browser-first platform with two modes | Standalone sharp TUI |
| Launch | `python -m web` (browser) | `python -m lite` |
| Interface | Web UI (primary) · CLI (automation) | Textual TUI → CLI fallback |
| Modes | **Monitor** (over time) + **One-Time** (right now, pentest) | quick snapshot only |
| State | SQLite history + deltas (monitor mode) | none |
| Engine | the rebuilt first-class `omnirecon/engine` brain | its own lightweight mini-engine |
| Best for | full audits, ongoing monitoring, home labs | quick portable snapshots, no install friction |

The **browser is the front door** for the main program. A headless CLI mirrors it for automation and scheduled scans. `legacy/` is frozen reference code — nothing imports or runs it.

---

## The two modes (main program)

The main program points one shared brain at two different goals:

- **Monitor** — *over time.* "What changed?" Persistent SQLite, baselines, deltas, cert tracking, posture scoring. `omnirecon monitor …`
- **One-Time** — *right now.* "Tell me everything." Deep enumeration, stress testing, and **pentest**. Stateless by default. `omnirecon scan …`

Pentest lives only in one-time mode. The one bridge from one-time → monitor is an opt-in *save* (web checkbox / `--save`) that seeds a baseline.

---

## Repository Structure

```
omnirecon/
├── update_oui.py       — Update the MAC vendor (OUI) database
├── oui.txt             — MAC vendor database
├── ARCHITECTURE.md     — full design spec
│
├── omnirecon/          — MAIN · logic (the brain + two modes)
│   ├── __main__.py     — `python -m omnirecon` (secondary CLI)
│   ├── cli.py          — top-level dispatch: scan (one-time) vs monitor
│   ├── engine/         — THE BRAIN (mode/interface-agnostic scan engine)
│   │   ├── primitives.py · netinfo.py · oui.py · discovery.py
│   │   ├── ports.py · enrichment.py · tls.py · snmp.py · ssdp.py
│   │   ├── zeroconf_disc.py · passive.py · topology.py
│   │   ├── intel.py    — CVE/NVD + CISA KEV correlation
│   │   ├── extintel.py — Shodan/Censys/VirusTotal lookup (public IPs)
│   │   ├── hygiene.py  — findings + exposure map + posture grade
│   │   ├── tags.py     — asset role/owner annotations
│   │   ├── plugins.py  — user-droppable analysis/active check loader
│   │   ├── report.py   — normalized schema + HTML/JSON/CSV/MD/PDF writers
│   │   └── engine.py   — run_engine(EngineOptions) → report
│   ├── monitor/        — MODE 1 · over time (persistent)
│   │   ├── store.py    — SQLite: scans · assets · snapshots · certs · deltas
│   │   ├── score.py    — posture scoring
│   │   ├── rules.py    — YAML/JSON alert policies (suppress · re-rate · route)
│   │   ├── alerts.py   — log · webhook · desktop · email on qualifying deltas
│   │   ├── schedule.py — OS scheduler register + daemon loop
│   │   ├── scan.py     — run_monitored_scan()
│   │   └── cli.py      — monitor scan|history|diff|ack|certs|…|daemon|schedule
│   └── onetime/        — MODE 2 · right now (stateless)
│       ├── scan.py     — run_onetime_scan() (+ opt-in --save bridge)
│       ├── pentest/    — tls_audit · http_checks · services · runner
│       └── cli.py      — scan …
│
├── web/                — MAIN · primary interface (browser front door)
│   ├── __main__.py     — `python -m web`
│   ├── app.py          — Flask app (drives the engine in-process)
│   ├── jobs.py         — background scan jobs + live SSE streaming
│   ├── templates/      — Dashboard · Scan · Findings · Assets · History · Certs · Reports
│   └── static/         — CSS + JS
│
├── plugins/            — user-droppable checks (analysis + active) + examples
├── tests/              — offline pytest suite (separate from the app body)
├── pyproject.toml      — packaging + pytest config + optional-dependency extras
├── lite/               — LITE program: standalone TUI + mini-engine
├── legacy/             — FROZEN reference scripts (not imported, not run)
├── examples/           — sample alerts.json · rules.yaml · extintel.json · asset_tags.json
├── reports/            — default output dir (reports + omnirecon.db + alerts.log)
└── expansions.md       — feature roadmap
```

---

## Quick Start

### Main — Web UI (primary)

```bash
# 1. Install dependencies
pip install flask psutil requests

# 2. (optional) Update the MAC vendor database
python update_oui.py

# 3. Launch — the browser opens automatically at http://127.0.0.1:5000
python -m web
```

The dashboard shows scan history, asset inventory, posture score, and certs.
**Findings** surfaces the latest scan's hygiene issues and A–F posture grade;
**Reports** lists every generated artifact (HTML · JSON · CSV · Markdown) for
download. **New Scan** lets you pick a **Scan Type** (Monitor or One-Time),
configure options, and watch live output stream in the browser. One-time scans
are stateless unless you tick *Save to monitor*.

Every report opens as a polished, **dark-mode HTML** page with an executive
summary (posture grade, severity distribution, device-type breakdown, top
issues), a findings table, and a per-host exposure map.

### Main — CLI (automation / scheduled scans)

```bash
# One-time, right-now scan (stateless)
python -m omnirecon scan --service-hints --cve

# Full aggressive suite (authorization required)
python -m omnirecon scan --pentest all --i-have-authorization

# Seed a monitor baseline from a one-time run
python -m omnirecon scan --save

# Monitor mode — persistent, over time
python -m omnirecon monitor scan            # run + record + diff
python -m omnirecon monitor history         # scan timeline
python -m omnirecon monitor diff            # changes since previous scan
python -m omnirecon monitor ack <mac|ip>    # trust a device (or --all)
python -m omnirecon monitor certs           # certificate inventory
python -m omnirecon monitor assets          # asset table
python -m omnirecon monitor score           # posture score

# Scheduled / continuous monitoring
python -m omnirecon monitor daemon --interval 6h        # foreground re-scan loop
python -m omnirecon monitor schedule add --interval 6h  # register an OS job
python -m omnirecon monitor schedule list               # (and: schedule remove)
```

### Alerting, tags & exports

```bash
# Monitor alerting — copy the sample, edit, and monitor scans fire on changes
cp examples/alerts.json reports/alerts.json     # webhook / desktop / log
python -m omnirecon monitor alerts --test        # verify config + send a sample

# Asset tags — annotate devices so findings know what's a server
cp examples/asset_tags.json reports/asset_tags.json
python -m omnirecon scan --tags-file reports/asset_tags.json

# Extra report formats (PDF needs WeasyPrint or wkhtmltopdf)
python -m omnirecon scan --export csv,md,pdf

# Alert policy rules — suppress, re-rate, or route deltas per channel
cp examples/rules.yaml reports/rules.yaml        # needs PyYAML (or use a .json)

# Plugins — drop *.py into ./plugins, then:
python -m omnirecon scan --list-plugins          # see what's discoverable
python -m omnirecon scan --plugins               # run analysis + active plugins

# External intel — Shodan/Censys/VirusTotal on your PUBLIC IP (never LAN)
cp examples/extintel.json reports/extintel.json  # add your API keys
python -m omnirecon scan --extintel
```

Alerts fire on deltas at or above `min_severity` (new device, new open port,
cert expiry, …) through any configured channel: webhook (Slack/Discord/Teams/
ntfy via one URL), email (SMTP), an OS desktop toast, and an always-on
`reports/alerts.log`. A `rules.yaml` can suppress, re-rate, or route them.

### Lite — standalone TUI

Lite is intentionally compact: host discovery, port scan, MAC vendor +
device-type, and an optional basic service banner — no pentest, CVE, passive, or
SNMP. Sharp TUI with a plain-CLI fallback.

```bash
pip install psutil requests textual

python -m lite                          # Textual TUI (auto-falls-back to CLI)
python -m lite --no-tui --service-hints # headless, with banner hints
python -m lite --no-tui --json          # headless, pipeable
```

---

## Scan capabilities (current engine)

The rebuilt engine has full feature parity with the legacy engine:

| Capability | Flag / option |
|---|---|
| Host discovery — modes: auto · arp · icmp · udp · tcp · combined | `--discovery-mode` |
| ARP prime · IPv6 neighbors · UDP probe · TTL OS guess | `--arp-prime --ipv6 --udp-probe --ttl-os` |
| MAC vendor (OUI) + device-type classification | automatic |
| Name resolution: reverse DNS · NetBIOS · mDNS | automatic |
| TCP port scan | `--probe-ports` |
| Service hints (banner · HTTP headers/title · TLS cert) | `--service-hints` |
| SNMP enrichment (sysName/sysDescr) | `--snmp` |
| Zeroconf/mDNS browse · SSDP/UPnP discovery | `--zeroconf --ssdp` |
| Passive sniffing (ARP/mDNS/NetBIOS/SSDP/DHCP/LLMNR) | `--passive` |
| CVE correlation (NVD + CISA KEV + impact classification, cached) | `--cve` |
| Topology map | `--topology` |
| Pentest: tls-audit · headers · http-vulns · ftp-anon · ssh-defaults · smb-enum | `--pentest <modules> --i-have-authorization` |
| **Network hygiene findings** (Telnet/FTP/plaintext mgmt · SMB · exposed DB · self-signed/expired/weak TLS · missing rDNS · public DNS · SMBv1) | automatic |
| **Exposure map + posture grade** (per-host service grouping, A–F score) | automatic |
| **Asset tags** (role/owner annotations; suppress noise on known servers) | `--tags-file` |
| **Plugins** (user-droppable analysis + active checks) | `--plugins` · `--list-plugins` |
| **External intel** (Shodan · Censys · VirusTotal on public IPs) | `--extintel` |
| **Extra exports** (CSV · Markdown · PDF, on top of HTML+JSON) | `--export csv,md,pdf` |
| **Monitor alerting** (log · webhook · desktop · email on qualifying deltas) | `reports/alerts.json` |
| **Alert rule policies** (suppress · re-rate · route deltas) | `reports/rules.yaml` |
| **Scheduling & daemon** (OS scheduler job · foreground loop) | `monitor schedule` · `monitor daemon` |
| Save one-time run to monitor | `--save` |

> Optional dependencies degrade gracefully: SNMP needs `puresnmp`, Zeroconf needs
> `zeroconf`, passive sniffing needs `scapy` (+ root/Npcap), `ssh-defaults` needs
> `paramiko`, `smb-enum` needs `smbprotocol`, YAML rules need `PyYAML`, PDF export
> needs `weasyprint` (or a `wkhtmltopdf` binary). Missing ones are skipped, not fatal.

---

## Dependencies

The core runs on the **standard library**. Everything below is optional and
declared as an extra in `pyproject.toml` — a missing one disables only its
feature.

| Component | Required packages |
|---|---|
| Web UI / main | `flask psutil requests` |
| Lite TUI | `psutil requests textual` |
| Pentest extras | `paramiko` (ssh-defaults), `smbprotocol` (smb-enum) |
| Enrichment extras | `puresnmp` (SNMP), `zeroconf` (mDNS), `scapy` (passive) |
| Alert rules / PDF | `PyYAML` (YAML rules), `weasyprint` (PDF export) |
| Tests | `pytest` (+ `PyYAML`) |

```bash
pip install flask psutil requests textual
pip install -e ".[dev]"        # editable install + test deps, then: pytest
```

---

## Legal

Penetration-testing features must **only** be used on networks you own or have
**explicit written authorization** to test. Unauthorized scanning may violate
local and international law. The web UI requires an authorization checkbox, and
the pentest CLI requires `--i-have-authorization`.

Licensed under the **MIT License** — see [LICENSE](LICENSE).
