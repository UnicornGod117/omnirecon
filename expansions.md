# OmniRecon: Expansion & Overhaul Roadmap

Potential expansions and improvements across appeal, efficiency, effectiveness, and long-term viability.

---

## ✅ Delivered in the rebuild

Already shipped in the current build (`omnirecon/` + `web/` + `lite/`):

- **Two-mode architecture** — browser-first main program (Monitor + One-Time) over a shared `engine/` brain; standalone Lite TUI; frozen `legacy/`.
- **Monitoring core** — SQLite store, MAC-keyed identity, baseline/`ack`, severity-rated diff engine, posture scoring, certificate inventory, CVE+CISA KEV correlation with a 7-day cache.
- **Network hygiene checks** — `engine/hygiene.py`: Telnet/FTP/plaintext-mgmt, SMB & exposed-DB ports, self-signed/expired/weak TLS, missing rDNS, public DNS, SMBv1 (from pentest). Role-aware (tagged servers don't trip "mgmt on a non-server").
- **Exposure mapping + posture grade** — per-host service grouping and an A–F report card derived from findings.
- **Asset tags** — `engine/tags.py` + `--tags-file`: IP/MAC → role/owner annotations (`examples/asset_tags.json`).
- **Enhanced reporting** — dark-mode self-contained HTML with an executive summary (grade, severity distribution, device-type breakdown, top issues), findings table, and exposure map. **CSV + Markdown** export (`--export csv,md`).
- **Alerting** — `monitor/alerts.py`: webhook (Slack/Discord/Teams/ntfy), desktop toast, and always-on `reports/alerts.log` on qualifying deltas (`examples/alerts.json`, `monitor alerts --test`).
- **Web front door** — Dashboard, Findings, Assets, History, Certs, Reports (download HTML/JSON/CSV/MD), live-streamed scans.

### Still open (good next lifts)

- **Plugin system** — turn hygiene/pentest checks into user-droppable plugins (see *Effectiveness › Plugin System*).
- **External intel** — Shodan/Censys/VirusTotal exposure context (see *External Intelligence Integration*).
- **Rule engine + scheduling** — YAML alert policies and cron/Task-Scheduler daemon mode (see *Rule Engine*, *Scheduled Collection*).
- **PDF export, Docker image, pytest/CI** — packaging & polish.

---

## Appeal & Usability

### Modern CLI Experience
- **Rich UI**: Integrate `rich` for progress bars, status indicators, and formatted tables.
- **Interactive Mode**: Use `questionary` or `inquirer` to guide users through scan configuration (subnets, modules, report types).
- **Live Dashboard**: A TUI that shows discovery results in real-time as they are found.

### Enhanced Reporting
- **Design**: Modern, responsive HTML report with dark mode support and customizable branding for professional audits.
- **Executive Summary**: High-level dashboard tab with charts (severity distribution, device types, historical trends).
- **Multiple Formats**: PDF (`weasyprint`), Markdown (GitHub/GitLab), and CSV export options.
- **Polished Output**: Most open-source tools have mediocre reports — a well-designed report is a differentiator. Include: executive summary, asset inventory, security findings, network map, change history, risk breakdown.

### Localization
- Multi-language support for HTML reports and CLI prompts.

---

## Monitoring & Change Intelligence

> Most tools tell you what your network looks like *today*. Administrators care more about *what changed*. This section covers what it takes to turn OmniRecon into a monitoring platform — while keeping it fully functional as a one-time scan tool.

---

### Two Modes, One Tool

OmniRecon should operate in two distinct modes that share the same core engine:

| | **Audit Mode** (one-time) | **Monitor Mode** (continuous) |
|---|---|---|
| Invocation | `omnirecon scan` | `omnirecon daemon` |
| Output | HTML/JSON report | Database + alerts + reports |
| State | Stateless | Persistent SQLite DB |
| Audience | Pentesters, one-off audits | Sysadmins, homelabs, SMBs |

The key constraint: **monitor mode features must be opt-in.** A user running a one-time scan should never have to think about a database or a daemon.

---

### The Data Pipeline

Every scan — whether one-time or scheduled — runs the same pipeline. The difference is what happens *after*:

```
Scan
 └─ Normalize assets into a standard schema
     └─ [Audit Mode]   → Generate report → done
     └─ [Monitor Mode] → Write to DB → Diff against last scan → Evaluate rules → Alert
```

The "normalize" step is critical: every asset needs a stable identity across scans (likely MAC address as primary key, with IP as secondary) so the diff engine can match devices even when IPs change.

---

### Asset Identity & The Baseline Problem

The first scan is a bootstrapping problem. OmniRecon needs to know what's "normal" before it can flag anomalies.

**Proposed approach:**
1. First scan creates the **baseline** — all discovered assets are marked `known`, status `trusted`.
2. Subsequent scans diff against the baseline. New findings are marked `unverified` until acknowledged.
3. Users confirm or reject: `omnirecon ack 192.168.1.45` → moves to `trusted`.
4. Unacknowledged new devices stay flagged across every subsequent report until resolved.

```
omnirecon ack --all          # Trust everything in last scan
omnirecon ack 192.168.1.45   # Trust a specific device
omnirecon ignore 192.168.1.99 --reason "guest wifi"
```

This prevents alert fatigue while still surfacing genuinely new things.

---

### The Diff Engine

The core of monitoring. On each scan, compare current state to last scan and categorize every delta by severity:

| Change Type | Severity | Example |
|---|---|---|
| New unacknowledged device | High | Unknown MAC on network |
| New open port on known device | Medium | Port 22 appeared on a printer |
| Device disappeared | Low / Info | Laptop went offline |
| New CVE matched to known asset | High | NVD update hit a tracked version |
| Certificate expiring soon | Medium | <30 days |
| Certificate expired | High | Past expiry |
| Service version changed | Info | Apache 2.4.51 → 2.4.57 |
| IP changed for known MAC | Info | DHCP churn |

Each delta gets a timestamp, severity, and context stored in the DB — not just "it changed," but *what* changed and *when*.

---

### Rule Engine (Alerting Policies)

Users should be able to define what they care about without writing code. A simple YAML-based rule file:

```yaml
# .omnirecon/rules.yaml

rules:
  - name: "New device on network"
    trigger: new_device
    severity: high
    alert: [email, webhook]

  - name: "SSH exposed on non-server"
    trigger: new_service
    match:
      port: 22
      asset_role: "!server"
    severity: medium
    alert: [log]

  - name: "Certificate expiring"
    trigger: cert_expiry
    threshold_days: 30
    alert: [email]

  - name: "Ignore guest devices"
    trigger: new_device
    match:
      subnet: "192.168.10.0/24"
    action: suppress
```

---

### Alert Channels

Keep it simple and progressively configurable:

1. **Local log** — always on, written to `.omnirecon/alerts.log`
2. **Terminal output** — colorized summary at end of each scan run
3. **Email** — SMTP config in `.omnirecon/config.yaml`
4. **Webhook** — POST JSON payload to any URL (covers Slack, Discord, Teams, ntfy, etc.)
5. **Desktop notification** — OS-level toast via `plyer` (good for home lab users)

Webhook format makes it easy to wire into anything without building native integrations.

---

### Scheduled Collection & Daemon Mode

```
omnirecon daemon --interval 6h    # Run every 6 hours in foreground
omnirecon schedule daily 02:00    # Register as a cron/Task Scheduler job
omnirecon schedule add --cron "0 */6 * * *"
```

On Windows: register as a Windows Task Scheduler job.
On Linux/macOS: write a systemd unit or launchd plist.

The daemon doesn't need to be a long-running process — it can be a scheduled invocation that exits cleanly after each run. Simpler, more resilient, easier to debug.

---

### Security Baseline Scoring

Generate a scored posture report — people respond well to measurable trends over time:

```
Network Security Posture          2026-06-17    (↑ +3 from last week)
------------------------
Asset Inventory:        100%  ████████████████████
TLS Configuration:       85%  █████████████████░░░
Patch Exposure:          72%  ██████████████░░░░░░
Management Interfaces:   90%  ██████████████████░░

Overall Score: 84/100

Top Issues:
  [HIGH]   2 certificates expire within 14 days
  [MEDIUM] SMBv1 enabled on fileserver
  [LOW]    3 devices missing reverse DNS
```

Score history stored in the DB so trends are visible over time — not just a snapshot.

---

### Certificate Inventory

Track all TLS certs discovered across the network in one place:

```
Certificate Inventory                    Last updated: 2026-06-17

Host               Expires        Issuer          Status
api.local          19 days        Let's Encrypt   ⚠ Expiring soon
nas.local          182 days       Self-signed     ✓ OK
mail.local         3 days ago     Let's Encrypt   ✗ EXPIRED
internal-ca.local  2 years        Internal CA     ✓ OK
```

Tracks: expiration dates, issuer, subject CN, SAN entries, weak algorithms (SHA-1, RC4), self-signed flag.

---

### Local Vulnerability Intelligence Cache

Rather than querying CVEs live on every scan, maintain a local indexed database updated on demand:

```
omnirecon update-intel     # Pull latest NVD, CISA KEV, vendor feeds
```

- **Sources**: NVD, CISA Known Exploited Vulnerabilities (KEV), vendor-specific advisories
- **Backend**: SQLite (same DB as scan history — one file, no setup)
- **Correlation**: Match discovered service versions against the cache at scan time
- **Offline-capable**: Once updated, works with no internet connection

The KEV list is particularly high-signal — if a CVE is in CISA KEV, it's actively exploited in the wild and should surface as a critical finding immediately.

---

## Asset Management

### Asset Tags
Let users classify and annotate devices in a config file:
```yaml
192.168.1.10:
  role: fileserver
  owner: infrastructure

192.168.1.20:
  role: printer
  owner: office
```
Tagged assets make reports significantly more useful.

### Exposure Mapping
Translate raw port lists into operational context:
```
fileserver

Management Interfaces:
  ✓ HTTPS
  ✓ SSH

File Sharing:
  ✓ SMB

Risk Notes:
  - SSH exposed
  - SMBv1 disabled
```

### Asset Relationship Mapping
Go beyond topology to dependency mapping. Identify critical nodes and single points of failure:
```
Router
 ├─ Switch
 │   ├─ NAS
 │   ├─ Printer
 │   └─ Workstation
 └─ Access Point
     ├─ Phone
     └─ IoT Camera

Single Point of Failure: Core Switch
```

### Vendor & Lifecycle Intelligence
Extend existing OUI support into asset management territory:
```
Synology NAS
  Vendor:   Synology
  Firmware: DSM 7.0
  Status:   Supported
  High-Risk CVEs: 2
```

---

## Efficiency & Performance

### Full Asynchronous Migration
- Transition `pentest` and `enrichment` modules from `ThreadPoolExecutor` to native `asyncio` or `anyio` (addresses the thread pool churn identified in the V6 audit).
- **Adaptive Timing**: Implement Nmap-style `-T` timing profiles (paranoid → insane) to auto-adjust scan speed based on network conditions.

### High-Performance Data Backend
- **SQLite/DuckDB**: Replace history-parsing (reading all JSON files) with a proper local database. Enables instant historical comparisons and complex queries.
- Shared backend for scan history, asset tags, certificate inventory, and vulnerability cache.

### Smart Resource Management
- Centralized task queue across all operations (discovery, enrichment, pentest) to control concurrency and prevent exhaustion on low-power devices.

---

## Effectiveness & Features

### IPv6 First-Class Support
Move beyond NDP table reading. Implement active IPv6 discovery (Multicast Listener Discovery, Neighbor Solicitations) and full port scanning for IPv6 targets.

### Plugin System
The most compelling architectural addition for an open-source project. Let users extend the platform without touching the core:
```python
class Plugin:
    name = "tls_audit"

    def run(asset):
        pass
```
```
plugins/
├─ tls_audit.py
├─ snmp_inventory.py
├─ cert_inventory.py
└─ dns_audit.py
```

### Advanced Fingerprinting
- **Deep Packet Inspection**: Use Scapy more extensively to fingerprint OS/services based on TCP/IP stack quirks, beyond banner grabbing.

### Network Hygiene Checks
Small checks, high value — practical findings for any audit:
- SMBv1 enabled
- Telnet exposed
- HTTP management interfaces
- Self-signed certificates
- Public DNS in use
- Missing reverse DNS
- Open relay indicators
- Unencrypted management protocols

### External Intelligence Integration
- **Cloud Enrichment**: Cross-reference local findings with Shodan, Censys, or VirusTotal.
- **CMDB/ITAM Integration**: Sync with Configuration Management or IT Asset Management systems.

### Expanded Pentest Suite
- **Active Directory**: Basic LDAP/AD checks (null sessions, user listing).
- **Web Fuzzing**: Simple parameter fuzzing for XSS, SQLi, and open redirects.

---

## Architectural Overhaul

### Package Structure
Break the 5,000+ line `omnirecon.py` into a proper Python package:
```
omnirecon/
├── core/        # Scanning engine, asyncio logic
├── discovery/   # ARP, ICMP, UDP, TCP
├── enrichment/  # DNS, SNMP, OUI, Zeroconf
├── modules/     # Pentest modules (pluggable)
├── reporting/   # HTML, JSON, PDF generators
└── utils/       # Helpers, OS-specific logic
```

### API-First Design
- **REST API**: Wrap the core engine in FastAPI or Flask. Run OmniRecon as a background service controllable via browser or remote scripts.
- **Web UI**: React or Vue.js frontend for a full "Cybersecurity Command Center" experience.

### Testing & CI/CD
- **Test Suite**: `pytest` + `mock` covering Windows, Linux, and macOS.
- **Automated Audits**: `bandit` (security) and `mypy` (typing) in CI to catch issues like those found in the V6 audit early.

### Containerization
Official Docker image with all dependencies (libpcap, Scapy, etc.) pre-configured — ensures "it just works" regardless of host OS.
