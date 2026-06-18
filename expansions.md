# OmniRecon: Expansion & Overhaul Roadmap

Potential expansions and improvements across appeal, efficiency, effectiveness, and long-term viability.

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

> This is probably the highest-value category. Most tools tell you what your network looks like *today*. Administrators care more about *what changed*.

### Change Tracking & Historical Analysis
Turn OmniRecon from a scanner into a monitoring platform:
```
New devices discovered: 3
Removed devices: 1
New listening services:
  - fileserver:8443
Certificate expiring in 14 days:
  - wiki.company.local
New CVEs since last scan:
  - CVE-2026-XXXX
```

### Snapshot Comparison
Store scans as named snapshots and diff them:
```
omnirecon compare scan_001.json scan_002.json
```
```
Differences Found

+ New Device     Printer-02
+ New Service    NAS TCP/443
- Removed Device Old Laptop
! Cert Changed   internal-api.local
```

### Scheduled Collection
Run OmniRecon as a background service to generate historical records automatically:
```
omnirecon daemon
omnirecon schedule daily
```

### Security Baseline Scoring
Generate a scored posture report — people respond well to measurable trends:
```
Network Security Posture
------------------------
Asset Inventory:        100%
TLS Configuration:       85%
Patch Exposure:          72%
Management Interfaces:   90%

Overall Score: 84/100
```

### Certificate Inventory
Track across the whole network: expiration dates, issuer, subject, SAN entries, weak algorithms. A lot of organizations have poor certificate visibility.
```
Certificates

api.local     Expires: 19 days
nas.local     Expires: 182 days
mail.local    Expired: 3 days ago
```

### Local Vulnerability Intelligence Cache
Rather than querying CVEs live every scan, maintain a local indexed database:
- Sources: NVD, CISA KEV, vendor advisories
- Backend: SQLite or DuckDB (ties into the data backend work below)
- Enables offline lookups and bypasses API rate limits

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
