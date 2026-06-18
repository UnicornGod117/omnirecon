# OmniRecon

OmniRecon is a comprehensive cross-platform network diagnostic and discovery toolset. This project provides both a lightweight diagnostic script (`omnirecon_lite.py`) and an extended version with advanced security auditing and reconnaissance capabilities (`omnirecon.py`).

## Features

### OmniRecon Lite (Basic)
- **System Info:** OS, platform, and python version details.
- **Identity:** Hostname and FQDN resolution.
- **Network Interfaces:** Detailed breakdown of interfaces, MAC addresses, and IP assignments.
- **Routing:** Default gateway detection and routing table summaries.
- **DNS:** Current DNS configuration.
- **Public IP:** Retrieval via external services.
- **Active Connections:** Sampled list of current network connections and listening ports.
- **Host Discovery:** Ping-based sweep of local subnets with reverse DNS resolution.
- **Port Probing:** Conservative TCP port scanning on discovered hosts.
- **HTML/JSON Reports:** Generates stylized HTML reports and raw JSON data.

### OmniRecon (Advanced/Extended)
- **Passive Sniffing:** Zero-probe discovery using Scapy (ARP, mDNS, NetBIOS, SSDP, DHCP, LLMNR).
- **Service Fingerprinting:** Banner grabbing for SSH, HTTP, and TLS.
- **CVE Cross-Referencing:** Correlations service versions with the NVD (National Vulnerability Database).
- **CISA KEV Integration:** Flags vulnerabilities listed in the Known Exploited Vulnerabilities catalog.
- **Interactive Topology:** Renders a network graph using vis.js.
- **Penetration Testing Module:** Modular suite for TLS audits, HTTP security headers, anonymous FTP, and default credential checks.
- **SNMP Probing:** Retrieves system information from SNMP-enabled devices.

## Requirements

### Basic (OmniRecon Lite)
```bash
pip install psutil requests
```

### Extended (OmniRecon)
```bash
pip install scapy puresnmp zeroconf paramiko
```
*Note: On Windows, Scapy requires [Npcap](https://npcap.com/) installed in WinPcap compatibility mode.*

## Setup

Before running the extended reconnaissance, it is recommended to download or update the vendor database:

```bash
python update_oui.py
```

## Usage

### Lightweight Diagnostics
```bash
# Basic system and network diagnostics
python omnirecon_lite.py

# Include LAN discovery
python omnirecon_lite.py --discover

# Discovery + common port probing
python omnirecon_lite.py --discover --probe-ports --outdir ./reports
```

### Advanced Auditing (Requires Elevation)
```bash
# Extensive scan with CVE check and topology
python omnirecon.py --discover --snmp --probe-ports --service-hints --zeroconf --cve-check --topology --outdir ./reports --i-have-authorization
```

## Legal Warning

The penetration testing features in `omnirecon.py` must **ONLY** be used against networks and systems you own or have explicit written authorization to test. Unauthorized use may violate local and international laws. This tool logs actions for audit purposes.

## License

This project is licensed under the **MIT License**. This ensures you can use and modify the code as long as attribution is maintained. The author provides the software "as is" and is not accountable for any actions taken or damages caused by individuals using this program. See the [LICENSE](LICENSE) file for the full text.
