"""
Report assembly + writers.

A report is a plain dict following the normalized schema in ARCHITECTURE.md.
This module renders it to a self-contained, dark-mode HTML file (with an
executive summary, charts, findings, and exposure map) and exports it to JSON,
CSV, and Markdown. The monitor store and the web views read the same dict.

Writers:
    write_json      → report_<stamp>.json
    write_reports   → (html, json)   — the default pair
    write_csv       → host inventory CSV
    write_markdown  → report_<stamp>.md
    write_pdf       → report_<stamp>.pdf   (WeasyPrint or wkhtmltopdf; optional)
    write_exports   → any subset of {html, json, csv, md, pdf}, returns {fmt: path}
"""

from __future__ import annotations

import csv
import html as _html
import json
import os
from typing import Any, Dict, List, Tuple

from .primitives import now_stamp

_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
_SEV_COLOR = {"high": "#ef4444", "medium": "#f59e0b", "low": "#3b82f6", "info": "#6b7280"}


# ── Writers ───────────────────────────────────────────────────────────────────

def write_json(report: Dict[str, Any], outdir: str, prefix: str = "report") -> str:
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, f"{prefix}_{now_stamp()}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    return path


def write_reports(report: Dict[str, Any], outdir: str,
                  prefix: str = "report") -> Tuple[str, str]:
    os.makedirs(outdir, exist_ok=True)
    stamp = now_stamp()
    json_path = os.path.join(outdir, f"{prefix}_{stamp}.json")
    html_path = os.path.join(outdir, f"{prefix}_{stamp}.html")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(render_html(report))
    return html_path, json_path


def write_csv(report: Dict[str, Any], outdir: str, prefix: str = "report") -> str:
    """Host-inventory CSV — one row per discovered host."""
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, f"{prefix}_{now_stamp()}.csv")
    hosts = (report.get("discovery") or {}).get("hosts", [])
    by_host = (report.get("hygiene") or {}).get("by_host", {})
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["IP", "MAC", "Name", "Vendor", "Type", "Role", "OS Guess",
                    "Open Ports", "Risk Notes"])
        for h in hosts:
            notes = "; ".join(by_host.get(h.get("ip"), {}).get("risk_notes", []))
            w.writerow([
                h.get("ip", ""), h.get("mac", "") or "",
                h.get("device_name") or h.get("reverse_dns") or "",
                h.get("vendor") or "", h.get("device_type") or "",
                h.get("role") or (h.get("tags") or {}).get("role") or "",
                h.get("os_guess") or "",
                " ".join(map(str, h.get("open_ports") or [])), notes,
            ])
    return path


def write_markdown(report: Dict[str, Any], outdir: str, prefix: str = "report") -> str:
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, f"{prefix}_{now_stamp()}.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_markdown(report))
    return path


def pdf_available() -> bool:
    """Whether a PDF backend (WeasyPrint or wkhtmltopdf) is usable."""
    try:
        import weasyprint  # type: ignore  # noqa: F401
        return True
    except Exception:
        pass
    import shutil
    return shutil.which("wkhtmltopdf") is not None


def write_pdf(report: Dict[str, Any], outdir: str, prefix: str = "report") -> str:
    """Render the HTML report to PDF via WeasyPrint, falling back to a
    wkhtmltopdf binary. Raises RuntimeError if neither is available."""
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, f"{prefix}_{now_stamp()}.pdf")
    html_str = render_html(report)
    try:
        import weasyprint  # type: ignore
        weasyprint.HTML(string=html_str).write_pdf(path)
        return path
    except ImportError:
        pass
    import shutil
    import subprocess
    import tempfile
    if shutil.which("wkhtmltopdf"):
        with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False,
                                         encoding="utf-8") as tf:
            tf.write(html_str)
            tmp = tf.name
        try:
            r = subprocess.run(["wkhtmltopdf", "--quiet", tmp, path],
                               capture_output=True, text=True)
            if r.returncode != 0:
                raise RuntimeError(f"wkhtmltopdf failed: {r.stderr.strip()}")
        finally:
            os.unlink(tmp)
        return path
    raise RuntimeError(
        "PDF export needs WeasyPrint (`pip install weasyprint`) or the "
        "wkhtmltopdf binary on PATH.")


def write_exports(report: Dict[str, Any], outdir: str, formats: List[str],
                  prefix: str = "report") -> Dict[str, str]:
    """Write any subset of {html,json,csv,md,pdf}. Returns {format: path}.

    A failed PDF export (no backend installed) is reported as an error string
    under the "pdf" key rather than aborting the other formats."""
    out: Dict[str, str] = {}
    writers = {
        "json": lambda: write_json(report, outdir, prefix),
        "csv": lambda: write_csv(report, outdir, prefix),
        "md": lambda: write_markdown(report, outdir, prefix),
    }
    if "html" in formats:
        stamp = now_stamp()
        html_path = os.path.join(outdir, f"{prefix}_{stamp}.html")
        os.makedirs(outdir, exist_ok=True)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(render_html(report))
        out["html"] = html_path
    for fmt in formats:
        if fmt in writers:
            out[fmt] = writers[fmt]()
    if "pdf" in formats:
        try:
            out["pdf"] = write_pdf(report, outdir, prefix)
        except RuntimeError as e:
            out["pdf"] = f"ERROR: {e}"
    return out


# ── HTML helpers ──────────────────────────────────────────────────────────────

def _esc(s: Any) -> str:
    return _html.escape(str(s), quote=True)


def _section(title: str, body: str) -> str:
    return f'<section><h2>{_esc(title)}</h2>{body}</section>' if body else ""


def _device_breakdown(hosts: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for h in hosts:
        t = h.get("device_type") or "Unknown"
        counts[t] = counts.get(t, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


def _bar(label: str, value: int, total: int, color: str) -> str:
    pct = int(value / total * 100) if total else 0
    return (
        f'<div class="bar-row"><span class="bar-label">{_esc(label)}</span>'
        f'<span class="bar-track"><span class="bar-fill" style="width:{pct}%;'
        f'background:{color}"></span></span>'
        f'<span class="bar-val">{value}</span></div>'
    )


def _exec_summary(report: Dict[str, Any]) -> str:
    hosts = (report.get("discovery") or {}).get("hosts", [])
    hyg = report.get("hygiene") or {}
    summary = hyg.get("summary") or {}
    counts = summary.get("counts") or {"high": 0, "medium": 0, "low": 0, "info": 0}
    n_ports = sum(len(h.get("open_ports") or []) for h in hosts)
    grade = summary.get("grade", "—")
    score = summary.get("score", "—")
    findings = hyg.get("findings", [])

    grade_color = {"A": "#22c55e", "B": "#84cc16", "C": "#f59e0b",
                   "D": "#f97316", "F": "#ef4444"}.get(grade, "#6b7280")

    cards = "".join([
        f'<div class="card"><div class="card-num" style="color:{grade_color}">{_esc(grade)}'
        f'</div><div class="card-lbl">Posture · {_esc(score)}/100</div></div>',
        f'<div class="card"><div class="card-num">{len(hosts)}</div>'
        f'<div class="card-lbl">Hosts</div></div>',
        f'<div class="card"><div class="card-num">{n_ports}</div>'
        f'<div class="card-lbl">Open ports</div></div>',
        f'<div class="card"><div class="card-num" style="color:{_SEV_COLOR["high"]}">'
        f'{counts.get("high",0)}</div><div class="card-lbl">High findings</div></div>',
        f'<div class="card"><div class="card-num" style="color:{_SEV_COLOR["medium"]}">'
        f'{counts.get("medium",0)}</div><div class="card-lbl">Medium findings</div></div>',
    ])

    # Severity distribution
    sev_total = sum(counts.values()) or 1
    sev_bars = "".join(
        _bar(sev.capitalize(), counts.get(sev, 0), sev_total, _SEV_COLOR[sev])
        for sev in ("high", "medium", "low", "info")
    )

    # Device-type breakdown
    dev = _device_breakdown(hosts)
    dev_total = sum(dev.values()) or 1
    dev_bars = "".join(
        _bar(t, n, dev_total, "#38bdf8") for t, n in list(dev.items())[:8]
    ) or '<p class="dim">No hosts.</p>'

    # Top issues
    top = findings[:6]
    if top:
        items = "".join(
            f'<li><span class="sev sev-{f["severity"]}">{f["severity"].upper()}</span> '
            f'{_esc(f["title"])}<span class="dim"> — {_esc(f.get("ip") or "local")}</span></li>'
            for f in top
        )
        top_block = f'<ul class="top-issues">{items}</ul>'
    else:
        top_block = '<p class="dim ok">No hygiene issues detected. ✓</p>'

    return (
        '<section class="exec"><h2>Executive Summary</h2>'
        f'<div class="cards">{cards}</div>'
        '<div class="charts">'
        f'<div class="chart"><h3>Findings by severity</h3>{sev_bars}</div>'
        f'<div class="chart"><h3>Device types</h3>{dev_bars}</div>'
        '</div>'
        f'<div class="chart"><h3>Top issues</h3>{top_block}</div>'
        '</section>'
    )


def _findings_table(report: Dict[str, Any]) -> str:
    findings = (report.get("hygiene") or {}).get("findings", [])
    if not findings:
        return ""
    rows = "".join(
        f'<tr><td><span class="sev sev-{f["severity"]}">{f["severity"].upper()}</span></td>'
        f'<td>{_esc(f.get("category",""))}</td>'
        f'<td>{_esc(f.get("ip") or "—")}</td>'
        f'<td><b>{_esc(f.get("title",""))}</b><br><span class="dim">{_esc(f.get("detail",""))}</span></td>'
        f'<td>{_esc(f.get("recommendation",""))}</td></tr>'
        for f in findings
    )
    return _section("Security Findings",
        '<table><thead><tr><th>Severity</th><th>Category</th><th>Host</th>'
        f'<th>Finding</th><th>Recommendation</th></tr></thead><tbody>{rows}</tbody></table>')


def _host_rows(hosts: List[Dict[str, Any]], by_host: Dict[str, Any]) -> str:
    rows = ""
    for h in hosts:
        ports = ", ".join(map(str, h.get("open_ports", []))) or "—"
        name = h.get("device_name") or h.get("reverse_dns") or ""
        tag = ""
        if h.get("is_self"):
            tag = ' <span class="badge self">this host</span>'
        elif h.get("passive_only"):
            tag = ' <span class="badge passive">passive</span>'
        role = h.get("role") or (h.get("tags") or {}).get("role") or ""
        if role:
            tag += f' <span class="badge role-tag">{_esc(role)}</span>'
        os_guess = h.get("os_guess") or ""
        icon = h.get("device_icon") or ""
        notes = by_host.get(h.get("ip"), {}).get("risk_notes", [])
        note_cell = (f'<span class="sev sev-warn">{len(notes)}</span>' if notes else "—")
        rows += (
            f'<tr><td>{_esc(h["ip"])}{tag}</td>'
            f'<td>{_esc(h.get("mac") or "")}</td>'
            f'<td>{_esc(name)}</td>'
            f'<td>{_esc(h.get("vendor") or "")}</td>'
            f'<td>{_esc(icon)} {_esc(h.get("device_type") or "")}</td>'
            f'<td>{_esc(os_guess)}</td>'
            f'<td class="ports">{_esc(ports)}</td>'
            f'<td>{note_cell}</td></tr>'
        )
    return rows


def _signal_bar(pct: Any) -> str:
    try:
        p = max(0, min(100, int(pct)))
    except (TypeError, ValueError):
        return ""
    color = "#22c55e" if p >= 66 else "#f59e0b" if p >= 33 else "#ef4444"
    return (f'<span class="sig-track"><span class="sig-fill" '
            f'style="width:{p}%;background:{color}"></span></span>')


def _wifi_panel(wifi: Dict[str, Any], gw_info: Dict[str, Any]) -> str:
    """Render the wireless/router uplink as a labelled detail grid."""
    if not wifi or not wifi.get("connected"):
        note = "Wired or no wireless link detected."
        if wifi and wifi.get("error"):
            note += f' ({_esc(wifi["error"])})'
        return f'<div class="uplink-card"><div class="exp-ip">Uplink</div>' \
               f'<p class="dim">{note}</p></div>'

    dbm = wifi.get("signal_dbm")
    pct = wifi.get("signal_pct")
    sig_txt = "—"
    if dbm is not None or pct is not None:
        bits = []
        if dbm is not None:
            bits.append(f"{_esc(dbm)} dBm")
        if pct is not None:
            bits.append(f"{_esc(pct)}%")
        q = wifi.get("signal_quality")
        if q:
            bits.append(f"({_esc(q)})")
        sig_txt = " ".join(bits) + _signal_bar(pct)

    rate = "—"
    if wifi.get("tx_rate_mbps") or wifi.get("rx_rate_mbps"):
        rate = (f'↑ {_esc(wifi.get("tx_rate_mbps") or "—")} / '
                f'↓ {_esc(wifi.get("rx_rate_mbps") or "—")} Mbps')
    chan = wifi.get("channel")
    if chan and wifi.get("channel_width_mhz"):
        chan = f'{chan} ({_esc(wifi["channel_width_mhz"])} MHz wide)'

    rows = [
        ("SSID", wifi.get("ssid")),
        ("BSSID (AP radio)", wifi.get("bssid")),
        ("Signal", sig_txt),
        ("Band", wifi.get("band")),
        ("Channel", chan),
        ("Frequency", f'{_esc(wifi["frequency_mhz"])} MHz' if wifi.get("frequency_mhz") else None),
        ("PHY / mode", wifi.get("phy_mode")),
        ("Security", wifi.get("security")),
        ("Link rate", rate),
        ("Tx power", f'{_esc(wifi["tx_power_dbm"])} dBm' if wifi.get("tx_power_dbm") else None),
        ("SNR", f'{_esc(wifi["snr_db"])} dB' if wifi.get("snr_db") is not None else None),
        ("Noise", f'{_esc(wifi["noise_dbm"])} dBm' if wifi.get("noise_dbm") is not None else None),
        ("Beacon interval", wifi.get("beacon_interval")),
        ("DTIM period", wifi.get("dtim_period")),
        ("BSS flags", wifi.get("bss_flags")),
        ("Interface", wifi.get("interface")),
    ]
    body = "".join(
        f'<div class="exp-grp"><span class="exp-lbl">{_esc(k)}</span>'
        f'<span class="exp-svc">{v if k == "Signal" else _esc(v)}</span></div>'
        for k, v in rows if v not in (None, "", "—") or k == "Signal"
    )
    return (f'<div class="uplink-card"><div class="exp-ip">📶 Wireless uplink → '
            f'{_esc(wifi.get("ssid") or "router")}</div>{body}</div>')


def _router_panel(gw_info: Dict[str, Any]) -> str:
    if not gw_info or not gw_info.get("ip"):
        return ""
    rows = [
        ("Gateway IP", gw_info.get("ip")),
        ("MAC (ARP)", gw_info.get("mac")),
        ("Vendor", gw_info.get("vendor")),
        ("Name", gw_info.get("device_name")),
        ("ARP state", gw_info.get("arp_state")),
        ("Local interface", gw_info.get("interface")),
        ("Uplink", gw_info.get("uplink")),
        ("Open ports", ", ".join(map(str, gw_info.get("open_ports") or [])) or None),
    ]
    body = "".join(
        f'<div class="exp-grp"><span class="exp-lbl">{_esc(k)}</span>'
        f'<span class="exp-svc">{_esc(v)}</span></div>'
        for k, v in rows if v not in (None, "")
    )
    return f'<div class="uplink-card"><div class="exp-ip">🌐 Router / gateway</div>{body}</div>'


def _neighbors_block(report: Dict[str, Any]) -> str:
    """ARP / NDP neighbor table rendered as a tidy sortable table."""
    nb = report.get("neighbors") or {}
    neighbors = nb.get("neighbors") or []
    if not neighbors:
        return ""
    gw = (report.get("routes") or {}).get("default_gateway")
    rows = ""
    for n in sorted(neighbors, key=lambda x: (x.get("version", 4), str(x.get("ip")))):
        tag = ' <span class="badge role-tag">gateway</span>' if n.get("ip") == gw else ""
        rows += (
            f'<tr><td>{_esc(n.get("ip"))}{tag}</td>'
            f'<td>{_esc(n.get("mac") or "—")}</td>'
            f'<td>IPv{_esc(n.get("version") or 4)}</td>'
            f'<td>{_esc(n.get("interface") or "—")}</td>'
            f'<td>{_esc(n.get("state") or "—")}</td></tr>'
        )
    return _section(
        f"ARP / NDP Neighbors ({len(neighbors)})",
        '<table><thead><tr><th>IP</th><th>MAC</th><th>Family</th>'
        f'<th>Interface</th><th>State</th></tr></thead><tbody>{rows}</tbody></table>')


def _exposure_block(report: Dict[str, Any]) -> str:
    by_host = (report.get("hygiene") or {}).get("by_host", {})
    cards = ""
    for ip, info in by_host.items():
        exposure = info.get("exposure") or {}
        if not exposure:
            continue
        groups = "".join(
            f'<div class="exp-grp"><span class="exp-lbl">{_esc(grp)}</span>'
            f'<span class="exp-svc">{_esc(", ".join(svcs))}</span></div>'
            for grp, svcs in exposure.items()
        )
        notes = info.get("risk_notes") or []
        notes_html = (
            '<div class="exp-notes">⚠ ' + " · ".join(_esc(n) for n in notes) + '</div>'
            if notes else ""
        )
        cards += f'<div class="exp-card"><div class="exp-ip">{_esc(ip)}</div>{groups}{notes_html}</div>'
    return _section("Exposure Map", f'<div class="exp-grid">{cards}</div>') if cards else ""


# ── HTML render ───────────────────────────────────────────────────────────────

def render_html(report: Dict[str, Any]) -> str:
    sys_ = report.get("system", {})
    ident = report.get("identity", {})
    disc = report.get("discovery", {})
    hosts = disc.get("hosts", [])
    routes = report.get("routes", {})
    priv = report.get("privileges", {})
    by_host = (report.get("hygiene") or {}).get("by_host", {})

    host_table = (
        '<table><thead><tr><th>IP</th><th>MAC</th><th>Name</th><th>Vendor</th>'
        '<th>Type</th><th>OS guess</th><th>Open Ports</th><th>Risks</th></tr></thead>'
        f'<tbody>{_host_rows(hosts, by_host)}</tbody></table>'
        if hosts else '<p>No hosts discovered.</p>'
    )

    # CVEs
    cve_block = ""
    findings = (report.get("intel") or {}).get("findings", [])
    if findings:
        crows = "".join(
            f'<tr><td>{_esc(c.get("id"))}{" 🔥KEV" if c.get("kev") else ""}</td>'
            f'<td>{_esc(c.get("score"))}</td><td>{_esc(c.get("impact_icon",""))} {_esc(c.get("impact",""))}</td>'
            f'<td>{_esc(c.get("ip"))}</td><td>{_esc(c.get("service"))}</td>'
            f'<td>{_esc(c.get("description"))}</td></tr>'
            for c in findings
        )
        cve_block = _section("CVE Correlation",
            '<table><thead><tr><th>CVE</th><th>CVSS</th><th>Impact</th><th>Host</th>'
            f'<th>Service</th><th>Summary</th></tr></thead><tbody>{crows}</tbody></table>')

    # Topology
    topo_block = ""
    topo = report.get("topology")
    if topo and topo.get("nodes"):
        def _topo_li(n: Dict[str, Any]) -> str:
            mac = (f'<span class="dim mono">{_esc(n.get("mac"))}</span> '
                   if n.get("mac") else "")
            return (
                f'<li>{_esc(n.get("icon") or "")} <b>{_esc(n.get("label"))}</b> '
                f'<span class="dim">{_esc(n.get("ip") or "")}</span> {mac}'
                f'<span class="role role-{_esc(n.get("role"))}">{_esc(n.get("role"))}</span></li>'
            )
        items = "".join(_topo_li(n) for n in topo["nodes"])
        gw_info = topo.get("gateway_info") or {}
        uplink = (f'<div class="uplink-grid">{_router_panel(gw_info)}'
                  f'{_wifi_panel(report.get("wifi") or topo.get("wifi") or {}, gw_info)}</div>')
        topo_block = _section(
            f"Topology ({_esc(topo.get('node_count'))} nodes, gateway {_esc(topo.get('gateway'))})",
            f'{uplink}<ul class="topo">{items}</ul>')

    # SSDP / UPnP
    ssdp_block = ""
    ssdp = report.get("ssdp") or []
    if ssdp:
        srows = "".join(
            f'<tr><td>{_esc(d.get("ip"))}</td><td>{_esc(d.get("friendlyName") or "")}</td>'
            f'<td>{_esc(d.get("manufacturer") or "")}</td><td>{_esc(d.get("modelName") or "")}</td>'
            f'<td>{_esc(d.get("server") or "")}</td></tr>'
            for d in ssdp
        )
        ssdp_block = _section("SSDP / UPnP Devices",
            '<table><thead><tr><th>IP</th><th>Name</th><th>Manufacturer</th>'
            f'<th>Model</th><th>Server</th></tr></thead><tbody>{srows}</tbody></table>')

    # Passive observations
    passive_block = ""
    passive_hosts = [h for h in hosts if h.get("passive_protocols")]
    if passive_hosts:
        prows = "".join(
            f'<tr><td>{_esc(h["ip"])}</td><td>{_esc(", ".join(h.get("passive_protocols", [])))}</td>'
            f'<td>{_esc(", ".join(h.get("passive_services", [])))}</td></tr>'
            for h in passive_hosts
        )
        passive_block = _section("Passive Observations",
            '<table><thead><tr><th>IP</th><th>Protocols</th><th>Services</th></tr></thead>'
            f'<tbody>{prows}</tbody></table>')

    # Pentest
    pentest_block = ""
    pentest = report.get("pentest")
    if pentest:
        pentest_block = _section("Pentest Findings",
            f'<pre>{_esc(json.dumps(pentest, indent=2, ensure_ascii=False))}</pre>')

    return (
        f'<!doctype html><html lang="en" data-theme="dark"><head><meta charset="utf-8">'
        f'<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<title>OmniRecon Report</title><style>{_CSS}</style></head><body>'
        f'<header class="top"><div><h1>OmniRecon Report</h1>'
        f'<div class="meta">Generated {_esc(sys_.get("timestamp_local",""))} · '
        f'{_esc(ident.get("hostname",""))} · {_esc(len(hosts))} host(s) · '
        f'mode={_esc(disc.get("mode",""))} · gateway={_esc(routes.get("default_gateway",""))} · '
        f'{"admin" if priv.get("is_root_or_admin") else "unprivileged"}</div></div>'
        f'<button id="theme" onclick="toggleTheme()" title="Toggle theme">◐</button>'
        f'</header>'
        f'{_exec_summary(report)}'
        f'{_findings_table(report)}'
        f'{_section("Host Inventory", host_table)}'
        f'{_exposure_block(report)}'
        f'{cve_block}{topo_block}{_neighbors_block(report)}{ssdp_block}{passive_block}{pentest_block}'
        f'{_section("Full Report (JSON)", f"<pre>{_esc(json.dumps(report, indent=2, ensure_ascii=False))}</pre>")}'
        f'<script>{_JS}</script>'
        f'</body></html>'
    )


# ── Markdown render ───────────────────────────────────────────────────────────

def render_markdown(report: Dict[str, Any]) -> str:
    sys_ = report.get("system", {})
    ident = report.get("identity", {})
    hosts = (report.get("discovery") or {}).get("hosts", [])
    hyg = report.get("hygiene") or {}
    summary = hyg.get("summary") or {}
    counts = summary.get("counts") or {}
    by_host = hyg.get("by_host", {})

    lines: List[str] = []
    lines.append("# OmniRecon Report")
    lines.append("")
    lines.append(f"_Generated {sys_.get('timestamp_local','')} · "
                 f"{ident.get('hostname','')} · {len(hosts)} host(s)_")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- **Posture:** {summary.get('grade','—')} ({summary.get('score','—')}/100)")
    lines.append(f"- **Findings:** {counts.get('high',0)} high · {counts.get('medium',0)} medium · "
                 f"{counts.get('low',0)} low · {counts.get('info',0)} info")
    lines.append(f"- **Open ports:** {sum(len(h.get('open_ports') or []) for h in hosts)}")
    lines.append("")

    findings = hyg.get("findings", [])
    if findings:
        lines.append("## Security Findings")
        lines.append("")
        lines.append("| Severity | Category | Host | Finding | Recommendation |")
        lines.append("|---|---|---|---|---|")
        for f in findings:
            lines.append(f"| {f['severity'].upper()} | {f.get('category','')} | "
                         f"{f.get('ip') or '—'} | {f.get('title','')} | "
                         f"{f.get('recommendation','')} |")
        lines.append("")

    lines.append("## Host Inventory")
    lines.append("")
    lines.append("| IP | MAC | Name | Vendor | Type | Open Ports | Risks |")
    lines.append("|---|---|---|---|---|---|---|")
    for h in hosts:
        name = h.get("device_name") or h.get("reverse_dns") or ""
        ports = " ".join(map(str, h.get("open_ports") or [])) or "—"
        risks = len(by_host.get(h.get("ip"), {}).get("risk_notes", []))
        lines.append(f"| {h.get('ip','')} | {h.get('mac') or ''} | {name} | "
                     f"{h.get('vendor') or ''} | {h.get('device_type') or ''} | "
                     f"{ports} | {risks or '—'} |")
    lines.append("")

    # Router / wireless uplink
    routes = report.get("routes") or {}
    wifi = report.get("wifi") or {}
    gw = routes.get("default_gateway")
    topo = report.get("topology") or {}
    gw_info = topo.get("gateway_info") or {}
    if gw or wifi.get("connected"):
        lines.append("## Router / Uplink")
        lines.append("")
        lines.append(f"- **Gateway:** {gw or '—'}"
                     + (f" ({gw_info.get('mac')})" if gw_info.get("mac") else ""))
        if gw_info.get("vendor"):
            lines.append(f"- **Gateway vendor:** {gw_info['vendor']}")
        if wifi.get("connected"):
            sig = wifi.get("signal_dbm")
            sig_s = (f"{sig} dBm" if sig is not None else "—")
            if wifi.get("signal_pct") is not None:
                sig_s += f" / {wifi['signal_pct']}%"
            if wifi.get("signal_quality"):
                sig_s += f" ({wifi['signal_quality']})"
            lines.append(f"- **SSID:** {wifi.get('ssid') or '—'}")
            lines.append(f"- **BSSID:** {wifi.get('bssid') or '—'}")
            lines.append(f"- **Signal:** {sig_s}")
            band = wifi.get("band")
            chan = wifi.get("channel")
            if band or chan:
                lines.append(f"- **Band / channel:** {band or '—'} / {chan or '—'}")
            if wifi.get("tx_rate_mbps") or wifi.get("rx_rate_mbps"):
                lines.append(f"- **Link rate:** ↑ {wifi.get('tx_rate_mbps') or '—'} / "
                             f"↓ {wifi.get('rx_rate_mbps') or '—'} Mbps")
            if wifi.get("security"):
                lines.append(f"- **Security:** {wifi['security']}")
        else:
            lines.append("- **Uplink:** wired or no wireless link detected")
        lines.append("")

    # ARP / NDP neighbors
    neighbors = (report.get("neighbors") or {}).get("neighbors") or []
    if neighbors:
        lines.append("## ARP / NDP Neighbors")
        lines.append("")
        lines.append("| IP | MAC | Family | Interface | State |")
        lines.append("|---|---|---|---|---|")
        for n in sorted(neighbors, key=lambda x: (x.get("version", 4), str(x.get("ip")))):
            lines.append(f"| {n.get('ip','')} | {n.get('mac') or '—'} | "
                         f"IPv{n.get('version', 4)} | {n.get('interface') or '—'} | "
                         f"{n.get('state') or '—'} |")
        lines.append("")

    return "\n".join(lines)


# ── Static assets (kept inline so the HTML is fully self-contained) ────────────

_CSS = """
:root{--bg:#0f1419;--panel:#1a2029;--panel2:#222a35;--border:#2c3543;
--text:#e6edf3;--dim:#8b97a7;--accent:#38bdf8}
html[data-theme=light]{--bg:#f7f9fc;--panel:#fff;--panel2:#f0f3f8;--border:#dce3ec;
--text:#111827;--dim:#6b7280;--accent:#0369a1}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:0;
background:var(--bg);color:var(--text);line-height:1.5}
.top{display:flex;justify-content:space-between;align-items:center;
padding:20px 28px;border-bottom:1px solid var(--border)}
h1{margin:0;font-size:22px}h2{font-size:17px;margin:0 0 12px}
h3{font-size:13px;color:var(--dim);text-transform:uppercase;letter-spacing:.04em;margin:0 0 8px}
.meta{color:var(--dim);font-size:12px;margin-top:4px}
#theme{background:var(--panel2);border:1px solid var(--border);color:var(--text);
border-radius:8px;width:38px;height:38px;font-size:18px;cursor:pointer}
section{padding:22px 28px;border-top:1px solid var(--border)}
.exec{border-top:none}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:12px;
padding:14px 18px;min-width:120px;flex:1}
.card-num{font-size:30px;font-weight:700;line-height:1}
.card-lbl{color:var(--dim);font-size:12px;margin-top:6px}
.charts{display:flex;gap:20px;flex-wrap:wrap}
.chart{flex:1;min-width:280px;background:var(--panel);border:1px solid var(--border);
border-radius:12px;padding:14px 18px;margin-bottom:16px}
.bar-row{display:flex;align-items:center;gap:10px;margin:6px 0;font-size:13px}
.bar-label{width:120px;color:var(--dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar-track{flex:1;height:9px;background:var(--panel2);border-radius:5px;overflow:hidden}
.bar-fill{display:block;height:100%;border-radius:5px}
.bar-val{width:28px;text-align:right;font-variant-numeric:tabular-nums}
.top-issues{list-style:none;padding:0;margin:0}
.top-issues li{padding:5px 0;border-bottom:1px solid var(--border);font-size:13px}
.top-issues li:last-child{border:none}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border:1px solid var(--border);padding:8px;text-align:left;vertical-align:top}
th{background:var(--panel2);color:var(--dim);font-weight:600}
td{background:var(--panel)}
.ports{font-family:ui-monospace,monospace;font-size:12px}
.dim{color:var(--dim)}.ok{color:#22c55e}
.sev{font-size:10px;font-weight:700;padding:2px 7px;border-radius:6px;color:#fff;white-space:nowrap}
.sev-high{background:#ef4444}.sev-medium{background:#f59e0b}.sev-low{background:#3b82f6}
.sev-info{background:#6b7280}.sev-warn{background:#f59e0b}
.badge{font-size:10px;padding:1px 6px;border-radius:8px;color:#fff}
.badge.self{background:#2563eb}.badge.passive{background:#7c3aed}.badge.role-tag{background:#0d9488}
ul.topo{list-style:none;padding-left:0}ul.topo li{padding:3px 0}
.role{font-size:10px;padding:1px 6px;border-radius:8px;background:var(--panel2);color:var(--dim)}
.role-gateway{background:#fde68a;color:#000}.role-self{background:#bfdbfe;color:#000}
pre{background:var(--panel2);padding:12px;overflow:auto;border:1px solid var(--border);
border-radius:8px;font-size:12px}
.exp-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}
.exp-card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:12px 14px}
.exp-ip{font-weight:700;font-family:ui-monospace,monospace;margin-bottom:8px}
.exp-grp{display:flex;gap:8px;font-size:12px;padding:2px 0}
.exp-lbl{width:130px;color:var(--dim)}.exp-svc{flex:1}
.exp-notes{margin-top:8px;font-size:12px;color:#f59e0b}
.uplink-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));
gap:12px;margin-bottom:16px}
.uplink-card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:12px 14px}
.mono{font-family:ui-monospace,monospace;font-size:12px}
.sig-track{display:inline-block;vertical-align:middle;width:90px;height:8px;
background:var(--panel2);border-radius:5px;overflow:hidden;margin-left:8px}
.sig-fill{display:block;height:100%;border-radius:5px}
"""

_JS = """
function toggleTheme(){var h=document.documentElement;
h.dataset.theme=h.dataset.theme==='dark'?'light':'dark';
try{localStorage.setItem('omnirecon-theme',h.dataset.theme)}catch(e){}}
(function(){try{var t=localStorage.getItem('omnirecon-theme');
if(t)document.documentElement.dataset.theme=t}catch(e){}})();
"""
