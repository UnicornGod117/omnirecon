# OmniRecon Architecture

OmniRecon is **two programs**, divided by *purpose and time* — not by feature.

```
   ▓▓ MAIN program ▓▓  (browser is the front door)
   ┌──────────────────────────── web/ (Flask) ────────────────────────────┐
   │   Monitor section            │            One-Time section            │
   │   (over time)                │            (right now)                 │
   └───────────────┬──────────────┴───────────────┬───────────────────────┘
                   ▼                               ▼
            ┌─────────────┐                 ┌──────────────┐
            │  MONITOR    │                 │  ONE-TIME    │
            │ DB·diff·    │                 │ deep·stress· │
            │ trend·score │                 │ PENTEST·report│
            └──────┬──────┘                 └──────┬───────┘
                   └───────────────┬───────────────┘
                                   ▼
                    ┌──────────────────────────┐
                    │        THE BRAIN         │  shared, mode-agnostic,
                    │  engine/ discovery·scan· │  interface-agnostic
                    │        enrich·intel      │  (first-class code)
                    └──────────────────────────┘

   ▓▓ LITE program ▓▓  — a sharp standalone TUI (lite/). Tiny deps, own mini-engine.
   ▓▓ legacy/ ▓▓       — FROZEN. Reference only. Not imported, not executed.
```

- **MAIN** is a **browser-first web application**. The browser is the primary interface because it is the easiest and most malleable way to run it. Behind the web UI sits the shared brain and the two modes (`monitor`, `onetime`). A headless CLI exists too, but it is the **secondary** path — for automation and scheduled monitor scans, not the headline.
- **LITE** is a separate, self-contained program: a nicely made, sharp **TUI** (Textual, with a plain-CLI fallback). Minimal dependencies, its own lightweight engine, no history, no pentest. It never imports the brain.
- **legacy/** is frozen reference code. Nothing in the main program imports or launches it.

---

## The axis of division

The split inside MAIN is **by goal/time**, not by interface:

| | **Monitor** (over time) | **One-time** (right now) |
|---|---|---|
| Question | *"What changed?"* | *"Tell me everything, now."* |
| Web area | Dashboard · History · Assets · Certs · Score | New Scan · live output · report |
| State | Persistent SQLite | Stateless (opt-in save) |
| Owns | history · baselines · deltas · trends · cert tracking · scoring · alerting | deep enumeration · stress testing · **pentest** |
| Audience | sysadmin / homelab watching a network | auditor / pentester hitting a target now |

Both modes are surfaced **through the browser**, and both point the **same brain** at different goals. The brain knows nothing about modes or interfaces — it discovers, scans, enriches, and returns a normalized report. Monitor and one-time are two different *consumers* of that report; the web UI is the *presentation* over both.

---

## Package layout

```
omnirecon/                    repo root
│
├─ omnirecon/                 ▓▓ MAIN · logic ▓▓  (the brain + two modes)
│  ├─ engine/                 ── THE BRAIN (first-class, mode/interface-agnostic) ──
│  │  ├─ primitives.py          ping · tcp_probe · banner · reverse DNS · platform
│  │  ├─ netinfo.py             host-local facts: system · interfaces · routes · ARP
│  │  ├─ oui.py                 MAC → vendor lookup (oui.txt)
│  │  ├─ discovery.py           ping sweep + ARP/vendor/rDNS/is-self enrichment
│  │  ├─ ports.py               threaded TCP port scan
│  │  ├─ enrichment.py          service hints: banner · TLS cert · HTTP title
│  │  ├─ intel.py               CVE/NVD + CISA KEV correlation (opt-in)
│  │  ├─ hygiene.py             derived findings + exposure map + posture grade
│  │  ├─ tags.py                asset role/owner annotations (optional file)
│  │  ├─ report.py              normalized schema + HTML/JSON/CSV/Markdown writers
│  │  └─ engine.py              run_engine(EngineOptions, callbacks) → report
│  │
│  ├─ monitor/                ── MODE 1 · over time (persistent) ──
│  │  ├─ store.py               SQLite: scans · assets · snapshots · certs · deltas
│  │  ├─ score.py               posture scoring
│  │  ├─ alerts.py              webhook · desktop · log on qualifying deltas
│  │  └─ cli.py                 secondary CLI: monitor scan|history|diff|ack|…|alerts
│  │
│  ├─ onetime/                ── MODE 2 · right now (stateless) ──
│  │  ├─ scan.py                deep one-shot orchestration (+ optional --save bridge)
│  │  ├─ pentest/               aggressive suite (authorization-gated)
│  │  │  ├─ runner.py · tls_audit.py · http_checks.py · services.py
│  │  └─ cli.py                 secondary CLI: scan …
│  │
│  └─ cli.py                  secondary/automation entry: `python -m omnirecon`
│
├─ web/                        ▓▓ MAIN · primary interface ▓▓  (browser front door)
│  ├─ app.py                    Flask app driving both modes via the engine IN-PROCESS
│  ├─ jobs.py                   background scan jobs + live progress streaming
│  ├─ templates/                Dashboard · Scan · Findings · Assets · History · Certs · Reports
│  └─ static/                   CSS + JS
│
├─ lite/                       ▓▓ LITE program ▓▓  — standalone sharp TUI + mini-engine
├─ legacy/                     ▓▓ FROZEN ▓▓ — reference only
└─ reports/                    output dir (reports + omnirecon.db)
```

The MAIN program is `omnirecon/` (logic) + `web/` (its browser interface). The clean seam between them is the engine's normalized report.

---

## Load-bearing rules

1. **The browser is the front door.** The web UI surfaces both modes and drives the engine **in-process** (a background job with live progress streamed to the page) — it does **not** subprocess `legacy/`.
2. **`engine/` is mode- and interface-agnostic.** It never imports `monitor`, `onetime`, or `web`; never writes to a DB; never runs pentest. It returns a normalized report dict. *Derived analysis* (`hygiene`, `tags`) lives here too: it only reads the report (and an optional read-only tags file) and annotates it — no network I/O, no persistence.
3. **Monitor owns all persistence and notification.** `store.py` and `alerts.py` live here. A one-time scan never touches a DB or fires an alert unless the user opts in. Alerts dispatch on computed deltas, after the diff.
4. **One-time owns all aggression.** Pentest and stress testing live here and *only* here. They never write to the monitor DB on their own.
5. **The one sanctioned bridge** from one-time → monitor is an opt-in *save* (web checkbox / `--save`), which records the run into the monitor store (e.g. to establish a baseline). Default is report-and-forget.
6. **The CLI is secondary.** It mirrors what the web does for automation and scheduled monitor scans; it is never the only way to do something.
7. **Lite is independent.** Its own lightweight engine, minimal deps, never depends on the brain. Stays runnable as a standalone TUI.
8. **Legacy is cold.** Nothing in the main program imports or launches `legacy/`.

---

## The normalized report schema

Every engine run yields this shape. The monitor store, the web views, and the reporters all read it, so it is the contract that keeps the modes and interfaces decoupled:

```jsonc
{
  "system":   { "timestamp_local": "…", "platform": "…", … },
  "identity": { "hostname": "…", "fqdn": "…" },
  "routes":   { "default_gateway": "…" },
  "discovery": {
    "performed": true,
    "subnets": ["192.168.1.0/24"],
    "hosts": [
      {
        "ip": "192.168.1.10",
        "mac": "aa:bb:cc:dd:ee:ff",   // stable identity key (falls back to ip:<addr>)
        "device_name": "nas.local",
        "device_type": "nas",
        "vendor": "Synology",
        "role": "fileserver",          // from the optional asset-tags file
        "tags": { "owner": "infra" },
        "is_self": false,
        "open_ports": [443, 5000],
        "service_hints": {
          "443": { "banner": "…", "http_title": "…",
                   "tls": { "subject": "CN=nas.local", "issuer": "…",
                            "not_after": "2026-09-01T00:00:00" } }
        }
      }
    ]
  },
  "hygiene": {                          // derived analysis (always on, no I/O)
    "summary": { "score": 82, "grade": "B",
                 "counts": { "high": 0, "medium": 1, "low": 2, "info": 1 } },
    "findings": [ { "severity": "medium", "category": "Exposure", "ip": "…",
                    "title": "…", "detail": "…", "recommendation": "…" } ],
    "by_host":  { "192.168.1.10": { "exposure": { "Web": ["HTTPS (443)"] },
                                    "risk_notes": ["…"], "findings": [ … ] } }
  },
  "pentest": {                          // present only for one-time pentest runs
    "192.168.1.10": {
      "tls_audit":  { "443": { "cert": {…}, "protocols": […], "weak_ciphers": […] } },
      "headers":    { "443": {…} },
      "http_vulns": { "443": […] },
      "ftp_anon":   {…}, "ssh_defaults": {…}, "smb_enum": {…}
    }
  }
}
```

Asset identity is **MAC-keyed** (`ip:<addr>` fallback) so a device is tracked across scans even when its DHCP lease changes.

---

## How you use it

```
┌─ MAIN (browser) ── python -m web ──────────────────────────────────────┐
│  Monitor area  → Dashboard, History, Assets, Certs, Score (reads DB)    │
│  One-Time area → New Scan: pick targets/modules, watch live output,     │
│                  get a report; optional "save to monitor" checkbox      │
└─────────────────────────────────────────────────────────────────────────┘

┌─ MAIN (secondary CLI, for automation / cron) ──────────────────────────┐
│  omnirecon scan [--service-hints] [--cve] [--pentest all --i-have-…]    │
│  omnirecon scan --save                  # seed the monitor baseline      │
│  omnirecon monitor scan                 # scheduled persistent scan      │
│  omnirecon monitor history|diff|ack|certs|assets|score                  │
└─────────────────────────────────────────────────────────────────────────┘

┌─ LITE (standalone) ── python -m lite ──────────────────────────────────┐
│  Sharp Textual TUI (CLI fallback). Quick snapshot, no DB, no pentest.   │
└─────────────────────────────────────────────────────────────────────────┘
```
