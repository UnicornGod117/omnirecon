"""
OmniRecon Lite — textual TUI.

Three screens:
  ConfigScreen   — subnets, options, authorization
  ScanScreen     — stage log + live host table + progress bar
  ResultsScreen  — stats + full host table + save/new-scan/quit
"""

from __future__ import annotations

import os
import threading
from typing import Any, Dict, List, Optional, Tuple

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Log,
    ProgressBar,
    Static,
)

from .scanner import (
    DEFAULT_PORTS,
    get_local_ipv4_networks,
    run_scan,
    write_reports,
)


# ── Config screen ─────────────────────────────────────────────────────────────

class ConfigScreen(Screen):
    CSS = """
    ConfigScreen {
        align: center middle;
    }
    #config-box {
        width: 72;
        height: auto;
        background: $surface;
        border: round $primary;
        padding: 1 2;
    }
    .section-title {
        color: $accent;
        text-style: bold;
        margin-top: 1;
    }
    .net-chip {
        color: $text-muted;
        margin: 0 1;
    }
    #auth-warning {
        color: $warning;
        text-style: italic;
        margin-top: 1;
    }
    #start-btn {
        margin-top: 1;
        width: 100%;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="config-box"):
            yield Static("OmniRecon Lite", classes="section-title")
            yield Static("Lightweight network recon — fast, portable, no root required.")

            yield Static(" ", classes="section-title")
            yield Static("Auto-detected networks:", classes="section-title")
            nets = get_local_ipv4_networks()
            if nets:
                for n in nets:
                    yield Static(
                        f"  {n['cidr']}  ({n['interface']})",
                        classes="net-chip",
                    )
            else:
                yield Static("  none detected", classes="net-chip")

            yield Static("Custom subnet (optional):", classes="section-title")
            yield Input(
                placeholder="192.168.1.0/24  or  10.0.0.0/8  (blank = auto)",
                id="subnet-input",
            )

            yield Static("Options:", classes="section-title")
            yield Checkbox("Host discovery (ping sweep)", id="cb-discover", value=True)
            yield Checkbox("Port scan discovered hosts", id="cb-ports", value=True)
            yield Checkbox("Service hints (grab banners)", id="cb-hints", value=False)

            yield Static(
                "⚠ Only scan networks you own or have explicit written authorization to test.",
                id="auth-warning",
            )
            yield Checkbox(
                "I have authorization to scan this network",
                id="cb-auth",
                value=False,
            )

            yield Button("▶  Start Scan", variant="primary", id="start-btn")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "start-btn":
            return

        auth = self.query_one("#cb-auth", Checkbox).value
        discover = self.query_one("#cb-discover", Checkbox).value

        if discover and not auth:
            self.notify(
                "Check 'I have authorization' before scanning.", severity="error"
            )
            return

        subnet_raw = self.query_one("#subnet-input", Input).value.strip()
        subnets = [s.strip() for s in subnet_raw.split(",") if s.strip()] if subnet_raw else []

        config = {
            "discover":      discover,
            "probe_ports":   self.query_one("#cb-ports", Checkbox).value,
            "service_hints": self.query_one("#cb-hints", Checkbox).value,
            "subnets":       subnets,
            "workers":       128,
        }

        self.app.push_screen(ScanScreen(config))


# ── Scan screen ───────────────────────────────────────────────────────────────

class ScanScreen(Screen):
    CSS = """
    ScanScreen {
        layout: vertical;
    }
    #scan-top {
        height: 6;
        padding: 0 1;
    }
    #stage-label {
        color: $accent;
        text-style: bold;
        height: 1;
    }
    #scan-progress {
        height: 1;
        margin-top: 1;
    }
    #scan-body {
        layout: horizontal;
        height: 1fr;
    }
    #stage-log {
        width: 1fr;
        height: 100%;
        border: round $surface-lighten-1;
    }
    #host-table {
        width: 2fr;
        height: 100%;
        border: round $surface-lighten-1;
    }
    """

    def __init__(self, config: dict) -> None:
        super().__init__()
        self._config       = config
        self._report: Optional[Dict[str, Any]] = None
        self._total        = 0
        self._done         = 0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="scan-top"):
            yield Static("Initializing…", id="stage-label")
            yield ProgressBar(total=100, show_eta=False, id="scan-progress")
        with Container(id="scan-body"):
            yield Log(id="stage-log", highlight=True, markup=False)
            yield DataTable(id="host-table", cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#host-table", DataTable)
        table.add_columns("IP", "Hostname", "Vendor", "Type", "Ports")
        self._run_scan()

    @work(thread=True)
    def _run_scan(self) -> None:
        config = dict(self._config)
        config["stage_cb"]    = self._on_stage
        config["progress_cb"] = self._on_progress

        report = run_scan(config, stage_cb=self._on_stage)
        self.app.call_from_thread(self._scan_finished, report)

    def _on_stage(self, name: str) -> None:
        self.app.call_from_thread(self._update_stage, name)

    def _on_progress(self, done: int, total: int) -> None:
        self.app.call_from_thread(self._update_progress, done, total)

    def _update_stage(self, name: str) -> None:
        try:
            label = self.query_one("#stage-label", Static)
            label.update(name)
            log = self.query_one("#stage-log", Log)
            log.write_line(name)
        except Exception:
            pass

    def _update_progress(self, done: int, total: int) -> None:
        try:
            bar = self.query_one("#scan-progress", ProgressBar)
            if total != self._total:
                self._total = total
                bar.update(total=max(1, total))
            bar.progress = done
        except Exception:
            pass

    def _add_host_row(self, host: Dict[str, Any]) -> None:
        try:
            table = self.query_one("#host-table", DataTable)
            ports = ", ".join(map(str, host.get("open_ports", []))) or "—"
            table.add_row(
                host["ip"],
                host.get("hostname") or "—",
                (host.get("vendor") or "—")[:22],
                host.get("device_type") or "—",
                ports,
            )
        except Exception:
            pass

    def _scan_finished(self, report: Dict[str, Any]) -> None:
        self._report = report
        hosts = report.get("discovery", {}).get("hosts", [])
        for h in hosts:
            self._add_host_row(h)
        self.app.push_screen(ResultsScreen(report))


# ── Results screen ────────────────────────────────────────────────────────────

class ResultsScreen(Screen):
    CSS = """
    ResultsScreen {
        layout: vertical;
    }
    #stats-bar {
        height: 3;
        padding: 0 2;
        layout: horizontal;
        background: $surface;
    }
    .stat-cell {
        width: 1fr;
        height: 100%;
        content-align: center middle;
    }
    .stat-label {
        color: $text-muted;
        text-style: bold;
    }
    .stat-value {
        color: $accent;
        text-style: bold;
    }
    #result-table {
        height: 1fr;
    }
    #action-bar {
        height: 3;
        layout: horizontal;
        align: center middle;
        background: $surface;
    }
    #action-bar Button {
        margin: 0 1;
    }
    #save-status {
        color: $success;
        margin: 0 1;
    }
    """

    def __init__(self, report: Dict[str, Any]) -> None:
        super().__init__()
        self._report = report

    def compose(self) -> ComposeResult:
        hosts   = self._report.get("discovery", {}).get("hosts", [])
        n_hosts = len(hosts)
        n_ports = sum(len(h.get("open_ports", [])) for h in hosts)
        pub_ip  = self._report.get("public_ip", {}).get("public_ip") or "unknown"

        yield Header(show_clock=True)
        with Horizontal(id="stats-bar"):
            yield Static(f"Hosts found: [bold]{n_hosts}[/]", markup=True, classes="stat-cell")
            yield Static(f"Open ports: [bold]{n_ports}[/]",  markup=True, classes="stat-cell")
            yield Static(f"Public IP: [bold]{pub_ip}[/]",    markup=True, classes="stat-cell")

        yield DataTable(id="result-table", cursor_type="row")

        with Horizontal(id="action-bar"):
            yield Button("💾  Save Report", id="btn-save", variant="primary")
            yield Button("↩  New Scan",    id="btn-new",  variant="default")
            yield Button("✗  Quit",        id="btn-quit", variant="error")
            yield Static("", id="save-status")

        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#result-table", DataTable)
        table.add_columns("IP", "Hostname", "Vendor", "Type", "Open Ports", "Hint")
        hosts = self._report.get("discovery", {}).get("hosts", [])
        for h in hosts:
            ports = ", ".join(map(str, h.get("open_ports", []))) or "—"
            table.add_row(
                h["ip"],
                h.get("hostname") or "—",
                (h.get("vendor") or "—")[:22],
                h.get("device_type") or "—",
                ports,
                h.get("service_hint") or "—",
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id

        if btn_id == "btn-save":
            self._save_report()

        elif btn_id == "btn-new":
            while len(self.app.screen_stack) > 1:
                self.app.pop_screen()

        elif btn_id == "btn-quit":
            self.app.exit()

    def _save_report(self) -> None:
        outdir = os.path.join(os.getcwd(), "reports")
        try:
            html_path, json_path = write_reports(self._report, outdir)
            status = self.query_one("#save-status", Static)
            status.update(f"Saved → {os.path.relpath(html_path)}")
            self.notify(f"Report saved to {html_path}", title="Saved")
        except Exception as e:
            self.notify(str(e), title="Save failed", severity="error")


# ── App entry point ───────────────────────────────────────────────────────────

class OmniReconLite(App):
    TITLE   = "OmniRecon Lite"
    CSS_PATH = None

    BINDINGS = [
        ("q",      "quit",      "Quit"),
        ("ctrl+c", "quit",      "Quit"),
        ("?",      "help",      "Help"),
    ]

    def on_mount(self) -> None:
        self.push_screen(ConfigScreen())

    def action_help(self) -> None:
        self.notify(
            "OmniRecon Lite — lightweight network recon\n"
            "Start a scan from the config screen.\n"
            "Press Q or Ctrl+C to quit.",
            title="Help",
        )
