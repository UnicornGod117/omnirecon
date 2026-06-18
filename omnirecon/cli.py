#!/usr/bin/env python3
"""
omnirecon — secondary command-line entry point for the MAIN program.

The browser (`python -m web`) is the primary front door; this CLI mirrors it for
automation and scheduled monitor scans.

  omnirecon scan [...]              one-time, right-now scan (stateless; pentest here)
  omnirecon monitor <subcommand>   over-time monitoring (persistent)

Run `omnirecon scan -h` or `omnirecon monitor -h` for details.
"""

from __future__ import annotations

import argparse
import sys

from .monitor import cli as monitor_cli
from .onetime import cli as onetime_cli


def _force_utf8() -> None:
    """Box-drawing output (─ █ ✓) breaks on a cp1252 console — force UTF-8."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except Exception:
            pass


def main(argv=None) -> None:
    _force_utf8()
    ap = argparse.ArgumentParser(
        prog="omnirecon",
        description="OmniRecon — one-time scanning + over-time monitoring.",
    )
    modes = ap.add_subparsers(dest="mode", metavar="{scan,monitor}")
    modes.required = True

    # One-time mode is a single command.
    scan_p = modes.add_parser("scan", help="One-time, right-now scan (pentest lives here)")
    onetime_cli.build_parser(scan_p)

    # Monitor mode has its own subcommands.
    monitor_p = modes.add_parser("monitor", help="Over-time monitoring (persistent)")
    monitor_p.add_argument("--db", default=None, metavar="PATH")
    monitor_sub = monitor_p.add_subparsers(dest="command", metavar="COMMAND")
    monitor_sub.required = True
    monitor_cli.build_parser(monitor_sub)

    args = ap.parse_args(argv)

    if args.mode == "monitor":
        monitor_cli.dispatch(args)
    else:
        args.func(args)


if __name__ == "__main__":
    sys.exit(main())
