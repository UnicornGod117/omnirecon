"""One-time mode — right-now, point-in-time scanning.

Owns deep enumeration and the aggressive pentest suite. Stateless by default;
the only path to persistence is an explicit opt-in save into the monitor store.
"""

from .scan import run_onetime_scan

__all__ = ["run_onetime_scan"]
