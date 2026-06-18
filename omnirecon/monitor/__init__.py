"""Monitor mode — persistent, over-time network monitoring.

Owns all persistence (the SQLite store), the diff engine, posture scoring, and
the monitored-scan orchestration. A one-time scan never touches this unless the
user opts in via save.
"""

from .scan import run_monitored_scan
from .store import Store
from . import alerts, score

__all__ = ["run_monitored_scan", "Store", "score", "alerts"]
