"""
The OmniRecon brain — a shared, mode- and interface-agnostic scan engine.

Front-ends (web, CLI, monitor, onetime) call run_engine(EngineOptions) and
consume the normalized report it returns. This package never imports monitor,
onetime, or web, and never persists or runs pentest.
"""

from .engine import EngineOptions, run_engine
from .ports import DEFAULT_PORTS
from . import hygiene, report, tags

# We intentionally use verify=False for service hints / pentest against arbitrary
# hosts with self-signed certs; silence the resulting urllib3 warning once.
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

DISCOVERY_MODES = ["auto", "arp", "icmp", "udp", "tcp", "combined"]

__all__ = ["EngineOptions", "run_engine", "DEFAULT_PORTS", "report", "hygiene",
           "tags", "DISCOVERY_MODES"]
