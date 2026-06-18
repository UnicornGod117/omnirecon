"""
SNMP enrichment — query sysName / sysDescr / sysLocation / sysContact over
SNMP v2c using a community list. Optional: needs `puresnmp`. Degrades to None
when the library is absent or the host doesn't answer.
"""

from __future__ import annotations

from typing import Dict, List, Optional

try:
    import puresnmp  # type: ignore
    _HAS_PURESNMP = True
except ImportError:
    _HAS_PURESNMP = False

_SNMP_OIDS = {
    "sysDescr":    "1.3.6.1.2.1.1.1.0",
    "sysName":     "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "sysContact":  "1.3.6.1.2.1.1.4.0",
}


def available() -> bool:
    return _HAS_PURESNMP


def probe(ip: str, communities: List[str],
          timeout_s: float = 1.5) -> Optional[Dict[str, str]]:
    if not _HAS_PURESNMP:
        return None
    for community in communities:
        try:
            results: Dict[str, str] = {}
            for name, oid in _SNMP_OIDS.items():
                try:
                    val = puresnmp.get(ip, community, oid, port=161, timeout=timeout_s)
                    if val is not None:
                        results[name] = str(val).strip()
                except Exception:
                    pass
            if results:
                results["_community"] = community
                return results
        except Exception:
            continue
    return None
