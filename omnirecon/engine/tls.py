"""
Stdlib-only TLS certificate retrieval and parsing.

Fetches a server certificate without verification (so self-signed and expired
certs are still inspected), then normalizes it into a small dict whose
`not_after` is ISO-8601 — the format the monitor store and reporters expect.

Shared by enrichment.py (passive service hints) and the pentest tls_audit.
"""

from __future__ import annotations

import datetime as dt
import os
import socket
import ssl
import tempfile
from typing import Any, Dict, List, Optional, Tuple


def _name_to_str(name: Optional[Tuple]) -> str:
    """Flatten ssl's nested RDN structure, preferring commonName."""
    if not name:
        return ""
    flat: Dict[str, str] = {}
    for rdn in name:
        for k, v in rdn:
            flat[k] = v
    return flat.get("commonName") or "; ".join(f"{k}={v}" for k, v in flat.items())


def _parse_ssl_datetime(value: Optional[str]) -> Optional[str]:
    """'Jun  1 12:00:00 2026 GMT' → ISO-8601, or None."""
    if not value:
        return None
    try:
        parsed = dt.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
        return parsed.isoformat()
    except (ValueError, TypeError):
        return None


def _decode_der(der: bytes) -> Optional[Dict[str, Any]]:
    """Parse a DER cert into ssl's dict form via a temp PEM file (stdlib only)."""
    pem = ssl.DER_cert_to_PEM_cert(der)
    tmp = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False, encoding="utf-8")
    try:
        tmp.write(pem)
        tmp.close()
        return ssl._ssl._test_decode_cert(tmp.name)  # type: ignore[attr-defined]
    except Exception:
        return None
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


def fetch_cert(ip: str, port: int, server_hostname: Optional[str] = None,
               timeout: float = 4.0) -> Optional[Dict[str, Any]]:
    """Retrieve and normalize a TLS cert. Returns None if no TLS on the port."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_hostname or ip) as ss:
                version = ss.version()
                cipher = ss.cipher()
                der = ss.getpeercert(binary_form=True)
    except Exception:
        return None

    parsed = _decode_der(der) if der else None
    if parsed is None:
        return {"protocol": version, "cipher": cipher[0] if cipher else None}

    subject = _name_to_str(parsed.get("subject"))
    issuer = _name_to_str(parsed.get("issuer"))
    sans = [v for (t, v) in parsed.get("subjectAltName", ()) if t == "DNS"]
    return {
        "subject":        subject,
        "common_name":    subject,
        "issuer":         issuer,
        "not_after":      _parse_ssl_datetime(parsed.get("notAfter")),
        "not_before":     _parse_ssl_datetime(parsed.get("notBefore")),
        "san":            sans,
        "is_self_signed": bool(subject and issuer and subject == issuer),
        "protocol":       version,
        "cipher":         cipher[0] if cipher else None,
    }


# Protocols/ciphers considered weak for the pentest tls_audit.
_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def probe_protocols(ip: str, port: int, timeout: float = 3.0) -> Dict[str, Any]:
    """Best-effort: which TLS version negotiates, and is it weak?"""
    info = fetch_cert(ip, port, timeout=timeout)
    if not info:
        return {"tls": False}
    proto = info.get("protocol")
    return {
        "tls": True,
        "negotiated_protocol": proto,
        "weak_protocol": proto in _WEAK_PROTOCOLS if proto else False,
        "cipher": info.get("cipher"),
    }
