"""
Low-level network primitives for the OmniRecon brain.

Pure, dependency-free (stdlib only) helpers used across the engine. These never
know about scan modes — they just do one network thing each. Ported from the
legacy engine so the rebuilt brain retains full capability.
"""

from __future__ import annotations

import concurrent.futures as cf
import datetime as dt
import ipaddress
import os
import platform
import re
import shutil
import socket
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

# Shared pool for reverse DNS so we never mutate the global socket timeout.
_RDNS_POOL: cf.ThreadPoolExecutor = cf.ThreadPoolExecutor(
    max_workers=64, thread_name_prefix="rdns"
)


def now_stamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def iso_now() -> str:
    return dt.datetime.now().isoformat()


def is_windows() -> bool:
    return platform.system().lower().startswith("win")


def is_macos() -> bool:
    return platform.system().lower() == "darwin"


def is_linux() -> bool:
    return platform.system().lower() == "linux"


def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def is_root() -> bool:
    try:
        if is_windows():
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


def check_privileges() -> Dict[str, Any]:
    """What elevated capabilities are available this run (for the report)."""
    root = is_root()
    return {
        "is_root_or_admin": root,
        "raw_socket": root,            # UDP-unreachable probing needs raw sockets
        "passive_sniff": root,         # scapy capture needs root/admin (+ Npcap on Win)
        "platform": platform.system(),
    }


def is_private_or_lan_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback or addr.is_link_local or addr.is_private:
            return True
        if addr.version == 4 and addr in ipaddress.ip_network("100.64.0.0/10"):
            return True
    except Exception:
        pass
    return False


def safe_run(cmd: List[str], timeout: int = 10) -> Dict[str, Any]:
    """Run a subprocess, never raising. Returns stdout/stderr/returncode."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"cmd": cmd, "returncode": p.returncode,
                "stdout": p.stdout.strip(), "stderr": p.stderr.strip()}
    except Exception as e:
        return {"cmd": cmd, "error": repr(e)}


# ── Liveness probes ───────────────────────────────────────────────────────────

def ping_with_ttl(ip: str, timeout_s: int = 1) -> Tuple[bool, Optional[int]]:
    """Ping and extract the response TTL. Returns (alive, ttl)."""
    if is_windows():
        cmd = ["ping", "-n", "1", "-w", str(timeout_s * 1000), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]
    res = safe_run(cmd, timeout=timeout_s + 2)
    alive = res.get("returncode", 1) == 0
    ttl: Optional[int] = None
    if alive:
        m = re.search(r"\bttl=(\d+)\b", res.get("stdout", ""), re.I)
        if m:
            try:
                ttl = int(m.group(1))
            except Exception:
                pass
    return alive, ttl


def ping(ip: str, timeout_s: int = 1) -> bool:
    alive, _ = ping_with_ttl(ip, timeout_s)
    return alive


# Backwards-compatible alias used in a few call sites.
ping_one = ping


_TTL_OS_MAP: List[Tuple[range, str]] = [
    (range(60, 66),   "Linux / macOS / Android"),
    (range(125, 130), "Windows"),
    (range(252, 256), "Cisco / Network gear / FreeBSD"),
    (range(250, 252), "Cisco (some)"),
    (range(30, 33),   "Network gear (low TTL)"),
]


def guess_os_from_ttl(ttl: Optional[int]) -> str:
    if ttl is None:
        return ""
    for rng, label in _TTL_OS_MAP:
        if ttl in rng:
            return label
    return f"Unknown (TTL {ttl})"


def udp_probe_alive(ip: str, port: int = 33434, timeout: float = 0.8) -> bool:
    """
    Send a UDP datagram to a likely-closed port. A live host returns ICMP
    port-unreachable (type 3). Requires a raw socket (root/admin); returns
    False when privilege is insufficient.
    """
    if not is_root():
        return False
    recv_sock: Optional[socket.socket] = None
    send_sock: Optional[socket.socket] = None
    try:
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_sock.settimeout(timeout)
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        send_sock.settimeout(timeout)
        send_sock.sendto(b"\x00" * 8, (ip, port))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = recv_sock.recvfrom(1024)
                if addr[0] != ip or len(data) < 1:
                    continue
                ip_hdr_len = (data[0] & 0x0F) * 4
                if len(data) < ip_hdr_len + 1:
                    continue
                if data[ip_hdr_len] == 3:  # Destination Unreachable
                    return True
            except socket.timeout:
                break
        return False
    except Exception:
        return False
    finally:
        for s in (recv_sock, send_sock):
            if s:
                try:
                    s.close()
                except Exception:
                    pass


def tcp_probe(ip: str, port: int, timeout: float = 0.7) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def grab_banner(ip: str, port: int, timeout: float = 1.5,
                send: Optional[bytes] = None) -> Optional[str]:
    """Best-effort plaintext banner grab. Returns a short decoded string or None."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        if send:
            s.sendall(send)
        data = s.recv(256)
        text = data.decode("utf-8", "replace").strip()
        return text or None
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def resolve_reverse(ip: str, timeout: float = 1.5) -> Optional[str]:
    try:
        fut = _RDNS_POOL.submit(socket.gethostbyaddr, ip)
        name, _, _ = fut.result(timeout=timeout)
        return name
    except Exception:
        return None


def ip_sort_key(ip: str) -> Tuple:
    """Sort IPv4 numerically, IPv6/other lexically after."""
    try:
        return (0,) + tuple(int(p) for p in ip.split("."))
    except Exception:
        return (1, ip)
