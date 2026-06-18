"""Shared helpers — platform detection, subprocess, network primitives."""

import concurrent.futures as cf
import datetime as dt
import platform
import socket
import subprocess
from typing import Any, Dict, List, Optional

# Module-level pool for reverse DNS to avoid mutating the global socket timeout
_RDNS_POOL: cf.ThreadPoolExecutor = cf.ThreadPoolExecutor(
    max_workers=64, thread_name_prefix="rdns"
)


def now_stamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def is_windows() -> bool:
    return platform.system().lower().startswith("win")


def is_macos() -> bool:
    return platform.system().lower() == "darwin"


def is_linux() -> bool:
    return platform.system().lower() == "linux"


def safe_run(cmd: List[str], timeout: int = 10) -> Dict[str, Any]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"cmd": cmd, "returncode": p.returncode,
                "stdout": p.stdout.strip(), "stderr": p.stderr.strip()}
    except Exception as e:
        return {"cmd": cmd, "error": repr(e)}


def ping(ip: str, timeout_s: int = 1) -> bool:
    if is_windows():
        cmd = ["ping", "-n", "1", "-w", str(timeout_s * 1000), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]
    res = safe_run(cmd, timeout=timeout_s + 2)
    return res.get("returncode", 1) == 0


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


def resolve_reverse(ip: str, timeout: float = 1.5) -> Optional[str]:
    try:
        fut = _RDNS_POOL.submit(socket.gethostbyaddr, ip)
        name, _, _ = fut.result(timeout=timeout)
        return name
    except Exception:
        return None


def grab_banner(ip: str, port: int, timeout: float = 1.2) -> Optional[str]:
    """Best-effort short banner grab for a basic service hint."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in (80, 8080, 8000):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = s.recv(200)
        text = data.decode("utf-8", "replace").strip()
        if not text:
            return None
        # For HTTP, surface the Server header if present.
        for line in text.splitlines():
            if line.lower().startswith("server:"):
                return line.split(":", 1)[1].strip()[:60]
        return text.splitlines()[0][:60]
    except Exception:
        return None
