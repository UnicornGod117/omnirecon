# OmniRecon — Full Codebase Audit Report

> [!NOTE]
> Audit performed on the full repository: [omnirecon.py](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon.py) (5,267 lines), [omnirecon_lite.py](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon_lite.py) (675 lines), [update_oui.py](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/update_oui.py), and [commands.txt](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/commands.txt).

---

## 🔴 Critical Issues (Script-breaking / Data-corrupting)

### 1. Syntax error on last line — `omnirecon.py` won't run
**File:** [omnirecon.py:L5267](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon.py#L5267)
```python
main()in()
```
The final line has garbage appended. This is a `SyntaxError` that **prevents the entire script from executing**.

**Fix:** `main()`

---

### 2. Global suppression of TLS warnings — masks MITM attacks
**File:** [omnirecon.py:L70-74](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon.py#L70-L74)
```python
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
```
This globally silences all TLS verification warnings for the **entire process** — including external API calls to NVD, CISA KEV, and public IP services. An attacker performing MITM on the NVD API could feed malicious CVE data with no warning.

**Fix:** Only use `verify=False` for LAN device probing. Add explicit `verify=True` to all external API calls (NVD, CISA, ipify).

---

### 3. Broken HTML output when no hosts discovered (`omnirecon_lite.py`)
**File:** [omnirecon_lite.py:L541-545](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon_lite.py#L541-L545)
```python
host_table = (
    "<table>..." "<tbody>" + "\n".join(host_rows) + "</tbody></table>"
    if hosts else "<p>No discovery performed...</p>"
)
```
Python's ternary `X if C else Y` has very low precedence. When `hosts` is falsy, the result is a dangling `<table>` tag concatenated with the fallback `<p>`, producing **broken HTML**.

**Fix:** Add explicit parentheses around the truthy branch:
```python
host_table = (
    ("<table>..." "<tbody>" + "\n".join(host_rows) + "</tbody></table>")
    if hosts
    else "<p>No discovery performed...</p>"
)
```

---

### 4. `grab_tls_subject()` always returns `None`
**File:** [omnirecon.py:L1640-1655](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon.py#L1640-L1655)
```python
ctx.verify_mode = ssl.CERT_NONE
...
cert = ssock.getpeercert()  # Returns {} with CERT_NONE
if not cert: return None    # {} is falsy → always returns None
```
With `CERT_NONE`, `getpeercert()` returns an empty dict `{}`. Since `{}` is falsy, the function **never returns certificate data**.

**Fix:** Use `getpeercert(binary_form=True)` and parse with `cryptography`, or set `verify_mode = ssl.CERT_REQUIRED` with `check_hostname = False`.

---

## 🟠 High Severity Issues

### 5. Socket leaks in SSH, FTP, and ARP functions
**Files:** [omnirecon.py:L1601-1608](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon.py#L1601-L1608), [L1667-1674](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon.py#L1667-L1674), [L3143-3146](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon.py#L3143-L3146)
```python
s = socket.create_connection((ip, port), timeout=timeout)
s.settimeout(timeout)
data = s.recv(256); s.close()  # If recv() throws, socket leaks
```
If any exception occurs before `s.close()`, the socket file descriptor leaks. Over hundreds of hosts, this causes `OSError: [Errno 24] Too many open files`.

**Fix:** Use context managers: `with socket.create_connection(...) as s:`

---

### 6. Race condition — `socket.setdefaulttimeout()` mutates global state (`omnirecon_lite.py`)
**File:** [omnirecon_lite.py:L53-59](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon_lite.py#L53-L59)
```python
def resolve_reverse(ip: str, timeout: float = 1.5) -> Optional[str]:
    socket.setdefaulttimeout(timeout)  # Process-wide global!
    name, _, _ = socket.gethostbyaddr(ip)
```
Called from a `ThreadPoolExecutor` with 128 workers. Every thread mutates global socket timeout, affecting **all sockets in the process** including `requests` HTTPS connections and `tcp_probe()`.

**Fix:** Avoid global state. Use `dnspython` for timeout-aware reverse DNS, or save/restore the default timeout with proper locking.

---

### 7. Unhandled exceptions from futures crash discovery (`omnirecon_lite.py`)
**Files:** [omnirecon_lite.py:L456-460](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon_lite.py#L456-L460), [L483-484](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon_lite.py#L483-L484)
```python
for fut in cf.as_completed(futures):
    r = fut.result()  # Unhandled — crashes the entire discovery pass
```

**Fix:** Wrap in `try/except`:
```python
for fut in cf.as_completed(futures):
    try:
        r = fut.result()
        if r: discovered.append(r)
    except Exception:
        pass
```

---

### 8. Working passwords persisted in JSON report
**File:** [omnirecon.py:L2519-2521](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon.py#L2519-L2521)

Successful SSH credential pairs (`username:password`) are stored in `result["findings"]` and serialized to the JSON report on disk. Anyone with read access to the report file can extract working credentials.

**Fix:** Redact passwords in findings: `"admin:****"`. Optionally offer a `--show-creds` flag.

---

### 9. `datetime.utcnow()` and `fromtimestamp()` deprecated (Python 3.12+)
**Files:** [omnirecon.py:L2227](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon.py#L2227), [L2816](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon.py#L2816) · [omnirecon_lite.py:L96](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon_lite.py#L96), [L103](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon_lite.py#L103)

```python
dt.datetime.utcnow()                          # Deprecated
dt.datetime.fromtimestamp(psutil.boot_time())  # Creates naive datetime
```

**Fix:**
```python
dt.datetime.now(dt.timezone.utc)
dt.datetime.fromtimestamp(psutil.boot_time(), tz=dt.timezone.utc)
```

---

### 10. `ssl.PROTOCOL_TLS` deprecated since Python 3.10
**File:** [omnirecon.py:L1991, L2147-2153](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon.py#L1991)

**Fix:** Use `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)` (available since Python 3.6).

---

### 11. SSDP socket `UnboundLocalError` on creation failure
**File:** [omnirecon.py:L1298-1339](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon.py#L1298-L1339)

If `socket.socket()` fails, the `finally: sock.close()` throws `UnboundLocalError`.

**Fix:** Initialize `sock = None` before the try block; check `if sock:` in finally.

---

### 12. `AddressFamily` enum comparison uses string representation (`omnirecon_lite.py`)
**File:** [omnirecon_lite.py:L351](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon_lite.py#L351)
```python
if str(a.family) in ("AddressFamily.AF_INET", "2"):  # Fragile!
```

**Fix:** `if a.family == socket.AF_INET:`

---

## 🟡 Medium Severity Issues

### 13. Enrichment creates 4 thread pools per host (1,016 pools for a /24)
**File:** [omnirecon.py:L3366-3391](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon.py#L3366-L3391)

`_enrich_one()` creates four separate `ThreadPoolExecutor(max_workers=1)` instances per host. For 254 hosts, that's 1,016 thread pool create/destroy cycles.

**Fix:** Share a single executor across all enrichment operations.

---

### 14. Sequential pentest execution — no host-level parallelism
**File:** [omnirecon.py:L2630-2709](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon.py#L2630-L2709)

All pentest modules (TLS audit, HTTP probes, FTP, SSH creds, SMB) run sequentially per host with no parallelism.

**Fix:** Use `concurrent.futures.ThreadPoolExecutor` across hosts.

---

### 15. HTTP path probing: 25 paths × 3s timeout = 75s per host
**File:** [omnirecon.py:L2391-2412](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon.py#L2391-L2412)

`probe_http_vulns()` iterates 25+ sensitive paths sequentially with individual `requests.get()` calls, each with a 3s timeout.

**Fix:** Parallelize with `concurrent.futures` or `aiohttp`.

---

### 16. Connectivity checks run sequentially (`omnirecon_lite.py`)
**File:** [omnirecon_lite.py:L394-421](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon_lite.py#L394-L421)

3 pings (1s each) + 2 HTTP probes (5s each) = **13+ seconds** worst case.

**Fix:** Use `ThreadPoolExecutor` to parallelize all checks.

---

### 17. `asyncio.get_event_loop()` deprecated in async contexts
**File:** [omnirecon.py:L3201, L3205, L3211, L3215](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon.py#L3201)

**Fix:** Use `asyncio.get_running_loop()` (Python 3.10+).

---

### 18. `puresnmp.get()` is the v1.x API — v2.x is async
**File:** [omnirecon.py:L1538-1539](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon.py#L1538-L1539)

**Fix:** Pin `puresnmp<2` in requirements, or migrate to the v2 async API.

---

### 19. `hashlib.md5()` for CVE cache — crashes on FIPS systems
**File:** [omnirecon.py:L1901](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon.py#L1901)

**Fix:** Use `hashlib.md5(..., usedforsecurity=False)` (Python 3.9+) or switch to `sha256`.

---

### 20. Host list materialized into memory before capping (`omnirecon_lite.py`)
**File:** [omnirecon_lite.py:L451](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon_lite.py#L451)
```python
hosts = list(net.hosts())  # 65K objects for a /16 before max_hosts cap
```

**Fix:** `hosts = list(itertools.islice(net.hosts(), max_hosts_per_subnet))`

---

### 21. `load_history()` re-parses ALL previous JSON reports every run
**File:** [omnirecon.py:L2741-2800](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon.py#L2741-L2800)

**Fix:** Maintain a lightweight history summary (SQLite or single JSON file).

---

### 22. IPv6 DNS servers silently dropped (`omnirecon_lite.py`)
**File:** [omnirecon_lite.py:L226-236](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon_lite.py#L226-L236)

Only IPv4 regex `^\d+\.\d+\.\d+\.\d+$` matches. IPv6 DNS servers are silently discarded.

**Fix:** Use `ipaddress.ip_address()` to validate both families.

---

### 23. User-Agent version inconsistency
**Files:** [omnirecon.py:L1347, L1624, L2830, L3118](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon.py#L1347)

Some places say `OmniRecon/5.0`, others `OmniRecon/6.0`. No `__version__` constant exists.

**Fix:** Define `__version__ = "6.0"` and reference it everywhere.

---

### 24. CVE cache has no expiry
**File:** [omnirecon.py:L1729-1744](file:///c:/Users/thiya/Documents/github%20repos/omnirecon/omnirecon.py#L1729-L1744)

Cached CVE results are never refreshed, even if NVD updates the data.

**Fix:** Add a TTL (e.g., 7 days) to cache entries.

---

## 🔵 Modernization Opportunities

| # | What | Where | Suggested Change |
|---|------|-------|------------------|
| 25 | Custom `html_escape()` | Both files | Use `html.escape()` from stdlib |
| 26 | Custom `which()` shells out | omnirecon.py:L617 | Use `shutil.which()` (Python 3.3+) |
| 27 | `os.path` everywhere | Both files | Migrate to `pathlib.Path` |
| 28 | Raw `Dict[str, Any]` for everything | Both files | Use `dataclasses` or `TypedDict` |
| 29 | `import ipaddress` inside functions | omnirecon_lite.py:L360, L431 | Move to top-level imports |
| 30 | `dict.fromkeys()` then `sorted()` | omnirecon_lite.py:L237 | Just use `sorted(set(dns))` |
| 31 | Monolithic 5,267-line file | omnirecon.py | Split into modules: `discovery.py`, `passive.py`, `enrichment.py`, `pentest.py`, `cve.py`, `report.py`, `utils.py` |
| 32 | `paramiko.AutoAddPolicy()` | omnirecon.py:L2496 | Use `WarningPolicy()` and log unknown keys |

---

## 🟢 Missing Features

| # | Feature | Impact |
|---|---------|--------|
| 33 | **No logging framework** — all output via `print()` | Can't control verbosity, no file logging |
| 34 | **No `--quiet` / `--verbose` flags** | Can't script or reduce noise |
| 35 | **No progress indicator** in lite version | 30+ second scans with no feedback |
| 36 | **No signal handling / graceful shutdown** | Ctrl+C leaves threads, sockets, partial files |
| 37 | **No retry logic for NVD API** | Transient failures lose CVE data |
| 38 | **No global `--timeout`** | Scan can run indefinitely on huge/unresponsive networks |
| 39 | **No IPv6 discovery support** | Only IPv4 subnets scanned |
| 40 | **No OUI lookup in lite version** | `oui.txt` exists but lite never uses it |
| 41 | **No exit code semantics** | Always exits 0 regardless of failures |

---

## 📝 `commands.txt` Typos & Issues

| Line | Issue | Fix |
|------|-------|-----|
| L46 | "installion" | "installation" |
| L51 | "pakcages" | "packages" |
| L57 | "Npap" | "Npcap" |
| L52-55 | `--break-system-packages` advice | Recommend venv instead |

---

## 📝 `update_oui.py` Issues

| # | Issue | Fix |
|---|-------|-----|
| 1 | Writes to CWD, not script directory | Use `os.path.dirname(os.path.abspath(__file__))` |
| 2 | No download progress indicator | Add progress bar or dot printing |
| 3 | No checksum/integrity verification | Verify file size matches `content-length` at minimum |
| 4 | 1MB block size is unnecessarily large | Use 8–64KB blocks |

---

## 📊 Summary

| Severity | Count | Key Examples |
|----------|-------|--------------|
| 🔴 **Critical** | 4 | Syntax error prevents running, global TLS suppression, broken HTML, TLS grab always returns None |
| 🟠 **High** | 8 | Socket leaks, race conditions, unhandled futures, passwords in reports, deprecated datetime |
| 🟡 **Medium** | 12 | Thread pool churn, sequential pentest, no parallelism, stale CVE cache |
| 🔵 **Modernization** | 8 | pathlib, dataclasses, stdlib replacements, module splitting |
| 🟢 **Missing Features** | 9 | Logging, graceful shutdown, retries, IPv6, progress bars |

**Total: 41 actionable findings**
