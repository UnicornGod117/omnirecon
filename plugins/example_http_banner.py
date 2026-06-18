"""
Example ActivePlugin — grabs the HTTP `Server:` banner from web ports.

Active plugins probe a host over the network, so they run in ONE-TIME mode only
(`omnirecon scan --plugins`, or the web One-Time area). This one is benign (a
single HEAD request), so it does NOT require authorization. Set
`requires_authorization = True` on plugins that do anything intrusive — they will
then be skipped unless the user passes the pentest consent flag.
"""

import http.client
import socket

from omnirecon.engine.plugins import ActivePlugin, finding

WEB_PORTS = (80, 443, 8000, 8080, 8443, 8888, 9090)


class HttpBannerPlugin(ActivePlugin):
    name = "http-banner"
    description = "Capture the HTTP Server header from web ports"
    requires_authorization = False

    def applies(self, host):
        return bool(set(host.get("open_ports") or []) & set(WEB_PORTS))

    def run(self, host):
        ip = host.get("ip")
        banners = {}
        for port in sorted(set(host.get("open_ports") or []) & set(WEB_PORTS)):
            tls = port in (443, 8443)
            try:
                cls = http.client.HTTPSConnection if tls else http.client.HTTPConnection
                conn = cls(ip, port, timeout=4)
                conn.request("HEAD", "/", headers={"User-Agent": "OmniRecon/7"})
                resp = conn.getresponse()
                server = resp.getheader("Server")
                if server:
                    banners[str(port)] = server
                conn.close()
            except (OSError, socket.error, http.client.HTTPException):
                continue
        return {"server_banners": banners} if banners else {}

    def findings(self, host, result):
        out = []
        for port, server in (result.get("server_banners") or {}).items():
            # Only flag banners that disclose a version number.
            if any(ch.isdigit() for ch in server):
                out.append(finding(
                    "info", "Information Disclosure", host.get("ip"),
                    f"HTTP server banner discloses version on :{port}",
                    f"Server header: {server!r}.",
                    "Suppress or genericize the Server header to avoid "
                    "advertising exact software versions.",
                ))
        return out
