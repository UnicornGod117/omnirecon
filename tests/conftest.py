"""
Shared pytest fixtures.

Tests are fully offline — they exercise the pure logic (hygiene, reporting,
rules, plugin loading, schedule helpers, intel finding-building) without touching
the network or the OS scheduler. The repo root is on sys.path so `import
omnirecon` resolves when pytest runs from anywhere.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from omnirecon.engine import hygiene  # noqa: E402


@pytest.fixture
def raw_report():
    """A normalized report BEFORE hygiene runs, shaped to trip several findings."""
    return {
        "system": {"timestamp_local": "2026-06-18T10:00:00", "platform": "Test"},
        "identity": {"hostname": "tester", "fqdn": "tester.local"},
        "routes": {"default_gateway": "192.168.1.1"},
        "dns_servers": ["192.168.1.1", "8.8.8.8"],   # 8.8.8.8 → public-DNS finding
        "public_ip": "93.184.216.34",                # routable → external-intel target
        "discovery": {
            "performed": True,
            "subnets": ["192.168.1.0/24"],
            "hosts": [
                {"ip": "192.168.1.1", "mac": "aa:bb:cc:00:00:01", "is_self": False,
                 "device_name": "gateway", "device_type": "router", "role": "router",
                 "open_ports": [53, 443], "service_hints": {}},
                {"ip": "192.168.1.10", "mac": "aa:bb:cc:00:00:10", "is_self": False,
                 "device_name": "nas", "device_type": "nas", "role": "fileserver",
                 "open_ports": [443, 445],
                 "service_hints": {"443": {"tls": {
                     "subject": "CN=nas.local", "not_after": "2000-01-01T00:00:00",
                     "is_self_signed": True}}}},
                {"ip": "192.168.1.20", "mac": "aa:bb:cc:00:00:20", "is_self": False,
                 "device_name": None, "device_type": "printer",
                 "open_ports": [23, 80, 9100], "service_hints": {}},
                {"ip": "192.168.1.50", "mac": "aa:bb:cc:00:00:50", "is_self": False,
                 "device_name": "busybox", "device_type": "host",
                 "open_ports": [21, 22, 53, 80, 139, 443, 445, 3306, 8080],
                 "service_hints": {}},
            ],
        },
    }


@pytest.fixture
def report(raw_report):
    """A report WITH hygiene applied (what writers/plugins normally consume)."""
    raw_report["hygiene"] = hygiene.analyze(raw_report)
    return raw_report


@pytest.fixture
def sample_deltas():
    return [
        {"delta_type": "new_device", "severity": "medium", "ip": "192.168.1.99",
         "detail": {"vendor": "Acme", "device_name": "mystery", "open_ports": [22]}},
        {"delta_type": "port_added", "severity": "medium", "ip": "192.168.1.20",
         "detail": {"port": 22, "role": "printer"}},
        {"delta_type": "cert_expiring", "severity": "medium", "ip": "192.168.1.10",
         "detail": {"port": 443, "days_left": 12, "subject": "CN=nas.local"}},
        {"delta_type": "cert_expiring", "severity": "low", "ip": "192.168.1.11",
         "detail": {"port": 443, "days_left": 200, "subject": "CN=far.local"}},
    ]
