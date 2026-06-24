"""Pure-logic tests for the v7 recon expansion modules (offline, no I/O)."""

from omnirecon.engine import anomaly, lifecycle, pathmap, topology, trends, wireless


# ── wireless ──────────────────────────────────────────────────────────────────

def test_wireless_analyze_rogue_wps_and_channel():
    aps = [
        {"ssid": "Home", "bssid": "aa:bb:cc:00:00:01", "band": "2.4 GHz",
         "channel": 6, "security": "WPA2", "signal_dbm": -50},
        {"ssid": "Home", "bssid": "de:ad:be:ef:00:01", "band": "2.4 GHz",
         "channel": 1, "security": "Open", "signal_dbm": -70, "wps": True},
    ]
    out = wireless.analyze(aps, {"ssid": "Home", "bssid": "aa:bb:cc:00:00:01"})
    titles = [f["title"] for f in out["findings"]]
    assert "Possible evil-twin / rogue AP" in titles
    assert any("WPS" in t for t in titles)
    assert out["recommended_channel_24ghz"] == 11   # 1 & 6 are taken
    assert len(out["rogue_aps"]) == 1


# ── anomaly ───────────────────────────────────────────────────────────────────

def test_anomaly_duplicate_and_gateway_mac():
    report = {
        "routes": {"default_gateway": "192.168.1.1"},
        "neighbors": {"neighbors": [
            {"ip": "192.168.1.1", "mac": "aa:bb:cc:00:00:01"},
            {"ip": "192.168.1.9", "mac": "aa:bb:cc:00:00:01"},
        ]},
        "dhcp_servers": ["192.168.1.1", "192.168.1.7"],
    }
    findings = anomaly.analyze(report)
    titles = [f["title"] for f in findings]
    assert "One MAC claims multiple IPs" in titles
    assert "Gateway MAC shared with another host" in titles
    assert "Multiple DHCP servers on the segment" in titles
    assert all(f["severity"] == "high" for f in findings)


def test_anomaly_baseline_gateway_mac_change():
    report = {"routes": {"default_gateway": "192.168.1.1"},
              "neighbors": {"neighbors": [{"ip": "192.168.1.1", "mac": "11:11:11:11:11:11"}]}}
    findings = anomaly.analyze(report, baseline_gateway_mac="22:22:22:22:22:22")
    assert any(f["title"] == "Gateway MAC changed" for f in findings)


# ── pathmap ───────────────────────────────────────────────────────────────────

def test_pathmap_parse_and_double_nat():
    text = ("1  192.168.1.1  1.2 ms\n"
            "2  10.0.0.1  5 ms\n"
            "3  * * *\n"
            "4  93.184.216.34  20 ms\n")
    hops = pathmap.parse_hops(text)
    assert len(hops) == 4
    assert hops[2]["timeout"] and hops[2]["ip"] is None
    ana = pathmap.analyze({"hops": hops})
    assert ana["double_nat"] is True
    assert ana["isp_edge_ip"] == "93.184.216.34"
    assert ana["hop_count"] == 3


# ── lifecycle ─────────────────────────────────────────────────────────────────

def test_lifecycle_extract_products():
    pairs = lifecycle.extract_products("Apache/2.4.51 (Ubuntu) OpenSSH_8.2 nginx/1.18.0")
    assert ("apache", "2.4.51") in pairs
    assert ("openssh", "8.2") in pairs
    assert ("nginx", "1.18.0") in pairs


def test_lifecycle_eol_matching():
    cycles = [{"cycle": "2.4", "eol": "2099-01-01", "latest": "2.4.99"},
              {"cycle": "2.2", "eol": "2017-12-31", "latest": "2.2.34"}]
    assert lifecycle._eol_for_version(cycles, "2.4.51")["cycle"] == "2.4"
    assert lifecycle._is_eol("2017-12-31") is True
    assert lifecycle._is_eol("2099-01-01") is False
    assert lifecycle._is_eol(True) is True


# ── topology extras + exports ─────────────────────────────────────────────────

def _topo():
    hosts = [
        {"ip": "192.168.1.1", "device_type": "Network / NAS", "mac": "aa:bb:cc:00:00:01"},
        {"ip": "192.168.1.50", "is_self": True, "mac": "aa:bb:cc:00:00:02"},
        {"ip": "10.0.0.5", "device_type": "Printer", "mac": "aa:bb:cc:00:00:03"},
    ]
    return topology.build(
        hosts, {"default_gateway": "192.168.1.1"},
        local_networks=[{"cidr": "192.168.1.0/24"}, {"cidr": "10.0.0.0/24"}],
        dns_servers=["192.168.1.1"],
        l2_neighbors=[{"protocol": "LLDP", "system_name": "core-sw",
                       "port_id": "Gi0/3", "vlan": 10, "chassis_id": "c1"}],
        conversations=[{"a": "192.168.1.50", "b": "192.168.1.1", "packets": 9}])


def test_topology_segments_switches_spof():
    topo = _topo()
    assert len(topo["segments"]) == 2
    assert topo["switches"] and topo["switches"][0]["system_name"] == "core-sw"
    spofs = [c["ip"] for c in topo["critical_nodes"] if c["spof"]]
    assert "192.168.1.1" in spofs
    assert any(n["role"] == "switch" for n in topo["nodes"])
    assert topo["comm_edges"] and topo["comm_edges"][0]["packets"] == 9


def test_topology_exports():
    topo = _topo()
    assert topology.to_mermaid(topo).startswith("graph TD")
    assert topology.to_dot(topo).startswith("graph omnirecon")
    assert topology.to_graphml(topo).startswith("<?xml")
    # every export format routes through export()
    for fmt in ("mermaid", "dot", "graphml"):
        assert topology.export(topo, fmt)


# ── trends (time-lapse + signal trend) ────────────────────────────────────────

def _reports():
    return [
        {"system": {"timestamp_local": "t1"},
         "discovery": {"hosts": [{"ip": "192.168.1.1"}, {"ip": "192.168.1.2"}]},
         "wifi": {"signal_dbm": -45}},
        {"system": {"timestamp_local": "t2"},
         "discovery": {"hosts": [{"ip": "192.168.1.1"}, {"ip": "192.168.1.2"},
                                 {"ip": "192.168.1.9"}]},
         "wifi": {"signal_dbm": -58}},
    ]


def test_trends_timeline_and_signal():
    out = trends.from_reports(_reports())
    tl = out["topology_timeline"]
    assert tl["added_last"] == ["192.168.1.9"]
    new = [n for n in tl["nodes"] if n["status"] == "new"]
    assert new and new[0]["ip"] == "192.168.1.9"
    st = out["signal_trend"]
    assert st["trend"] == "degraded"
    assert st["delta_db"] == -13


def test_trends_insufficient_signal():
    out = trends.from_reports(_reports()[:1])
    assert out["signal_trend"]["trend"] == "insufficient data"
