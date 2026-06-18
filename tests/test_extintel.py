"""External-intel target selection, config loading, and finding-building.

No network: only the offline helpers are exercised. The provider HTTP calls are
not invoked.
"""

import json

from omnirecon.engine import extintel


def test_target_ips_skips_private(report):
    targets = extintel._target_ips(report)
    assert "93.184.216.34" in targets         # the public IP
    assert all(not ip.startswith("192.168.") for ip in targets)


def test_target_ips_includes_public_hosts():
    rep = {"public_ip": None, "discovery": {"hosts": [
        {"ip": "192.168.1.5"}, {"ip": "45.33.32.156"}]}}
    assert extintel._target_ips(rep) == ["45.33.32.156"]


def test_load_config_env(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)               # no config files present
    monkeypatch.setenv("SHODAN_API_KEY", "abc")
    monkeypatch.delenv("OMNIRECON_EXTINTEL", raising=False)
    cfg = extintel.load_config()
    assert cfg["shodan_api_key"] == "abc"
    assert extintel._has_any_key(cfg)


def test_load_config_file_wins(tmp_path):
    p = tmp_path / "ext.json"
    p.write_text(json.dumps({"virustotal_api_key": "vt", "max_targets": 3}),
                 encoding="utf-8")
    cfg = extintel.load_config(str(p))
    assert cfg["virustotal_api_key"] == "vt"
    assert cfg["max_targets"] == 3


def test_findings_from_vt_and_shodan():
    providers = {
        "virustotal": {"malicious": 7, "suspicious": 1},
        "shodan": {"vulns": ["CVE-2021-1", "CVE-2021-2"]},
    }
    fs = extintel._findings_for("93.184.216.34", providers)
    titles = {f["title"] for f in fs}
    assert "IP flagged malicious by VirusTotal" in titles
    assert "Known vulnerabilities indexed by Shodan" in titles
    assert any(f["severity"] == "high" for f in fs)


def test_no_findings_when_clean():
    providers = {"virustotal": {"malicious": 0}, "shodan": {"vulns": []}}
    assert extintel._findings_for("93.184.216.34", providers) == []


def test_enrich_skips_without_keys(report, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    for var in ("SHODAN_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET",
                "VT_API_KEY", "VIRUSTOTAL_API_KEY", "OMNIRECON_EXTINTEL"):
        monkeypatch.delenv(var, raising=False)
    res = extintel.enrich(report)
    assert res["by_ip"] == {}
    assert "no API keys" in res["skipped"]
