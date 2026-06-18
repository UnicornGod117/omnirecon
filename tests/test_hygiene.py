"""Hygiene analysis + the new fold_in_findings merge path."""

from omnirecon.engine import hygiene


def _titles(findings):
    return {f["title"] for f in findings}


def test_analyze_produces_expected_findings(report):
    findings = report["hygiene"]["findings"]
    titles = _titles(findings)
    assert "Telnet exposed" in titles               # 192.168.1.20:23
    assert any("Expired certificate" in t for t in titles)   # nas cert
    assert "Public DNS resolver in use" in titles   # 8.8.8.8
    # A fileserver-tagged NAS must NOT trip "management on a non-server".
    assert "Management interface on a non-server" in titles  # printer (telnet)


def test_summary_grade_and_counts(report):
    summary = report["hygiene"]["summary"]
    assert set(summary["counts"]) == {"high", "medium", "low", "info"}
    assert 0 <= summary["score"] <= 100
    assert summary["grade"] in {"A", "B", "C", "D", "F"}
    assert summary["total"] == len(report["hygiene"]["findings"])


def test_exposure_map_groups_ports(report):
    by_host = report["hygiene"]["by_host"]
    exposure = by_host["192.168.1.50"]["exposure"]
    assert "Web" in exposure
    assert "Database" in exposure
    assert "File Sharing" in exposure


def test_fold_in_findings_rescore(report):
    before = report["hygiene"]["summary"]["score"]
    extra = [hygiene._finding("high", "Plugin: x", "192.168.1.50",
                              "Synthetic high", "detail", "fix")]
    hygiene.fold_in_findings(report, extra)
    after = report["hygiene"]["summary"]
    assert after["score"] < before                      # high finding lowered it
    assert "Synthetic high" in _titles(report["hygiene"]["findings"])
    # The host-level view also gained it.
    assert any(f["title"] == "Synthetic high"
               for f in report["hygiene"]["by_host"]["192.168.1.50"]["findings"])


def test_fold_in_findings_noop_without_hygiene():
    assert hygiene.fold_in_findings({}, [{"severity": "high"}]) == {}
