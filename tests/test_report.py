"""Report rendering and the export matrix, including the PDF degrade path."""

import os

from omnirecon.engine import report as report_mod
from omnirecon.engine import topology


def test_render_html_is_self_contained(report):
    html = report_mod.render_html(report)
    assert html.lstrip().lower().startswith("<!doctype html")
    assert "nas.local" in html or "nas" in html
    assert "<script src=" not in html       # self-contained, no external JS


def test_render_markdown(report):
    md = report_mod.render_markdown(report)
    assert md.startswith("#")
    assert "Telnet" in md or "telnet" in md.lower()


def test_write_exports_basic(report, tmp_path):
    out = report_mod.write_exports(report, str(tmp_path), ["json", "csv", "md"],
                                   prefix="t")
    assert set(out) == {"json", "csv", "md"}
    for path in out.values():
        assert os.path.exists(path)


def test_csv_has_header_and_rows(report, tmp_path):
    path = report_mod.write_csv(report, str(tmp_path), prefix="t")
    lines = open(path, encoding="utf-8").read().splitlines()
    assert lines[0].startswith("IP,MAC,Name")
    assert len(lines) == 1 + len(report["discovery"]["hosts"])


def test_pdf_export_degrades_or_succeeds(report, tmp_path):
    out = report_mod.write_exports(report, str(tmp_path), ["pdf"], prefix="t")
    assert "pdf" in out
    if report_mod.pdf_available():
        assert os.path.exists(out["pdf"])
    else:
        assert out["pdf"].startswith("ERROR:")


def test_topology_build(report):
    hosts = report["discovery"]["hosts"]
    graph = topology.build(hosts, report["routes"])
    assert graph["nodes"] and graph["edges"]
    gw_nodes = [n for n in graph["nodes"] if n.get("role") == "gateway"]
    assert gw_nodes and gw_nodes[0]["id"] == "192.168.1.1"
