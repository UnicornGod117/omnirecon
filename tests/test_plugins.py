"""Plugin discovery, analysis execution, and active-plugin auth gating."""

from omnirecon.engine import plugins

ANALYSIS_PLUGIN = '''
from omnirecon.engine.plugins import AnalysisPlugin, finding

class P(AnalysisPlugin):
    name = "synthetic-analysis"
    description = "flags everything"
    def analyze(self, report):
        hosts = (report.get("discovery") or {}).get("hosts", [])
        return [finding("low", "Synthetic", h["ip"], "synthetic finding", "d", "r")
                for h in hosts]
'''

ACTIVE_PLUGIN = '''
from omnirecon.engine.plugins import ActivePlugin, finding

class Safe(ActivePlugin):
    name = "safe-active"
    requires_authorization = False
    def applies(self, host): return True
    def run(self, host): return {"hello": host["ip"]}
    def findings(self, host, result):
        return [finding("info", "Synthetic", host["ip"], "active finding", "d")]

class Aggressive(ActivePlugin):
    name = "aggressive-active"
    requires_authorization = True
    def applies(self, host): return True
    def run(self, host): return {"boom": True}
'''


def _write(tmp_path, name, body):
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return str(tmp_path)


def test_load_and_list(tmp_path):
    d = _write(tmp_path, "a_analysis.py", ANALYSIS_PLUGIN)
    loaded = plugins.load(dirs=[d])
    assert any(p.name == "synthetic-analysis" for p in loaded)
    meta = plugins.list_plugins(dirs=[d])
    assert meta[0]["kind"] == "analysis"


def test_underscore_files_skipped(tmp_path):
    _write(tmp_path, "_private.py", ANALYSIS_PLUGIN)
    assert plugins.load(dirs=[str(tmp_path)]) == []


def test_run_analysis(tmp_path, report):
    d = _write(tmp_path, "a_analysis.py", ANALYSIS_PLUGIN)
    found = plugins.run_analysis(report, dirs=[d])
    assert len(found) == len(report["discovery"]["hosts"])
    assert all(f["plugin"] == "synthetic-analysis" for f in found)


def test_active_auth_gate(tmp_path):
    d = _write(tmp_path, "b_active.py", ACTIVE_PLUGIN)
    hosts = [{"ip": "192.168.1.10", "open_ports": [80]}]

    unauth = plugins.run_active(hosts, authorized=False, dirs=[d])
    assert "aggressive-active" in unauth["skipped"]
    assert "safe-active" in unauth["results"]
    assert unauth["findings"][0]["title"] == "active finding"

    auth = plugins.run_active(hosts, authorized=True, dirs=[d])
    assert auth["skipped"] == []
    assert "aggressive-active" in auth["results"]


def test_name_filter(tmp_path):
    _write(tmp_path, "a_analysis.py", ANALYSIS_PLUGIN)
    assert plugins.load(dirs=[str(tmp_path)], names=["nope"]) == []
    assert len(plugins.load(dirs=[str(tmp_path)], names=["synthetic-analysis"])) == 1


def test_broken_plugin_does_not_raise(tmp_path):
    _write(tmp_path, "broken.py", "this is not valid python :(")
    # Must swallow the import error and return nothing rather than blow up.
    assert plugins.load(dirs=[str(tmp_path)]) == []
