"""Alert dispatch: severity threshold, rule routing, and the log channel."""

import json
import os

from omnirecon.monitor import alerts


def test_summarize(sample_deltas):
    text = alerts.summarize(sample_deltas)
    assert "OmniRecon" in text
    assert "change(s)" in text


def test_disabled_config_is_noop(sample_deltas, tmp_path):
    res = alerts.dispatch(sample_deltas, "STAMP", str(tmp_path),
                          {"enabled": False})
    assert res["dispatched"] is False


def test_log_channel_threshold(sample_deltas, tmp_path):
    cfg = {"enabled": True, "min_severity": "medium", "log": True}
    res = alerts.dispatch(sample_deltas, "STAMP", str(tmp_path), cfg)
    assert "log" in res["channels"]
    log_path = os.path.join(str(tmp_path), "alerts.log")
    lines = [json.loads(ln) for ln in open(log_path, encoding="utf-8")]
    # The 'low' (200-day) cert is below min_severity → not logged.
    assert all(d["severity"] in ("medium", "high") for d in lines)
    assert len(lines) == 3


def test_rules_suppress_then_dispatch(sample_deltas, tmp_path):
    rules_path = tmp_path / "rules.json"
    rules_path.write_text(json.dumps({"rules": [
        {"name": "drop new devices", "trigger": "new_device", "action": "suppress"},
    ]}), encoding="utf-8")
    cfg = {"enabled": True, "min_severity": "low", "log": True,
           "rules_file": str(rules_path)}
    res = alerts.dispatch(sample_deltas, "STAMP", str(tmp_path), cfg)
    assert res["rules_applied"] == 1
    lines = [json.loads(ln) for ln in
             open(os.path.join(str(tmp_path), "alerts.log"), encoding="utf-8")]
    assert all(d["type"] != "new_device" for d in lines)


def test_all_suppressed(sample_deltas, tmp_path):
    rules_path = tmp_path / "rules.json"
    rules_path.write_text(json.dumps({"rules": [
        {"name": "drop all", "trigger": "*", "action": "suppress"}]}),
        encoding="utf-8")
    res = alerts.dispatch(sample_deltas, "STAMP", str(tmp_path),
                          {"enabled": True, "rules_file": str(rules_path)})
    assert res["dispatched"] is False
