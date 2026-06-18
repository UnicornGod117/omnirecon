"""Rule engine: loading, matching, and evaluation (suppress / re-rate / route)."""

import json

from omnirecon.monitor import rules


def _rules_file(tmp_path, data):
    p = tmp_path / "rules.json"
    p.write_text(json.dumps({"rules": data}), encoding="utf-8")
    return str(p)


def test_load_json(tmp_path):
    path = _rules_file(tmp_path, [{"name": "r", "trigger": "new_device"}])
    loaded = rules.load(path)
    assert loaded == [{"name": "r", "trigger": "new_device"}]


def test_load_missing_returns_empty():
    assert rules.load("does-not-exist.yaml") == []


def test_trigger_alias_maps_to_delta_type():
    rule = {"trigger": "new_service"}              # → port_added
    assert rules.matches(rule, {"delta_type": "port_added", "detail": {}})
    assert not rules.matches(rule, {"delta_type": "new_device", "detail": {}})


def test_wildcard_trigger_matches_all():
    assert rules.matches({"trigger": "*"}, {"delta_type": "anything", "detail": {}})


def test_subnet_match(sample_deltas):
    rule = {"trigger": "new_device", "match": {"subnet": "192.168.1.0/24"}}
    new_dev = sample_deltas[0]
    assert rules.matches(rule, new_dev)
    rule2 = {"trigger": "new_device", "match": {"subnet": "10.0.0.0/8"}}
    assert not rules.matches(rule2, new_dev)


def test_port_and_negated_role(sample_deltas):
    rule = {"trigger": "new_service", "match": {"port": 22, "asset_role": "!server"}}
    port_delta = sample_deltas[1]                  # port 22 on a printer
    assert rules.matches(rule, port_delta)


def test_cert_threshold(sample_deltas):
    rule = {"trigger": "cert_expiry", "threshold_days": 30}
    near = sample_deltas[2]                         # 12 days → within threshold
    far = sample_deltas[3]                          # 200 days → outside
    assert rules.matches(rule, near)
    assert not rules.matches(rule, far)


def test_evaluate_suppress_and_override(sample_deltas):
    policy = [
        {"name": "drop guest", "trigger": "new_device",
         "match": {"subnet": "192.168.1.0/24"}, "action": "suppress"},
        {"name": "loud cert", "trigger": "cert_expiry", "severity": "high",
         "alert": ["webhook"]},
    ]
    out = rules.evaluate(sample_deltas, policy)
    types = [d["delta_type"] for d, _ in out]
    assert "new_device" not in types               # suppressed
    cert = next((d, c) for d, c in out if d["delta_type"] == "cert_expiring"
                and d["ip"] == "192.168.1.10")
    assert cert[0]["severity"] == "high"           # overridden
    assert cert[1] == {"webhook"}                  # routed
    assert cert[0]["rule"] == "loud cert"


def test_unmatched_passes_through(sample_deltas):
    out = rules.evaluate(sample_deltas, [{"trigger": "ip_changed"}])
    assert len(out) == len(sample_deltas)
    assert all(channels is None for _, channels in out)
