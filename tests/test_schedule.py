"""Scheduling helpers: interval parsing, cron conversion, command, daemon loop."""

import sys

import pytest

from omnirecon.monitor import schedule


@pytest.mark.parametrize("text,secs", [
    ("60s", 60), ("30m", 1800), ("6h", 21600), ("1d", 86400), ("120", 120),
])
def test_parse_interval(text, secs):
    assert schedule.parse_interval(text) == secs


@pytest.mark.parametrize("bad", ["", "10s", "abc", "0"])
def test_parse_interval_rejects(bad):
    with pytest.raises(ValueError):
        schedule.parse_interval(bad)


def test_interval_to_cron():
    assert schedule._interval_to_cron(21600) == "0 */6 * * *"
    assert schedule._interval_to_cron(86400) == "0 2 * * *"
    assert schedule._interval_to_cron(900) == "*/15 * * * *"


def test_build_command():
    cmd = schedule.build_command(db="x.db", subnet="192.168.1.0/24",
                                 extra_args=["--cve"])
    assert cmd[0] == sys.executable
    assert cmd[1:4] == ["-m", "omnirecon", "monitor"]
    assert "--db" in cmd and "scan" in cmd and "--cve" in cmd


def test_cron_to_schtasks():
    assert schedule._cron_to_schtasks("0 */6 * * *") == ["/sc", "HOURLY", "/mo", "6"]
    assert schedule._cron_to_schtasks("*/15 * * * *") == ["/sc", "MINUTE", "/mo", "15"]
    assert schedule._cron_to_schtasks("30 2 * * *") == ["/sc", "DAILY", "/st", "02:30"]
    assert schedule._cron_to_schtasks("garbage") is None


def test_daemon_bounded_loop():
    calls = []
    runs = schedule.daemon(lambda: calls.append(1), interval_seconds=0,
                           max_iterations=3)
    assert runs == 3
    assert len(calls) == 3


def test_daemon_survives_failing_scan():
    state = {"n": 0}

    def boom():
        state["n"] += 1
        raise RuntimeError("scan failed")

    runs = schedule.daemon(boom, interval_seconds=0, max_iterations=2)
    assert runs == 2          # loop kept going despite exceptions
    assert state["n"] == 2
