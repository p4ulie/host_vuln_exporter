import os
import stat
from pathlib import Path

import pytest
from prometheus_client import CollectorRegistry, generate_latest

from host_vuln_exporter import exporter
from host_vuln_exporter.exporter import Collector, State, load_targets, prepare_key, run_once, scan_all
from host_vuln_exporter.scan import Config, Critical, HostResult, ScanError, SEVERITIES, Target

CFG = Config(Path("k"), Path("kh"), Path("c"), Path("w"))
H1, H2 = Target("h1", "10.0.0.1"), Target("h2", "10.0.0.2")


def result(crit_fixed=1):
    counts = {(s, f): 0 for s in SEVERITIES for f in (True, False)}
    counts[("CRITICAL", True)] = crit_fixed
    counts[("HIGH", False)] = 2
    return HostResult(counts, [Critical("CVE-1", "libfoo", "1.0-2")], True)


def render(state):
    registry = CollectorRegistry()
    registry.register(Collector(state))
    return generate_latest(registry).decode()


def fake(results):
    def scan(target, cfg):
        r = results[target.name]
        if isinstance(r, Exception):
            raise r
        return r
    return scan


def test_load_targets(tmp_path):
    p = tmp_path / "t.yaml"
    p.write_text("- {name: h1, host: 10.0.0.1}\n- {name: h2, host: 10.0.0.2}\n")
    assert load_targets(p) == [H1, H2]


def test_metrics_for_successful_scan(monkeypatch):
    monkeypatch.setattr(exporter, "scan_host", fake({"h1": result()}))
    state = State([H1], start=100.0)
    scan_all([H1], CFG, state)
    out = render(state)
    assert 'host_vuln_count{fixable="true",host="h1",severity="CRITICAL"} 1.0' in out
    assert 'host_vuln_count{fixable="false",host="h1",severity="HIGH"} 2.0' in out
    assert 'host_vuln_info{cve="CVE-1",fixed_version="1.0-2",host="h1",package="libfoo",severity="CRITICAL"} 1.0' in out
    assert out.count("host_vuln_info{") == 1
    assert 'host_scan_success{host="h1"} 1.0' in out
    assert 'host_reboot_required{host="h1"} 1.0' in out


def test_failed_host_keeps_last_counts(monkeypatch):
    state = State([H1], start=100.0)
    monkeypatch.setattr(exporter, "scan_host", fake({"h1": result()}))
    scan_all([H1], CFG, state)
    ts = state.hosts["h1"].timestamp
    monkeypatch.setattr(exporter, "scan_host", fake({"h1": ScanError("boom")}))
    scan_all([H1], CFG, state)
    out = render(state)
    assert 'host_vuln_count{fixable="true",host="h1",severity="CRITICAL"} 1.0' in out
    assert 'host_scan_success{host="h1"} 0.0' in out
    assert state.hosts["h1"].timestamp == ts


def test_one_host_failing_does_not_stop_others(monkeypatch):
    monkeypatch.setattr(exporter, "scan_host", fake({"h1": FileNotFoundError("ssh"), "h2": result()}))
    state = State([H1, H2], start=100.0)
    scan_all([H1, H2], CFG, state)
    out = render(state)
    assert 'host_scan_success{host="h1"} 0.0' in out
    assert 'host_scan_success{host="h2"} 1.0' in out


def test_never_scanned_host_has_start_timestamp():
    out = render(State([H1], start=123.0))
    assert 'host_scan_timestamp_seconds{host="h1"} 123.0' in out
    assert 'host_scan_success{host="h1"} 0.0' in out
    assert "host_vuln_count{" not in out


def test_db_update_failure_still_scans(monkeypatch):
    monkeypatch.setattr(exporter, "update_db", lambda cfg: False)
    monkeypatch.setattr(exporter, "scan_host", fake({"h1": result()}))
    state = State([H1], start=100.0)
    run_once([H1], CFG, state)
    assert 'host_scan_success{host="h1"} 1.0' in render(state)


def test_key_copied_private(tmp_path, monkeypatch):
    src = tmp_path / "mounted"
    src.write_text("SECRET")
    src.chmod(0o644)
    monkeypatch.setenv("TMPDIR", str(tmp_path / "tmp"))
    (tmp_path / "tmp").mkdir()
    dst = prepare_key(src)
    assert dst != src and dst.read_text() == "SECRET"
    assert stat.S_IMODE(dst.stat().st_mode) == 0o600
    assert dst.parent == tmp_path / "tmp"


def test_empty_tmpdir_is_not_cwd(tmp_path, monkeypatch):
    src = tmp_path / "k"
    src.write_text("key")
    monkeypatch.setenv("TMPDIR", "")
    monkeypatch.chdir(tmp_path)
    dst = prepare_key(src)
    try:
        assert dst.parent != tmp_path
    finally:
        dst.unlink()


def test_cycle_survives_unexpected_exception(monkeypatch, caplog):
    def boom(*a):
        raise RuntimeError("boom")
    monkeypatch.setattr(exporter, "run_once", boom)
    exporter.cycle([], None, None)  # must not raise
    assert "boom" in caplog.text
