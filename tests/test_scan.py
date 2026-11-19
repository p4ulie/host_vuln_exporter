import io
import json
import stat
import tarfile
from pathlib import Path

import pytest

from host_vuln_exporter.scan import (
    Config, Critical, ScanError, Target, fetch, scan_host, summarize, update_db,
)

REPORT = json.loads((Path(__file__).parent / "fixtures" / "trivy-debian.json").read_text())


def test_counts_by_severity_and_fixable():
    r = summarize(REPORT, reboot_required=False)
    assert len(r.counts) == 10
    nonzero = {k: v for k, v in r.counts.items() if v}
    assert nonzero == {
        ("CRITICAL", True): 1,
        ("CRITICAL", False): 1,
        ("HIGH", True): 1,
        ("LOW", False): 1,
    }


def test_criticals_listed_with_fixed_version():
    r = summarize(REPORT, reboot_required=True)
    assert r.reboot_required is True
    assert r.criticals == [
        Critical("CVE-2026-0001", "libfoo", "1.0-2"),
        Critical("CVE-2026-0002", "libbar", ""),
    ]


def test_no_os_detected_is_an_error():
    with pytest.raises(ScanError):
        summarize({"Metadata": {}, "Results": []}, reboot_required=False)


def test_no_results_is_zero_not_error():
    r = summarize({"Metadata": {"OS": {"Family": "debian"}}}, reboot_required=False)
    assert len(r.counts) == 10 and not any(r.counts.values())


FIXTURE = Path(__file__).parent / "fixtures" / "trivy-debian.json"


def _script(path: Path, body: str):
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def make_tar(path: Path, names):
    with tarfile.open(path, "w") as t:
        for n in names:
            data = b"x\n"
            info = tarfile.TarInfo(n)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Fake ssh (cats a tar, records argv) and fake trivy (prints the fixture) first on PATH."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    tar_path = tmp_path / "db.tar"
    make_tar(tar_path, ["etc/os-release", "var/lib/dpkg/status"])
    _script(bin_dir / "ssh", f'echo "$@" > {tmp_path}/ssh-argv\ncat {tar_path}\n')
    _script(bin_dir / "trivy", f"cat {FIXTURE}\n")
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    cfg = Config(tmp_path / "key", tmp_path / "known_hosts", tmp_path / "cache", tmp_path / "work")
    return tmp_path, bin_dir, tar_path, cfg


def test_fetch_extracts_package_db(env):
    tmp, _, _, cfg = env
    dest = tmp / "dest"
    dest.mkdir()
    fetch(Target("web", "web.lan"), cfg, dest)
    assert (dest / "etc/os-release").exists()
    assert (dest / "var/lib/dpkg/status").exists()


def test_missing_dpkg_status_raises_scan_error(env):
    tmp, _, tar_path, cfg = env
    make_tar(tar_path, ["etc/os-release"])
    with pytest.raises(ScanError, match="web"):
        fetch(Target("web", "web.lan"), cfg, tmp)


def test_reboot_flag_from_marker(env):
    _, _, tar_path, cfg = env
    make_tar(tar_path, ["etc/os-release", "var/lib/dpkg/status", "var/run/reboot-required"])
    assert scan_host(Target("web", "web.lan"), cfg).reboot_required is True


def test_ssh_failure_raises_scan_error(env):
    _, bin_dir, _, cfg = env
    _script(bin_dir / "ssh", "echo boom >&2\nexit 255\n")
    with pytest.raises(ScanError, match="web"):
        scan_host(Target("web", "web.lan"), cfg)


def test_ssh_arguments(env):
    tmp, _, _, cfg = env
    fetch(Target("web", "web.lan"), cfg, tmp)
    argv = (tmp / "ssh-argv").read_text()
    for part in (f"-i {cfg.key_file}", "-o BatchMode=yes", f"-o UserKnownHostsFile={cfg.known_hosts}",
                 "-o StrictHostKeyChecking=yes", "-F /dev/null", "vulnscan@web.lan"):
        assert part in argv


def test_trivy_timeout_raises_scan_error(env):
    tmp, bin_dir, _, cfg = env
    _script(bin_dir / "trivy", "sleep 5\n")
    cfg = Config(cfg.key_file, cfg.known_hosts, cfg.cache_dir, cfg.work_dir, trivy_timeout=1)
    with pytest.raises(ScanError, match="web"):
        scan_host(Target("web", "web.lan"), cfg)


def test_update_db_failure_returns_false(env):
    _, bin_dir, _, cfg = env
    _script(bin_dir / "trivy", "exit 1\n")
    assert update_db(cfg) is False


def test_work_dir_cleaned_after_scan(env):
    _, _, _, cfg = env
    scan_host(Target("web", "web.lan"), cfg)
    assert list(cfg.work_dir.iterdir()) == []
