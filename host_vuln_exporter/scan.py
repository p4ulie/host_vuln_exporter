"""Fetch a host's package database over SSH, scan it with Trivy, and turn the report into per-host counts."""
import io
import json
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


class ScanError(Exception):
    pass


@dataclass(frozen=True)
class Target:
    name: str
    host: str


@dataclass(frozen=True)
class Config:
    key_file: Path
    known_hosts: Path
    cache_dir: Path
    work_dir: Path
    ssh_timeout: int = 120
    trivy_timeout: int = 600


@dataclass(frozen=True)
class Critical:
    cve: str
    package: str
    fixed_version: str  # "" when unfixed


@dataclass
class HostResult:
    counts: dict[tuple[str, bool], int]  # (severity, fixable) -> count
    criticals: list[Critical]
    reboot_required: bool


def summarize(report: dict, reboot_required: bool) -> HostResult:
    # No OS means Trivy could not read the host's package database; that is a failed scan, not a clean one.
    if not (report.get("Metadata") or {}).get("OS"):
        raise ScanError("trivy detected no OS in the report")
    counts = {(s, f): 0 for s in SEVERITIES for f in (True, False)}
    criticals = []
    for result in report.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            sev = v.get("Severity")
            if sev not in SEVERITIES:
                sev = "UNKNOWN"
            fixed = v.get("FixedVersion") or ""
            counts[(sev, bool(fixed))] += 1
            if sev == "CRITICAL":
                criticals.append(Critical(v.get("VulnerabilityID", "?"), v.get("PkgName") or "", fixed))
    return HostResult(counts, criticals, reboot_required)


REMOTE_CMD = (
    "tar -C / -cf - --ignore-failed-read etc/os-release usr/lib/os-release "
    "var/lib/dpkg/status var/lib/dpkg/status.d var/run/reboot-required 2>/dev/null"
)


def fetch(target: Target, cfg: Config, dest: Path) -> None:
    cmd = [
        "ssh", "-F", "/dev/null", "-i", str(cfg.key_file), "-o", "BatchMode=yes",
        "-o", f"UserKnownHostsFile={cfg.known_hosts}", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15",
        f"vulnscan@{target.host}", REMOTE_CMD,
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=cfg.ssh_timeout)
    except subprocess.TimeoutExpired:
        raise ScanError(f"{target.name}: ssh timed out") from None
    if p.returncode != 0:
        err = p.stderr.decode(errors="replace").strip()[:200]
        raise ScanError(f"{target.name}: ssh failed ({p.returncode}): {err}")
    try:
        with tarfile.open(fileobj=io.BytesIO(p.stdout)) as t:
            t.extractall(dest, filter="data")
    except (tarfile.TarError, OSError) as e:
        raise ScanError(f"{target.name}: bad package database archive: {e}") from None
    # An empty or unreadable package DB must fail, never read as "0 vulnerabilities".
    if not (dest / "var/lib/dpkg/status").exists():
        raise ScanError(f"{target.name}: no var/lib/dpkg/status in fetched data")


def _trivy(args: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(["trivy", *args], capture_output=True, timeout=timeout)


def run_trivy(root: Path, cfg: Config) -> dict:
    args = ["rootfs", "--skip-db-update", "--cache-dir", str(cfg.cache_dir), "--scanners", "vuln",
            "--format", "json", "--quiet", str(root)]
    try:
        p = _trivy(args, cfg.trivy_timeout)
    except subprocess.TimeoutExpired:
        raise ScanError("trivy timed out") from None
    if p.returncode != 0:
        raise ScanError(f"trivy failed ({p.returncode}): {p.stderr.decode(errors='replace').strip()[:200]}")
    try:
        return json.loads(p.stdout)
    except ValueError:
        raise ScanError("trivy produced invalid JSON") from None


def update_db(cfg: Config) -> bool:
    try:
        p = _trivy(["rootfs", "--download-db-only", "--cache-dir", str(cfg.cache_dir)], cfg.trivy_timeout)
    except (subprocess.TimeoutExpired, OSError):
        return False
    return p.returncode == 0


def scan_host(target: Target, cfg: Config) -> HostResult:
    cfg.work_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=cfg.work_dir) as d:
        root = Path(d)
        fetch(target, cfg, root)
        try:
            report = run_trivy(root, cfg)
            return summarize(report, (root / "var/run/reboot-required").exists())
        except ScanError as e:
            raise ScanError(f"{target.name}: {e}") from None
