"""Turn a Trivy `rootfs --format json` report into per-host counts."""
from dataclasses import dataclass

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


class ScanError(Exception):
    pass


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
                criticals.append(Critical(v["VulnerabilityID"], v.get("PkgName", ""), fixed))
    return HostResult(counts, criticals, reboot_required)
