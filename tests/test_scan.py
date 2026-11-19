import json
from pathlib import Path

import pytest

from host_vuln_exporter.scan import Critical, ScanError, summarize

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
