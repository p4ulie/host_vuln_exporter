"""Prometheus exporter: a background thread scans the hosts, scrapes only format the last result."""
import logging
import os
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import yaml
from prometheus_client import start_http_server
from prometheus_client.core import REGISTRY, GaugeMetricFamily

from .scan import Config, HostResult, Target, scan_host, update_db

log = logging.getLogger("host_vuln_exporter.exporter")


@dataclass
class HostState:
    timestamp: float  # last successful scan; the exporter's start time until one succeeds
    result: HostResult | None = None
    success: bool = False


class State:
    def __init__(self, targets: list[Target], start: float | None = None):
        start = time.time() if start is None else start
        self.hosts = {t.name: HostState(start) for t in targets}


def load_targets(path: Path) -> list[Target]:
    return [Target(d["name"], d["host"]) for d in yaml.safe_load(Path(path).read_text())]


def scan_all(targets: list[Target], cfg: Config, state: State) -> None:
    for t in targets:
        hs = state.hosts[t.name]
        try:
            hs.result = scan_host(t, cfg)
        except Exception as e:  # ScanError, or a missing ssh/trivy binary: one host never stops the others
            hs.success = False
            log.warning("scan of %s failed: %s: %s", t.name, type(e).__name__, e)
            continue
        hs.timestamp, hs.success = time.time(), True


RETRY_SECONDS = 600.0  # next try after a failed first DB download, instead of the full interval


def run_once(targets: list[Target], cfg: Config, state: State) -> bool:
    """Returns False when the DB update failed and there is no cached DB at all (retry soon)."""
    updated = update_db(cfg)
    if not updated:
        log.warning("trivy DB update failed; scanning with the cached DB")
    scan_all(targets, cfg, state)
    return updated or (cfg.cache_dir / "db" / "trivy.db").exists()


def wait_seconds(cycle_ok: bool, interval: float) -> float:
    return interval if cycle_ok else RETRY_SECONDS


class Collector:
    def __init__(self, state: State):
        self.state = state

    def collect(self):
        count = GaugeMetricFamily("host_vuln_count", "Vulnerabilities per severity and fixability",
                                  labels=("host", "severity", "fixable"))
        info = GaugeMetricFamily("host_vuln_info", "CRITICAL vulnerabilities",
                                 labels=("host", "cve", "package", "severity", "fixed_version"))
        reboot = GaugeMetricFamily("host_reboot_required", "1 if the host needs a reboot", labels=("host",))
        ok = GaugeMetricFamily("host_scan_success", "1 if the last scan succeeded", labels=("host",))
        ts = GaugeMetricFamily("host_scan_timestamp_seconds", "Unix time of the last successful scan", labels=("host",))
        for name, hs in list(self.state.hosts.items()):
            ok.add_metric([name], float(hs.success))
            ts.add_metric([name], hs.timestamp)
            r = hs.result
            if r is None:
                continue
            for (sev, fixable), n in r.counts.items():
                count.add_metric([name, sev, str(fixable).lower()], n)
            for c in r.criticals:
                info.add_metric([name, c.cve, c.package, "CRITICAL", c.fixed_version], 1)
            reboot.add_metric([name], float(r.reboot_required))
        yield from (count, info, reboot, ok, ts)


def prepare_key(src: Path) -> Path:
    """ssh refuses a key it does not own with 0600; the mounted secret is neither, so copy it."""
    fd, dst = tempfile.mkstemp(prefix="ssh-key-", dir=os.environ.get("TMPDIR") or None)  # mkstemp creates 0600
    with os.fdopen(fd, "wb") as f:
        f.write(Path(src).read_bytes())
    return Path(dst)


def cycle(targets: list[Target], cfg: Config, state: State) -> bool:
    try:
        return run_once(targets, cfg, state)
    except Exception:  # an unexpected bug must not kill the thread; try again next cycle
        log.exception("scan cycle failed")
        return True


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    env = os.environ.get
    targets = load_targets(Path(env("HOSTVULN_TARGETS", "/etc/host-vuln-exporter/targets.yaml")))
    tmp = Path(env("TMPDIR") or tempfile.gettempdir())
    cfg = Config(
        key_file=prepare_key(Path(env("HOSTVULN_SSH_KEY", "/secrets/ssh-private-key"))),
        known_hosts=Path(env("HOSTVULN_KNOWN_HOSTS", "/etc/host-vuln-exporter/known_hosts")),
        cache_dir=Path(env("HOSTVULN_CACHE", "/data/trivy")),
        work_dir=tmp / "work",
    )
    interval = max(60.0, float(env("HOSTVULN_INTERVAL", "43200")))
    port = int(env("HOSTVULN_EXPORTER_PORT", "9880"))
    state = State(targets)
    REGISTRY.register(Collector(state))
    start_http_server(port)
    print(f"host vuln exporter on :{port}/metrics, {len(targets)} hosts, every {interval:g}s", flush=True)

    def loop():
        while True:
            time.sleep(wait_seconds(cycle(targets, cfg, state), interval))

    threading.Thread(target=loop, daemon=True).start()
    threading.Event().wait()


if __name__ == "__main__":
    main()
