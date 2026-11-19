import subprocess

import yaml

CHART = "helm/host-vuln-exporter"
REQUIRED = ["--set", "sshKeySecret.name=vuln-key"]


def template(*args):
    return subprocess.run(["helm", "template", "t", CHART, *args], capture_output=True, text=True)


def render_all(*args):
    out = template(*args)
    assert out.returncode == 0, out.stderr
    return [d for d in yaml.safe_load_all(out.stdout) if d]


def render(*args):
    return {d["kind"]: d for d in render_all(*args)}


def pod(*args):
    return render(*REQUIRED, *args)["Deployment"]["spec"]["template"]["spec"]


def test_requires_ssh_key_secret():
    assert template().returncode != 0


def test_targets_and_known_hosts_in_configmap():
    cm = render(*REQUIRED, "--set-json", 'targets=[{"name":"a","host":"10.0.0.1"}]',
                "--set", "knownHosts=10.0.0.1 ssh-ed25519 AAAA")["ConfigMap"]
    assert yaml.safe_load(cm["data"]["targets.yaml"]) == [{"name": "a", "host": "10.0.0.1"}]
    assert cm["data"]["known_hosts"].startswith("10.0.0.1 ssh-ed25519")
    # empty defaults still render a parseable list
    assert yaml.safe_load(render(*REQUIRED)["ConfigMap"]["data"]["targets.yaml"]) == []


def test_pod_restricted():
    p = pod()
    assert p["enableServiceLinks"] is False
    # fsGroup makes the 0400 secret group-readable and the PVC group-writable for uid 65534
    assert p["securityContext"] == {"runAsNonRoot": True, "runAsUser": 65534, "fsGroup": 65534,
                                    "seccompProfile": {"type": "RuntimeDefault"}}
    assert p["containers"][0]["securityContext"] == {
        "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}


def test_secret_mounted_read_only_with_0400():
    p = pod()
    vol = next(v for v in p["volumes"] if "secret" in v)
    assert vol["secret"]["secretName"] == "vuln-key"
    assert vol["secret"]["defaultMode"] == 0o400
    m = next(m for m in p["containers"][0]["volumeMounts"] if m["name"] == vol["name"])
    assert m["mountPath"] == "/secrets" and m["readOnly"] is True


def test_tmp_and_data_mounts():
    p = pod()
    mounts = {m["mountPath"]: m["name"] for m in p["containers"][0]["volumeMounts"]}
    vols = {v["name"]: v for v in p["volumes"]}
    assert "emptyDir" in vols[mounts["/tmp"]]
    assert vols[mounts["/data"]]["persistentVolumeClaim"]["claimName"]
    env = {e["name"]: e.get("value") for e in p["containers"][0]["env"]}
    assert env["TMPDIR"] == "/tmp" and env["HOSTVULN_INTERVAL"] == "43200"
    assert env["HOSTVULN_CACHE"] == "/data/trivy"


def test_recreate_strategy():
    assert render(*REQUIRED)["Deployment"]["spec"]["strategy"] == {"type": "Recreate"}


def test_pvc_kept_on_uninstall():
    pvc = render(*REQUIRED, "--set", "persistence.size=3Gi")["PersistentVolumeClaim"]
    assert pvc["metadata"]["annotations"]["helm.sh/resource-policy"] == "keep"
    assert pvc["spec"]["resources"]["requests"]["storage"] == "3Gi"
    assert "storageClassName" not in pvc["spec"]


def test_toggles_and_rules():
    docs = render(*REQUIRED, "--set", "serviceMonitor.enabled=true", "--set", "prometheusRule.enabled=true")
    assert docs["ServiceMonitor"]["spec"]["endpoints"][0]["port"] == "metrics"
    assert docs["Service"]["spec"]["ports"][0]["port"] == 9880
    rules = {r["alert"]: r for g in docs["PrometheusRule"]["spec"]["groups"] for r in g["rules"]}
    assert {n: (r["expr"], r.get("for")) for n, r in rules.items()} == {
        "VulnCriticalFixableHost": ('host_vuln_count{severity="CRITICAL",fixable="true"} > 0', "1h"),
        "HostRebootRequired": ("host_reboot_required == 1", "7d"),
        "HostVulnScanFailing": ("time() - host_scan_timestamp_seconds > 129600", None),
    }
    assert all("{{ $labels.host }}" in r["annotations"]["summary"] for r in rules.values())
    assert set(render(*REQUIRED)) == {"Deployment", "Service", "ConfigMap", "PersistentVolumeClaim"}


def test_chart_and_app_and_image_version_agree():
    chart = yaml.safe_load(open(f"{CHART}/Chart.yaml"))
    assert chart["version"] == chart["appVersion"]
    img = render(*REQUIRED)["Deployment"]["spec"]["template"]["spec"]["containers"][0]["image"]
    assert img == f"10.34.1.1:30095/host-vuln-exporter:{chart['appVersion']}"
