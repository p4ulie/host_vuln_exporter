# host_vuln_exporter

Prometheus exporter that scans Debian hosts for known vulnerabilities. It never installs anything on the hosts.

A background thread, every `HOSTVULN_INTERVAL` seconds (default 43200, minimum 60), updates the Trivy DB, then for each
host fetches over SSH the dpkg database and the reboot-required flag, and scans that copy with Trivy locally. `:9880/metrics` (`HOSTVULN_EXPORTER_PORT`) only formats the last result. One failing host never stops the others.

| Metric | Meaning |
|---|---|
| `host_vuln_count{host,severity,fixable}` | Vulnerabilities per severity and whether an update fixes them |
| `host_vuln_info{host,cve,package,severity,fixed_version}` | One series per CRITICAL vulnerability |
| `host_reboot_required{host}` | 1 if the host needs a reboot |
| `host_scan_success{host}` | 1 if the last scan succeeded |
| `host_scan_timestamp_seconds{host}` | Unix time of the last successful scan (the start time until one succeeds) |

| Env | Default |
|---|---|
| `HOSTVULN_TARGETS` | `/etc/host-vuln-exporter/targets.yaml`, a YAML list of `{name, host}` |
| `HOSTVULN_SSH_KEY` | `/secrets/ssh-private-key` |
| `HOSTVULN_KNOWN_HOSTS` | `/etc/host-vuln-exporter/known_hosts` |
| `HOSTVULN_CACHE` | `/data/trivy` |
| `HOSTVULN_INTERVAL`, `HOSTVULN_EXPORTER_PORT` | `43200`, `9880` |

```sh
mise run test
mise run exporter                  # local
mise run image:build               # host-vuln-exporter:dev
```

## Owner steps

1. Create an SSH key pair for scanning. Put the private key in OpenBao.
2. Install the public key on every target host through the Ansible role in homenet_2.0 (a restricted read-only user).
3. Collect the host keys (`ssh-keyscan`) into `knownHosts`; the exporter trusts nothing else.
4. Create the Secret `sshKeySecret.name` with key `ssh-private-key` (homenet_2.0 syncs it from OpenBao). The chart creates none.

## Helm chart

```sh
helm install vuln helm/host-vuln-exporter --set sshKeySecret.name=vuln-ssh-key \
  --set-json 'targets=[{"name":"pve1","host":"10.34.1.10"}]' --set-file knownHosts=known_hosts
```

| Value | Default | Meaning |
|---|---|---|
| `image.repository` | `10.34.1.1:30095/host-vuln-exporter` | Image to run |
| `image.tag` | `""` | Empty means the chart's `appVersion` |
| `targets` | `[]` | List of `{name, host}` |
| `knownHosts` | `""` | Content of the known_hosts file |
| `sshKeySecret.name`, `.key` | none, `ssh-private-key` | Required existing Secret holding the private key |
| `interval` | `43200` | Seconds between scan cycles |
| `persistence.size`, `.storageClass` | `2Gi`, `""` | PVC for the Trivy DB cache; kept on uninstall |
| `resources` | 50m CPU, 256Mi request, 1Gi limit | Pod resources |
| `serviceMonitor.enabled`, `.interval` | `false`, `60s` | Prometheus Operator scrape config |
| `prometheusRule.enabled` | `false` | Alerts: `VulnCriticalFixableHost` (1h), `HostRebootRequired` (7d), `HostVulnScanFailing` (no scan for 36h) |

The chart installs no CRDs and no dashboard (the combined dashboard lives in homenet_2.0). The pod runs as uid 65534
with a read-only root filesystem; `/tmp` is an emptyDir and the Deployment uses `Recreate` because the cache PVC is ReadWriteOnce.

## Release

1. Bump `version` and `appVersion` in `helm/host-vuln-exporter/Chart.yaml` (same value), commit, tag `v<version>`, push.
2. `mise run image:push` builds and pushes `${REGISTRY:-10.34.1.1:30095}/host-vuln-exporter:<version>`, with the version read from `Chart.yaml`.
3. Point the Argo CD Application at the tag.
