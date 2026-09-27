# Flamingo Helm Chart

A production-grade Helm chart for deploying [Flamingo](https://github.com/atredispartners/flamingo) (a network credential harvester & honeypot) on Kubernetes.

## Features

- **Workload Modes**: Run as a standard `Deployment` or as a cluster-wide honeypot `DaemonSet` on every node.
- **Host Networking**: Optional `hostNetwork: true` with `ClusterFirstWithHostNet` DNS policy for catching node-level credential spraying and lateral movement.
- **Configurable Listeners**: Support for SSH, SNMP, LDAP, LDAPS, HTTP, HTTPS, DNS, FTP, IMAP, and IMAPS credential capturing.
- **Privileged Port Binding**: Built-in `NET_BIND_SERVICE` Linux capability configuration to safely bind privileged low ports (<1024) under an unprivileged user.
- **Persistent SSH Host Key**: Mount custom SSH host key secrets to prevent host key change warnings across pod restarts.
- **Secret Outputs**: Safely store sensitive webhook URLs (Slack, Discord, Mattermost) or syslog endpoints inside Kubernetes Secrets.
- **Split-Protocol Services**: Option to split into separate `<release>-tcp` and `<release>-udp` services for cloud load balancers that do not allow mixed-protocol Services.
- **Persistent Storage**: Configurable PVC support for logging collected credentials directly to disk.
- **Zero-Trust NetworkPolicy**: Optional template to lock down pod ingress and egress traffic.
- **Probes & Helm Test**: Configurable liveness/readiness probes and `helm test` connection validation.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+

## Installing the Chart

### 1. Basic Deployment

```bash
helm install flamingo ./helm/flamingo
```

### 2. Node-Wide Honeypot (DaemonSet + HostNetwork)

To run Flamingo directly on every Kubernetes node's host interface to detect lateral movement across your cluster:

```bash
helm install flamingo ./helm/flamingo \
  --set kind=DaemonSet \
  --set hostNetwork=true \
  --set dnsPolicy=ClusterFirstWithHostNet
```

### 3. Exposing via Cloud Load Balancer (Split TCP/UDP)

For cloud providers (like AWS Classic ELB) that require dedicated services for TCP vs UDP:

```bash
helm install flamingo ./helm/flamingo \
  --set service.type=LoadBalancer \
  --set service.splitProtocols=true
```

### 4. Passing Sensitive Webhook Destinations via Secrets

```yaml
config:
  secretOutputs:
    - "https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXX"
```

## Configuration Parameters

| Parameter | Description | Default |
| --- | --- | --- |
| `kind` | Workload type (`Deployment` or `DaemonSet`) | `Deployment` |
| `replicaCount` | Replicas (only for `kind: Deployment`) | `1` |
| `hostNetwork` | Use host network namespace | `false` |
| `dnsPolicy` | Pod DNS policy | `ClusterFirst` |
| `image.repository` | Container image repository | `ghcr.io/joshuacox/flamingo` |
| `image.tag` | Container image tag (defaults to `Chart.appVersion`) | `""` |
| `securityContext.capabilities.add` | Container capabilities | `[NET_BIND_SERVICE]` |
| `config.protocols` | Enabled protocols | `ssh,snmp,ldap,http,dns,ftp,imap,pop3,smtp,redis,telnet,postgres,mysql,mongodb` |
| `config.ports.*` | Port configuration per protocol | See `values.yaml` |
| `config.banners.*` | Deception banners per protocol | See `values.yaml` |
| `config.sshHostKeySecret` | Name of Secret containing `id_rsa` host key | `""` |
| `config.customTlsSecret` | Name of Secret containing `tls.crt` and `tls.key` | `""` |
| `config.outputs` | Plaintext output targets (stdout, syslog, webhook, es://, loki://) | `["stdout"]` |
| `config.secretOutputs` | List of secret output targets stored in chart Secret | `[]` |
| `metrics.enabled` | Enable Prometheus metrics endpoint | `true` |
| `metrics.serviceMonitor.enabled` | Enable Prometheus Operator ServiceMonitor | `false` |
| `grafanaDashboard.enabled` | Deploy pre-configured Grafana analytics dashboard | `false` |
| `ingress.enabled` | Enable Kubernetes Ingress for HTTP/HTTPS listener | `false` |
| `livenessProbe.enabled` | Enable liveness probe | `false` |
| `readinessProbe.enabled` | Enable readiness probe | `false` |
| `service.type` | Kubernetes service type (`ClusterIP`, `NodePort`, `LoadBalancer`) | `ClusterIP` |
| `service.splitProtocols` | Split into separate TCP and UDP services | `false` |
| `networkPolicy.enabled` | Enable Kubernetes NetworkPolicy | `false` |
| `persistence.enabled` | Enable PVC for file logging | `false` |
