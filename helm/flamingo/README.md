# Flamingo Helm Chart

A Helm chart for deploying [Flamingo](https://github.com/atredispartners/flamingo) (a network credential harvester) on Kubernetes.

## Features

- Configurable protocol listeners (SSH, SNMP, LDAP, LDAPS, HTTP, HTTPS, DNS, FTP).
- Flexible output sinks: standard output, webhook endpoints, syslog receivers, or mounted persistent volumes.
- Pod security context with `NET_BIND_SERVICE` capability for binding to standard low-numbered network ports (21, 22, 53, 80, 161, 389, 443, etc.).
- Optional TLS secret mounting for custom certificates.
- Optional PersistentVolumeClaim support for logging credentials to disk.
- Exposes listeners via a configurable Kubernetes Service (ClusterIP, NodePort, or LoadBalancer).

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+

## Installing the Chart

To install the chart with the release name `flamingo`:

```bash
helm install flamingo ./helm/flamingo
```

To expose listeners using a LoadBalancer (e.g. cloud provider load balancer or MetalLB):

```bash
helm install flamingo ./helm/flamingo \
  --set service.type=LoadBalancer
```

## Configuration

The following table lists the primary configurable parameters of the chart and their defaults:

| Parameter | Description | Default |
| --- | --- | --- |
| `replicaCount` | Number of flamingo replicas | `1` |
| `image.repository` | Container image repository | `flamingo` |
| `image.tag` | Container image tag | Chart `appVersion` (`latest`) |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `securityContext.capabilities.add` | Capabilities to add to container | `[NET_BIND_SERVICE]` |
| `config.protocols` | Enabled listener protocols (comma-separated) | `ssh,snmp,ldap,http,dns,ftp` |
| `config.ports.ftp` | Port(s) for FTP listener | `"21"` |
| `config.ports.ssh` | Port(s) for SSH listener | `"22"` |
| `config.ports.dns` | Port(s) for DNS listener | `"53,5353"` |
| `config.ports.dnsResolveToIP` | Optional IP to resolve DNS queries to | `""` |
| `config.ports.http` | Port(s) for HTTP listener | `"80"` |
| `config.ports.https` | Port(s) for HTTPS listener | `"443"` |
| `config.ports.ldap` | Port(s) for LDAP listener | `"389"` |
| `config.ports.ldaps` | Port(s) for LDAPS listener | `"636"` |
| `config.ports.snmp` | Port(s) for SNMP listener | `"161"` |
| `config.httpRealm` | Basic auth realm name | `Administration` |
| `config.httpAuthMode` | Authentication mode (`ntlm` or `basic`) | `ntlm` |
| `config.customTlsSecret` | Name of existing secret containing `tls.crt` and `tls.key` | `""` |
| `config.outputs` | Output destinations (arguments to binary) | `["stdout"]` |
| `persistence.enabled` | Enable persistent storage for file logging | `false` |
| `persistence.mountPath` | Path to mount persistent volume | `/var/log/flamingo` |
| `service.type` | Kubernetes service type | `ClusterIP` |
| `service.ports.*` | Enable or disable specific ports on the Service | See `values.yaml` |

## Examples

### Sending logs to an external webhook

```yaml
config:
  outputs:
    - "stdout"
    - "https://webhook.site/your-webhook-id"
```

### Logging to persistent storage

```yaml
persistence:
  enabled: true
  size: 5Gi

config:
  outputs:
    - "stdout"
    - "/var/log/flamingo/captured-creds.log"
```
