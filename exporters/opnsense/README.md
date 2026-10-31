# OPNsense setup

Four things on the firewall feed the dashboard. Example addresses: firewall `192.168.1.1`,
Docker host with the monitoring stack `192.168.1.10`.

## 1. Firewall log via syslog → Alloy → Loki

*System → Settings → Logging → Remote → +*

| Field | Value |
|---|---|
| Transport | UDP(4) |
| Applications | `filter (filterlog)` |
| Hostname | `192.168.1.10` (Docker host) |
| Port | `1514` |
| RFC5424 | enabled |

Make sure the WAN block rules have **logging enabled** (the default "block all" rule does).
The panel shows blocks on the interface configured as `WAN_IF` in `panel/html/config.js`.

## 2. node_exporter (CPU, RAM, temperatures, interfaces)

*System → Firmware → Plugins → `os-node_exporter`*, then *Services → Node Exporter*: enable,
listen on the LAN address, port `9100`. Prometheus job: `firewall`.

## 3. API user for opnsense-exporter

*System → Access → Users → +* a user (e.g. `prometheus`) without a login shell,
with the privileges the [opnsense-exporter](https://github.com/AthennaMind/opnsense-exporter)
README lists (read-only status pages). Create an **API key** for the user and put key and secret into
`monitoring/.env` (`OPN_API_KEY`, `OPN_API_SECRET`). Never into a file that is committed.

## 4. CrowdSec metrics

Install the `os-crowdsec` plugin and enable it. Then let it export Prometheus metrics on the
LAN address. Create `/usr/local/etc/crowdsec/config.yaml.local` (this file survives updates):

```yaml
prometheus:
  enabled: true
  level: full
  listen_addr: 192.168.1.1
  listen_port: 6060
```

`service crowdsec restart`. The tile uses the metric `cs_active_decisions{origin,reason,action}`.

### Never ban your own public IP

```sh
cscli parsers install crowdsecurity/whitelists
```

and a post-overflow whitelist,
`/usr/local/etc/crowdsec/postoverflows/s01-whitelist/my-public-ip.yaml`:

```yaml
name: me/my-public-ip
description: "Never ban my own public IP (dynamic DNS name)"
whitelist:
  reason: "own IP"
  expression:
    - evt.Overflow.Alert.Source.IP in LookupHost("home.example.com")
```

## Firewall rules

Allow on LAN: Docker host → firewall TCP `9100` (node_exporter) and TCP `6060` (CrowdSec),
and HTTPS to the GUI port for the API exporter. Do **not** allow any of these from WAN.
