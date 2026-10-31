# Troubleshooting

Open the panel on a PC and press **F12 → Console**: every failed query is logged with its name.

## "Data error: …" in the header

| Part | Check |
|---|---|
| Firewall log / Map | `docker logs alloy`; is syslog arriving? `tcpdump -ni any udp port 1514` on the Docker host. Is `WAN_IF` right? Does the GeoIP database exist (`docker exec alloy ls /geoip`)? |
| Prometheus | `docker compose ps` in `monitoring/`; `curl http://<docker-host>:8088/prom/api/v1/query?query=up` |
| WAN history | `wan.down`/`wan.up` return nothing: check the device name in `opnsense_interfaces_received_bytes_total` |
| Backups | `pbs_up` missing: token, role *Audit* on `/`, `PBS_ENDPOINT` reachable? |
| CrowdSec | `curl http://<firewall>:6060/metrics` from the Docker host; firewall rule on LAN? |
| Security check | `curl http://<scanner>:8081/api/job`; CORS errors in the console mean the scanner is not reachable from the browser |

## A tile shows "–"

The query for this value returns no data. Paste it into Prometheus (`http://localhost:9090` on the
Docker host, or Grafana *Explore*) and adjust the labels in `config.js`. Typical causes:

- CPU temperature: different `chip`/`sensor` labels (AMD, other boards).
- SMART: the `smartmon`/`nvme` timers run every 15 minutes – wait, or start them once:
  `systemctl start prometheus-node-exporter-smartmon.service`.
- Drive health on the NAS: `smartctl-exporter` needs `privileged: true`.

## Map stays empty, log works

The map counts blocks with a GeoIP country. If `geoip_country_code` is empty for all lines, the
GeoLite2 database is missing or the `stage.geoip` path in `config.alloy` is wrong.

## "Too many entries" on the Firewall page

Loki's `max_entries_limit_per_query` (in `loki-config.yml`) must be at least `fwSample`.

## Fan

- `No PWM controller found` → the `dtoverlay=pwm,pin=18,func=2` line is missing or the Pi was not
  rebooted.
- RPM stays 0 → green wire on pin 18? `python3-lgpio` installed?
- "Rack fan stopped" although it spins → check `PULSES_PER_REV` (2 for Noctua).

## Buttons are grey

- "Control only works on the rack display" → this device is not in `CONTROL_CLIENTS`
  (`/etc/default/vulnscan-api` on the scanner).
- *Patch vulnerabilities* is grey when there is nothing to update or a job is running.
- A patch run fails at once: `journalctl -u vulnscan-api` on the scanner and
  `ls /var/lib/vulnscan-api/logs/` for the full Ansible output.

## Display does not wake up / shows the desktop

- Screen blanking: `raspi-config` → *Display Options → Screen Blanking → off*.
- Autostart: the file must be `~/.config/labwc/autostart` of the user that logs in automatically.
  Test the command from the file in a terminal on the Pi.
