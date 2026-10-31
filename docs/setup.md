# Setup guide

This guide builds the complete dashboard step by step. Plan about two to three hours if your
firewall and Proxmox hosts are already running.

All addresses are examples from a flat `192.168.1.0/24` network – replace them with yours:

| Device | Example IP | Role |
|---|---|---|
| Firewall (OPNsense) | 192.168.1.1 | filterlog, node_exporter, CrowdSec, API |
| pve1, pve2 (Proxmox VE) | 192.168.1.5, .6 | hosts, node_exporter + SMART |
| NAS | 192.168.1.8 | node_exporter, smartctl_exporter |
| Proxmox Backup Server | 192.168.1.9 | backups |
| Docker host | 192.168.1.10 | monitoring stack + panel (port 8088) |
| Raspberry Pi (display) | 192.168.1.20 | Chromium kiosk, fan control |
| Scanner (LXC) | 192.168.1.30 | vulnscan dashboard 8080, API 8081 |
| Ansible host | 192.168.1.31 | patch status and updates |

```sh
git clone https://github.com/<you>/homelab-rack-dashboard.git
```

---

## 1. Monitoring stack (Docker host)

Any Linux machine or LXC with Docker and Docker Compose. In an unprivileged Proxmox LXC enable
*nesting* (and *keyctl*).

```sh
cd homelab-rack-dashboard/monitoring
cp .env.example .env && chmod 600 .env
nano .env               # OPNsense API key/secret, MaxMind account + licence key
nano prometheus.yml     # your IPs; job names must match panel/html/config.js
docker compose up -d
docker compose ps       # all "running"; geoipupdate downloads GeoLite2-City on first start
```

Check: `curl -s localhost:9090/api/v1/targets | grep -o '"health":"[a-z]*"' | sort | uniq -c`
(targets turn `up` once the exporters of the next steps are running).

> The MaxMind GeoLite2 database is free but needs an account and may not be redistributed.
> That is why it is downloaded by the `geoipupdate` container and never committed.

## 2. Firewall (OPNsense)

Follow [exporters/opnsense/README.md](../exporters/opnsense/README.md):

1. remote syslog of `filterlog` to the Docker host, UDP 1514, RFC5424,
2. plugin `os-node_exporter` on port 9100,
3. read-only API user for the opnsense-exporter,
4. CrowdSec metrics on port 6060.

Check after a minute (on the Docker host):

```sh
curl -sG localhost:3100/loki/api/v1/query --data-urlencode 'query=count_over_time({job="opnsense"}[5m])'
```

If your WAN interface is not `vtnet1`, note its name (*Interfaces → Overview*, the device in
brackets) – you will need it in step 4.

## 3. Exporters on the hosts

**Proxmox VE hosts** (as root on each host):

```sh
bash exporters/proxmox/setup.sh
```

This installs `prometheus-node-exporter` with the SMART and NVMe collectors. If an SSD reports its
wear in vendor-specific attributes (e.g. SanDisk), see `exporters/proxmox/ssd-wear-prom.sh`.

**NAS:** create a Docker project from `exporters/nas/docker-compose.yml` (UGOS: Docker app →
Project → Create). Synology/TrueNAS work the same way.

**Proxmox Backup Server:** create an API token with the *Audit* role (instructions in the file),
then on the Docker host:

```sh
cd exporters/pbs && cp .env.example .env && chmod 600 .env && nano .env
docker compose up -d
```

Reload Prometheus: `curl -X POST localhost:9090/-/reload`.

## 4. Panel

```sh
cd panel
nano html/config.js     # brand, language, WAN_IF, systems, drives – see docs/configuration.md
docker compose up -d
```

Open `http://192.168.1.10:8088` on a PC. Press F12 → *Console* to see failed queries. The header
shows *Data error: …* as long as a part has no data.

## 5. Raspberry Pi with the display

1. Flash **Raspberry Pi OS (64-bit, with desktop)** with Raspberry Pi Imager; set hostname, user
   and SSH there. A cable connection is recommended.
2. Connect the display as described by its manufacturer (video and touch).
3. `sudo raspi-config` → *System Options → Boot / Auto Login → Desktop Autologin*,
   *Display Options → Screen Blanking → off*.
4. Kiosk autostart:

   ```sh
   mkdir -p ~/.config/labwc
   cp raspberry-pi/autostart ~/.config/labwc/autostart
   nano ~/.config/labwc/autostart      # URL of your panel
   sudo reboot
   ```

   On older images the browser is called `chromium-browser`.

The panel scales itself to the screen. It reloads every 6 hours to pick up changes; after editing
`config.js` you can also just reboot the Pi.

## 6. Rack fan (optional)

Wiring: [hardware.md](hardware.md#fan-wiring). Then on the Pi:

```sh
echo 'dtoverlay=pwm,pin=18,func=2' | sudo tee -a /boot/firmware/config.txt
sudo apt install -y python3-lgpio
sudo cp raspberry-pi/rackfan.py /usr/local/bin/ && sudo chmod +x /usr/local/bin/rackfan.py
sudo nano /usr/local/bin/rackfan.py        # PROM (panel URL) and QUERY (your hosts)
sudo reboot
sudo python3 /usr/local/bin/rackfan.py --test     # speed must rise with the duty cycle
sudo cp raspberry-pi/rackfan.service /etc/systemd/system/
sudo systemctl enable --now rackfan
curl -s localhost:9101/metrics
```

The fan curve: ≤ 45 °C 25 %, 55 °C 40 %, 65 °C 70 %, ≥ 72 °C 100 % (linear in between), slowing down
by at most 5 % per 10 s. Without Prometheus it runs at 70 %, when the service stops at 100 %.

## 7. Vulnerability scanner (optional)

See [vulnscan/README.md](../vulnscan/README.md). Afterwards set `vuln:` in `config.js` to
`http://<scanner>:8081/api`. Without the scanner, set `vuln: null` – the firewall log then uses the
free space.

## Updating

```sh
git pull
cd monitoring && docker compose pull && docker compose up -d
```

Your `config.js` is a tracked file. To keep updates conflict-free, commit your changes to your own
fork or keep a copy and compare after `git pull`.
