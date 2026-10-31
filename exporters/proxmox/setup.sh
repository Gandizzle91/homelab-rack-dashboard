#!/bin/bash
# Run on every Proxmox VE host (Debian): node_exporter plus the SMART and NVMe collectors.
set -euo pipefail
apt-get install -y prometheus-node-exporter prometheus-node-exporter-collectors smartmontools nvme-cli
systemctl enable --now prometheus-node-exporter
# The collectors run as systemd timers and write to /var/lib/prometheus/node-exporter/*.prom
systemctl enable --now prometheus-node-exporter-smartmon.timer prometheus-node-exporter-nvme.timer
systemctl list-timers 'prometheus-node-exporter-*'
echo "--- sample metrics (may take up to 15 minutes to appear):"
curl -s localhost:9100/metrics | grep -E '^(smartmon_device_smart_healthy|nvme_temperature_celsius)' | head || true
