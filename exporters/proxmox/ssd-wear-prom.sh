#!/bin/bash
# Wear and total writes of a SATA SSD whose vendor attributes the smartmon collector does not know
# (example: SanDisk SSD PLUS – attributes 230, 234, 241). Check yours with: smartctl -A /dev/sdX
#
# Install:  cp ssd-wear-prom.sh /usr/local/bin/ && chmod +x /usr/local/bin/ssd-wear-prom.sh
# Cron:     */15 * * * * /usr/local/bin/ssd-wear-prom.sh
set -u
DEV=${1:-/dev/sda}
OUT=/var/lib/prometheus/node-exporter/ssd-wear.prom
A=$(smartctl -A "$DEV")
v() { echo "$A" | awk -v id="$1" '$1==id {print $NF; exit}'; }
wear=$(v 230)    # Media_Wearout_Indicator (percent used)
cache=$(v 234)   # SLC cache wear (percent used)
gib=$(v 241)     # Total_Writes_GiB
{
  echo "# HELP ssd_wear_ratio Used lifetime 0..1"
  echo "# TYPE ssd_wear_ratio gauge"
  [ -n "$wear" ] && echo "ssd_wear_ratio $(awk -v x="$wear" 'BEGIN{printf "%.4f", x/100}')"
  echo "# HELP ssd_wear_cache_ratio Used lifetime of the SLC cache 0..1"
  echo "# TYPE ssd_wear_cache_ratio gauge"
  [ -n "$cache" ] && echo "ssd_wear_cache_ratio $(awk -v x="$cache" 'BEGIN{printf "%.4f", x/100}')"
  echo "# HELP ssd_written_bytes Total bytes written"
  echo "# TYPE ssd_written_bytes gauge"
  [ -n "$gib" ] && echo "ssd_written_bytes $(awk -v x="$gib" 'BEGIN{printf "%.0f", x*1073741824}')"
} > "$OUT.tmp" && mv "$OUT.tmp" "$OUT"
