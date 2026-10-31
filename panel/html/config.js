/* =====================================================================
   Rack dashboard – configuration
   ---------------------------------------------------------------------
   This is the only file you normally need to edit. Everything here is
   plain JavaScript, so you can use variables and template strings.

   Text values (brand, system names, descriptions …) may be a plain
   string or an object with one value per language:
       role: { en: 'Firewall VM', de: 'Firewall-VM' }
   ===================================================================== */

// Name of the firewall's WAN interface as it appears in the filterlog and
// in the exporter metrics (OPNsense on Proxmox/virtio: vtnet1, bare metal: igb0, em0 …)
const WAN_IF = 'vtnet1';

// CPU temperature from node_exporter (Intel: platform_coretemp_0 / temp1, AMD: pci0000:00_0000:00:18_3 / temp1)
const coreTemp = job => `node_hwmon_temp_celsius{job="${job}", chip="platform_coretemp_0", sensor="temp1"}`;

window.DASHBOARD_CONFIG = {
  brand: 'HOMELAB',              // text in the top left corner
  lang: 'en',                    // 'en' or 'de' – can be overridden per device with ?lang=de in the URL
  locale: null,                  // number/date format, e.g. 'en-US'; null = en-GB (24 h clock) or de-DE

  // Data sources. The panel's own nginx proxies these paths (GET only) to Prometheus and Loki.
  prom: '/prom/api/v1',
  loki: '/loki/loki/api/v1',
  // vulnscan API on the scanner (security tile, scan and patch buttons). null = hide the tile.
  vuln: 'http://192.168.1.30:8081/api',

  /* ---------------- Firewall & attacks (Loki) ----------------
     Only blocks whose sender has a GeoIP country, i.e. real internet addresses
     (private addresses in front of the WAN port have no GeoIP data). */
  logQuery:  `{job="opnsense"} | action="block" | iface="${WAN_IF}" | geoip_country_code != ""`,
  mapQuery:  'sum by (geoip_country_code) (count_over_time({job="opnsense"} | action="block" | geoip_country_code != "" [24h]))',
  hourQuery: 'sum(count_over_time({job="opnsense"} | action="block" | geoip_country_code != "" [1h]))',
  rateQuery: `sum(count_over_time({job="opnsense"} | action="block" | iface="${WAN_IF}" | geoip_country_code != "" [5m]))`,

  /* ---------------- WAN traffic (Prometheus) ----------------
     $win is replaced by the rate window, $range by the selected time range (e.g. 24h).
     Uses the opnsense-exporter and falls back to node_exporter on the firewall. */
  wan: {
    device: WAN_IF,
    down: `max(rate(opnsense_interfaces_received_bytes_total{device="${WAN_IF}"}[$win]) * 8) or max(rate(node_network_receive_bytes_total{device="${WAN_IF}"}[$win]) * 8)`,
    up:   `max(rate(opnsense_interfaces_transmitted_bytes_total{device="${WAN_IF}"}[$win]) * 8) or max(rate(node_network_transmit_bytes_total{device="${WAN_IF}"}[$win]) * 8)`,
    volDown: `max(increase(opnsense_interfaces_received_bytes_total{device="${WAN_IF}"}[$range])) or max(increase(node_network_receive_bytes_total{device="${WAN_IF}"}[$range]))`,
    volUp:   `max(increase(opnsense_interfaces_transmitted_bytes_total{device="${WAN_IF}"}[$range])) or max(increase(node_network_transmit_bytes_total{device="${WAN_IF}"}[$range]))`,
  },

  /* ---------------- Systems ----------------
     name     shown on the panel
     job      Prometheus job of the host's node_exporter
     temp     PromQL for the CPU temperature, null = no sensor (e.g. a VM)
     role     one-line description on the "Systems" page
     overview true = row in the "Systems" tile on the overview (fits 3)
     pill     true = status dot in the header */
  systems: [
    { name: 'Firewall', job: 'firewall', temp: null,           role: 'OPNsense · VM on pve2',          overview: false, pill: true },
    { name: 'pve1',     job: 'pve1',     temp: coreTemp('pve1'), role: 'Proxmox VE · mini PC',           overview: true,  pill: true },
    { name: 'pve2',     job: 'pve2',     temp: coreTemp('pve2'), role: 'Proxmox VE · firewall host',     overview: true,  pill: true },
    { name: 'NAS',      job: 'nas',      temp: coreTemp('nas'),  role: 'UGREEN DXP2800 · UGOS',          overview: true,  pill: true },
  ],
  cpuTemp: [70, 85],             // CPU temperature: orange / red from (°C)
  usage:   [85, 95],             // CPU and RAM usage: orange / red from (%)

  /* ---------------- Drives ----------------
     name, location   shown on the panel
     health           1 = healthy, 0 = SMART failure
     temp             temperature in °C (null = none)
     wear             used lifetime 0..1 (null = none, e.g. HDD)
     warn, crit       temperature thresholds (°C)
     written, hours, errors   optional, for the "Drives" page */
  drives: [
    { name: 'NVMe', location: 'pve1', color: '#4cc2ff',
      health:  'smartmon_device_smart_healthy{job="pve1", disk="/dev/nvme0"}',
      temp:    'nvme_temperature_celsius{job="pve1"}',
      wear:    'nvme_percentage_used_ratio{job="pve1"}',
      written: 'nvme_data_units_written_total{job="pve1"} * 512000',
      hours:   'nvme_power_on_hours_total{job="pve1"}',
      errors:  'sum(nvme_media_errors_total{job="pve1"})',
      warn: 60, crit: 70 },
    { name: 'SATA SSD', location: 'pve1', color: '#a78bfa',
      health:  'smartmon_device_smart_healthy{job="pve1", disk="/dev/sda"}',
      temp:    'smartmon_temperature_celsius_raw_value{job="pve1", disk="/dev/sda"}',
      wear:    '(100 - smartmon_percent_lifetime_remain_value{job="pve1", disk="/dev/sda"}) / 100',
      written: 'smartmon_total_lbas_written_raw_value{job="pve1", disk="/dev/sda"} * 512',
      hours:   'smartmon_power_on_hours_raw_value{job="pve1", disk="/dev/sda"}',
      errors:  'sum({__name__=~"smartmon_(reallocated_sector_ct|reported_uncorrect|offline_uncorrectable|current_pending_sector)_raw_value", job="pve1", disk="/dev/sda"})',
      warn: 60, crit: 70 },
    { name: 'Boot SSD', location: 'pve2', color: '#3ddc84',
      health:  'smartmon_device_smart_healthy{job="pve2", disk="/dev/sda"}',
      temp:    null,
      wear:    'ssd_wear_ratio{job="pve2"}',              // from exporters/proxmox/ssd-wear-prom.sh
      written: 'ssd_written_bytes{job="pve2"}',
      hours:   'smartmon_power_on_hours_raw_value{job="pve2", disk="/dev/sda"}',
      errors:  'sum({__name__=~"smartmon_(reallocated_sector_ct|reported_uncorrect|offline_uncorrectable|current_pending_sector)_raw_value", job="pve2", disk="/dev/sda"})',
      warn: 60, crit: 70 },
    { name: 'NAS HDD 1', location: 'NAS · sda', color: '#ffb547',
      health:  'smartctl_device_smart_status{job="nas_smart", device="sda"}',
      temp:    'smartctl_device_temperature{job="nas_smart", device="sda", temperature_type="current"}',
      wear:    null,
      hours:   'smartctl_device_power_on_seconds{job="nas_smart", device="sda"} / 3600',
      errors:  'sum(smartctl_device_attribute{job="nas_smart", device="sda", attribute_value_type="raw", attribute_name=~"Reallocated_Sector_Ct|Current_Pending_Sector|Offline_Uncorrectable|Reported_Uncorrect"})',
      warn: 46, crit: 52 },
    { name: 'NAS HDD 2', location: 'NAS · sdb', color: '#f472b6',
      health:  'smartctl_device_smart_status{job="nas_smart", device="sdb"}',
      temp:    'smartctl_device_temperature{job="nas_smart", device="sdb", temperature_type="current"}',
      wear:    null,
      hours:   'smartctl_device_power_on_seconds{job="nas_smart", device="sdb"} / 3600',
      errors:  'sum(smartctl_device_attribute{job="nas_smart", device="sdb", attribute_value_type="raw", attribute_name=~"Reallocated_Sector_Ct|Current_Pending_Sector|Offline_Uncorrectable|Reported_Uncorrect"})',
      warn: 46, crit: 52 },
  ],

  /* ---------------- Other Prometheus jobs ----------------
     Names for alerts when a scrape target is down (systems above are added automatically),
     the page that opens when the alert is tapped, and 'warn' for targets that are not critical. */
  jobs: {
    'opnsense-exporter': { name: 'OPNsense API' },
    nas_smart:  { name: 'NAS SMART', page: 'drives' },
    pbs:        { name: 'PBS exporter', page: 'backups' },
    crowdsec:   { name: 'CrowdSec', page: 'attacks' },
    prometheus: { name: 'Prometheus' },
    rackfan:    { name: 'Fan control', level: 'warn' },
  },

  /* ---------------- Rack fan (raspberry-pi/rackfan.py) ----------------
     Alarm when the fan should spin (duty > 0) but turns slower than minRpm. null = no fan. */
  fan: { rpm: 'rackfan_rpm', duty: 'rackfan_duty_percent', input: 'rackfan_input_celsius', job: 'rackfan',
         minRpm: 200, model: 'Noctua NF-A12x25 · Raspberry Pi' },

  /* ---------------- Backups (Proxmox Backup Server, pbs-exporter) ----------------
     A guest is up to date if its newest snapshot is younger than maxAgeH hours.
     Guests whose newest backup is older than ignoreAfterD days are not counted (deleted VMs). null = no backups. */
  backup: { maxAgeH: 26, ignoreAfterD: 30, ignoreIds: [] },

  // Extra/override labels for CrowdSec scenarios, e.g. { 'my-scenario': 'My label' }
  reasons: {},

  logRows: null,                 // rows in the live firewall log; null = as many as fit
  fwSample: 5000,                // "Firewall" page: number of recent WAN blocks to analyse
  detailTimeout: 60,             // seconds without touch until a detail page returns to the overview
  modalTimeout: 120,             // seconds without touch until the patch dialog cancels itself
};
