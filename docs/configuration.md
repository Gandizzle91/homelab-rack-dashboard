# Configuration

Everything about the panel is set in **`panel/html/config.js`**. It is plain JavaScript, so you can use
variables and template strings. After a change, reload the page (on the Pi: reboot, or wait for the
automatic reload every 6 hours).

## Basics

| Key | Default | Meaning |
|---|---|---|
| `brand` | `'HOMELAB'` | text in the top left corner |
| `lang` | `'en'` | `'en'` or `'de'`; per device overridable with `?lang=de` in the URL |
| `locale` | `null` | number and date format, e.g. `'en-US'`; `null` = `en-GB` (24 h clock) or `de-DE` |
| `prom`, `loki` | `/prom/api/v1`, `/loki/loki/api/v1` | API paths through the panel's nginx proxy |
| `vuln` | `http://192.168.1.30:8081/api` | vulnscan API; `null` hides the security tile |

Text values like `brand`, `name` or `role` can also be translated per language:

```js
role: { en: 'Firewall VM', de: 'Firewall-VM' },
```

## Firewall and WAN

`WAN_IF` at the top of the file is the firewall's WAN device (`vtnet1` for OPNsense on Proxmox with
VirtIO, `igb0`/`em0`/… on bare metal). It is used in:

- `logQuery`, `mapQuery`, `hourQuery`, `rateQuery` – LogQL queries on the filterlog stream in Loki.
  They only count blocks whose sender has a GeoIP country, i.e. real internet addresses.
- `wan.down`, `wan.up` – PromQL for the current bandwidth in bit/s. `$win` is replaced by the rate
  window. `wan.volDown`, `wan.volUp` – transferred bytes; `$range` is replaced by the selected range.

## Systems

```js
systems: [
  { name: 'pve1', job: 'pve1', temp: coreTemp('pve1'), role: 'Proxmox VE · mini PC', overview: true, pill: true },
],
```

| Field | Meaning |
|---|---|
| `name` | label on the panel |
| `job` | Prometheus job name of the host's node_exporter |
| `temp` | PromQL for the CPU temperature; `null` = no sensor (VMs) |
| `role` | one line of description on the *Systems* page |
| `overview` | `true` = row in the *Systems* tile (there is room for 3) |
| `pill` | `true` = status dot in the header |

`coreTemp(job)` is a small helper at the top of the file for Intel CPUs. For AMD use something like
`node_hwmon_temp_celsius{job="x", chip=~"pci0000:00_0000:00:18_3", sensor="temp1"}` – check with
`curl -s <host>:9100/metrics | grep hwmon_temp`.

`cpuTemp` and `usage` are the orange/red thresholds.

## Drives

```js
{ name: 'NVMe', location: 'pve1', color: '#4cc2ff',
  health: '…', temp: '…', wear: '…', written: '…', hours: '…', errors: '…', warn: 60, crit: 70 },
```

`health` must return `1` for a healthy disk and `0` for a SMART failure. `wear` is the used lifetime
from `0` to `1`. Any query can be `null`. The tile has room for 5 drives; the *Drives* page shows all.
Typical HDD limits are 46/52 °C, SSD 60/70 °C.

## Other Prometheus jobs

```js
jobs: { pbs: { name: 'PBS exporter', page: 'backups' }, rackfan: { name: 'Fan control', level: 'warn' } },
```

When any scrape target is down, the panel raises an alarm "*name* offline". `page` is opened when you
tap the alarm, `level: 'warn'` makes it orange instead of red. Systems from `systems` are added
automatically.

## Fan, backups

- `fan` – metric names of `rackfan.py`, `minRpm` (alarm threshold) and the `model` text. `null` = no fan.
- `backup` – `maxAgeH`: a guest counts as backed up if its newest snapshot is younger;
  `ignoreAfterD`: guests whose newest backup is older are ignored (deleted VMs); `ignoreIds`: VM IDs
  to ignore. `null` = no backups. Only snapshots in a PBS **namespace** are counted.

## Timing

| Key | Default | |
|---|---|---|
| `logRows` | `null` | rows in the live firewall log; `null` = as many as fit |
| `fwSample` | `5000` | number of blocks analysed on the *Firewall* page (Loki's `max_entries_limit_per_query` must be at least this) |
| `detailTimeout` | `60` | seconds until a detail page returns to the overview |
| `modalTimeout` | `120` | seconds until the patch dialog cancels itself |

## CrowdSec labels

Scenario names are shown as short labels (`crowdsecurity/ssh-bf` → *SSH brute force*). Add or
override labels with `reasons: { 'my-scenario': 'My label' }`.

## Translations

`panel/html/i18n.js` maps each English text to its translation. A missing entry falls back to
English, so a partial translation never breaks the panel. To add a language, copy the `de` block,
rename it (e.g. `fr`) and set `lang: 'fr'`. Country names are translated by the browser.
