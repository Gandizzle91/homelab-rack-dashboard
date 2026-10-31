# Changelog

## 1.0.0 – 2026-10-31

First public release.

- Panel: overview with map, live firewall log, WAN, systems, drives; 7 detail pages; alarms.
- English and German UI (`lang` in `config.js` or `?lang=de`), locale-aware numbers and dates.
- All hosts, drives, queries and thresholds configurable in `config.js`; fan, backups and
  security tile can be switched off.
- Rack fan controller for a Noctua 5 V PWM fan on a Raspberry Pi (`rackfan.py`).
- vulnscan: patch status, Nuclei and external view; API with *Start scan* and *Patch* buttons,
  machine-readable reasons (`reason_codes`) and error codes.
- Demo server with fictional data (`panel/demo/demo-server.py`).
