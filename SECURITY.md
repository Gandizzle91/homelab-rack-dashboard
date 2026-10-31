# Security

This project shows sensitive information about your network and can install updates on your
servers. Please read this before you deploy it.

## Design assumptions

- **LAN only.** The panel (port 8088), Prometheus, Loki, the scanner dashboard (8080) and the
  vulnscan API (8081) have **no login**. Never forward these ports from the internet and never put
  them behind a public reverse proxy. If you need remote access, use a VPN.
- **Read-only panel.** The panel's nginx only proxies `GET` requests to Prometheus and Loki.
  Prometheus and Loki themselves are bound to `127.0.0.1` on the Docker host by default.
- **Secrets in `.env` only.** `monitoring/.env` and `exporters/pbs/.env` hold API keys and tokens;
  they are listed in `.gitignore`. Use read-only API users (OPNsense) and the "Audit" role (PBS).

## The patch button

The *Patch vulnerabilities* button runs `apt` upgrades on the systems in your Ansible inventory.
It is protected in several layers (details in [vulnscan/README.md](vulnscan/README.md)):

- only addresses in `control_clients` may start jobs (default: the display's Pi),
- `POST` requests from foreign web pages are rejected (Origin check),
- the display only sends host names; the packages come from the scanner's stored patch plan,
- the scanner's SSH key can only run a fixed trigger script (`command=`, `from=`, `restrict`),
- only already installed packages are upgraded, nothing is rebooted automatically.

Anyone who can touch the display can still start a patch run. If that is a problem in your
environment, set `control_clients: []` in `vulnscan/vars.yml`.

## Nuclei

Only scan systems you own or are explicitly allowed to test. The default run excludes intrusive
checks (`dos, fuzz, intrusive, brute-force, default-login`), but scanning can still trigger alarms
or rate limits on third-party services.

## Before you publish your own fork

- Replace real IP addresses, domain names and host names you don't want to share.
- Run a secret scanner, e.g. `gitleaks detect --source . -v`, before every push.
- Check that no `.env`, `*.mmdb`, SSH keys or backups are tracked: `git ls-files`.

## Reporting a vulnerability

Please do not open a public issue for security problems. Use GitHub's
**Security → Report a vulnerability** (private vulnerability reporting) on this repository instead.
