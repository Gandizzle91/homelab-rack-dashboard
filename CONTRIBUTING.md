# Contributing

Issues and pull requests are welcome.

- **Bugs:** please include your setup (firewall, hosts, display), what you expected and what happened,
  and the browser console output (open the panel on a PC, press F12).
- **New language:** copy the `de` block in `panel/html/i18n.js`, translate the values and open a PR.
  The demo server helps: `python3 panel/demo/demo-server.py`, then open `/?lang=xx`.
- **Screenshots and examples** must not contain real public IPs, domains or secrets. Use
  `192.168.x.x`, `203.0.113.x` and `example.com`.
- Keep the panel dependency-free (plain HTML/CSS/JS, no build step).
