#!/usr/bin/env python3
"""Demo server: runs the panel with made-up data, no Prometheus/Loki/scanner needed.

    python3 panel/demo/demo-server.py            # then open http://localhost:8099
    python3 panel/demo/demo-server.py --lang de  # German UI
    python3 panel/demo/demo-server.py --fan-stopped   # show the fan alarm

It serves panel/html and answers the Prometheus, Loki and vulnscan API calls the
panel makes with realistic but fictional values. The "Start scan" and "Patch now"
buttons work and finish after a few seconds. Nothing is sent anywhere.
"""
import argparse
import http.server
import json
import math
import os
import random
import threading
import time
import urllib.parse
from datetime import datetime, timedelta, timezone

HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "html")
ARGS = None
RND = random.Random(7)

SYSTEMS = ["firewall", "pve1", "pve2", "nas"]
COUNTRIES = [("US", 37.1, -95.7), ("CN", 35.9, 104.2), ("NL", 52.1, 5.3), ("DE", 51.2, 10.4), ("RU", 61.5, 105.3),
             ("BG", 42.7, 25.5), ("FR", 46.2, 2.2), ("GB", 55.4, -3.4), ("BR", -14.2, -51.9), ("IN", 20.6, 79.0),
             ("KZ", 48.0, 68.0), ("VN", 14.1, 108.3), ("SG", 1.35, 103.8), ("HK", 22.3, 114.2), ("KR", 35.9, 127.8),
             ("ZA", -30.6, 22.9)]
PORTS = [22, 23, 80, 443, 3389, 445, 8080, 5060, 1433, 6379, 8443, 5900, 2222, 27017, 8728]


def iso(dt):
    return dt.astimezone().isoformat(timespec="seconds")


def rand_ip():
    # only addresses reserved for documentation (RFC 5737) and benchmarking (RFC 2544),
    # so no real network appears as an "attacker" in screenshots
    r = RND.random()
    if r < .7:
        return "198.%d.%d.%d" % (RND.randint(18, 19), RND.randint(0, 255), RND.randint(1, 254))
    prefix = RND.choice(["192.0.2", "198.51.100", "203.0.113"])
    return "%s.%d" % (prefix, RND.randint(1, 254))


SCANNERS = [rand_ip() for _ in range(30)]


def log_entry(ts_ns, ip=None):
    c = RND.choice(COUNTRIES[:12])
    port = RND.choice(PORTS) if RND.random() < .7 else RND.randint(1024, 65000)
    return {"stream": {"job": "opnsense", "action": "block", "iface": "vtnet1", "src_ip": ip or rand_ip(),
                       "dst_port": str(port), "proto": "udp" if port == 5060 else "tcp",
                       "geoip_country_code": c[0],
                       "geoip_location_latitude": str(c[1] + RND.uniform(-3, 3)),
                       "geoip_location_longitude": str(c[2] + RND.uniform(-3, 3))},
            "values": [[str(ts_ns), "demo"]]}


NOW_NS = time.time_ns()
LIVE_LOG = [log_entry(NOW_NS - int(i * 4.1e9)) for i in range(40)]
DAY_LOG = [log_entry(NOW_NS - int(i * 7.7e9), RND.choice(SCANNERS) if RND.random() < .35 else None) for i in range(5000)]


def vec(metric, value):
    return {"metric": metric, "value": [time.time(), str(value)]}


def per_job(d):
    return [vec({"job": j}, v) for j, v in d.items()]


GUESTS = [("pve1", "101", "docker", 21.2), ("pve1", "102", "homeassistant", 21.4), ("pve1", "103", "paperless", 21.4),
          ("pve1", "104", "nextcloud", 21.3), ("pve1", "105", "gameserver", 21.3), ("pve1", "106", "guacamole", 21.3),
          ("pve1", "107", "ansible", 21.2), ("pve1", "108", "scanner", 21.2), ("pve1", "109", "pihole", 21.1),
          ("pve1", "120", "test-vm", 46 * 24), ("pve2", "100", "opnsense", 18.1), ("pve2", "110", "unifi", 18.0)]


def prom(q):
    fan = not ARGS.no_fan
    if "rackfan" in q and not fan:
        return []
    if q == "rackfan_rpm":
        return [vec({"job": "rackfan"}, 0 if ARGS.fan_stopped else 1243)]
    if q == "rackfan_duty_percent":
        return [vec({"job": "rackfan"}, 48)]
    if q == "rackfan_input_celsius":
        return [vec({"job": "rackfan"}, 57.7)]
    if q == 'up{job="rackfan"}':
        return [vec({"job": "rackfan"}, 1)]
    if q == "up":
        return [vec({"job": j}, 1) for j in SYSTEMS + ["pbs", "crowdsec", "nas_smart"] + (["rackfan"] if fan else [])]
    if q.startswith("up{"):
        return per_job({j: 1 for j in SYSTEMS})
    if q.startswith("sum(cs_active_decisions{origin"):
        return [vec({}, 48)]
    if q == "sum(cs_active_decisions)":
        return [vec({}, 20512)]
    if q.startswith("sum by (origin)"):
        return [vec({"origin": o}, v) for o, v in [("CAPI", 15820), ("lists:firehol_greensnow", 4644), ("crowdsec", 44), ("cscli", 4)]]
    if "sum by (reason)" in q:
        return [vec({"reason": r}, v) for r, v in [("crowdsecurity/http-probing", 8120), ("firehol_greensnow", 4644),
                                                   ("crowdsecurity/ssh-bf", 3410), ("crowdsecurity/iptables-scan-multi_ports", 2310),
                                                   ("crowdsecurity/http-bad-user-agent", 1220), ("crowdsecurity/CVE-2023-22515", 410),
                                                   ("crowdsecurity/http-sensitive-files", 330)]]
    if "cs_bucket_overflowed" in q:
        return [vec({}, 187)]
    now = time.time()
    if q.startswith("pbs_snapshot_vm_last_timestamp"):
        return [vec({"namespace": ns, "vm_id": i, "vm_name": n, "datastore": "backups"}, now - h * 3600)
                for ns, i, n, h in GUESTS if "namespace!=" not in q or ns]
    if q.startswith("pbs_snapshot_vm_count"):
        return [vec({"namespace": ns, "vm_id": i}, 3 if n == "test-vm" else 14 - int(i) % 5) for ns, i, n, _ in GUESTS]
    if q.startswith("pbs_snapshot_vm_last_verify"):
        return [vec({"namespace": ns, "vm_id": i}, 1) for ns, i, n, _ in GUESTS if n not in ("gameserver", "ansible")]
    simple = {"max(pbs_used) / max(pbs_size)": .47, "pbs_up": 1, "pbs_host_cpu_usage": .04, "pbs_host_memory_used": 2.1 * 2**30,
              "pbs_host_memory_total": 4 * 2**30, "pbs_host_uptime": 24 * 86400 + 5 * 3600, "pbs_host_load1": .18}
    if q in simple:
        return [vec({}, simple[q])]
    if q == "pbs_used":
        return [vec({"datastore": "backups"}, 0.94e12)]
    if q == "pbs_size":
        return [vec({"datastore": "backups"}, 2.0e12)]
    if q.startswith("sum by (interface, device)"):
        rx = "received" in q
        return [vec({"interface": i, "device": d}, a if rx else b) for i, d, a, b in
                [("WAN", "vtnet1", 23.4e6, 3.1e6), ("LAN", "vtnet0", 2.6e6, 19.8e6), ("SERVER", "vlan20", 0.9e6, 1.6e6),
                 ("IOT", "vlan30", 0.4e6, 0.2e6), ("GUEST", "vlan40", 1.1e6, 6.3e6), ("DMZ", "vlan50", 0.3e6, 0.2e6)]]
    if "increase(opnsense_interfaces_received" in q:
        return [vec({}, 61.7e9)]
    if "increase(opnsense_interfaces_transmitted" in q:
        return [vec({}, 11.2e9)]
    for key, v in [("nvme_data_units_written", 29.4e12), ("nvme_power_on_hours", 9620), ("nvme_media_errors", 0),
                   ("smartmon_total_lbas_written", 18.3e12), ("ssd_written_bytes", 3.2e12), ("ssd_wear_ratio", .14),
                   ("smartctl_device_attribute", 0), ("nvme_percentage", .09), ("lifetime", .11), ("nvme_temperature", 49),
                   ("smartmon_temperature", 44)]:
        if key in q:
            return [vec({}, v)]
    if "smartmon_power_on_hours" in q:
        return [vec({}, 14210 if "pve1" in q else 3880)]
    if '__name__=~"smartmon_' in q:
        return [vec({}, 0)]
    if "smartctl_device_power_on_seconds" in q:
        return [vec({}, (8740 if "sda" in q else 8731))]
    if "smartctl_device_temperature" in q:
        return [vec({}, 41 if "sda" in q else 43)]
    if 'job="pve2", chip' in q:
        return [vec({}, 61)]
    if 'job="nas", chip' in q:
        return [vec({}, 52)]
    if "coretemp" in q:
        return [vec({}, 57)]
    if "node_cpu" in q and "count" in q:
        return per_job({"firewall": 4, "pve1": 8, "pve2": 4, "nas": 4})
    if "node_cpu" in q:
        return per_job({"firewall": .04, "pve1": .07, "pve2": .03, "nas": .05})
    if "MemAvailable" in q:
        return per_job({"firewall": .74, "pve1": .46, "pve2": .71, "nas": .38})
    if "boot_time" in q:
        return per_job({"firewall": 9e5, "pve1": 2e5, "pve2": 2e6, "nas": 3e6})
    if "node_load1" in q:
        return per_job({"firewall": .3, "pve1": 1.4, "pve2": .5, "nas": .9})
    if "MemTotal" in q:
        return per_job({"firewall": 16 * 2**30, "pve1": 32 * 2**30, "pve2": 16 * 2**30, "nas": 8 * 2**30})
    if "smart_status" in q or "smart_healthy" in q:
        return [vec({}, 1)]
    if "received" in q:
        return [vec({}, 18e6)]
    if "transmitted" in q:
        return [vec({}, 2e6)]
    return []


def prom_range(q, start, end, step):
    ts = [start + i * step for i in range(int((end - start) / step) + 1)]

    def wave(base, amp):
        return [[t, str(base + amp * math.sin(t / 5000) + random.uniform(-amp / 3, amp / 3))] for t in ts]
    if "rackfan" in q and ARGS.no_fan:
        return []
    if q == "rackfan_rpm":
        return [{"metric": {}, "values": wave(1200, 250)}]
    if q == "rackfan_duty_percent":
        return [{"metric": {}, "values": wave(46, 10)}]
    if q == "rackfan_input_celsius":
        return [{"metric": {}, "values": wave(57, 3)}]
    if "node_cpu" in q:
        return [{"metric": {"job": j}, "values": wave(.06, .03)} for j in SYSTEMS]
    if "MemAvailable" in q:
        return [{"metric": {"job": j}, "values": wave(.5, .02)} for j in SYSTEMS]
    if 'job="pve2", chip' in q:
        return [{"metric": {}, "values": wave(61, 6)}]
    if 'job="nas", chip' in q:
        return [{"metric": {}, "values": wave(53, 4)}]
    if "coretemp" in q:
        return [{"metric": {}, "values": wave(57, 5)}]
    if "nvme_temperature" in q:
        return [{"metric": {}, "values": wave(49, 2.5)}]
    if "smartmon_temperature" in q:
        return [{"metric": {}, "values": wave(44, 1.5)}]
    if "smartctl_device_temperature" in q:
        return [{"metric": {}, "values": [[t, str(round(float(v)))] for t, v in wave(41 if "sda" in q else 43, 1.2)]}]
    if "transmit" in q:
        return [{"metric": {}, "values": wave(2.4e6, 1.1e6)}]
    return [{"metric": {}, "values": wave(15e6, 5e6)}]


# ---------------- vulnscan API ----------------
NOW = datetime.now(timezone.utc)
GEN = iso(NOW - timedelta(minutes=50))
LAST_SCAN = NOW - timedelta(hours=11)


def host(name, addr, os_, sec, pkgs, reboot=False):
    return {"host": name, "address": addr, "os": os_, "kernel": "6.12", "upgradable": len(pkgs), "security": sec,
            "packages": pkgs, "reboot_required": reboot, "checked": GEN}


DEB12 = ["bind9-dnsutils", "bind9-host", "bind9-libs", "libexpat1", "tzdata", "libssl3"]
SUMMARY = {
    "generated": GEN, "status": "warn",
    "reasons": ["18 security updates pending", "Reboot required: pve1", "Medium findings: 1"],
    "reason_codes": [{"id": "security_updates", "n": 18}, {"id": "reboot", "hosts": ["pve1"]}, {"id": "medium_findings", "n": 1}],
    "patches": {"generated": GEN, "hosts": [
        host("paperless", "192.168.1.43", "Debian 12.12", 6, DEB12),
        host("gameserver", "192.168.1.45", "Debian 12.12", 6, DEB12),
        host("nextcloud", "192.168.1.44", "Debian 12.12", 6, DEB12),
        host("pve1", "192.168.1.5", "Debian 13.1", 0, ["proxmox-kernel-6.17", "pve-manager", "libpve-common-perl", "pve-container",
                                                         "qemu-server", "pve-firmware", "pve-i18n", "tzdata"], reboot=True),
        host("pbs", "192.168.1.9", "Debian 13.1", 0, ["proxmox-backup-server", "proxmox-backup-client", "libproxmox-acme-plugins",
                                                       "proxmox-widget-toolkit", "tzdata", "pve-firmware"]),
        host("docker", "192.168.1.10", "Debian 13.1", 0, []), host("guacamole", "192.168.1.46", "Debian 13.1", 0, []),
        host("ansible", "192.168.1.31", "Debian 13.1", 0, []), host("pve2", "192.168.1.6", "Debian 13.1", 0, [])],
        "unreachable": [], "total_security": 18, "total_upgradable": 30, "reboot_needed": ["pve1"]},
    "nuclei": {"lastrun": iso(LAST_SCAN), "counts": {"critical": 0, "high": 0, "medium": 1, "low": 2}, "findings": [
        {"severity": "medium", "name": "Prometheus Metrics - Unauthenticated", "template": "prometheus-metrics", "target": "http://192.168.1.10:9090"},
        {"severity": "low", "name": "Missing Security Headers", "template": "http-missing-security-headers", "target": "https://cloud.example.com"},
        {"severity": "low", "name": "Loki - Unauthenticated API", "template": "loki-unauth", "target": "http://192.168.1.10:3100"}]},
    "external": {"checked": iso(NOW - timedelta(minutes=35)), "host": "home.example.com", "ip": "203.0.113.48", "ports": [443],
                 "vulns": [], "hostnames": [], "cpes": [], "note": None,
                 "certs": [{"domain": d, "days_left": n} for d, n in [("home.example.com", 71), ("cloud.example.com", 64),
                                                                       ("docs.example.com", 80), ("vpn.example.com", 86)]]}}
STEPS = {"scan": [("status", "Read patch status"), ("external", "Check external view"), ("nuclei", "Nuclei scan")],
         "patch": [("install", "Install updates"), ("status", "Re-read patch status")]}


def done_job(kind, started, ended, result, data):
    # realistic step lengths: patch status ~30 s, external check ~2 s, the rest is Nuclei
    cuts = [started, started + timedelta(seconds=31), started + timedelta(seconds=33), ended]
    return {"id": "demo", "kind": kind, "state": "done", "started": iso(started), "ended": iso(ended), "result": result,
            "result_data": data, "log": [],
            "steps": [{"key": k, "name": n, "state": "ok", "started": iso(cuts[i]), "ended": iso(cuts[i + 1])}
                      for i, (k, n) in enumerate(STEPS[kind])]}


JOB = {"control": True, "running": False,
       "job": done_job("scan", LAST_SCAN - timedelta(minutes=28), LAST_SCAN, "Attention · 18 security updates pending; Medium findings: 1",
                       {"failed": [], "status": "warn", "security": [18, 18], "upgradable": [30, 30],
                        "reason_codes": SUMMARY["reason_codes"][:2]})}


def finish_later(kind):
    def run():
        time.sleep(5)
        end = datetime.now(timezone.utc)
        for s in JOB["job"]["steps"]:
            s.update(state="ok", ended=iso(end))
        if kind == "patch":
            data = {"failed": [], "security": [18, 0], "upgradable": [30, 12]}
            result = "Security updates 18 → 0 · all updates 30 → 12"
        else:
            data = {"failed": [], "status": "warn", "security": [18, 18], "upgradable": [30, 30], "reason_codes": SUMMARY["reason_codes"][:2]}
            result = "Attention · 18 security updates pending; Reboot required: pve1"
        JOB["job"].update(state="done", ended=iso(end), result=result, result_data=data)
        JOB["running"] = False
    threading.Thread(target=run, daemon=True).start()


def vapi(h, method, path, body):
    if method == "GET" and path == "/vapi/summary":
        return h.send(200, SUMMARY)
    if method == "GET" and path == "/vapi/job":
        return h.send(200, JOB)
    if JOB["running"]:
        return h.send(409, {"error": "A job is already running", "code": "busy"})
    if path == "/vapi/patch" and body.get("plan") != GEN:
        return h.send(409, {"error": "The patch status has changed – please review the list again", "code": "stale", "stale": True})
    kind = {"/vapi/scan": "scan", "/vapi/patch": "patch"}.get(path)
    if not kind:
        return h.send(404, {"error": "Not found", "code": "not_found"})
    start = datetime.now(timezone.utc)
    JOB["running"] = True
    JOB["job"] = {"id": "demo2", "kind": kind, "state": "running", "started": iso(start), "ended": None, "result": None,
                  "log": ["$ ssh " + ("patch" if kind == "patch" else "status"), "PLAY [Collect patch status of all systems]"],
                  "steps": [{"key": k, "name": n, "state": "run" if i == 0 else "wait", "started": iso(start)} for i, (k, n) in enumerate(STEPS[kind])]}
    if kind == "patch":
        JOB["job"].update(hosts=body.get("hosts"), packages=18)
    finish_later(kind)
    return h.send(202, {"job": JOB["job"]})


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=HTML, **k)

    def log_message(self, *a):
        pass

    def send(self, code, data, wrap=False):
        body = json.dumps({"status": "success", "data": data} if wrap else data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            body = {}
        return vapi(self, "POST", urllib.parse.urlparse(self.path).path, body)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        qq = q.get("query", [""])[0]
        if u.path.startswith("/vapi/"):
            return vapi(self, "GET", u.path, None)
        if u.path == "/config.js":   # the real config, pointed at the demo API
            with open(os.path.join(HTML, "config.js"), encoding="utf-8") as f:
                js = f.read() + "\n/* demo-server */\nwindow.DASHBOARD_CONFIG.vuln = '/vapi';\n"
            if ARGS.lang:
                js += "window.DASHBOARD_CONFIG.lang = %s;\n" % json.dumps(ARGS.lang)
            if ARGS.no_fan:
                js += "window.DASHBOARD_CONFIG.fan = null;\n"
            body = js.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/javascript; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return self.wfile.write(body)
        if u.path == "/prom/api/v1/query":
            return self.send(200, {"resultType": "vector", "result": prom(qq)}, True)
        if u.path == "/prom/api/v1/query_range":
            return self.send(200, {"resultType": "matrix", "result": prom_range(qq, float(q["start"][0]), float(q["end"][0]), float(q["step"][0]))}, True)
        if u.path == "/loki/loki/api/v1/query":
            if "by (geoip_country_code)" in qq:
                return self.send(200, {"resultType": "vector", "result": [vec({"geoip_country_code": c[0]}, int(14800 / (i + 1) ** 1.15))
                                                                          for i, c in enumerate(COUNTRIES)]}, True)
            return self.send(200, {"resultType": "vector", "result": [vec({}, 131)]}, True)
        if u.path == "/loki/loki/api/v1/query_range":
            if "step" in q:   # blocks per hour
                st, en, sp = int(q["start"][0]) / 1e9, int(q["end"][0]) / 1e9, float(q["step"][0])
                pts = [[t, str(int(1400 + 500 * math.sin(t / 14000) + RND.uniform(-200, 200) + (1900 if abs(t - en + 9 * 3600) < 1800 else 0)))]
                       for t in [st + i * sp for i in range(int((en - st) / sp) + 1)]]
                return self.send(200, {"resultType": "matrix", "result": [{"metric": {}, "values": pts}]}, True)
            if int(q.get("limit", ["40"])[0]) >= 1000:
                return self.send(200, {"resultType": "streams", "result": DAY_LOG}, True)
            for _ in range(RND.randint(0, 2)):
                LIVE_LOG.insert(0, log_entry(time.time_ns()))
            del LIVE_LOG[200:]
            return self.send(200, {"resultType": "streams", "result": LIVE_LOG[:40]}, True)
        return super().do_GET()


def main():
    global ARGS
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--port", type=int, default=8099)
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--lang", choices=["en", "de"], help="override the language from config.js")
    p.add_argument("--no-fan", action="store_true", help="pretend there is no rack fan")
    p.add_argument("--fan-stopped", action="store_true", help="show the 'fan stopped' alarm")
    ARGS = p.parse_args()
    print(f"Demo panel on http://{ARGS.bind}:{ARGS.port}/  (Ctrl+C to stop)", flush=True)
    http.server.ThreadingHTTPServer((ARGS.bind, ARGS.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
