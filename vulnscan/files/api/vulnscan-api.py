#!/usr/bin/env python3
"""vulnscan-api – buttons for the rack panel: start a scan and install updates.

Runs on the scanner as user vulnscan-api on port 8081.

  GET  /api/summary   summary (same content as www/data/summary.json)
  GET  /api/job       running or last job, plus "control": may this device start jobs?
  POST /api/scan      re-check patch status, external view and Nuclei
  POST /api/patch     {"plan": "<patches.generated>", "hosts": ["paperless", ...], "confirm": true}

Anyone in the LAN may read (the data is on port 8080 anyway).
Only addresses in CONTROL_CLIENTS (default: the rack display) may start jobs, and only from a
web page with a private address (Origin check against foreign web pages / CSRF).

Patch status and patching run on the Ansible host: the scanner may trigger exactly one command
there via SSH (vulnscan-trigger, forced command in authorized_keys). Which packages get installed
is decided solely by the patch status stored here on the scanner; the display only sends the
names of the selected hosts.

Errors are returned as {"error": "<English text>", "code": "<id>"} so clients can translate them.
"""
import ipaddress
import json
import os
import subprocess
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

PORT = int(os.environ.get("PORT", "8081"))
SUMMARY = os.environ.get("SUMMARY", "/opt/vulnscan/www/data/summary.json")
STATE_DIR = os.environ.get("STATE_DIR", "/var/lib/vulnscan-api")
ANSIBLE_HOST = os.environ.get("ANSIBLE_HOST", "")
SSH_KEY = os.environ.get("SSH_KEY", os.path.join(STATE_DIR, ".ssh", "id_ed25519"))
SUDO = os.environ.get("SUDO", "/usr/bin/sudo")
SYSTEMCTL = os.environ.get("SYSTEMCTL", "/usr/bin/systemctl")
SSH = os.environ.get("SSH", "/usr/bin/ssh")


def _nets(value):
    out = []
    for part in value.split(","):
        part = part.strip()
        if part:
            out.append(ipaddress.ip_network(part, strict=False))
    return out


CONTROL_CLIENTS = _nets(os.environ.get("CONTROL_CLIENTS", "127.0.0.1"))
ORIGIN_NETS = _nets(os.environ.get("ORIGIN_NETS", "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"))
ORIGIN_HOSTS = {h.strip().lower() for h in os.environ.get("ORIGIN_HOSTS", "localhost").split(",") if h.strip()}

JOB_FILE = os.path.join(STATE_DIR, "job.json")
LOG_DIR = os.path.join(STATE_DIR, "logs")
LOCK = threading.Lock()
JOB = None          # current or last job
RUNNING = False


def now():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def load_summary():
    with open(SUMMARY, encoding="utf-8") as f:
        return json.load(f)


def save_job():
    try:
        tmp = JOB_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(JOB, f, ensure_ascii=False)
        os.replace(tmp, JOB_FILE)
    except OSError:
        pass


def public_job():
    if JOB is None:
        return None
    j = {k: v for k, v in JOB.items() if k != "log"}
    j["log"] = JOB.get("log", [])[-8:]
    return j


def set_step(key, state, detail=None):
    for s in JOB["steps"]:
        if s["key"] == key:
            s["state"] = state
            if detail is not None:
                s["detail"] = detail
            if state == "run":
                s["started"] = now()
            elif state in ("ok", "fail", "skip"):
                s["ended"] = now()
    save_job()


def add_log(line, logf):
    line = line.rstrip("\n")
    logf.write(line + "\n")
    logf.flush()
    if not line.strip():
        return
    JOB["log"].append(line[:300])
    del JOB["log"][:-200]


def run_cmd(cmd, logf, stdin_data=None, on_line=None, timeout=4 * 3600):
    """Runs a command, writes its output to the log and returns the exit code."""
    add_log("$ " + " ".join(["ssh", cmd[-1]] if cmd[0] == SSH else cmd), logf)
    try:
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    except OSError as e:
        add_log(f"Could not start: {e}", logf)
        return 127
    if stdin_data is not None:
        try:
            p.stdin.write(stdin_data)
            p.stdin.close()
        except OSError:
            pass
    timer = threading.Timer(timeout, p.kill)
    timer.start()
    try:
        for line in p.stdout:
            if on_line and on_line(line.rstrip("\n")):
                continue
            add_log(line, logf)
            save_job()
        return p.wait()
    finally:
        timer.cancel()


def ssh_cmd(action):
    return [SSH, "-i", SSH_KEY,
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "UserKnownHostsFile=" + os.path.join(STATE_DIR, ".ssh", "known_hosts"),
            "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=10",
            f"root@{ANSIBLE_HOST}", action]


def remote(action, logf, stdin_data=None):
    """Calls the trigger on the Ansible host. Lines '### STEP <key>' advance the steps."""
    def on_line(line):
        if line.startswith("### STEP "):
            key = line.split()[2]
            for s in JOB["steps"]:
                if s["state"] == "run" and s["key"] != key:
                    s["state"] = "ok"
                    s["ended"] = now()
            set_step(key, "run")
            return True
        if line.startswith("### RESULT "):
            for item in line.split()[2:]:
                key, _, rc = item.partition("=")
                set_step(key, "ok" if rc == "0" else "fail")
            return True
        return line.startswith("### ")
    if not ANSIBLE_HOST:
        add_log("ANSIBLE_HOST is not set (/etc/default/vulnscan-api)", logf)
        return 2
    return run_cmd(ssh_cmd(action), logf, stdin_data=stdin_data, on_line=on_line)


def unit(name, logf):
    return run_cmd([SUDO, "-n", SYSTEMCTL, "start", name], logf)


def counts(summary):
    p = (summary or {}).get("patches") or {}
    return p.get("total_security", 0), p.get("total_upgradable", 0)


def worker(kind, payload):
    global RUNNING
    os.makedirs(LOG_DIR, exist_ok=True)
    logpath = os.path.join(LOG_DIR, f"{JOB['started'][:19].replace(':', '-')}-{kind}.log")
    try:
        before = load_summary()
    except (OSError, ValueError):
        before = None
    failed = []
    with open(logpath, "w", encoding="utf-8") as logf:
        try:
            if kind == "scan":
                set_step("status", "run")
                rc = remote("status", logf)
                set_step("status", "ok" if rc == 0 else "fail")
                if rc:
                    failed.append("status")
                set_step("external", "run")
                rc = unit("vulnscan-external.service", logf)
                set_step("external", "ok" if rc == 0 else "fail")
                if rc:
                    failed.append("external")
                set_step("nuclei", "run")
                rc = unit("vulnscan-nuclei.service", logf)
                set_step("nuclei", "ok" if rc == 0 else "fail")
                if rc:
                    failed.append("nuclei")
            else:
                set_step("install", "run")
                rc = remote("patch", logf, stdin_data=json.dumps(payload))
                for s in JOB["steps"]:
                    if s["state"] == "run":
                        set_step(s["key"], "ok" if rc == 0 else "fail")
                    elif s["state"] == "wait":
                        set_step(s["key"], "skip" if rc else "ok")
                if rc:
                    failed.append("install")
        except Exception as e:  # noqa: BLE001 – a job must never get stuck
            add_log(f"Internal error: {e}", logf)
            failed.append("internal")
            for s in JOB["steps"]:
                if s["state"] in ("run", "wait"):
                    s["state"] = "fail" if s["state"] == "run" else "skip"
    try:
        after = load_summary()
    except (OSError, ValueError):
        after = None
    sb, ub = counts(before)
    sa, ua = counts(after)
    # result: English text for humans and logs, result_data for clients that translate
    data = {"failed": failed, "security": [sb, sa], "upgradable": [ub, ua]}
    if kind == "patch":
        result = f"Security updates {sb} → {sa} · all updates {ub} → {ua}"
    else:
        st = (after or {}).get("status")
        data.update(status=st, reasons=(after or {}).get("reasons", [])[:2], reason_codes=(after or {}).get("reason_codes", [])[:2])
        result = {"ok": "All good", "warn": "Attention", "crit": "Critical"}.get(st, "finished")
        if after:
            result += " · " + "; ".join((after.get("reasons") or [])[:2])
    if failed:
        result = "Failed: " + ", ".join(failed) + " · " + result
    JOB.update(state="failed" if failed else "done", ended=now(), result=result, result_data=data, logfile=logpath)
    save_job()
    with LOCK:
        RUNNING = False


def start_job(kind, title, steps, payload=None):
    global JOB, RUNNING
    with LOCK:
        if RUNNING:
            return False
        RUNNING = True
        JOB = {"id": uuid.uuid4().hex[:8], "kind": kind, "title": title, "state": "running",
               "started": now(), "ended": None, "result": None, "log": [],
               "steps": [{"key": k, "name": n, "state": "wait"} for k, n in steps]}
        if payload:
            JOB["hosts"] = sorted(payload["hosts"].keys())
            JOB["packages"] = sum(len(v) for v in payload["hosts"].values())
        save_job()
    threading.Thread(target=worker, args=(kind, payload), daemon=True).start()
    return True


def origin_ok(origin):
    if not origin:
        return False
    try:
        host = (urlsplit(origin).hostname or "").lower()
    except ValueError:
        return False
    if host in ORIGIN_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip in n for n in ORIGIN_NETS)


def client_ok(addr):
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return any(ip in n for n in CONTROL_CLIENTS)


class Handler(BaseHTTPRequestHandler):
    server_version = "vulnscan-api"
    sys_version = ""

    def log_message(self, fmt, *args):  # log write requests only
        if self.command != "GET":
            super().log_message(fmt, *args)

    def send_err(self, status, code, message, cors_origin="*", **extra):
        return self.send_json(status, dict(error=message, code=code, **extra), cors_origin)

    def send_json(self, code, data, cors_origin="*"):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        if cors_origin:
            self.send_header("Access-Control-Allow-Origin", cors_origin)
            if cors_origin != "*":
                self.send_header("Vary", "Origin")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        origin = self.headers.get("Origin", "")
        self.send_response(204)
        if origin_ok(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Allow-Private-Network", "true")
            self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/api/summary":
            try:
                return self.send_json(200, load_summary())
            except (OSError, ValueError):
                return self.send_err(503, "no_summary", "No summary available yet")
        if path == "/api/job":
            return self.send_json(200, {"control": client_ok(self.client_address[0]), "running": RUNNING,
                                        "job": public_job()})
        return self.send_err(404, "not_found", "Not found")

    def do_POST(self):
        path = urlsplit(self.path).path
        origin = self.headers.get("Origin", "")
        local = self.client_address[0] in ("127.0.0.1", "::1")
        cors = origin if origin_ok(origin) else None
        if not client_ok(self.client_address[0]):
            return self.send_err(403, "control_denied", "Control is only allowed from the rack display", cors)
        if not (cors or (local and not origin)):
            return self.send_err(403, "origin_denied", "Request from a foreign web page rejected", None)
        if "application/json" not in self.headers.get("Content-Type", ""):
            return self.send_err(415, "json_expected", "JSON expected", cors)
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = 0
        if n > 65536:
            return self.send_err(413, "too_large", "Request too large", cors)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
            if not isinstance(body, dict):
                raise ValueError
        except ValueError:
            return self.send_err(400, "bad_json", "Invalid JSON", cors)

        if path == "/api/scan":
            ok = start_job("scan", "Scan", [("status", "Read patch status"), ("external", "Check external view"),
                                             ("nuclei", "Nuclei scan")])
            if not ok:
                return self.send_err(409, "busy", "A job is already running", cors)
            return self.send_json(202, {"job": public_job()}, cors)

        if path == "/api/patch":
            if body.get("confirm") is not True:
                return self.send_err(400, "no_confirm", "Confirmation missing", cors)
            try:
                summary = load_summary()
            except (OSError, ValueError):
                return self.send_err(503, "no_plan", "No patch status available", cors)
            patches = summary.get("patches") or {}
            if not patches.get("generated") or body.get("plan") != patches.get("generated"):
                return self.send_err(409, "stale", "The patch status has changed – please review the list again", cors,
                                     stale=True)
            wanted = body.get("hosts")
            if not isinstance(wanted, list) or not wanted or not all(isinstance(h, str) for h in wanted):
                return self.send_err(400, "no_hosts", "No systems selected", cors)
            known = {h.get("host"): h.get("packages") or [] for h in patches.get("hosts") or []}
            plan = {}
            for h in wanted:
                if h not in known:
                    return self.send_err(400, "unknown_host", f"Unknown system: {h}", cors, host=h)
                if known[h]:
                    plan[h] = known[h]
            if not plan:
                return self.send_err(400, "nothing_to_do", "Nothing to update for the selection", cors)
            payload = {"plan": patches.get("generated"), "hosts": plan}
            ok = start_job("patch", "Patch", [("install", "Install updates"), ("status", "Re-read patch status")],
                           payload)
            if not ok:
                return self.send_err(409, "busy", "A job is already running", cors)
            return self.send_json(202, {"job": public_job()}, cors)

        return self.send_err(404, "not_found", "Not found", cors)


def main():
    global JOB
    os.makedirs(LOG_DIR, exist_ok=True)
    try:
        with open(JOB_FILE, encoding="utf-8") as f:
            JOB = json.load(f)
        if JOB.get("state") == "running":  # the service was restarted in the middle of a job
            JOB.update(state="failed", ended=now(), result="Aborted (service restarted)", result_data={"aborted": True})
            for s in JOB.get("steps", []):
                if s.get("state") in ("run", "wait"):
                    s["state"] = "skip"
            save_job()
    except (OSError, ValueError):
        JOB = None
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    srv.daemon_threads = True
    print(f"vulnscan-api on port {PORT}, Ansible host {ANSIBLE_HOST or '(not set)'}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
