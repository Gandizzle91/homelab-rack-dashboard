#!/usr/bin/env python3
"""vulnscan-trigger – forced SSH command for the scanner (vulnscan-api).

Listed in /root/.ssh/authorized_keys of the Ansible host as
  command="/usr/local/sbin/vulnscan-trigger",from="<scanner IP>",restrict ssh-ed25519 ... vulnscan-api
With it the scanner can start exactly three things, nothing else:
  ping     connection test
  status   collect the patch status of all systems (patchstatus.yml)
  patch    install confirmed updates; the plan arrives as JSON on stdin:
           {"plan": "...", "hosts": {"paperless": ["bind9-host", ...], ...}}
           Hosts must be in the Ansible inventory, package names must be valid Debian names.
Settings: /etc/default/vulnscan-trigger (BASE, INVENTORY, ANSIBLE_PLAYBOOK)
"""
import fcntl
import json
import os
import re
import subprocess
import sys
import tempfile

CONF = "/etc/default/vulnscan-trigger"
PKG = re.compile(r"^[a-z0-9][a-z0-9+.\-]{0,99}(:[a-z0-9]+)?$")


def conf():
    cfg = {"BASE": "/root/vulnscan", "INVENTORY": "/root/ansible/inventory.yml", "ANSIBLE_PLAYBOOK": "ansible-playbook"}
    try:
        with open(CONF, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    cfg[k.strip()] = v.strip().strip('"')
    except OSError:
        pass
    return cfg


CFG = conf()
ENV = dict(os.environ, LC_ALL="C.UTF-8", LANG="C.UTF-8", ANSIBLE_NOCOLOR="1", ANSIBLE_FORCE_COLOR="0",
           ANSIBLE_RETRY_FILES_ENABLED="0", ANSIBLE_HOST_KEY_CHECKING="False", PYTHONUNBUFFERED="1",
           PATH=os.path.dirname(CFG["ANSIBLE_PLAYBOOK"]) + ":/usr/local/bin:/usr/bin:/bin" if "/" in CFG["ANSIBLE_PLAYBOOK"]
           else "/root/.local/bin:/usr/local/bin:/usr/bin:/bin")


def say(msg):
    print(msg, flush=True)


def playbook(*args):
    cmd = [CFG["ANSIBLE_PLAYBOOK"], "-i", CFG["INVENTORY"], *args]
    if os.path.exists(os.path.join(CFG["BASE"], "vars.yml")):
        cmd += ["-e", "@vars.yml"]
    return subprocess.run(cmd, cwd=CFG["BASE"], env=ENV, stdin=subprocess.DEVNULL).returncode


def inventory_hosts():
    tool = CFG["ANSIBLE_PLAYBOOK"].replace("ansible-playbook", "ansible-inventory")
    out = subprocess.run([tool, "-i", CFG["INVENTORY"], "--list"], cwd=CFG["BASE"], env=ENV,
                         stdin=subprocess.DEVNULL, capture_output=True, text=True, check=True).stdout
    inv = json.loads(out)
    names = set((inv.get("_meta") or {}).get("hostvars", {}).keys())
    for group in inv.values():
        if isinstance(group, dict):
            names.update(group.get("hosts") or [])
    names.discard("vulnscan")
    return names


def lock():
    f = open("/run/lock/vulnscan-trigger.lock", "w")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        say("Another run is still active, waiting …")
        fcntl.flock(f, fcntl.LOCK_EX)
    return f


def do_status():
    say("### STEP status")
    rc = playbook("patchstatus.yml")
    say(f"### RESULT status={rc}")
    return rc


def do_patch():
    raw = sys.stdin.read(200000)
    try:
        data = json.loads(raw)
        hosts = data["hosts"]
        if not isinstance(hosts, dict) or not hosts:
            raise ValueError("no hosts")
    except (ValueError, KeyError, TypeError) as e:
        say(f"Invalid plan: {e}")
        return 2
    known = inventory_hosts()
    plan = {}
    for host, pkgs in hosts.items():
        if host not in known:
            say(f"Rejected: {host} is not in the inventory")
            return 2
        if not isinstance(pkgs, list) or not all(isinstance(p, str) and PKG.match(p) for p in pkgs):
            say(f"Rejected: invalid package names for {host}")
            return 2
        if pkgs:
            plan[host] = sorted(set(pkgs))
    if not plan:
        say("Nothing to do")
        return 0
    say(f"Plan of {data.get('plan', '?')}: " + ", ".join(f"{h} ({len(p)})" for h, p in sorted(plan.items())))
    fd, path = tempfile.mkstemp(prefix=".vulnscan-patch-", suffix=".json", dir=CFG["BASE"])
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"vuln_patch": plan}, f)
        say("### STEP install")
        rc_install = playbook("patch.yml", "-e", "@" + path, "--limit", ",".join(sorted(plan)))
        say(f"### RESULT install={rc_install}")
    finally:
        os.unlink(path)
    rc_status = do_status()
    return rc_install or rc_status


def main():
    action = (os.environ.get("SSH_ORIGINAL_COMMAND") or (sys.argv[1] if len(sys.argv) > 1 else "")).strip()
    if action == "ping":
        say("pong")
        return 0
    if action not in ("status", "patch"):
        say(f"Not allowed: {action!r}")
        return 1
    _l = lock()
    return do_status() if action == "status" else do_patch()


if __name__ == "__main__":
    sys.exit(main())
