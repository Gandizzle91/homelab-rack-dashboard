#!/usr/bin/env python3
"""Combines patch status, Nuclei findings and the external view into www/data/summary.json.

The scanner web page and the vulnscan API read only this one file.
Runs after every check and additionally once an hour.

"reasons" are English sentences; "reason_codes" carry the same information in machine-readable
form ({"id": ..., parameters}) so that the rack panel can show them in its own language.
"""
import json
import os
from datetime import datetime, timezone

BASE = os.environ.get("VULNSCAN_BASE", "/opt/vulnscan")
DATA = os.path.join(BASE, "data")
OUT = os.path.join(BASE, "www", "data", "summary.json")

SEV_ORDER = ["critical", "high", "medium", "low"]


def load_json(name, default):
    try:
        with open(os.path.join(DATA, name), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def read_text(name):
    try:
        with open(os.path.join(DATA, name), encoding="utf-8") as f:
            return f.read().strip() or None
    except OSError:
        return None


def to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def to_bool(v):
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("true", "1", "yes")


def build_patches():
    raw = load_json("patches.json", None)
    if raw is None:
        return {"generated": None, "hosts": [], "unreachable": [], "total_security": 0,
                "total_upgradable": 0, "reboot_needed": []}
    hosts = []
    for h in raw.get("hosts", []):
        hosts.append({
            "host": h.get("host"),
            "address": h.get("address"),
            "os": h.get("os"),
            "kernel": h.get("kernel"),
            "upgradable": to_int(h.get("upgradable")),
            "security": to_int(h.get("security")),
            "packages": h.get("packages") or [],
            "reboot_required": to_bool(h.get("reboot_required")),
            "checked": h.get("checked"),
        })
    hosts.sort(key=lambda h: (-h["security"], -h["upgradable"], h["host"] or ""))
    return {
        "generated": raw.get("generated"),
        "hosts": hosts,
        "unreachable": raw.get("unreachable") or [],
        "total_security": sum(h["security"] for h in hosts),
        "total_upgradable": sum(h["upgradable"] for h in hosts),
        "reboot_needed": [h["host"] for h in hosts if h["reboot_required"]],
    }


def build_nuclei():
    findings = []
    path = os.path.join(DATA, "nuclei.jsonl")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                info = r.get("info") or {}
                sev = (info.get("severity") or "unknown").lower()
                if sev not in SEV_ORDER:
                    continue
                findings.append({
                    "severity": sev,
                    "name": info.get("name") or r.get("template-id"),
                    "template": r.get("template-id"),
                    "target": r.get("host"),
                    "matched": r.get("matched-at"),
                    "description": (info.get("description") or "").strip(),
                    "reference": (info.get("reference") or [None])[0] if isinstance(info.get("reference"), list) else info.get("reference"),
                    "found": r.get("timestamp"),
                })
    rank = {s: i for i, s in enumerate(SEV_ORDER)}
    findings.sort(key=lambda x: (rank.get(x["severity"], 9), x["target"] or ""))
    counts = {s: sum(1 for x in findings if x["severity"] == s) for s in SEV_ORDER}
    return {"lastrun": read_text("nuclei.lastrun"), "counts": counts, "findings": findings}


def build_external():
    raw = load_json("external.json", None)
    if raw is None:
        return {"checked": None, "host": None, "ip": None, "ports": [], "vulns": [], "hostnames": [],
                "cpes": [], "note": "No check has run yet", "certs": []}
    idb = raw.get("internetdb") or {}
    note = idb.get("detail")
    if note == "No information available":
        note = "Shodan does not know this IP at the moment (no open services recorded)"
    certs = sorted(raw.get("certs") or [],
                   key=lambda c: (c.get("days_left") is None, c.get("days_left") or 0))
    return {
        "checked": raw.get("checked"),
        "host": raw.get("host"),
        "ip": raw.get("ip"),
        "ports": sorted(idb.get("ports") or []),
        "vulns": sorted(idb.get("vulns") or []),
        "hostnames": idb.get("hostnames") or [],
        "cpes": idb.get("cpes") or [],
        "note": note,
        "certs": certs,
    }


def overall(patches, nuclei, external):
    """Returns (status, reasons, reason_codes). crit wins over warn."""
    crit, warn = [], []

    def add(lst, text, rid, **params):
        lst.append((text, dict(id=rid, **params)))

    c = nuclei["counts"]
    if c["critical"] or c["high"]:
        n = c["critical"] + c["high"]
        add(crit, f"{n} severe findings", "high_findings", n=n)
    if external["vulns"]:
        n = len(external["vulns"])
        add(crit, f"{n} known vulnerabilities visible from outside", "external_vulns", n=n)
    if patches["total_security"]:
        n = patches["total_security"]
        add(warn, f"{n} security updates pending", "security_updates", n=n)
    if patches["reboot_needed"]:
        add(warn, f"Reboot required: {', '.join(patches['reboot_needed'])}", "reboot", hosts=patches["reboot_needed"])
    if patches["unreachable"]:
        add(warn, f"Not reached: {', '.join(patches['unreachable'])}", "unreachable", hosts=patches["unreachable"])
    if c["medium"]:
        add(warn, f"Medium findings: {c['medium']}", "medium_findings", n=c["medium"])
    for cert in external["certs"]:
        d, dom = cert.get("days_left"), cert["domain"]
        if d is None:
            add(warn, f"Certificate not checkable: {dom}", "cert_unchecked", domain=dom)
        elif d < 7:
            add(crit, f"Certificate expires in {d} days: {dom}", "cert_expiring", n=d, domain=dom)
        elif d < 14:
            add(warn, f"Certificate expires in {d} days: {dom}", "cert_expiring", n=d, domain=dom)
    items = crit + warn
    status = "crit" if crit else "warn" if warn else "ok"
    if not items:
        items = [("All good", {"id": "all_ok"})]
    return status, [t for t, _ in items], [r for _, r in items]


def main():
    patches = build_patches()
    nuclei = build_nuclei()
    external = build_external()
    status, reasons, codes = overall(patches, nuclei, external)
    summary = {
        "generated": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "status": status,
        "reasons": reasons,
        "reason_codes": codes,
        "patches": patches,
        "nuclei": nuclei,
        "external": external,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    tmp = OUT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=1)
    os.replace(tmp, OUT)


if __name__ == "__main__":
    main()
