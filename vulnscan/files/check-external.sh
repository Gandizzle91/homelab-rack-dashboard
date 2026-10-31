#!/bin/bash
# Daily: what does the internet see of your connection?
# 1. Find the public IP (as the internet sees it; falls back to the dynamic DNS name)
# 2. Ask Shodan InternetDB (free, no account): open ports and known vulnerabilities
# 3. Check the certificate expiry of all domains in domains.txt
set -uo pipefail
cd /opt/vulnscan

[ -r /etc/default/vulnscan ] && . /etc/default/vulnscan
HOST="${DDNS_HOST:-home.example.com}"
NOW=$(date -Iseconds)
IP=$(curl -sS --max-time 10 https://api.ipify.org 2>/dev/null | grep -E '^[0-9]+(\.[0-9]+){3}$')
[ -z "$IP" ] && IP=$(dig +short A "$HOST" | grep -E '^[0-9.]+$' | tail -n1)

if [ -n "$IP" ]; then
  RESP=$(curl -sS --max-time 20 "https://internetdb.shodan.io/$IP" || true)
else
  RESP=''
fi
if ! echo "$RESP" | jq -e . >/dev/null 2>&1; then
  RESP='{"detail":"No valid answer from InternetDB"}'
fi

CERTS='[]'
while read -r d; do
  [ -z "$d" ] && continue
  END=$(echo | timeout 15 openssl s_client -servername "$d" -connect "$d:443" 2>/dev/null \
        | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
  if [ -n "$END" ]; then
    END_TS=$(date -d "$END" +%s)
    DAYS=$(( (END_TS - $(date +%s)) / 86400 ))
    CERTS=$(echo "$CERTS" | jq --arg d "$d" --arg e "$(date -d "$END" -Iseconds)" --argjson n "$DAYS" \
      '. + [{domain:$d, expires:$e, days_left:$n}]')
  else
    CERTS=$(echo "$CERTS" | jq --arg d "$d" '. + [{domain:$d, expires:null, days_left:null}]')
  fi
done < <(sed -e 's/[[:space:]]*#.*$//' -e 's/[[:space:]]*$//' domains.txt | grep -v '^[[:space:]]*$')

jq -n --arg host "$HOST" --arg ip "$IP" --arg ts "$NOW" \
      --argjson idb "$RESP" --argjson certs "$CERTS" \
      '{host:$host, ip:$ip, checked:$ts, internetdb:$idb, certs:$certs}' \
      > data/external.json

/usr/bin/python3 /opt/vulnscan/build.py
