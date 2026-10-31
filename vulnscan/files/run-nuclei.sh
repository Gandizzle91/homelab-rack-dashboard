#!/bin/bash
# Weekly Nuclei run against all targets in targets.txt.
# Excluded are all checks that could break something, try logins or lock accounts
# (dos, fuzz, intrusive, brute-force, default-login).
set -uo pipefail
cd /opt/vulnscan

# drop comments (whole lines and trailing "# ...") and empty lines
sed -e 's/[[:space:]]*#.*$//' -e 's/[[:space:]]*$//' targets.txt | grep -v '^[[:space:]]*$' > data/targets.clean
: > data/nuclei-new.jsonl

/usr/local/bin/nuclei -update-templates -silent || true

if /usr/local/bin/nuclei \
  -list data/targets.clean \
  -severity low,medium,high,critical \
  -exclude-tags dos,fuzz,intrusive,brute-force,bruteforce,default-login \
  -rate-limit 30 -concurrency 10 -timeout 10 -retries 1 \
  -no-interactsh -disable-update-check -silent \
  -jsonl -output data/nuclei-new.jsonl
then
  # replace the results only after a successful run, otherwise the old findings stay
  mv data/nuclei-new.jsonl data/nuclei.jsonl
  date -Iseconds > data/nuclei.lastrun
else
  echo "Nuclei run failed, keeping the previous results" >&2
fi
/usr/bin/python3 /opt/vulnscan/build.py
