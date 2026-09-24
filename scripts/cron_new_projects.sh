#!/usr/bin/env bash
# Daily driver for new_projects_watch.py — cron-friendly.
#
# Establishes a baseline on first run, then every day reports in-scope assets
# first seen within NPW_MAX_AGE_DAYS. Pure stdlib: needs only python3.
#
# Crontab (run 07:15 daily):
#   15 7 * * * /path/to/apk-drill/scripts/cron_new_projects.sh >> /path/to/apk-drill/state/cron.log 2>&1
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

PY="${NPW_PYTHON:-python3}"
MAX_AGE="${NPW_MAX_AGE_DAYS:-7}"

echo "=== $(date -u +%FT%TZ) new_projects_watch (max-age=${MAX_AGE}d) ==="
"$PY" scripts/new_projects_watch.py \
  --max-age-days "$MAX_AGE" \
  --state-dir state \
  --report-dir reports \
  "$@"

# Latest report path (if one was written today), for downstream hooks/notify.
today="$(date -u +%F)"
if [[ -f "reports/new-projects-${today}.md" ]]; then
  echo "NEW: reports/new-projects-${today}.md"
fi
