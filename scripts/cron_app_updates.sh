#!/usr/bin/env bash
# Daily driver for app_updates_watch.py — polls Play for new builds of in-scope
# Android apps. Needs the isolated venv (google-play-scraper).
#
# Crontab (07:45 daily, after the scope watcher at 07:15):
#   45 7 * * * /path/to/apk-drill/scripts/cron_app_updates.sh >> /path/to/apk-drill/state/cron.log 2>&1
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

if [[ -f .venv/bin/activate ]]; then
  # shellcheck disable=SC1091
  . .venv/bin/activate
else
  echo "ERROR: .venv missing — create it (python3 -m venv --without-pip .venv; bootstrap pip; pip install google-play-scraper)" >&2
  exit 1
fi

MAX_AGE="${APW_MAX_AGE_DAYS:-7}"
DELAY="${APW_DELAY:-1.0}"

echo "=== $(date -u +%FT%TZ) app_updates_watch (max-age=${MAX_AGE}d, delay=${DELAY}s) ==="
python scripts/app_updates_watch.py \
  --max-age-days "$MAX_AGE" \
  --delay "$DELAY" \
  --state-dir state \
  --report-dir reports \
  "$@"

today="$(date -u +%F)"
if [[ -f "reports/app-updates-${today}.md" ]]; then
  echo "NEW: reports/app-updates-${today}.md"
fi
