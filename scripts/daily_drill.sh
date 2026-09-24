#!/usr/bin/env bash
# daily_drill.sh — the capstone. For every in-scope Android app that shipped a
# new build today, it: downloads the APK via authenticated Google Play, records
# the Play "What's new", scans it for secrets, maps its attack surface, then
# DELETES THE APK. Analysis output is kept for RETAIN_DAYS, then auto-pruned.
#
# Net effect: the footprint never grows — only a rolling few days of small text
# results (secrets JSON + surface map + changelog) that you hand to AI to review.
#
# Depends on: reports/updated-android-<date>.txt (from app_updates_watch.py),
# a working GPLAY_AAS_TOKEN in .gplay.env, apkeep, trufflehog, androguard venv.
#
# Crontab (08:15 daily, after app_updates_watch at 07:45):
#   15 8 * * * /home/xiaoshi/apk-drill/scripts/daily_drill.sh >> /home/xiaoshi/apk-drill/state/cron.log 2>&1
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
# shellcheck disable=SC1091
[[ -f .venv/bin/activate ]] && . .venv/bin/activate

DATE="$(date -u +%F)"
RETAIN_DAYS="${DRILL_RETAIN_DAYS:-3}"
CREDS="${DRILL_CREDS:-.gplay.env}"
DRILL_ROOT="drill"
OUT="$DRILL_ROOT/$DATE"

echo "=== $(date -u +%FT%TZ) daily_drill (retain=${RETAIN_DAYS}d) ==="

# 1) Gather today's targets: apps with a NEW build (primary) + newly in-scope apps.
mapfile -t PKGS < <(cat "reports/updated-android-${DATE}.txt" "reports/new-android-${DATE}.txt" 2>/dev/null \
                    | grep -vE '^\s*#|^\s*$' | sort -u)
if [[ ${#PKGS[@]} -eq 0 ]]; then
  echo "No changed/new Android apps today — nothing to drill."
else
  echo "Drilling ${#PKGS[@]} app(s): ${PKGS[*]}"
  mkdir -p "$OUT"
  for pkg in "${PKGS[@]}"; do
    echo "--- $pkg ---"
    TMP="$(mktemp -d)"
    printf '%s\n' "$pkg" > "$TMP/pkgs.txt"

    # Download via REAL Google Play (authenticated, your account) into TMP only.
    python apk_fetch.py --sources google-play --creds "$CREDS" "$TMP/pkgs.txt" "$TMP/apks" 2>&1 \
      | sed 's/^/    /'

    if compgen -G "$TMP/apks/$pkg/*" > /dev/null; then
      mkdir -p "$OUT/$pkg"
      # changelog
      python scripts/play_whatsnew.py "$pkg" > "$OUT/$pkg/whatsnew.txt" 2>/dev/null || true
      # attack-surface map (from the already-downloaded APK; no re-download)
      python apk_surface_map.py --from-dir "$TMP/apks" -o "$OUT/$pkg/surface.jsonl" 2>&1 | sed 's/^/    /'
      [[ -s "$OUT/$pkg/surface.jsonl" ]] && \
        python surface_report.py "$OUT/$pkg/surface.jsonl" -o "$OUT/$pkg/surface.md" 2>/dev/null || true
      # secret scan (from the same APK)
      python apk_secret_scan.py --from-dir "$TMP/apks" "$TMP/pkgs.txt" -o "$OUT/$pkg/secrets.jsonl" 2>&1 | sed 's/^/    /'
      [[ -s "$OUT/$pkg/secrets.jsonl" ]] && \
        python report.py "$OUT/$pkg/secrets.jsonl" -o "$OUT/$pkg/secrets.md" 2>/dev/null || true
      echo "    kept: $OUT/$pkg/ (apk discarded)"
    else
      echo "    download failed (token expired? not on Play for this account/region) — skipping"
    fi

    rm -rf "$TMP"   # APK + extraction gone immediately
  done
fi

# 2) Retention: drop analysis older than RETAIN_DAYS so the footprint stays flat.
if [[ -d "$DRILL_ROOT" ]]; then
  find "$DRILL_ROOT" -mindepth 1 -maxdepth 1 -type d -name '20*' -mtime "+${RETAIN_DAYS}" \
    -exec rm -rf {} + 2>/dev/null || true
fi
echo "Retained drill days: $(ls "$DRILL_ROOT" 2>/dev/null | tr '\n' ' ')"
