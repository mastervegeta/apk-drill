#!/usr/bin/env bash
# recon.sh <program> — the web recon pipeline, end to end.
#
#   program name -> in-scope web domains -> subdomains + live hosts -> pull each
#   live host's JavaScript, all organized under recon/<program>/<date>/ ready to
#   hand to an LLM.
#
# Usage:
#   scripts/recon.sh wolt
#   scripts/recon.sh wolt --bounty-only --crawl 3
#   scripts/recon.sh wolt --brute            # active DNS brute (policy permitting)
#   scripts/recon.sh wolt --no-js            # stop after live hosts
#   scripts/recon.sh wolt --max-hosts 5      # only js_pull the first N live hosts
#
# A scope listing is not authorization — confirm the program's policy (and that
# active scanning is allowed, for --brute) before running.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
export PATH="$HOME/.local/bin:$PATH"          # find subfinder/httpx (incl. under cron)
# shellcheck disable=SC1091
[[ -f .venv/bin/activate ]] && . .venv/bin/activate
PY="${RECON_PYTHON:-python3}"

[[ $# -ge 1 ]] || { echo "usage: recon.sh <program> [--bounty-only] [--brute] [--crawl N] [--no-js] [--max-hosts N]"; exit 2; }
PROGRAM="$1"; shift

SCOPE_ARGS=(); BRUTE=(); CRAWL=0; DO_JS=1; MAX_HOSTS=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bounty-only) SCOPE_ARGS+=(--bounty-only); shift;;
    --brute)       BRUTE+=(--brute); shift;;
    --crawl)       CRAWL="$2"; shift 2;;
    --no-js)       DO_JS=0; shift;;
    --max-hosts)   MAX_HOSTS="$2"; shift 2;;
    *) echo "unknown option: $1"; exit 2;;
  esac
done

DATE="$(date -u +%F)"
OUT="recon/$PROGRAM/$DATE"
mkdir -p "$OUT"
echo "=== $(date -u +%FT%TZ) recon: $PROGRAM -> $OUT ==="

# 1) scope -> in-scope web domains
echo "[1/3] scope -> domains"
"$PY" scripts/scope_to_domains.py --program "$PROGRAM" "${SCOPE_ARGS[@]}" \
  --txt "$OUT/seeds.txt" -o "$OUT/domains.csv" | sed 's/^/    /'
SEEDS=$(grep -vcE '^\s*#|^\s*$' "$OUT/seeds.txt" 2>/dev/null || echo 0)
if [[ "$SEEDS" -eq 0 ]]; then
  echo "No in-scope web domains for '$PROGRAM' (check the program name/handle). Stopping."
  exit 0
fi

# 2) subdomains + liveness
echo "[2/3] subdomains + liveness (${SEEDS} seed domain(s))"
"$PY" scripts/recon_subdomains.py --list "$OUT/seeds.txt" -o "$OUT/recon" "${BRUTE[@]}" | sed 's/^/    /'
cat "$OUT"/recon/*/live_hosts.txt 2>/dev/null | sort -u > "$OUT/live_all.txt"
LIVE=$(grep -cvE '^\s*$' "$OUT/live_all.txt" 2>/dev/null || echo 0)
echo "    live hosts: $LIVE -> $OUT/live_all.txt"

# 3) pull JavaScript from each live host
if [[ "$DO_JS" -eq 1 && "$LIVE" -gt 0 ]]; then
  mapfile -t HOSTS < "$OUT/live_all.txt"
  [[ "$MAX_HOSTS" -gt 0 ]] && HOSTS=("${HOSTS[@]:0:$MAX_HOSTS}")
  echo "[3/3] js_pull ${#HOSTS[@]} host(s) (crawl=$CRAWL)"
  for url in "${HOSTS[@]}"; do
    [[ -z "$url" ]] && continue
    "$PY" scripts/js_pull.py "$url" --out "$OUT/js" --crawl "$CRAWL" 2>&1 | sed 's/^/    /'
  done
else
  echo "[3/3] js_pull skipped"
fi

echo "=== done: $OUT ==="
echo "  domains: $OUT/domains.csv"
echo "  live:    $OUT/live_all.txt"
[[ "$DO_JS" -eq 1 ]] && echo "  js:      $OUT/js/<host>/  (feed these to your LLM)"
