#!/usr/bin/env python3
"""
new_projects_watch.py

"Hunt where the crowd hasn't been yet." Snapshot every in-scope asset across the
public bug-bounty directories (HackerOne, Bugcrowd, Intigriti, YesWeHack, mirrored
daily by arkadiyt/bounty-targets-data), diff against the previous run, and surface
only what is *newly added* — a just-listed asset has been tested by almost nobody.

    python3 scripts/new_projects_watch.py                 # daily run (cron)
    python3 scripts/new_projects_watch.py --max-age-days 1 # only assets seen <1 day
    python3 scripts/new_projects_watch.py --android-only   # Play/APK targets only

State (a JSON snapshot with a first_seen date per asset) lives under --state-dir.
The FIRST run just establishes a baseline and reports nothing as new; every run
after that reports assets whose first_seen is within --max-age-days. Because
first_seen is *when we first saw it in scope*, the age filter is exactly your
"only work on programs updated in the last week/day" rule.

Exit status: 0 always (cron-friendly). A dated report is written under --report-dir
only when there is something new, so a quiet day leaves no noise.

IMPORTANT — a scope listing is not authorization. Before touching any target:
confirm the program's policy permits testing it, that the program is open to you,
and that the asset is still in scope (this mirror is a daily snapshot).
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path

# Reuse the fetch + parsing logic already proven in scope_to_packages.py.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from scope_to_packages import (  # noqa: E402
    PLATFORMS,
    extract_package,
    fetch,
    program_fields,
)

ANDROID_TOKENS = ("android", "google_play", "apk")
IOS_TOKENS = ("ios", "apple", "iphone", "ipad")
WEB_TOKENS = ("url", "wildcard", "domain", "website", "api", "cidr", "ip")
SOURCE_TOKENS = ("source_code", "source code", "github", "gitlab", "repository")


def classify(asset_type: str, raw: str) -> str:
    """Bucket an asset so we can prioritise Android/Play over everything else."""
    t = asset_type.lower()
    s = raw.lower()
    if any(tok in t for tok in ANDROID_TOKENS) or "play.google.com" in s or s.endswith(".apk"):
        return "android"
    if any(tok in t for tok in IOS_TOKENS) or "apps.apple.com" in s or "itunes.apple" in s:
        return "ios"
    if any(tok in t for tok in SOURCE_TOKENS):
        return "source"
    if any(tok in t for tok in WEB_TOKENS):
        return "web"
    return "other"


def bounty_flag(platform: str, prog: dict) -> bool:
    if platform == "hackerone":
        return bool(prog.get("offers_bounties"))
    if platform == "bugcrowd":
        return bool(prog.get("max_payout"))
    # intigriti / yeswehack don't expose a uniform bounty flag; assume payable.
    return True


def asset_key(platform: str, handle: str, atype: str, raw: str) -> str:
    return f"{platform}|{handle}|{atype}|{raw}"


def build_current(platforms, cache_dir) -> dict:
    """Flatten every in-scope asset into {key: record}."""
    assets: dict[str, dict] = {}
    for platform in platforms:
        try:
            data = fetch(platform, cache_dir)
        except Exception as e:  # network hiccup shouldn't wipe the snapshot
            print(f"  {platform}: FETCH FAILED ({e!r})", file=sys.stderr)
            return {}  # signal caller to abort rather than record a partial snapshot
        for prog in data:
            name, url = program_fields(platform, prog)
            handle = prog.get("handle") or name
            bounty = bounty_flag(platform, prog)
            for asset in (prog.get("targets") or {}).get("in_scope") or []:
                atype = str(asset.get("asset_type") or asset.get("type") or "")
                raw = str(asset.get("asset_identifier")
                          or asset.get("target")
                          or asset.get("endpoint") or "")
                if not raw or "█" in raw:  # empty or redacted private target
                    continue
                bucket = classify(atype, raw)
                rec = {
                    "platform": platform,
                    "program": name,
                    "handle": handle,
                    "policy_url": url,
                    "asset_type": atype,
                    "asset_raw": raw,
                    "bucket": bucket,
                    "bounty": bounty,
                }
                if bucket == "android":
                    rec["package"] = extract_package(raw)  # may be None (prose/publisher)
                assets[asset_key(platform, handle, atype, raw)] = rec
    return assets


def priority(rec: dict, new_program: bool) -> int:
    """Lower = hotter. Android on a bounty program wins."""
    bucket, bounty = rec["bucket"], rec["bounty"]
    if bucket == "android":
        return 1 if bounty else 2
    if new_program and bounty:
        return 2  # a brand-new bounty program is worth a look wholesale
    if bucket == "web":
        return 3 if bounty else 5
    if bucket in ("ios", "source"):
        return 4 if bounty else 6
    return 6


def load_snapshot(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"  WARN: could not read snapshot {path} ({e!r}); treating as first run",
              file=sys.stderr)
        return None


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Watch public bug-bounty scopes for newly-added assets.")
    ap.add_argument("--state-dir", type=Path, default=Path("state"),
                    help="Where the rolling snapshot lives (default: state/).")
    ap.add_argument("--report-dir", type=Path, default=Path("reports"),
                    help="Dated new-asset reports are written here (default: reports/).")
    ap.add_argument("--platforms", nargs="+", default=list(PLATFORMS), choices=PLATFORMS)
    ap.add_argument("--cache-dir", type=Path,
                    help="Reuse/store the downloaded JSON here instead of refetching.")
    ap.add_argument("--max-age-days", type=int, default=7,
                    help="Only report assets first seen within this many days (default: 7).")
    ap.add_argument("--android-only", action="store_true",
                    help="Only report Android/Play/APK assets.")
    ap.add_argument("--bounty-only", action="store_true",
                    help="Only report assets on bounty-paying programs.")
    ap.add_argument("--report-all", action="store_true",
                    help="On first run, report the whole baseline instead of staying quiet.")
    ap.add_argument("--quiet", action="store_true",
                    help="Suppress the per-platform stats line (cron).")
    args = ap.parse_args()

    now = datetime.now(timezone.utc)
    today = now.date().isoformat()
    snap_path = args.state_dir / "scope_snapshot.json"

    prev = load_snapshot(snap_path)
    prev_assets = (prev or {}).get("assets", {})
    prev_handles = {r["handle"] for r in prev_assets.values()} if prev else set()

    current = build_current(args.platforms, args.cache_dir)
    if not current:
        print("No assets fetched (network?); leaving snapshot untouched.", file=sys.stderr)
        return 0

    # Carry first_seen forward; stamp genuinely-new assets with today.
    merged: dict[str, dict] = {}
    new_keys: list[str] = []
    for key, rec in current.items():
        first_seen = prev_assets.get(key, {}).get("first_seen")
        if first_seen is None:
            first_seen = today
            if prev is not None:  # not the baseline run
                new_keys.append(key)
        rec["first_seen"] = first_seen
        merged[key] = rec

    # Persist the merged snapshot every run so first_seen keeps accumulating.
    args.state_dir.mkdir(parents=True, exist_ok=True)
    snap_path.write_text(json.dumps(
        {"generated": now.isoformat(), "assets": merged}, indent=0), encoding="utf-8")

    is_first_run = prev is None
    if is_first_run and not args.report_all:
        if not args.quiet:
            print(f"Baseline established: {len(merged)} assets tracked across "
                  f"{len(args.platforms)} platform(s). Re-run to see what's new.")
        return 0

    # Decide what to report: age-filtered, optionally android/bounty-only.
    def age_days(rec) -> int:
        try:
            return (date.fromisoformat(today) - date.fromisoformat(rec["first_seen"])).days
        except Exception:
            return 999

    pool = new_keys if not (is_first_run and args.report_all) else list(merged)
    reportable = []
    for key in pool:
        rec = merged[key]
        if age_days(rec) > args.max_age_days:
            continue
        if args.android_only and rec["bucket"] != "android":
            continue
        if args.bounty_only and not rec["bounty"]:
            continue
        rec["_new_program"] = rec["handle"] not in prev_handles
        rec["_prio"] = priority(rec, rec["_new_program"])
        reportable.append(rec)

    reportable.sort(key=lambda r: (r["_prio"], r["platform"], r["program"].lower()))

    if not args.quiet:
        n_android = sum(1 for r in reportable if r["bucket"] == "android")
        print(f"  scanned {len(current)} assets | new (≤{args.max_age_days}d): "
              f"{len(reportable)} | android: {n_android}")

    if not reportable:
        return 0

    # Write a dated report only when there's something to say.
    args.report_dir.mkdir(parents=True, exist_ok=True)
    out = args.report_dir / f"new-projects-{today}.md"
    lines = [
        f"# New in-scope assets — {today}",
        "",
        f"{len(reportable)} asset(s) first seen within {args.max_age_days} day(s). "
        "Priority 1 = Android/Play on a bounty program (freshest, lowest-competition surface).",
        "",
        "**A scope listing is not authorization** — confirm each program's policy "
        "permits testing before you touch anything.",
        "",
    ]
    cur_prio = None
    labels = {1: "P1 — Android/Play (bounty)", 2: "P2 — Android / new bounty program",
              3: "P3 — Web (bounty)", 4: "P4 — iOS / source (bounty)",
              5: "P5 — Web (no bounty)", 6: "P6 — other"}
    for rec in reportable:
        if rec["_prio"] != cur_prio:
            cur_prio = rec["_prio"]
            lines += ["", f"## {labels.get(cur_prio, cur_prio)}", ""]
        tag = " \U0001f195NEW PROGRAM" if rec["_new_program"] else ""
        pkg = f" → `{rec['package']}`" if rec.get("package") else ""
        lines.append(
            f"- **{rec['program']}** [{rec['platform']}]{tag} — "
            f"`{rec['asset_raw']}` ({rec['asset_type']}){pkg}  "
            f"\n  first seen {rec['first_seen']} · {rec['policy_url']}")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {out} — {len(reportable)} new asset(s).")

    # Emit android packages to a feed file so apk_fetch/apk_secret_scan can pick them up.
    pkgs = [r["package"] for r in reportable
            if r["bucket"] == "android" and r.get("package")]
    if pkgs:
        feed = args.report_dir / f"new-android-{today}.txt"
        feed.write_text("\n".join(dict.fromkeys(pkgs)) + "\n", encoding="utf-8")
        print(f"Wrote {feed} — {len(set(pkgs))} package(s) ready for apk_fetch.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
