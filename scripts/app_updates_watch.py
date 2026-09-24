#!/usr/bin/env python3
"""
app_updates_watch.py

The version-change half of the "work only on fresh code" workflow. For every
in-scope Android app (bounty programs by default), poll Google Play metadata,
remember the last-seen version + update date, and report apps that shipped a
NEW build since the last run.

    python3 scripts/app_updates_watch.py                    # daily run (cron)
    python3 scripts/app_updates_watch.py --max-age-days 1   # only builds <1 day old
    python3 scripts/app_updates_watch.py --limit 5          # smoke test

Why version/date and not the "What's new" text: Play's detail endpoint no longer
exposes a changelog field, and that text is marketing fluff anyway ("bug fixes").
The real trigger is a version bump; the real changelog is the APK diff (step 3).
Some apps report version="Varies with device" — for those we fall back to the
`updated` timestamp as the change signal.

Requires the isolated venv: `. .venv/bin/activate` (google-play-scraper).
Pure-stdlib scope parsing is reused from scope_to_packages.py.

State: state/app_versions.json ({pkg: {version, updated, ...}}), saved
incrementally so a mid-run crash doesn't lose progress. FIRST run only
establishes the baseline and reports nothing. Exit status is always 0 (cron).

IMPORTANT — a scope listing is not authorization. Confirm each program's policy
permits mobile/APK testing before you download or touch anything.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import date, datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scope_to_packages import (  # noqa: E402
    PLATFORMS,
    android_assets,
    extract_package,
    fetch,
    program_fields,
)
from new_projects_watch import bounty_flag  # noqa: E402

try:
    from google_play_scraper import app as play_app
    from google_play_scraper.exceptions import NotFoundError
except ImportError:
    sys.exit("google-play-scraper missing — activate the venv: . .venv/bin/activate")


def enumerate_targets(platforms, cache_dir, bounty_only) -> dict:
    """{package: {program, policy_url, platform}} for in-scope Android apps."""
    targets: dict[str, dict] = {}
    for platform in platforms:
        try:
            data = fetch(platform, cache_dir)
        except Exception as e:
            print(f"  {platform}: FETCH FAILED ({e!r})", file=sys.stderr)
            continue
        for prog in data:
            if bounty_only and not bounty_flag(platform, prog):
                continue
            name, url = program_fields(platform, prog)
            for _atype, raw in android_assets(prog):
                pkg = extract_package(raw)
                if pkg and pkg not in targets:  # first program that lists it wins
                    targets[pkg] = {"program": name, "policy_url": url, "platform": platform}
    return targets


def load_state(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"  WARN: bad state {path} ({e!r}); starting fresh", file=sys.stderr)
    return {}


def poll(pkg: str, lang: str, country: str) -> dict | None:
    """Return {version, updated, updated_date, title} or None if unavailable."""
    d = play_app(pkg, lang=lang, country=country)
    updated = int(d.get("updated") or 0)
    upd_date = (datetime.fromtimestamp(updated, timezone.utc).date().isoformat()
                if updated else None)
    return {
        "version": str(d.get("version") or ""),
        "updated": updated,
        "updated_date": upd_date,
        "title": str(d.get("title") or ""),
    }


def changed(prev: dict, cur: dict) -> bool:
    """A concrete version bump, or (when version is opaque) a newer update time."""
    pv, cv = prev.get("version", ""), cur.get("version", "")
    concrete = cv and "varies" not in cv.lower()
    if concrete and cv != pv:
        return True
    return int(cur.get("updated") or 0) > int(prev.get("updated") or 0)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Watch in-scope Android apps for new Play releases.")
    ap.add_argument("--state-dir", type=Path, default=Path("state"))
    ap.add_argument("--report-dir", type=Path, default=Path("reports"))
    ap.add_argument("--platforms", nargs="+", default=list(PLATFORMS), choices=PLATFORMS)
    ap.add_argument("--cache-dir", type=Path,
                    help="Reuse/store the scope JSON here instead of refetching.")
    ap.add_argument("--all-programs", action="store_true",
                    help="Poll every in-scope app, not just bounty-paying programs.")
    ap.add_argument("--max-age-days", type=int, default=7,
                    help="Only report builds whose update date is within N days (default 7).")
    ap.add_argument("--delay", type=float, default=1.0,
                    help="Seconds between Play requests (politeness/anti-block; default 1.0).")
    ap.add_argument("--lang", default="en")
    ap.add_argument("--country", default="us")
    ap.add_argument("--limit", type=int, help="Poll at most N apps (smoke test).")
    ap.add_argument("--report-all", action="store_true",
                    help="On first run, report the whole baseline instead of staying quiet.")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    now = datetime.now(timezone.utc)
    today = now.date().isoformat()
    state_path = args.state_dir / "app_versions.json"
    prev = load_state(state_path)
    is_first_run = not prev

    targets = enumerate_targets(args.platforms, args.cache_dir, not args.all_programs)
    pkgs = sorted(targets)
    if args.limit:
        pkgs = pkgs[:args.limit]
    if not args.quiet:
        print(f"  polling {len(pkgs)} app(s) "
              f"({'all' if args.all_programs else 'bounty'} programs)")

    state = dict(prev)
    updates: list[dict] = []
    errors = 0
    args.state_dir.mkdir(parents=True, exist_ok=True)

    for i, pkg in enumerate(pkgs, 1):
        try:
            cur = poll(pkg, args.lang, args.country)
        except NotFoundError:
            cur = None  # delisted / geo-gated / not an app id
        except Exception as e:
            errors += 1
            if not args.quiet:
                print(f"    {pkg}: {e!r}", file=sys.stderr)
            cur = None
        if cur:
            before = state.get(pkg)
            rec = {**cur, "last_checked": today, **targets.get(pkg, {})}
            if before and not is_first_run and changed(before, cur):
                updates.append({"package": pkg, "old": before.get("version"),
                                "new": cur["version"], **rec})
            state[pkg] = rec
        if i % 50 == 0:  # checkpoint against a mid-run crash
            state_path.write_text(json.dumps(state), encoding="utf-8")
        if args.delay:
            time.sleep(args.delay)

    state_path.write_text(json.dumps(state), encoding="utf-8")

    if is_first_run and not args.report_all:
        if not args.quiet:
            print(f"Baseline established: {len(state)} app version(s) recorded. "
                  f"Re-run to see new releases.")
        return 0

    def in_window(u: dict) -> bool:
        d = u.get("updated_date")
        if not d:
            return True  # opaque date but version changed — surface it
        try:
            return (date.fromisoformat(today) - date.fromisoformat(d)).days <= args.max_age_days
        except Exception:
            return True

    reportable = [u for u in updates if in_window(u)]
    reportable.sort(key=lambda u: (u.get("updated_date") or "", u["program"].lower()),
                    reverse=True)

    if not args.quiet:
        print(f"  updated (≤{args.max_age_days}d): {len(reportable)} | "
              f"errors: {errors} | tracked: {len(state)}")
    if not reportable:
        return 0

    args.report_dir.mkdir(parents=True, exist_ok=True)
    out = args.report_dir / f"app-updates-{today}.md"
    lines = [
        f"# In-scope Android apps updated — {today}",
        "",
        f"{len(reportable)} app(s) shipped a new Play build within {args.max_age_days} day(s). "
        "These are fresh, mostly-untested code. Pull the APK and diff the delta (step 3).",
        "",
        "**A scope listing is not authorization** — confirm mobile/APK testing is permitted first.",
        "",
    ]
    for u in reportable:
        ver = f"`{u['old']}` → `{u['new']}`" if u.get("old") else f"`{u['new']}`"
        lines.append(
            f"- **{u.get('title') or u['package']}** — `{u['package']}`  "
            f"\n  {ver} · updated {u.get('updated_date')} · "
            f"{u['program']} [{u['platform']}] · {u['policy_url']}")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {out} — {len(reportable)} updated app(s).")

    feed = args.report_dir / f"updated-android-{today}.txt"
    feed.write_text("\n".join(u["package"] for u in reportable) + "\n", encoding="utf-8")
    print(f"Wrote {feed} — ready for apk_fetch.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
