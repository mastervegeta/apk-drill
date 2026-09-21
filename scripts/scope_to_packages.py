#!/usr/bin/env python3
"""
scope_to_packages.py

Build an apk-drill package list from the public bug-bounty scope data mirrored
daily by arkadiyt/bounty-targets-data (HackerOne, Bugcrowd, Intigriti,
YesWeHack). No API keys required — these are the platforms' public directories.

    python3 scripts/scope_to_packages.py -o packages.csv

Outputs a CSV carrying provenance (platform, program, policy URL, the raw scope
string, and the date you pulled it) so a later report can show the target was
listed in scope on the day it was scanned. apk_secret_scan.py reads the
`package` column and ignores the rest.

Assets that name an app in prose ("Acrobat Reader Mobile App (Android)") can't
be resolved to a package id automatically; they are written to the
--unresolved file for manual Play Store lookup rather than guessed at.

IMPORTANT — this tool tells you what a program *lists*, not what you are
allowed to do. Before scanning anything from this output:
  * open the program's policy and confirm mobile/APK testing is permitted,
  * confirm the program is open to you (public vs invite-only),
  * confirm the asset is still in scope — this mirror is a daily snapshot.
A listing here is not authorization.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import urllib.request
from datetime import date
from pathlib import Path

BASE = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data"
PLATFORMS = ("hackerone", "bugcrowd", "intigriti", "yeswehack")

# asset-type tokens each platform uses for an Android target
ANDROID_TOKENS = ("android", "google_play", "apk")

PLAY_ID = re.compile(r"[?&]id=([a-zA-Z0-9_.]+)")
# /store/apps/developer?id=Sky+Betting and /store/apps/dev?id=<numeric> name a
# publisher, not an app — "everything we ship" needs manual enumeration.
PLAY_DEVELOPER = re.compile(r"/store/apps/(developer|dev)\b")
CANDIDATE = re.compile(r"\b([a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)+)\b")

# Enough TLDs to tell a reverse-DNS package from a hostname. A package whose
# first segment is a TLD (com.bumble.app) is reverse-DNS no matter what it ends
# with; a string that merely *ends* in a TLD (www.authy.com) is a hostname.
TLDS = {
    "com", "io", "org", "net", "de", "fr", "co", "app", "me", "eu", "ru", "br",
    "in", "us", "ai", "xyz", "uk", "nl", "se", "no", "fi", "es", "it", "pl",
    "ca", "au", "jp", "kr", "cn", "ch", "at", "be", "dk", "cz", "gr", "hu",
    "ie", "il", "mx", "my", "nz", "pt", "ro", "sg", "th", "tr", "tw", "ua",
    "vn", "za", "cloud", "dev", "tech", "mobi", "info", "biz", "gov", "edu",
}


def looks_like_package(candidate: str) -> bool:
    parts = candidate.split(".")
    if len(parts) < 2:
        return False
    if parts[0].lower() in TLDS:
        return True  # reverse-DNS: com.example.app, net.bitstamp.app, se.atg.live
    # not reverse-DNS — accept only a multi-segment id that doesn't end in a
    # TLD, which would make it a hostname (www.authy.com, cdn.foo.net)
    return len(parts) >= 3 and parts[-1].lower() not in TLDS


def extract_package(raw: str | None) -> str | None:
    """Pull an Android package id out of a scope string, or None."""
    s = str(raw or "").strip()
    if not s or "█" in s:          # redacted private-program target
        return None
    if "apple.com" in s:                # iOS asset filed under a mobile type
        return None
    if PLAY_DEVELOPER.search(s):        # publisher page, not a single app
        return None
    m = PLAY_ID.search(s)
    if m:
        pid = m.group(1)
        # a real package id is dotted and never all-digits (that is a dev id)
        if "." in pid and not pid.replace(".", "").isdigit():
            return pid
        return None
    if s.lower().endswith(".apk"):      # direct APK URL — apkeep can't take it
        return None
    if CANDIDATE.fullmatch(s) and looks_like_package(s):
        return s
    best = None                         # "Co-OYO Android App - com.oyo.partnerapp"
    for c in CANDIDATE.findall(s):
        if looks_like_package(c) and (best is None or len(c) > len(best)):
            best = c
    return best


def fetch(platform: str, cache_dir: Path | None) -> list:
    url = f"{BASE}/{platform}_data.json"
    if cache_dir:
        cached = cache_dir / f"{platform}_data.json"
        if cached.exists():
            return json.loads(cached.read_text(encoding="utf-8"))
    with urllib.request.urlopen(url, timeout=120) as r:
        body = r.read().decode("utf-8", "replace")
    if cache_dir:
        cache_dir.mkdir(parents=True, exist_ok=True)
        (cache_dir / f"{platform}_data.json").write_text(body, encoding="utf-8")
    return json.loads(body)


def program_fields(platform: str, prog: dict) -> tuple[str, str]:
    name = prog.get("name") or prog.get("handle") or "?"
    url = prog.get("url") or ""
    if not url and platform == "hackerone" and prog.get("handle"):
        url = f"https://hackerone.com/{prog['handle']}"
    return name, url


def android_assets(prog: dict):
    for asset in (prog.get("targets") or {}).get("in_scope") or []:
        atype = str(asset.get("asset_type") or asset.get("type") or "").lower()
        if any(tok in atype for tok in ANDROID_TOKENS):
            raw = (asset.get("asset_identifier")
                   or asset.get("target")
                   or asset.get("endpoint") or "")
            yield atype, str(raw)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Extract in-scope Android package names from public bug-bounty scopes.")
    ap.add_argument("-o", "--output", type=Path, default=Path("packages.csv"),
                    help="CSV with provenance (default: packages.csv).")
    ap.add_argument("--txt", type=Path,
                    help="Also write a plain one-package-per-line list here.")
    ap.add_argument("--unresolved", type=Path, default=Path("unresolved_assets.txt"),
                    help="Assets naming an app in prose, for manual lookup.")
    ap.add_argument("--platforms", nargs="+", default=list(PLATFORMS), choices=PLATFORMS)
    ap.add_argument("--bounty-only", action="store_true",
                    help="HackerOne/Bugcrowd: keep only bounty-paying programs.")
    ap.add_argument("--program", help="Case-insensitive substring filter on program name.")
    ap.add_argument("--cache-dir", type=Path,
                    help="Reuse/store the downloaded JSON here instead of refetching.")
    args = ap.parse_args()

    today = date.today().isoformat()
    rows: list[dict] = []
    unresolved: list[str] = []
    seen: set[str] = set()
    stats: dict[str, dict] = {}

    for platform in args.platforms:
        try:
            data = fetch(platform, args.cache_dir)
        except Exception as e:
            print(f"  {platform}: FETCH FAILED ({e!r})", file=sys.stderr)
            continue
        s = stats.setdefault(platform, {"assets": 0, "packages": 0, "manual": 0, "redacted": 0})
        for prog in data:
            name, url = program_fields(platform, prog)
            if args.program and args.program.lower() not in name.lower():
                continue
            if args.bounty_only:
                if platform == "hackerone" and not prog.get("offers_bounties"):
                    continue
                if platform == "bugcrowd" and not prog.get("max_payout"):
                    continue
            for atype, raw in android_assets(prog):
                s["assets"] += 1
                if "█" in raw:
                    s["redacted"] += 1
                    continue
                pkg = extract_package(raw)
                if not pkg:
                    s["manual"] += 1
                    unresolved.append(f"[{platform}] {name} :: {raw}")
                    continue
                s["packages"] += 1
                if pkg in seen:
                    continue
                seen.add(pkg)
                rows.append({
                    "package": pkg,
                    "platform": platform,
                    "program": name,
                    "policy_url": url,
                    "asset_raw": raw,
                    "checked": today,
                })

    rows.sort(key=lambda r: (r["platform"], r["program"].lower(), r["package"]))

    with args.output.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["package", "platform", "program",
                                           "policy_url", "asset_raw", "checked"])
        w.writeheader()
        w.writerows(rows)

    if args.txt:
        args.txt.write_text(
            "\n".join(
                ["# apk-drill package list — generated "
                 f"{today} from public bug-bounty scopes.",
                 "# Confirm each program's policy permits mobile/APK testing "
                 "before scanning.", ""]
                + [r["package"] for r in rows]
            ) + "\n",
            encoding="utf-8",
        )

    if unresolved and args.unresolved:
        args.unresolved.write_text(
            "\n".join(
                ["# Scope entries needing a manual Play Store lookup:",
                 "#   * an app named in prose (Acrobat Reader Mobile App)",
                 "#   * a publisher page (/store/apps/developer?id=...) — every",
                 "#     app that publisher ships is in scope; enumerate them",
                 "# Add the resolved package id to your list if it is in scope.", ""]
                + sorted(set(unresolved))
            ) + "\n",
            encoding="utf-8",
        )

    for platform, s in stats.items():
        print(f"  {platform:<11} android assets={s['assets']:<5} "
              f"packages={s['packages']:<5} manual={s['manual']:<4} redacted={s['redacted']}")
    print(f"\nWrote {args.output} — {len(rows)} unique package(s).")
    if args.txt:
        print(f"Wrote {args.txt}")
    if unresolved:
        print(f"Wrote {args.unresolved} — {len(set(unresolved))} asset(s) need a manual lookup.")
    print("\nA scope listing is not authorization: check each program's policy "
          "for mobile/APK permission before scanning.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
