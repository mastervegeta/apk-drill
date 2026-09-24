#!/usr/bin/env python3
"""
scope_to_domains.py

Step 2 of the web recon pipeline: read the in-scope WEB assets (domains,
wildcards, URLs) for a bug-bounty program from the public scope data mirrored by
arkadiyt/bounty-targets-data. Sibling of scope_to_packages.py (which does the
Android side).

    python3 scripts/scope_to_domains.py --program wolt
    python3 scripts/scope_to_domains.py --program wolt --bounty-only --txt seeds.txt

Output:
  * a CSV with provenance (host, kind, program, platform, policy URL, raw scope),
  * --txt: a deduped host list to feed the next steps. For a wildcard `*.foo.com`
    the "host" is the apex `foo.com` (the root you enumerate subdomains from);
    for a plain domain it's the host itself.

Kinds: `wildcard` (enumerate subdomains) vs `domain` (a specific host).

IMPORTANT — a scope listing is not authorization. Confirm the program's policy
(open to you, web testing permitted, asset still in scope) before you touch it.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
import urllib.parse
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scope_to_packages import PLATFORMS, fetch, program_fields  # noqa: E402
from new_projects_watch import bounty_flag  # noqa: E402

# asset-type tokens each platform uses for a web target
WEB_TOKENS = ("url", "wildcard", "domain", "website", "web-application", "web application", "api")
# skip these even if they sneak through
SKIP_TOKENS = ("android", "google_play", "apk", "ios", "apple", "source", "github",
               "executable", "binary", "hardware", "smart_contract", "smart contract")

_HOSTISH = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def extract_host(raw: str) -> tuple[str, str] | None:
    """Return (host, kind) where kind is 'wildcard' or 'domain', or None.

    For a wildcard, host is the apex to enumerate from (`*.foo.com` -> `foo.com`,
    `*.api.foo.com` -> `api.foo.com`).
    """
    s = (raw or "").strip()
    if not s or "█" in s:
        return None
    kind = "domain"
    if s.startswith("*."):
        kind = "wildcard"
        s = s[2:]
    # strip scheme + path/query/port; also handle "*.foo.com/path" and "foo.com:443"
    if "://" in s:
        s = urllib.parse.urlparse(s).netloc or s
    s = s.split("/")[0].split("?")[0].split("#")[0].split(":")[0].strip().rstrip(".")
    if s.startswith("*."):          # e.g. raw was "https://*.foo.com"
        kind = "wildcard"
        s = s[2:]
    if "*" in s or not _HOSTISH.match(s):
        return None
    return s.lower(), kind


def web_assets(prog: dict):
    for asset in (prog.get("targets") or {}).get("in_scope") or []:
        atype = str(asset.get("asset_type") or asset.get("type") or "").lower()
        if any(tok in atype for tok in SKIP_TOKENS):
            continue
        if not any(tok in atype for tok in WEB_TOKENS):
            continue
        raw = (asset.get("asset_identifier") or asset.get("target")
               or asset.get("endpoint") or "")
        yield atype, str(raw)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Extract in-scope web domains/wildcards from public bug-bounty scopes.")
    ap.add_argument("-o", "--output", type=Path, default=Path("domains.csv"))
    ap.add_argument("--txt", type=Path, help="Also write a deduped host list here (recon seeds).")
    ap.add_argument("--platforms", nargs="+", default=list(PLATFORMS), choices=PLATFORMS)
    ap.add_argument("--program", help="Case-insensitive substring filter on program name/handle.")
    ap.add_argument("--bounty-only", action="store_true",
                    help="Keep only bounty-paying programs.")
    ap.add_argument("--wildcards-only", action="store_true",
                    help="Keep only wildcard assets (best subdomain-enum seeds).")
    ap.add_argument("--cache-dir", type=Path,
                    help="Reuse/store the downloaded JSON here instead of refetching.")
    args = ap.parse_args()

    today = date.today().isoformat()
    rows: list[dict] = []
    seen: set[tuple[str, str]] = set()
    stats: dict[str, int] = {}

    for platform in args.platforms:
        try:
            data = fetch(platform, args.cache_dir)
        except Exception as e:
            print(f"  {platform}: FETCH FAILED ({e!r})", file=sys.stderr)
            continue
        for prog in data:
            name, url = program_fields(platform, prog)
            handle = prog.get("handle") or name
            if args.program and args.program.lower() not in f"{name} {handle}".lower():
                continue
            if args.bounty_only and not bounty_flag(platform, prog):
                continue
            for atype, raw in web_assets(prog):
                got = extract_host(raw)
                if not got:
                    continue
                host, kind = got
                if args.wildcards_only and kind != "wildcard":
                    continue
                key = (platform, host)
                if key in seen:
                    continue
                seen.add(key)
                stats[platform] = stats.get(platform, 0) + 1
                rows.append({"host": host, "kind": kind, "platform": platform,
                             "program": name, "policy_url": url, "asset_raw": raw,
                             "checked": today})

    rows.sort(key=lambda r: (r["platform"], r["program"].lower(), r["host"]))
    with args.output.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["host", "kind", "platform", "program",
                                           "policy_url", "asset_raw", "checked"])
        w.writeheader()
        w.writerows(rows)

    if args.txt:
        hosts = list(dict.fromkeys(r["host"] for r in rows))  # dedupe, keep order
        args.txt.write_text(
            "\n".join(["# in-scope web hosts — " + today
                       + " (wildcards listed as apex). Confirm policy before testing.", ""]
                      + hosts) + "\n", encoding="utf-8")

    n_wild = sum(1 for r in rows if r["kind"] == "wildcard")
    for platform, n in stats.items():
        print(f"  {platform:<11} web hosts={n}")
    print(f"\nWrote {args.output} — {len(rows)} host(s) ({n_wild} wildcard, "
          f"{len(rows) - n_wild} domain).")
    if args.txt:
        print(f"Wrote {args.txt}")
    print("\nA scope listing is not authorization: confirm the program's policy "
          "permits web testing before you touch anything.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
