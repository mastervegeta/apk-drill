#!/usr/bin/env python3
"""
apk_fetch.py

apk-drill — multi-source APK downloader (mirrors + authenticated Google Play).

Tries a source-priority chain per package (first hit wins), so packages missing
from APKPure — regional / satellite / B2B apps, the ones worth hunting — get
recovered from Google Play. Output is one directory per package, consumable by
apk_surface_map.py (and, later, apk_secret_scan.py) via their `--from-dir` mode,
so you fetch once and map/scan the cache repeatedly without re-downloading.

Google Play credentials are read from a creds file (default ./.gplay.env), NEVER
the command line — tokens stay out of shell history and process listings. The
one-time oauth->aas setup is in docs/DOWNLOAD-SPEC.md and this file's --help.

SCOPE / AUTHORIZATION
---------------------
Only fetch APKs you are authorized to test (your own apps, or packages whose
bug-bounty scope explicitly permits mobile/APK testing). Bulk Google Play use
should go through a dedicated throwaway account at a low, jittered rate — it is
a ban vector otherwise, and mass fetching outside scope is not authorized.

Requires: python3, apkeep (>= 1.0). For Google Play: a creds file with
GPLAY_EMAIL and GPLAY_AAS_TOKEN (see setup below).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from apk_secret_scan import log, read_packages, looks_like_package

DEFAULT_CREDS = Path(".gplay.env")
_SENSITIVE_KEYS = ("GPLAY_AAS_TOKEN", "GPLAY_OAUTH_TOKEN")


def load_creds(path: Path) -> dict:
    """Read KEY=VALUE lines from the creds file; env vars override. Values are
    never logged."""
    creds: dict[str, str] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            creds[k.strip()] = v.strip().strip('"').strip("'")
    for k in ("GPLAY_EMAIL", "GPLAY_AAS_TOKEN", "GPLAY_OAUTH_TOKEN"):
        if os.environ.get(k):
            creds[k] = os.environ[k]
    return creds


def has_apk(pkg_dir: Path) -> bool:
    if not pkg_dir.is_dir():
        return False
    for pat in ("*.apk", "*.xapk", "*.apks"):
        if any(pkg_dir.rglob(pat)):
            return True
    return False


def _redact(cmd: list[str]) -> str:
    """Render an apkeep command with token values masked for logging."""
    out, skip = [], False
    for c in cmd:
        if skip:
            out.append("<redacted>")
            skip = False
            continue
        out.append(c)
        if c in ("-t", "--aas-token", "--oauth-token", "--auth-token"):
            skip = True
    return " ".join(out)


def fetch_one(pkg: str, out_pkg: Path, source: str, creds: dict,
              sleep_ms: int, timeout: int) -> list[Path]:
    """Run apkeep for one (package, source). Returns the new files, or []."""
    out_pkg.mkdir(parents=True, exist_ok=True)
    before = set(out_pkg.iterdir())

    cmd = ["apkeep", "-a", pkg, "-d", source]
    if source == "google-play":
        email = creds.get("GPLAY_EMAIL")
        aas = creds.get("GPLAY_AAS_TOKEN")
        oauth = creds.get("GPLAY_OAUTH_TOKEN")
        if not email:
            raise RuntimeError("google-play requires GPLAY_EMAIL in the creds file")
        cmd += ["-e", email, "--accept-tos", "-s", str(sleep_ms)]
        if aas:
            cmd += ["-t", aas]
        elif oauth:
            # first-run: apkeep exchanges the oauth token for a long-lived aas
            cmd += ["--oauth-token", oauth]
        else:
            raise RuntimeError(
                "google-play requires GPLAY_AAS_TOKEN (or GPLAY_OAUTH_TOKEN for "
                "the one-time exchange) in the creds file")
    cmd += [str(out_pkg)]

    log(f"  try {source}: {_redact(cmd)}")
    try:
        subprocess.run(cmd, check=True, timeout=timeout,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except subprocess.TimeoutExpired:
        log(f"    {source} TIMEOUT after {timeout}s")
        return []
    except subprocess.CalledProcessError as e:
        tail = (e.output or b"").decode("utf-8", "replace").strip().splitlines()
        log(f"    {source} failed: {tail[-1] if tail else '(no output)'}")
        return []

    new_files = sorted(set(out_pkg.iterdir()) - before)
    return new_files


def main() -> int:
    ap = argparse.ArgumentParser(
        description="apk-drill: multi-source APK downloader (mirrors + Google Play).",
        epilog=(
            "One-time Google Play setup:\n"
            "  1. In a browser, open https://accounts.google.com/EmbeddedSetup and\n"
            "     sign in with your DEDICATED throwaway account.\n"
            "  2. DevTools > Application > Cookies > accounts.google.com: copy the\n"
            "     value of the 'oauth_token' cookie (starts with 'oauth2_4/').\n"
            "  3. Create .gplay.env (chmod 600) with:\n"
            "         GPLAY_EMAIL=throwaway@gmail.com\n"
            "         GPLAY_OAUTH_TOKEN=oauth2_4/...\n"
            "  4. Run one fetch of any Play app. apkeep exchanges the oauth token\n"
            "     for a long-lived aas token (printed once). Put THAT in .gplay.env\n"
            "     as GPLAY_AAS_TOKEN=... and delete GPLAY_OAUTH_TOKEN (single-use).\n"
            "  The oauth/aas tokens are secrets — keep .gplay.env gitignored, 600."),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("packages", type=Path, help="Package list (.txt or .csv).")
    ap.add_argument("out", type=Path, help="Output dir (one subdir per package).")
    ap.add_argument("--sources", default="apk-pure,google-play",
                    help="Comma-separated source-priority chain "
                         "(default: apk-pure,google-play).")
    ap.add_argument("--creds", type=Path, default=DEFAULT_CREDS,
                    help="Creds file for Google Play (default: .gplay.env).")
    ap.add_argument("--manifest", type=Path, default=None,
                    help="JSONL fetch log (default: <out>/_fetch_manifest.jsonl).")
    ap.add_argument("--sleep-ms", type=int, default=800,
                    help="Per-request sleep for Google Play, ms (default: 800).")
    ap.add_argument("--between-ms", type=int, default=1500,
                    help="Extra pause between packages when Play was used, ms.")
    ap.add_argument("--timeout", type=int, default=300, help="Per-fetch timeout (s).")
    ap.add_argument("--skip-downloaded", action="store_true",
                    help="Skip packages whose output dir already holds an APK.")
    args = ap.parse_args()

    sources = [s.strip() for s in args.sources.split(",") if s.strip()]
    valid = {"apk-pure", "google-play", "f-droid", "huawei-app-gallery"}
    bad = [s for s in sources if s not in valid]
    if bad:
        log(f"FATAL: unknown source(s): {', '.join(bad)}. Valid: {', '.join(sorted(valid))}")
        return 1

    creds = load_creds(args.creds)
    if "google-play" in sources and not creds.get("GPLAY_EMAIL"):
        log(f"NOTE: google-play is in the chain but no GPLAY_EMAIL in {args.creds}. "
            "Play fetches will error; mirror sources still work. See --help for setup.")

    if not args.packages.exists():
        log(f"FATAL: package list not found: {args.packages}")
        return 1
    packages = read_packages(args.packages)
    if not packages:
        log("FATAL: no package names read from input.")
        return 1

    args.out.mkdir(parents=True, exist_ok=True)
    manifest = args.manifest or (args.out / "_fetch_manifest.jsonl")

    log(f"Loaded {len(packages)} package(s). Chain: {' -> '.join(sources)}. "
        "Scope reminder: authorized targets only.")

    stats = {"packages": 0, "fetched": 0, "skipped": 0, "failed": 0}
    by_source: dict[str, int] = {}

    with manifest.open("a", encoding="utf-8") as mf:
        for i, pkg in enumerate(packages, 1):
            stats["packages"] += 1
            log(f"[{i}/{len(packages)}] {pkg}")
            if not looks_like_package(pkg):
                log("  skip: does not look like a package name")
                continue

            pkg_dir = args.out / pkg
            if args.skip_downloaded and has_apk(pkg_dir):
                log("  skip: already downloaded")
                stats["skipped"] += 1
                continue

            used_play = False
            got: list[Path] = []
            got_source = None
            for source in sources:
                if source == "google-play":
                    used_play = True
                try:
                    got = fetch_one(pkg, pkg_dir, source, creds,
                                    args.sleep_ms, args.timeout)
                except RuntimeError as e:
                    log(f"    {source} skipped: {e}")
                    continue
                if got:
                    got_source = source
                    break

            rec = {
                "package": pkg,
                "status": "ok" if got else "download_failed",
                "source": got_source,
                "files": [p.name for p in got],
                "at": datetime.now(timezone.utc).isoformat(),
            }
            mf.write(json.dumps(rec) + "\n")
            mf.flush()

            if got:
                stats["fetched"] += 1
                by_source[got_source] = by_source.get(got_source, 0) + 1
                log(f"  OK via {got_source}: {len(got)} file(s)")
            else:
                stats["failed"] += 1
                log("  FAILED on all sources")

            if used_play and args.between_ms and i < len(packages):
                time.sleep(args.between_ms / 1000.0)

    log("---- done ----")
    for k, v in stats.items():
        log(f"  {k}: {v}")
    if by_source:
        log("  by source: " + ", ".join(f"{k}={v}" for k, v in by_source.items()))
    log(f"Manifest: {manifest}")
    log(f"Next: python3 apk_surface_map.py --from-dir {args.out} -o surface.jsonl")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
