#!/usr/bin/env python3
"""
apk_secret_scan.py

apk-drill — single-machine APK secret-scanning pipeline.

For each package name in an input list:
  1. download the APK/bundle from APKPure (via `apkeep`)
  2. extract/merge split bundles into scannable files
  3. run TruffleHog (with --only-verified live-key verification available)
  4. append findings to a JSONL results file
  5. delete the downloaded files to save disk, move to the next package

SCOPE / AUTHORIZATION
---------------------
Only run this against APKs you are authorized to test: your own apps, or
packages whose bug-bounty program scope explicitly permits mobile/APK testing
(e.g. HackerOne/Bugcrowd/YesWeHack entries with Google Play asset type in scope).
Scanning arbitrary third-party apps for secrets is not authorized testing.

Requires: python3, apkeep, trufflehog, unzip. See install.sh / README.md.
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def which_or_die(binaries: list[str]) -> None:
    missing = [b for b in binaries if shutil.which(b) is None]
    if missing:
        log(f"FATAL: missing required tools: {', '.join(missing)}")
        log("Run ./install.sh or see README.md for install instructions.")
        sys.exit(1)


def read_packages(path: Path) -> list[str]:
    """
    Accept a plain text file (one package per line) or a CSV.
    For CSV, we look for a column named 'package' / 'package_name', else col 0.
    Lines starting with '#' and blanks are ignored.
    """
    text = path.read_text(encoding="utf-8", errors="replace")

    # try CSV first if it looks like one
    if path.suffix.lower() == ".csv" or ("," in text.splitlines()[0] if text.strip() else False):
        rows = list(csv.reader(text.splitlines()))
        if not rows:
            return []
        header = [h.strip().lower() for h in rows[0]]
        col = 0
        data_rows = rows
        for candidate in ("package", "package_name", "packagename", "id"):
            if candidate in header:
                col = header.index(candidate)
                data_rows = rows[1:]  # skip header
                break
        pkgs = []
        for r in data_rows:
            if not r:
                continue
            val = r[col].strip() if col < len(r) else ""
            if val and not val.startswith("#"):
                pkgs.append(val)
        return dedupe(pkgs)

    # plain text
    pkgs = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    return dedupe(pkgs)


def dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


def looks_like_package(name: str) -> bool:
    # basic sanity: reverse-DNS-ish, no spaces
    return " " not in name and "." in name and "/" not in name


def already_scanned(results_path: Path) -> set[str]:
    """
    Packages that already have a *successful* result in the JSONL (a finding, or
    a `clean` status). Used by --skip-scanned to resume a large run without
    redoing work. Failures (download_failed, error:*) are deliberately NOT
    counted as done, so a resume retries them — an APKPure miss is often
    transient or fixable by switching --source.
    """
    done: set[str] = set()
    if not results_path.exists():
        return done
    for line in results_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        pkg = rec.get("package")
        if not pkg:
            continue
        status = rec.get("status")
        if status is None or status == "clean":   # a finding row, or a clean scan
            done.add(pkg)
    return done


# --------------------------------------------------------------------------- #
# pipeline steps
# --------------------------------------------------------------------------- #

def download_apk(package: str, dest: Path, source: str, timeout: int) -> list[Path]:
    """
    Download `package` into `dest` using apkeep. Returns the list of files
    that landed in `dest` (apkeep may produce .apk, .xapk, or a split dir).
    """
    dest.mkdir(parents=True, exist_ok=True)
    before = set(dest.iterdir())

    cmd = ["apkeep", "-a", package, "-d", source, str(dest)]
    log(f"  download: {' '.join(cmd)}")
    try:
        subprocess.run(
            cmd,
            check=True,
            timeout=timeout,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except subprocess.TimeoutExpired:
        log(f"  download TIMEOUT after {timeout}s")
        return []
    except subprocess.CalledProcessError as e:
        out = (e.output or b"").decode("utf-8", "replace").strip().splitlines()
        tail = out[-1] if out else "(no output)"
        log(f"  download FAILED: {tail}")
        return []

    after = set(dest.iterdir())
    new_files = sorted(after - before)
    return new_files


def extract_bundles(files: list[Path], workdir: Path) -> Path:
    """
    APKs are zip files; split bundles (.xapk / .apks / a folder of .apk) hold
    several. Unzip everything reachable into `workdir` so TruffleHog can walk a
    flat tree of real files. We recursively unzip any zip/apk we find, one level
    deep past bundles, which is enough to expose classes.dex, resources, assets,
    and embedded config files where secrets typically live.
    """
    workdir.mkdir(parents=True, exist_ok=True)

    def try_unzip(archive: Path, into: Path) -> bool:
        try:
            with zipfile.ZipFile(archive) as zf:
                zf.extractall(into)
            return True
        except (zipfile.BadZipFile, OSError):
            return False

    # first pass: expand the top-level artifacts apkeep produced
    for f in files:
        if f.is_dir():
            # a folder of split apks — copy its apks in for the second pass
            for apk in f.rglob("*.apk"):
                shutil.copy2(apk, workdir / apk.name)
        else:
            target = workdir / (f.stem + "_extracted")
            if not try_unzip(f, target):
                # not a zip (rare) — just copy the raw file so it still gets scanned
                shutil.copy2(f, workdir / f.name)

    # second pass: any inner .apk (split bundle) is itself a zip — expand those too
    for apk in list(workdir.rglob("*.apk")):
        target = apk.parent / (apk.stem + "_apk")
        try_unzip(apk, target)

    return workdir


def run_trufflehog(scan_dir: Path, only_verified: bool, timeout: int) -> list[dict]:
    """
    Run trufflehog against a filesystem path in JSON mode and parse the
    line-delimited JSON output into a list of finding dicts.
    """
    cmd = ["trufflehog", "filesystem", str(scan_dir), "--json", "--no-update"]
    if only_verified:
        cmd.append("--only-verified")

    log(f"  scan: trufflehog{' (verified only)' if only_verified else ''}")
    try:
        proc = subprocess.run(
            cmd,
            timeout=timeout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except subprocess.TimeoutExpired:
        log(f"  scan TIMEOUT after {timeout}s")
        return []

    findings: list[dict] = []
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # trufflehog prints some non-JSON status lines
    return findings


def summarize_finding(package: str, raw: dict) -> dict:
    """Flatten a trufflehog finding into a compact record for the JSONL file."""
    src_meta = raw.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
    return {
        "package": package,
        "detector": raw.get("DetectorName"),
        "verified": bool(raw.get("Verified", False)),
        "file": src_meta.get("file"),
        "raw_secret_redacted": (raw.get("Redacted") or "")[:120],
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


# --------------------------------------------------------------------------- #
# main loop
# --------------------------------------------------------------------------- #

def main() -> int:
    ap = argparse.ArgumentParser(description="apk-drill: APK secret-scanning pipeline (single machine).")
    ap.add_argument("packages", type=Path, help="Path to package list (.txt or .csv).")
    ap.add_argument("-o", "--output", type=Path, default=Path("results_latest.jsonl"),
                    help="JSONL results file (default: results_latest.jsonl).")
    ap.add_argument("--source", default="apk-pure",
                    help="apkeep source (default: apk-pure).")
    ap.add_argument("--only-verified", action="store_true",
                    help="Keep only live/verified secrets (recommended to cut noise).")
    ap.add_argument("--keep-files", action="store_true",
                    help="Do NOT delete downloaded/extracted files after each package.")
    ap.add_argument("--skip-scanned", action="store_true",
                    help="Resume: skip packages already scanned OK in the output "
                         "file (failures are retried). Lets a big run resume.")
    ap.add_argument("--download-timeout", type=int, default=300)
    ap.add_argument("--scan-timeout", type=int, default=600)
    ap.add_argument("--workdir", type=Path, default=Path("._apk_work"),
                    help="Scratch directory (default: ._apk_work).")
    args = ap.parse_args()

    which_or_die(["apkeep", "trufflehog"])

    if not args.packages.exists():
        log(f"FATAL: package list not found: {args.packages}")
        return 1

    packages = read_packages(args.packages)
    if not packages:
        log("FATAL: no package names read from input.")
        return 1

    if args.skip_scanned:
        done = already_scanned(args.output)
        if done:
            before = len(packages)
            packages = [p for p in packages if p not in done]
            log(f"--skip-scanned: {before - len(packages)} already done, "
                f"{len(packages)} to go.")

    if not packages:
        log("Nothing to scan (all packages already done?). Exiting.")
        return 0

    log(f"Loaded {len(packages)} package(s). Scope reminder: authorized targets only.")
    args.workdir.mkdir(parents=True, exist_ok=True)

    stats = {"packages": 0, "downloaded": 0, "download_failed": 0,
             "findings": 0, "verified": 0}

    # open results file in append mode so re-runs accumulate
    with args.output.open("a", encoding="utf-8") as out_fh:
        for i, pkg in enumerate(packages, 1):
            stats["packages"] += 1
            log(f"[{i}/{len(packages)}] {pkg}")

            if not looks_like_package(pkg):
                log("  skip: does not look like a package name")
                continue

            pkg_dir = args.workdir / pkg
            try:
                downloaded = download_apk(pkg, pkg_dir, args.source, args.download_timeout)
                if not downloaded:
                    stats["download_failed"] += 1
                    _write_status(out_fh, pkg, "download_failed")
                    continue
                stats["downloaded"] += 1

                scan_dir = extract_bundles(downloaded, pkg_dir / "_extracted")
                findings = run_trufflehog(scan_dir, args.only_verified, args.scan_timeout)

                if not findings:
                    log("  no findings")
                    _write_status(out_fh, pkg, "clean")
                else:
                    pkg_verified = 0
                    for raw in findings:
                        rec = summarize_finding(pkg, raw)
                        out_fh.write(json.dumps(rec) + "\n")
                        stats["findings"] += 1
                        if rec["verified"]:
                            stats["verified"] += 1
                            pkg_verified += 1
                    out_fh.flush()
                    log(f"  {len(findings)} finding(s), {pkg_verified} verified")

            except KeyboardInterrupt:
                log("Interrupted by user.")
                break
            except Exception as e:  # keep the loop alive across per-package errors
                log(f"  ERROR: {e!r}")
                _write_status(out_fh, pkg, f"error:{type(e).__name__}")
            finally:
                if not args.keep_files and pkg_dir.exists():
                    shutil.rmtree(pkg_dir, ignore_errors=True)

    log("---- done ----")
    for k, v in stats.items():
        log(f"  {k}: {v}")
    log(f"Results: {args.output}")
    return 0


def _write_status(fh, package: str, status: str) -> None:
    fh.write(json.dumps({
        "package": package,
        "status": status,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }) + "\n")
    fh.flush()


if __name__ == "__main__":
    raise SystemExit(main())
