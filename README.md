# apk-drill

A single-machine pipeline that drills through Android APKs for leaked secrets:
download → extract → scan with **TruffleHog** (including live-key verification)
→ Markdown report with a remediation plan.

Built for authorized bug-bounty work. Lean and standalone — no fleet or
distribution layer.

## ⚠️ Scope & authorization

Run this **only** against APKs you are authorized to test:

- your own applications, or
- packages whose **bug-bounty program scope explicitly permits** mobile/APK
  testing (e.g. HackerOne / Bugcrowd / YesWeHack entries listing a Google Play
  asset in scope).

Scanning arbitrary third-party apps for their secrets is not authorized
security testing. When you find a live key in an in-scope app, report it through
the program — don't use it.

## Pipeline

```
package list ──> apkeep download ──> unzip/extract ──> trufflehog ──> results.jsonl ──> report.md
                     │                                                      ▲
                     └──────────── delete files after each package ────────┘
```

1. **`apk_secret_scan.py`** — loops over a package list: download, extract,
   scan, append findings to JSONL, delete the downloaded files, next.
   Per-package error handling keeps one bad package from killing the run.
2. **`report.py`** — turns the JSONL into a Markdown report (severity by whether
   the secret verified live) plus a remediation / fix plan.

## Install

```bash
chmod +x install.sh
./install.sh
```

Installs `apkeep` (downloader) and `trufflehog` (scanner). `apkeep` comes from
the prebuilt release binary where one matches the arch (x86_64 / aarch64 /
armv7 Linux), falling back to `cargo install` otherwise — so a server doesn't
need a Rust toolchain just for a downloader. Override with `APKEEP_VERSION=` or
`BIN_DIR=`.

Running against a box that already has other workloads? See
[docs/running-on-a-server.md](docs/running-on-a-server.md).

## Building a package list

For your own apps, the package is the `applicationId` in `app/build.gradle`.

For bug-bounty targets, `scripts/scope_to_packages.py` extracts the in-scope
Android assets from the public program directories of HackerOne, Bugcrowd,
Intigriti and YesWeHack (via the daily
[bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data) mirror —
no API keys):

```bash
python3 scripts/scope_to_packages.py -o packages.csv --txt packages.txt
```

It writes a CSV carrying provenance — platform, program, policy URL, the raw
scope string, and the date pulled — so a later report can show the asset was
listed in scope on the day it was scanned. The scanner reads the `package`
column and ignores the rest.

Assets that name an app in prose ("Acrobat Reader Mobile App (Android)") or
point at a publisher page ("every app by Sky Betting and Gaming") can't be
resolved to a package id automatically. They go to `unresolved_assets.txt` for
manual Play Store lookup rather than being guessed at.

Useful flags: `--platforms hackerone yeswehack`, `--program acme` (substring
filter), `--bounty-only`, `--cache-dir` (reuse the downloaded JSON).

> **A scope listing is not authorization.** The script reports what a program
> *lists*; it cannot tell you whether the program permits APK/mobile testing,
> whether it's open to you, or whether the listing is current. Read the policy
> before scanning anything it emits.

## Usage

**1. Prepare a package list** — plain text (one package per line) or a CSV with a
`package` column:

```
com.example.app
com.another.app
# lines starting with # are ignored
```

**2. Run the scan:**

```bash
python3 apk_secret_scan.py packages.txt -o results_latest.jsonl --only-verified
```

Useful flags:

| Flag | Meaning |
|---|---|
| `--only-verified` | Keep only live/verified secrets (cuts most false-positive noise). |
| `--keep-files` | Don't delete downloads after each package (debugging). |
| `--source apk-pure` | apkeep source (default; can also be `google-play`, `f-droid`). |
| `--download-timeout` / `--scan-timeout` | Per-package limits in seconds. |
| `--workdir` | Scratch directory for downloads/extraction. |

The results file is opened in **append** mode, so re-runs accumulate. Each line
is either a finding or a per-package status (`clean`, `download_failed`,
`error:*`).

**3. Build the report:**

```bash
python3 report.py results_latest.jsonl -o report.md
```

Open `report.md` for findings grouped by package, severity, and the fix plan.

## Severity model

| | Verified (live) | Unverified |
|---|---|---|
| **High-impact detector** (AWS, GCP, Stripe, PrivateKey, …) | CRITICAL | MEDIUM |
| Other detector | HIGH | LOW |

## Notes on accuracy

- **Verified ≠ exploitable.** TruffleHog verifying a key means it's live, not
  that it grants anything useful. Always assess real impact before reporting.
- **Unverified findings** are frequently dead keys or false positives — triage,
  don't assume.
- A raw **Firebase / Google API key** in an APK is often *not* sensitive by
  itself; check what it actually authorizes before treating it as a leak.
- `apkeep` and APKPure's endpoints change over time; if downloads start failing,
  update apkeep first (`cargo install apkeep --force`).

## Not built (yet)

Fan-out across multiple machines. The scanner runs fine standalone; a
per-package worker split would be the starting point if scaling is wanted later.

## Files

| File | Purpose |
|---|---|
| `apk_secret_scan.py` | Main download → extract → scan → JSONL pipeline. |
| `report.py` | JSONL → Markdown report + remediation plan. |
| `scripts/scope_to_packages.py` | Public bug-bounty scopes → package list with provenance. |
| `install.sh` | Dependency installer (Ubuntu). |
| `packages.example.txt` | Example package list. |

## License

MIT — see [LICENSE](LICENSE).
