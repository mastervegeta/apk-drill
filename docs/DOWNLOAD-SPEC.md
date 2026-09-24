# Bulk APK acquisition — design spec

## Problem
APKPure (and other mirrors) cover popular apps but systematically miss the
apps worth hunting for *unique* bugs:
- regional / satellite apps (driver, courier, merchant, B2B) — e.g. every
  `com.mercadoenvios.*` returned `download_failed` from apk-pure
- geo-locked, paid, freshly-published, or beta builds

The authoritative source for all of these is **Google Play itself**. So the
unlock is a Play-backed, multi-source downloader that feeds the existing
`apk_secret_scan.py` / `apk_surface_map.py` pipelines unchanged.

## Source landscape (ranked by coverage vs effort)
| Source | Coverage | Effort | Notes |
|---|---|---|---|
| apk-pure / apk-mirror / apk-combo | popular apps | low | HTML/mirror; apkeep already supports apk-pure, apk-mirror |
| F-Droid | FOSS only | low | irrelevant for commercial targets |
| **Google Play API (authenticated)** | **~everything installable by the account** | medium | the real unlock; needs a throwaway Google account + AAS token |
| Emulator/device + `adb pull` | anything the device can install | high | fallback for SafetyNet/region/device-gated apps |

## Architecture — `apk_fetch.py` (new orchestrator)
A source-priority chain per package; first hit wins; output lands in the same
workdir layout the scanner/mapper already consume.

```
for pkg in packages:
    for source in [apk-pure, apk-mirror, google-play]:   # configurable order
        files = apkeep(pkg, source)      # reuse apkeep; google-play backend below
        if files: break
    else: record download_failed(pkg)
```

- **Reuse apkeep** — it already speaks apk-pure, apk-mirror, **google-play**,
  f-droid, huawei. We only add credential wiring + the fallback loop.
- **Concurrency:** bounded worker pool (e.g. 4). Per-source token-bucket rate
  limit + exponential backoff. Never burst Play — that's a ban vector.
- **Resume/dedupe:** skip packages already downloaded (by pkg+versionCode);
  cache to disk. Same `--skip-*` model as the existing tools.
- **Scope gate:** cross-check every package against an in-scope allowlist
  (provenance already produced by `scripts/scope_to_packages.py`) before
  fetching. Authorized targets only — this stays first-class.

## The Google Play backend (the key piece)
apkeep's `--app-source google-play` needs three things, obtained **once**:
1. **A dedicated throwaway Google account** — never a personal one (bulk API
   use violates Play ToS and risks bans; isolate the blast radius).
2. **An AAS token** (`Android-Auth-Sub` / `oauth2:...` exchanged to AAS) — the
   long-lived credential apkeep/gpapi use instead of the password. Obtain via
   the aurora/gplaycli token dispenser or an oauth2→AAS exchange helper; store
   it **encrypted** (reuse the scraper's Fernet `CREDENTIALS_KEY` pattern).
3. **A device profile** — a `device.properties` (e.g. a Pixel config) giving a
   gsfId + supported features, so Play serves compatible splits.

Config (env, mirrors the scraper's style):
```
GPLAY_EMAIL=throwaway@gmail.com
GPLAY_AAS_TOKEN=enc:v1:...        # encrypted at rest
GPLAY_DEVICE=px_7                 # device_config profile name
GPLAY_COUNTRY=US                  # account region
GPLAY_PROXY=                      # optional, for geo-locked apps
```
apkeep returns base + split APKs; `extract_bundles()` already merges those, so
nothing downstream changes.

### Region / geo-locked apps
The account's country determines availability. For a target only published in
region X: use an account registered to X, and/or route `GPLAY_PROXY` through X.
Keep a small pool of region-specific accounts if you hunt across markets.

## Package discovery — feed the pipeline (bonus, high value)
The satellite apps are the point, so discovery matters as much as download:
1. **Scope feeds:** diff `arkadiyt/bounty-targets-data` (daily JSON of every
   H1/Bugcrowd/Intigriti scope) → keep `googleplay` asset types → package list.
   Extend `scripts/scope_to_packages.py`.
2. **Developer-page enumeration:** given a target company's Play *developer*
   account, list **all** its published apps (this is how you find the driver /
   merchant / B2B satellites nobody scans). Fetch only the ones whose package
   is in an authorized scope.
3. **Scope-diff monitor:** on a schedule, catch newly-added mobile targets →
   auto-queue fetch → map → report. First-mover advantage before the crowd.

## Emulator/device fallback (Phase 3, for the stubborn few)
Some apps gate on device integrity/region and refuse the Play API. Fallback:
- Dockerized Android emulator (e.g. `budtmo/docker-android`) with Google APIs,
  or a cheap physical device.
- Install via Aurora Store / Play, then `pm path <pkg>` → `adb pull` the base +
  splits. Route through a region proxy as needed.
- Cross-platform + reproducible (fits the Docker-first preference); reserve for
  the handful the API can't serve — it's heavier per app.

## Anti-ban / ToS discipline (do this, not optional)
- Dedicated throwaway account(s); assume they may get burned — rotate.
- Low, jittered request rate per source; back off on 429/403; never parallel-
  hammer Play.
- Only fetch apps in an authorized program scope. Log provenance per download.
- Cache aggressively so you never re-download the same versionCode.

## Phased build
- **Phase 1 — `apk_fetch.py`:** multi-source chain (apk-pure → apk-mirror →
  google-play) + AAS-token setup doc. Recovers most "not on apk-pure" apps by
  itself. *(smallest change, biggest coverage win)*
- **Phase 2 — discovery:** scope-feed + developer-page enumeration → auto
  package lists of in-scope satellites.
- **Phase 3 — emulator fallback** for API-refused apps.
- **Phase 4 — scope-diff monitor** → end-to-end first-mover pipeline
  (new target → fetch → map → ranked report).

## Bottom line
Phase 1 (apkeep google-play backend behind a source-priority chain, one
throwaway account + AAS token) is ~80% of the win and a small amount of code.
Everything downstream — secret scan and surface map — already consumes the
output unchanged.
