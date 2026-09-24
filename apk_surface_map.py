#!/usr/bin/env python3
"""
apk_surface_map.py

apk-drill — APK attack-surface mapper (companion to apk_secret_scan.py).

Where the secret scanner answers "is a credential leaking?", this answers
"what is there to test?". For each package it decompiles the APK and emits the
attack surface a manual hunter actually chases for non-duplicate bugs:

  * exported components   (activities / services / receivers / providers)
  * deeplinks             (BROWSABLE intent-filter scheme/host/path, App Links)
  * API endpoints         (hosts, /api|/v1|/graphql paths) the app talks to
  * Firebase config       (RTDB URLs, appspot buckets, google api keys)
  * GraphQL endpoints
  * manifest posture      (debuggable / allowBackup / cleartext / sdk levels)

Output is one JSON object per package (JSONL), same resume/append model as the
secret scanner, so `surface_report.py` can rank the results afterwards.

The point: endpoints + exported IPC + deeplinks are app-specific and far less
picked-over than hardcoded secrets, so leads mined here dup a lot less. This
tool only *maps* surface — it makes no requests. You test the leads yourself,
within the program's scope and rules.

SCOPE / AUTHORIZATION
---------------------
Only run against APKs you are authorized to test (your own apps, or packages
whose bug-bounty scope explicitly permits mobile/APK testing). Mapping surface
is passive, but acting on it is testing — stay in scope.

Requires: python3, apkeep, unzip. Manifest parsing additionally uses androguard
(`pip install androguard`); without it, component/deeplink extraction is skipped
and only the string-derived surface (endpoints/firebase/graphql) is produced.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

# reuse the secret scanner's battle-tested plumbing
from apk_secret_scan import (
    log,
    download_apk,
    extract_bundles,
    read_packages,
    looks_like_package,
)

# androguard is optional; degrade gracefully if it isn't installed
try:
    from androguard.core.apk import APK  # androguard >= 4
except Exception:  # pragma: no cover - import path varies by version
    try:
        from androguard.core.bytecodes.apk import APK  # androguard 3.x
    except Exception:
        APK = None

ANDROID_NS = "http://schemas.android.com/apk/res/android"


# --------------------------------------------------------------------------- #
# string-derived surface (no manifest needed)
# --------------------------------------------------------------------------- #

# files worth mining for URLs/config. dex/arsc/so are binary but URLs inside
# them are ASCII, so a latin-1 decode + regex finds them without a strings pass.
_TEXTLIKE_SUFFIXES = {".xml", ".json", ".txt", ".js", ".html", ".properties",
                      ".yaml", ".yml", ".graphql", ".gql"}
_BINARY_SUFFIXES = {".dex", ".arsc", ".so"}
_FILE_CAP_BYTES = 30 * 1024 * 1024  # skip pathological blobs

_URL_RE = re.compile(r"https?://[A-Za-z0-9._~%\-]+(?:\:[0-9]+)?(?:/[A-Za-z0-9._~%!$&'()*+,;=:@/\-]*)?")
_GOOGLE_API_KEY_RE = re.compile(r"AIza[0-9A-Za-z_\-]{35}")
_FIREBASE_RTDB_RE = re.compile(r"https?://[a-z0-9.\-]+\.firebase(?:io|database)\.[a-z.]+")
_APPSPOT_RE = re.compile(r"[a-z0-9.\-]+\.appspot\.com")
_FIREBASE_STORAGE_RE = re.compile(r"[a-z0-9.\-]+\.firebasestorage\.(?:app|googleapis\.com)")

# hosts that are framework/vendor boilerplate, not the app's own backend
_HOST_DENY_SUBSTR = (
    "schemas.android.com", "www.w3.org", "xmlpull.org", "java.sun.com",
    "apache.org", "json-schema.org", "goo.gl/", "play.google.com",
    "github.com", "reactnative.dev", "fonts.gstatic.com", "fonts.googleapis.com",
    "developer.android.com", "ns.adobe.com", "example.com", "localhost",
    "127.0.0.1", "gstatic.com/",
)


def _host_of(url: str) -> str:
    m = re.match(r"https?://([^/:]+)", url)
    return m.group(1).lower() if m else ""


def _interesting_host(host: str) -> bool:
    if not host or "." not in host:
        return False
    return not any(bad in host for bad in _HOST_DENY_SUBSTR)


def _iter_blobs(scan_dir: Path):
    """Yield (relpath, text) for files worth mining, binaries decoded latin-1."""
    for p in scan_dir.rglob("*"):
        if not p.is_file():
            continue
        suf = p.suffix.lower()
        try:
            size = p.stat().st_size
        except OSError:
            continue
        if size == 0 or size > _FILE_CAP_BYTES:
            continue
        if suf in _TEXTLIKE_SUFFIXES:
            try:
                yield p, p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
        elif suf in _BINARY_SUFFIXES or p.name == "AndroidManifest.xml":
            try:
                yield p, p.read_bytes().decode("latin-1", "replace")
            except OSError:
                continue


def scan_strings(scan_dir: Path) -> dict:
    """Mine the extracted tree for endpoints, firebase config, and graphql."""
    hosts: dict[str, int] = {}
    api_urls: set[str] = set()
    graphql: set[str] = set()
    fb_rtdb: set[str] = set()
    fb_bucket: set[str] = set()
    google_keys: set[str] = set()

    for _p, text in _iter_blobs(scan_dir):
        for m in _URL_RE.finditer(text):
            url = m.group(0).rstrip(".,)\"'")
            host = _host_of(url)
            if not _interesting_host(host):
                continue
            hosts[host] = hosts.get(host, 0) + 1
            low = url.lower()
            if "/graphql" in low:
                graphql.add(url.split("?")[0])
            if re.search(r"/(api|v\d+|rest|mobile|graphql)(/|$)", low) or host.startswith("api."):
                api_urls.add(url.split("?")[0])
        for m in _FIREBASE_RTDB_RE.finditer(text):
            fb_rtdb.add(m.group(0))
        for m in _APPSPOT_RE.finditer(text):
            fb_bucket.add(m.group(0))
        for m in _FIREBASE_STORAGE_RE.finditer(text):
            fb_bucket.add(m.group(0))
        for m in _GOOGLE_API_KEY_RE.finditer(text):
            google_keys.add(m.group(0))

    top_hosts = dict(sorted(hosts.items(), key=lambda kv: -kv[1])[:60])
    return {
        "hosts": top_hosts,
        "api_endpoints": sorted(api_urls)[:200],
        "graphql_endpoints": sorted(graphql)[:50],
        "firebase": {
            "rtdb": sorted(fb_rtdb),
            "buckets": sorted(fb_bucket),
            "google_api_keys": sorted(google_keys)[:20],
        },
    }


# --------------------------------------------------------------------------- #
# manifest-derived surface (needs androguard)
# --------------------------------------------------------------------------- #

# permissions that meaningfully widen attack surface if misused
_DANGEROUS_PERMS = {
    "WRITE_EXTERNAL_STORAGE", "READ_EXTERNAL_STORAGE", "SYSTEM_ALERT_WINDOW",
    "REQUEST_INSTALL_PACKAGES", "READ_CONTACTS", "ACCESS_FINE_LOCATION",
    "READ_SMS", "RECEIVE_SMS", "CAMERA", "RECORD_AUDIO", "READ_PHONE_STATE",
    "WRITE_SETTINGS", "MANAGE_EXTERNAL_STORAGE",
}


def _attr(el, name: str):
    return el.get(f"{{{ANDROID_NS}}}{name}")


def _intent_filters(comp):
    return comp.findall("intent-filter")


def _deeplinks_from(comp, comp_name: str) -> list[dict]:
    out: list[dict] = []
    for f in _intent_filters(comp):
        cats = {_attr(c, "name") for c in f.findall("category")}
        if "android.intent.category.BROWSABLE" not in cats:
            continue
        auto = (f.get(f"{{{ANDROID_NS}}}autoVerify") == "true")
        for d in f.findall("data"):
            scheme = _attr(d, "scheme")
            host = _attr(d, "host")
            if not scheme and not host:
                continue
            out.append({
                "scheme": scheme,
                "host": host,
                "path": (_attr(d, "path") or _attr(d, "pathPrefix")
                         or _attr(d, "pathPattern")),
                "app_link": bool(auto and scheme in ("http", "https")),
                "activity": comp_name,
            })
    return out


def _is_exported(comp, kind: str) -> tuple[bool, bool]:
    """Return (exported, exported_is_explicit)."""
    raw = _attr(comp, "exported")
    if raw is not None:
        return (raw == "true", True)
    # implicit: components with an intent-filter default to exported on
    # targetSdk < 31 (providers default exported=true pre-API-17). Flag as
    # implicit so the hunter checks the effective targetSdk.
    return (bool(_intent_filters(comp)) or kind == "provider", False)


def parse_manifest(apk_paths: list[Path]) -> dict:
    """Merge manifest surface across a bundle's APKs (base carries most)."""
    if APK is None:
        return {"parsed": False, "reason": "androguard not installed"}

    merged = {
        "parsed": True,
        "package": None,
        "min_sdk": None,
        "target_sdk": None,
        "debuggable": None,
        "allow_backup": None,
        "uses_cleartext_traffic": None,
        "network_security_config": None,
        "dangerous_permissions": set(),
        "exported": {"activities": [], "services": [], "receivers": [], "providers": []},
        "deeplinks": [],
    }
    seen = {"activities": set(), "services": set(), "receivers": set(),
            "providers": set()}
    parsed_any = False

    for apk in apk_paths:
        try:
            a = APK(str(apk))
            xml = a.get_android_manifest_xml()
        except Exception as e:  # a split with no usable manifest, etc.
            log(f"    manifest parse skipped for {apk.name}: {type(e).__name__}")
            continue
        if xml is None:
            continue
        parsed_any = True

        merged["package"] = merged["package"] or a.get_package()
        try:
            merged["min_sdk"] = merged["min_sdk"] or a.get_min_sdk_version()
            merged["target_sdk"] = merged["target_sdk"] or a.get_target_sdk_version()
        except Exception:
            pass

        app = xml.find("application")
        if app is not None:
            if merged["debuggable"] is None:
                merged["debuggable"] = _attr(app, "debuggable") == "true"
            if merged["allow_backup"] is None:
                ab = _attr(app, "allowBackup")
                merged["allow_backup"] = (ab != "false")  # default true
            if merged["uses_cleartext_traffic"] is None:
                merged["uses_cleartext_traffic"] = _attr(app, "usesCleartextTraffic") == "true"
            if merged["network_security_config"] is None:
                merged["network_security_config"] = bool(_attr(app, "networkSecurityConfig"))

        for perm in xml.findall("uses-permission"):
            name = (_attr(perm, "name") or "").split(".")[-1]
            if name in _DANGEROUS_PERMS:
                merged["dangerous_permissions"].add(name)

        if app is None:
            continue
        tagmap = {"activity": "activities", "activity-alias": "activities",
                  "service": "services", "receiver": "receivers",
                  "provider": "providers"}
        for tag, bucket in tagmap.items():
            for comp in app.findall(tag):
                name = _attr(comp, "name") or ""
                if not name or name in seen[bucket]:
                    continue
                exported, explicit = _is_exported(comp, tag.split("-")[0])
                if exported:
                    seen[bucket].add(name)
                    entry = {
                        "name": name,
                        "explicit_export": explicit,
                        "permission": _attr(comp, "permission"),
                        "has_intent_filter": bool(_intent_filters(comp)),
                    }
                    if tag == "provider":
                        entry["authorities"] = _attr(comp, "authorities")
                        entry["grant_uri_permissions"] = (
                            _attr(comp, "grantUriPermissions") == "true")
                    merged["exported"][bucket].append(entry)
                merged["deeplinks"].extend(_deeplinks_from(comp, name))

    if not parsed_any:
        return {"parsed": False, "reason": "no parsable manifest in bundle"}

    merged["dangerous_permissions"] = sorted(merged["dangerous_permissions"])
    # dedupe deeplinks
    uniq, keys = [], set()
    for d in merged["deeplinks"]:
        k = (d["scheme"], d["host"], d["path"])
        if k not in keys:
            keys.add(k)
            uniq.append(d)
    merged["deeplinks"] = uniq
    return merged


# --------------------------------------------------------------------------- #
# per-package mapping
# --------------------------------------------------------------------------- #

def map_package(pkg: str, downloaded: list[Path], workdir: Path,
                scan_timeout: int) -> dict:
    scan_dir = extract_bundles(downloaded, workdir / "_extracted")
    apk_paths = sorted(scan_dir.rglob("*.apk"))
    # also feed the originally-downloaded single apk(s) if apkeep gave .apk directly
    apk_paths += [f for f in downloaded if f.suffix.lower() == ".apk"]
    apk_paths = sorted(set(apk_paths))

    manifest = parse_manifest(apk_paths)
    strings = scan_strings(scan_dir)

    exported = manifest.get("exported", {}) if manifest.get("parsed") else {}
    counts = {
        "exported_activities": len(exported.get("activities", [])),
        "exported_services": len(exported.get("services", [])),
        "exported_receivers": len(exported.get("receivers", [])),
        "exported_providers": len(exported.get("providers", [])),
        "deeplinks": len(manifest.get("deeplinks", [])) if manifest.get("parsed") else 0,
        "api_endpoints": len(strings["api_endpoints"]),
        "graphql_endpoints": len(strings["graphql_endpoints"]),
        "hosts": len(strings["hosts"]),
        "firebase_rtdb": len(strings["firebase"]["rtdb"]),
    }
    return {
        "package": pkg,
        "manifest": manifest,
        "endpoints": {
            "hosts": strings["hosts"],
            "api": strings["api_endpoints"],
            "graphql": strings["graphql_endpoints"],
        },
        "firebase": strings["firebase"],
        "counts": counts,
        "mapped_at": datetime.now(timezone.utc).isoformat(),
    }


def already_mapped(results_path: Path) -> set[str]:
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
        # only a successful map counts as done; failures are retried
        if pkg and rec.get("counts") is not None:
            done.add(pkg)
    return done


def _write_status(fh, package: str, status: str) -> None:
    fh.write(json.dumps({
        "package": package,
        "status": status,
        "mapped_at": datetime.now(timezone.utc).isoformat(),
    }) + "\n")
    fh.flush()


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main() -> int:
    ap = argparse.ArgumentParser(
        description="apk-drill: APK attack-surface mapper (single machine).")
    ap.add_argument("packages", type=Path, help="Path to package list (.txt or .csv).")
    ap.add_argument("-o", "--output", type=Path, default=Path("surface_latest.jsonl"),
                    help="JSONL results file (default: surface_latest.jsonl).")
    ap.add_argument("--source", default="apk-pure", help="apkeep source (default: apk-pure).")
    ap.add_argument("--keep-files", action="store_true",
                    help="Do NOT delete downloaded/extracted files after each package.")
    ap.add_argument("--skip-mapped", action="store_true",
                    help="Resume: skip packages already mapped OK (failures retried).")
    ap.add_argument("--download-timeout", type=int, default=300)
    ap.add_argument("--scan-timeout", type=int, default=600)
    ap.add_argument("--workdir", type=Path, default=Path("._apk_surface_work"),
                    help="Scratch directory (default: ._apk_surface_work).")
    args = ap.parse_args()

    if shutil.which("apkeep") is None:
        log("FATAL: apkeep not found. Run ./install.sh or see README.md.")
        return 1
    if APK is None:
        log("NOTE: androguard not installed — manifest analysis (exported "
            "components, deeplinks) will be skipped. `pip install androguard` "
            "to enable it. String-derived surface still runs.")

    if not args.packages.exists():
        log(f"FATAL: package list not found: {args.packages}")
        return 1

    packages = read_packages(args.packages)
    if not packages:
        log("FATAL: no package names read from input.")
        return 1

    if args.skip_mapped:
        done = already_mapped(args.output)
        if done:
            before = len(packages)
            packages = [p for p in packages if p not in done]
            log(f"--skip-mapped: {before - len(packages)} already done, "
                f"{len(packages)} to go.")
    if not packages:
        log("Nothing to map. Exiting.")
        return 0

    log(f"Loaded {len(packages)} package(s). Scope reminder: authorized targets only.")
    args.workdir.mkdir(parents=True, exist_ok=True)

    stats = {"packages": 0, "mapped": 0, "download_failed": 0,
             "exported_total": 0, "deeplinks_total": 0, "api_total": 0}

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

                rec = map_package(pkg, downloaded, pkg_dir, args.scan_timeout)
                out_fh.write(json.dumps(rec) + "\n")
                out_fh.flush()
                stats["mapped"] += 1
                c = rec["counts"]
                exp = (c["exported_activities"] + c["exported_services"]
                       + c["exported_receivers"] + c["exported_providers"])
                stats["exported_total"] += exp
                stats["deeplinks_total"] += c["deeplinks"]
                stats["api_total"] += c["api_endpoints"]
                log(f"  exported={exp} (prov={c['exported_providers']}) "
                    f"deeplinks={c['deeplinks']} api={c['api_endpoints']} "
                    f"graphql={c['graphql_endpoints']} fb_rtdb={c['firebase_rtdb']}")
            except KeyboardInterrupt:
                log("Interrupted by user.")
                break
            except Exception as e:
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


if __name__ == "__main__":
    raise SystemExit(main())
