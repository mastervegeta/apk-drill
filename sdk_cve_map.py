#!/usr/bin/env python3
"""
sdk_cve_map.py

apk-drill — bundled-SDK -> known-CVE mapper (static, offline-safe).

Reads exact dependency versions straight out of an APK: Gradle drops a
`META-INF/<group>_<artifact>.version` file per AndroidX / Google / many 3rd-party
libraries, whose contents are the precise version string. Those map cleanly to
Maven coordinates, which OSV.dev resolves to known vulnerabilities.

No traffic to the target — it reads the .apk/.xapk zip locally and (unless
--offline) queries the public OSV.dev API for CVEs. Runs across a whole corpus.

Usage:
  sdk_cve_map.py app.apk
  sdk_cve_map.py --dir /path/of/apks -o sdk_cve.jsonl
  sdk_cve_map.py app.xapk --offline      # just list components + versions
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
import zipfile
from pathlib import Path

OSV_BATCH = "https://api.osv.dev/v1/querybatch"


def coords_from_apk(apk_path: Path) -> dict[str, str]:
    """Return {maven_coord: version} from META-INF/*.version entries.
    Handles .xapk (zip of apks) by recursing into inner .apk members."""
    coords: dict[str, str] = {}
    try:
        zf = zipfile.ZipFile(apk_path)
    except zipfile.BadZipFile:
        return coords
    with zf:
        inner_apks = [n for n in zf.namelist() if n.lower().endswith(".apk")]
        if inner_apks and not any(n.startswith("META-INF/") and n.endswith(".version")
                                  for n in zf.namelist()):
            # xapk / apks bundle: recurse into inner base apk(s)
            import io
            for n in inner_apks:
                try:
                    data = zf.read(n)
                    for c, v in _coords_from_zip(zipfile.ZipFile(io.BytesIO(data))).items():
                        coords.setdefault(c, v)
                except Exception:
                    continue
            return coords
        coords.update(_coords_from_zip(zf))
    return coords


def _coords_from_zip(zf: zipfile.ZipFile) -> dict[str, str]:
    out: dict[str, str] = {}
    for name in zf.namelist():
        if not (name.startswith("META-INF/") and name.endswith(".version")):
            continue
        stem = name[len("META-INF/"):-len(".version")]
        if "_" not in stem:
            continue
        group, artifact = stem.rsplit("_", 1)  # androidx.core_core -> androidx.core:core
        try:
            version = zf.read(name).decode("utf-8", "replace").strip()
        except Exception:
            continue
        if version:
            out[f"{group}:{artifact}"] = version
    return out


def query_osv(cv: list[tuple[str, str]], timeout: int = 30) -> dict[str, list[dict]]:
    """Query OSV.dev querybatch for Maven coord+version -> list of vuln stubs."""
    if not cv:
        return {}
    body = {"queries": [{"package": {"ecosystem": "Maven", "name": name}, "version": ver}
                        for name, ver in cv]}
    req = urllib.request.Request(OSV_BATCH, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        res = json.loads(r.read())
    out: dict[str, list[dict]] = {}
    for (name, ver), entry in zip(cv, res.get("results", [])):
        vulns = entry.get("vulns") or []
        if vulns:
            out[f"{name}@{ver}"] = vulns
    return out


def assemble(apk: str, coords: dict[str, str], osv: dict[str, list[dict]]) -> list[dict]:
    findings = []
    for coord, ver in sorted(coords.items()):
        vulns = osv.get(f"{coord}@{ver}")
        if not vulns:
            continue
        ids = sorted({v.get("id", "?") for v in vulns})
        findings.append({"apk": apk, "component": coord, "version": ver,
                         "vuln_count": len(ids), "ids": ids,
                         "bug_class": "KNOWN_VULN_COMPONENT"})
    return findings


def process(apk_path: Path, offline: bool) -> tuple[dict[str, str], list[dict]]:
    coords = coords_from_apk(apk_path)
    if offline or not coords:
        return coords, []
    osv = query_osv(list(coords.items()))
    return coords, assemble(apk_path.name, coords, osv)


def self_test() -> int:
    import io
    # Build an in-memory apk with two .version files, verify coord parsing.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("META-INF/androidx.core_core.version", "1.4.1\n")
        z.writestr("META-INF/com.squareup.okhttp3_okhttp.version", "3.12.0")
        z.writestr("classes.dex", b"\x00")
    coords = _coords_from_zip(zipfile.ZipFile(io.BytesIO(buf.getvalue())))
    assert coords == {"androidx.core:core": "1.4.1", "com.squareup.okhttp3:okhttp": "3.12.0"}, coords
    fake_osv = {"com.squareup.okhttp3:okhttp@3.12.0": [{"id": "GHSA-xxxx"}, {"id": "CVE-2021-0341"}]}
    fnd = assemble("t.apk", coords, fake_osv)
    assert len(fnd) == 1 and fnd[0]["component"] == "com.squareup.okhttp3:okhttp"
    assert fnd[0]["ids"] == ["CVE-2021-0341", "GHSA-xxxx"], fnd[0]["ids"]
    print("self-test OK")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="apk-drill bundled-SDK CVE mapper")
    ap.add_argument("apk", nargs="?", help=".apk or .xapk file")
    ap.add_argument("--dir", help="directory of apk/xapk files (recursive)")
    ap.add_argument("-o", "--output", help="JSONL findings file")
    ap.add_argument("--offline", action="store_true", help="list components only, no OSV query")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()

    apks: list[Path] = []
    if args.apk:
        apks.append(Path(args.apk))
    if args.dir:
        apks += [p for p in Path(args.dir).rglob("*") if p.suffix.lower() in (".apk", ".xapk")]
    if not apks:
        ap.error("provide an apk/xapk, --dir, or --self-test")

    out_f = open(args.output, "a", encoding="utf-8") if args.output else None
    total = 0
    for apk in apks:
        coords, findings = process(apk, args.offline)
        print(f"== {apk.name}: {len(coords)} components, {len(findings)} vulnerable ==")
        for f in findings:
            print(f"  [!] {f['component']} {f['version']}  ->  {f['vuln_count']} vuln(s): {', '.join(f['ids'][:6])}")
            if out_f:
                out_f.write(json.dumps(f) + "\n")
            total += 1
        if args.offline:
            for c, v in sorted(coords.items()):
                print(f"      {c} {v}")
    if out_f:
        out_f.close()
    print(f"total vulnerable components: {total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
