#!/usr/bin/env python3
"""
surface_report.py

Turn surface_latest.jsonl (from apk_surface_map.py) into a ranked, human-readable
Markdown report: which apps expose the most testable surface, and exactly which
leads to chase first. Ranking favours the surface that pays and dups least —
exported content providers, deeplinks, GraphQL, Firebase RTDB — over raw host
counts.

Usage:
    python3 surface_report.py surface_latest.jsonl -o surface_report.md
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


# weights reflect "bug value per lead, and how rarely it dups"
_SCORE = {
    "exported_providers": 6,    # content-provider SQLi / file read / IDOR
    "exported_receivers": 2,
    "exported_services": 2,
    "exported_activities": 1,   # cheap, but intent redirection / auth bypass
    "deeplinks": 3,             # open redirect / webview / deeplink ATO
    "graphql_endpoints": 4,     # introspection / BOLA on graphql
    "firebase_rtdb": 5,         # world-readable/writable RTDB
    "api_endpoints": 1,         # BOLA/IDOR hunting ground (volume-discounted)
}


def load(path: Path):
    recs, statuses = [], {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if r.get("counts") is not None:
            recs.append(r)
        elif r.get("status"):
            statuses[r["status"]] = statuses.get(r["status"], 0) + 1
    return recs, statuses


def score(rec: dict) -> int:
    c = rec.get("counts", {})
    s = 0
    for key, w in _SCORE.items():
        n = c.get(key, 0)
        if key == "api_endpoints":  # diminishing returns on sheer count
            n = min(n, 20)
        s += w * n
    return s


def fmt_pkg(rec: dict) -> str:
    pkg = rec.get("package", "?")
    c = rec.get("counts", {})
    man = rec.get("manifest", {})
    out = [f"### `{pkg}`  — score {score(rec)}\n"]

    posture = []
    if man.get("parsed"):
        if man.get("debuggable"):
            posture.append("**debuggable=true**")
        if man.get("uses_cleartext_traffic"):
            posture.append("cleartextTraffic=true")
        if man.get("allow_backup"):
            posture.append("allowBackup=true")
        if man.get("target_sdk"):
            posture.append(f"targetSdk={man.get('target_sdk')}")
        if man.get("dangerous_permissions"):
            posture.append("perms:" + ",".join(man["dangerous_permissions"][:6]))
    else:
        posture.append(f"_manifest not parsed ({man.get('reason','?')})_")
    if posture:
        out.append("- posture: " + " · ".join(posture))

    exp = man.get("exported", {}) if man.get("parsed") else {}
    provs = exp.get("providers", [])
    if provs:
        out.append(f"- **exported providers ({len(provs)})** — content-provider "
                   "SQLi / file read / IDOR:")
        for p in provs[:10]:
            gu = " grantUri" if p.get("grant_uri_permissions") else ""
            perm = f" perm={p['permission']}" if p.get("permission") else " (no permission)"
            out.append(f"    - {p['name']}  auth={p.get('authorities')}{gu}{perm}")
    for kind in ("services", "receivers", "activities"):
        items = exp.get(kind, [])
        if items:
            noperm = [e for e in items if not e.get("permission")]
            out.append(f"- exported {kind}: {len(items)} "
                       f"({len(noperm)} without a permission guard)")

    dls = man.get("deeplinks", []) if man.get("parsed") else []
    if dls:
        out.append(f"- **deeplinks ({len(dls)})**:")
        for d in dls[:12]:
            al = " [App Link/autoVerify]" if d.get("app_link") else ""
            loc = "://".join(x for x in (d.get("scheme"), d.get("host") or "") if x)
            out.append(f"    - {loc}{d.get('path') or ''}  → {d['activity']}{al}")

    ep = rec.get("endpoints", {})
    if ep.get("graphql"):
        out.append(f"- **GraphQL ({len(ep['graphql'])})**: " +
                   ", ".join(ep["graphql"][:6]))
    fb = rec.get("firebase", {})
    if fb.get("rtdb"):
        out.append(f"- **Firebase RTDB**: " + ", ".join(fb["rtdb"]) +
                   "  → test `<url>/.json` for open read/write")
    if fb.get("buckets"):
        out.append("- Firebase buckets: " + ", ".join(fb["buckets"][:6]))
    if ep.get("api"):
        out.append(f"- API endpoints ({c.get('api_endpoints',0)}) — BOLA/IDOR "
                   "hunting ground; top:")
        for u in ep["api"][:12]:
            out.append(f"    - {u}")
    hosts = ep.get("hosts", {})
    if hosts:
        top = ", ".join(f"{h}({n})" for h, n in list(hosts.items())[:10])
        out.append(f"- top hosts: {top}")
    out.append("")
    return "\n".join(out)


def build(recs: list[dict], statuses: dict) -> str:
    recs = sorted(recs, key=score, reverse=True)
    lines = ["# APK Attack-Surface Report\n"]
    lines.append(f"_{len(recs)} app(s) mapped. Ranked by testable surface "
                 "(exported providers / deeplinks / GraphQL / Firebase weigh "
                 "highest — they pay and dup least)._\n")
    if statuses:
        lines.append("Scan outcomes: " +
                     ", ".join(f"{k}={v}" for k, v in sorted(statuses.items())) + "\n")

    lines.append("## Priority queue\n")
    lines.append("| # | Package | Score | Exp. providers | Deeplinks | GraphQL | FB RTDB | API |")
    lines.append("|---|---|--:|--:|--:|--:|--:|--:|")
    for i, r in enumerate(recs, 1):
        c = r["counts"]
        lines.append(
            f"| {i} | `{r['package']}` | {score(r)} | "
            f"{c['exported_providers']} | {c['deeplinks']} | "
            f"{c['graphql_endpoints']} | {c['firebase_rtdb']} | {c['api_endpoints']} |")
    lines.append("")

    lines.append("## How to work this list\n")
    lines.append("- **Exported providers** → pull records / read files via the "
                 "`content://<authority>` URI (SQLi in selection, path traversal "
                 "in `openFile`). Highest bug-value, lowest dup rate.")
    lines.append("- **Deeplinks** → feed attacker-controlled URLs; look for "
                 "WebView loads, open redirect, and auth/token handling in the "
                 "target activity.")
    lines.append("- **GraphQL** → try introspection, then BOLA/field-level authz.")
    lines.append("- **Firebase RTDB** → append `/.json` and test unauthenticated "
                 "read/write.")
    lines.append("- **API endpoints** → the real money: enumerate object IDs for "
                 "BOLA/IDOR and mass-assignment on mobile-only params.\n")
    lines.append("> Surface is mapped passively. Act on these only within the "
                 "program's scope and rules.\n")

    lines.append("## Per-app detail\n")
    for r in recs:
        lines.append(fmt_pkg(r))
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Rank apk-drill surface-map results.")
    ap.add_argument("results", type=Path, help="surface_latest.jsonl")
    ap.add_argument("-o", "--output", type=Path, default=Path("surface_report.md"))
    args = ap.parse_args()
    if not args.results.exists():
        print(f"not found: {args.results}")
        return 1
    recs, statuses = load(args.results)
    args.output.write_text(build(recs, statuses), encoding="utf-8")
    print(f"Wrote {args.output} — {len(recs)} app(s) ranked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
