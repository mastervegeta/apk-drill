#!/usr/bin/env python3
"""
endpoints_from_surface.py

apk-drill — recon -> endpoint inventory.

Turns apk_surface_map JSONL into the canonical per-host inventory that
probe_authz.py consumes: one file per host (filename == host), one path per
line, sorted + de-duplicated. Runs additively — re-running merges new paths
into existing host files without losing what earlier recon found. See
docs/ENDPOINT-INVENTORY-RULE.md.

Any recon source (JS pull, mitmproxy log, crawler) can feed the same layout;
this script is just the APK-surface feeder.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

# Reuse the prober's URL filter + third-party denylist so the inventory matches
# exactly what the prober would consider.
from probe_authz import is_concrete_url, THIRD_PARTY_DENY


def is_third_party(host: str) -> bool:
    host = host.lower()
    return any(host == d or host.endswith("." + d) for d in THIRD_PARTY_DENY)


def merge_paths(host_file: Path, new_paths: set[str]) -> int:
    existing: set[str] = set()
    if host_file.exists():
        for line in host_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                existing.add(line)
    before = len(existing)
    existing |= new_paths
    host_file.write_text("\n".join(sorted(existing)) + "\n", encoding="utf-8")
    return len(existing) - before


def main() -> int:
    ap = argparse.ArgumentParser(description="apk-drill: surface JSONL -> per-host endpoint inventory")
    ap.add_argument("surface", help="apk_surface_map JSONL (one or many package records)")
    ap.add_argument("-o", "--out-dir", required=True, help="inventory dir (created if missing)")
    ap.add_argument("--keep-third-party", action="store_true",
                    help="also write third-party/SDK hosts (default: skip them)")
    args = ap.parse_args()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    by_host: dict[str, set[str]] = {}
    for line in Path(args.surface).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        ep = rec.get("endpoints", {}) or {}
        for key in ("api", "graphql"):
            for u in ep.get(key, []) or []:
                if not (isinstance(u, str) and is_concrete_url(u)):
                    continue
                p = urlparse(u)
                host = p.netloc.lower()
                if not args.keep_third_party and is_third_party(host):
                    continue
                path = p.path or "/"
                by_host.setdefault(host, set()).add(path)

    total_added = 0
    for host, paths in sorted(by_host.items()):
        added = merge_paths(out / host, paths)
        total_added += added
        print(f"  {host}: +{added} new ({len(paths)} seen) -> {out / host}")
    print(f"hosts={len(by_host)} new_paths={total_added} dir={out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
