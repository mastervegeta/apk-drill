#!/usr/bin/env python3
"""
nday_watch.py

The n-day first-responder (passive). New exploits/CVEs drop constantly; this asks
"do any apply to targets we already have?" by matching freshly-published,
actively-exploited vulns against the tech fingerprints in each target's assets.md.

    python3 scripts/nday_watch.py --recon-repo ~/bug-bounty-recon --days 30

Sources (public JSON, no target traffic, no keys):
  - CISA KEV (known *exploited* vulns)  — high-signal, small, "being used now".
  - NVD recent CVEs (last N days)       — broader, CVSS-scored.

Matches each vuln's vendor/product against the union of tech tokens parsed from
`companies/*/assets.md` "Tech stack" sections (populated by build_dossier's
httpx -td). Writes matches to <recon-repo>/nday/nday-<date>.md.

This is the PASSIVE tier — pure applicability triage. The ACTIVE tier (run new
nuclei templates against live_hosts) is opt-in and policy-gated; see --note.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = ("https://services.nvd.nist.gov/rest/json/cves/2.0"
           "?pubStartDate={start}&pubEndDate={end}&resultsPerPage=2000")

# tech tokens too generic to match on (avoid false "everything runs HTTP" hits)
STOP = {"http", "https", "hsts", "http/3", "http/2", "html", "css", "json", "rest",
        "api", "node.js", "nginx", "apache", "cloudflare", "amazon web services",
        "amazon cloudfront", "amazon s3", "aws", "google cloud", "envoy", "ssl",
        "tls", "cdn", "webpack", "react", "jquery", "hcaptcha", "recaptcha", "and",
        "google analytics", "google maps", "linkedin ads", "modernizr"}


def fetch_json(url: str, timeout: int = 60):
    req = urllib.request.Request(url, headers={"User-Agent": "nday-watch/1.0"})
    return json.loads(urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", "replace"))


def target_tech(recon_repo: Path) -> dict[str, set]:
    """{tech_token(lower): {slugs...}} parsed from each assets.md Tech stack section."""
    idx: dict[str, set] = {}
    for a in (recon_repo / "companies").glob("*/assets.md"):
        slug = a.parent.name
        text = a.read_text(encoding="utf-8", errors="replace")
        # tech stack bullets + any comma/·-separated tech names anywhere
        for line in text.splitlines():
            if line.strip().startswith("-"):
                for tok in re.split(r"[,·|]", line.lstrip("- ").strip()):
                    tok = re.sub(r"[:0-9.].*$", "", tok).strip().lower()  # drop versions
                    if len(tok) >= 3 and tok not in STOP:
                        idx.setdefault(tok, set()).add(slug)
    return idx


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def match_vuln(vendor: str, product: str, tech: dict) -> set:
    """Return slugs whose tech matches this vuln's vendor/product."""
    hay = f"{norm(vendor)} {norm(product)}"
    hits: set = set()
    for tok, slugs in tech.items():
        # word-boundary-ish containment either direction
        if re.search(rf"\b{re.escape(tok)}\b", hay) or (len(tok) >= 5 and tok in hay):
            hits |= slugs
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(description="Match new/exploited CVEs to target tech fingerprints.")
    ap.add_argument("--recon-repo", type=Path, required=True)
    ap.add_argument("--days", type=int, default=30, help="how recent (dateAdded/published).")
    ap.add_argument("--nvd", action="store_true", help="also pull NVD recent (slower).")
    ap.add_argument("--note", action="store_true", help="print the active-tier note and exit.")
    args = ap.parse_args()

    if args.note:
        print("ACTIVE tier (opt-in, policy-gated): run newly-added nuclei templates against\n"
              "  <recon>/companies/<slug> live_hosts, e.g.:\n"
              "    nuclei -l live_hosts.txt -nt -tags cve -rl 20 -o nday-active.txt\n"
              "  Only on programs whose policy permits active scanning.")
        return 0

    tech = target_tech(args.recon_repo)
    if not tech:
        print("No tech fingerprints found (run build_dossier first so assets.md has a Tech stack).",
              file=sys.stderr)
        return 0
    print(f"  {len(tech)} distinct tech token(s) across "
          f"{len({s for v in tech.values() for s in v})} target(s)")

    cutoff = date.today() - timedelta(days=args.days)
    matches = []  # (cve, product, slugs, dateAdded, why, source)

    # --- CISA KEV ---
    try:
        kev = fetch_json(KEV_URL)
        for v in kev.get("vulnerabilities", []):
            try:
                added = date.fromisoformat(v.get("dateAdded", ""))
            except Exception:
                added = None
            if added and added < cutoff:
                continue
            hits = match_vuln(v.get("vendorProject", ""), v.get("product", ""), tech)
            if hits:
                matches.append((v["cveID"], f"{v.get('vendorProject','')} {v.get('product','')}".strip(),
                                sorted(hits), v.get("dateAdded", ""),
                                v.get("vulnerabilityName", ""), "KEV(exploited)"))
    except Exception as e:
        print(f"  KEV fetch failed: {e!r}", file=sys.stderr)

    # --- NVD recent (optional) ---
    if args.nvd:
        try:
            now = datetime.now(timezone.utc)
            url = NVD_URL.format(
                start=(now - timedelta(days=args.days)).strftime("%Y-%m-%dT00:00:00.000"),
                end=now.strftime("%Y-%m-%dT23:59:59.000"))
            nvd = fetch_json(url, timeout=90)
            for item in nvd.get("vulnerabilities", []):
                c = item.get("cve", {})
                cid = c.get("id", "")
                # product from CPE configs (best-effort)
                prods = set()
                for conf in c.get("configurations", []):
                    for node in conf.get("nodes", []):
                        for m in node.get("cpeMatch", []):
                            parts = m.get("criteria", "").split(":")
                            if len(parts) > 4:
                                prods.add(parts[4].replace("_", " "))
                for p in prods:
                    hits = match_vuln("", p, tech)
                    if hits:
                        matches.append((cid, p, sorted(hits),
                                        c.get("published", "")[:10], "(NVD)", "NVD"))
                        break
        except Exception as e:
            print(f"  NVD fetch failed: {e!r}", file=sys.stderr)

    # dedupe by (cve, tuple(slugs))
    seen, uniq = set(), []
    for m in sorted(matches, key=lambda x: x[3], reverse=True):
        k = (m[0], tuple(m[2]))
        if k not in seen:
            seen.add(k); uniq.append(m)

    print(f"  matches: {len(uniq)}")
    if not uniq:
        return 0

    outdir = args.recon_repo / "nday"
    outdir.mkdir(exist_ok=True)
    out = outdir / f"nday-{date.today().isoformat()}.md"
    lines = [f"# n-day opportunities — {date.today().isoformat()}",
             f"\nNew/exploited CVEs (last {args.days}d) matching our targets' tech fingerprints. "
             "Confirm the target actually runs the affected version, in scope, before testing.\n",
             "| CVE | affected product | our target(s) | added | note | source |",
             "|---|---|---|---|---|---|"]
    for cid, prod, slugs, added, why, src in uniq:
        tgt = ", ".join(f"`{s}`" for s in slugs)
        lines.append(f"| [{cid}](https://nvd.nist.gov/vuln/detail/{cid}) | {prod} | {tgt} | {added} | {why[:60]} | {src} |")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {out} — {len(uniq)} opportunity(ies).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
