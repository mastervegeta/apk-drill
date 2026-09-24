#!/usr/bin/env python3
"""
js_pull.py

Give it a site, it collects that site's JavaScript and saves each file to a
folder — ready to hand to an LLM (or grep) for endpoints, secrets, and logic.

    python3 scripts/js_pull.py site.com
    python3 scripts/js_pull.py https://site.com --out js_out --crawl 15

What it does:
  1. fetch the page(s),
  2. pull every <script src=...> (external JS) and every inline <script>,
  3. download each unique JS file,
  4. save them under <out>/<host>/ with a manifest.

--crawl N also follows up to N same-site HTML links to discover more JS (SPAs
often load scripts from sub-pages). Default is the single URL you gave.

Pure stdlib. Optional: pip install jsbeautifier for readable output (--beautify).

SCOPE / AUTHORIZATION — only pull sites you're authorized to test (in bug-bounty
scope, or your own). Fetching JS is light, but stay within the program's rules.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
_INLINE = re.compile(r'<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>', re.I | re.S)
_HREF = re.compile(r'<a[^>]+href=["\']([^"\']+)["\']', re.I)

try:
    import jsbeautifier  # optional
except ImportError:
    jsbeautifier = None


def normalize(site: str) -> str:
    if not site.startswith(("http://", "https://")):
        site = "https://" + site
    return site


def get(url: str, timeout: int = 30) -> tuple[str, bytes]:
    """Return (final_url, body). Body decoded as text elsewhere."""
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.geturl(), r.read()


def safe_name(url: str, idx: int) -> str:
    """A readable, unique filename for a JS URL."""
    p = urllib.parse.urlparse(url)
    base = (p.path.rsplit("/", 1)[-1] or "index")
    if not base.endswith(".js"):
        base += ".js"
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)[:80]
    # prefix with a short hash of the full URL so same-named files don't collide
    h = hashlib.sha1(url.encode()).hexdigest()[:8]
    return f"{idx:03d}_{h}_{base}"


def beautify(text: str) -> str:
    if jsbeautifier:
        try:
            return jsbeautifier.beautify(text)
        except Exception:
            pass
    return text


def main() -> int:
    ap = argparse.ArgumentParser(description="Collect a site's JavaScript for analysis.")
    ap.add_argument("site", help="site.com or https://site.com")
    ap.add_argument("--out", type=Path, default=Path("js_out"), help="Output dir (default js_out).")
    ap.add_argument("--crawl", type=int, default=0,
                    help="Also follow up to N same-site HTML links to find more JS.")
    ap.add_argument("--beautify", action="store_true",
                    help="Prettify JS (needs jsbeautifier).")
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--max-bytes", type=int, default=8_000_000,
                    help="Skip JS files larger than this (default 8MB).")
    args = ap.parse_args()

    start = normalize(args.site)
    host = urllib.parse.urlparse(start).netloc
    outdir = args.out / host
    outdir.mkdir(parents=True, exist_ok=True)

    if args.beautify and not jsbeautifier:
        print("NOTE: --beautify given but jsbeautifier not installed; saving raw JS.",
              file=sys.stderr)

    pages = [start]
    visited_pages: set[str] = set()
    js_urls: list[str] = []
    seen_js: set[str] = set()
    inline_blobs: list[tuple[str, str]] = []  # (page, code)

    while pages and len(visited_pages) <= args.crawl:
        page = pages.pop(0)
        if page in visited_pages:
            continue
        visited_pages.add(page)
        try:
            final, body = get(page, args.timeout)
            html = body.decode("utf-8", "replace")
        except Exception as e:
            print(f"  page FAIL {page}: {e!r}", file=sys.stderr)
            continue

        for src in _SCRIPT_SRC.findall(html):
            ju = urllib.parse.urljoin(final, src)
            if ju not in seen_js:
                seen_js.add(ju)
                js_urls.append(ju)
        for code in _INLINE.findall(html):
            if code.strip():
                inline_blobs.append((final, code))

        if len(visited_pages) <= args.crawl:  # discover more same-host pages
            for href in _HREF.findall(html):
                nu = urllib.parse.urljoin(final, href)
                if urllib.parse.urlparse(nu).netloc == host and nu.split("#")[0] not in visited_pages:
                    if len(visited_pages) + len(pages) <= args.crawl:
                        pages.append(nu.split("#")[0])

    manifest = []
    saved = 0
    for i, ju in enumerate(js_urls, 1):
        try:
            _final, body = get(ju, args.timeout)
        except Exception as e:
            print(f"  js FAIL {ju}: {e!r}", file=sys.stderr)
            continue
        if len(body) > args.max_bytes:
            print(f"  skip (too big {len(body)}B) {ju}", file=sys.stderr)
            continue
        text = body.decode("utf-8", "replace")
        if args.beautify:
            text = beautify(text)
        fn = safe_name(ju, i)
        (outdir / fn).write_text(text, encoding="utf-8")
        manifest.append({"url": ju, "file": fn, "bytes": len(body),
                         "sha1": hashlib.sha1(body).hexdigest()})
        saved += 1

    for j, (page, code) in enumerate(inline_blobs, 1):
        if args.beautify:
            code = beautify(code)
        fn = f"inline_{j:03d}.js"
        (outdir / fn).write_text(f"// inline from {page}\n{code}", encoding="utf-8")
        manifest.append({"url": f"{page}#inline{j}", "file": fn,
                         "bytes": len(code), "sha1": hashlib.sha1(code.encode()).hexdigest()})

    (outdir / "manifest.jsonl").write_text(
        "\n".join(json.dumps(m) for m in manifest) + "\n", encoding="utf-8")

    print(f"\n{host}: {saved} external JS + {len(inline_blobs)} inline "
          f"from {len(visited_pages)} page(s) -> {outdir}/")
    print(f"manifest: {outdir/'manifest.jsonl'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
