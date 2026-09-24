#!/usr/bin/env python3
"""
play_whatsnew.py

Fetch the "What's new" release notes for a Google Play app from its public web
page (the metadata API no longer exposes this field). Pure stdlib, no download,
no disk — meant to be run only against the handful of apps that changed on a
given day, so the vague-but-real changelog lands right in the daily report.

    python3 scripts/play_whatsnew.py com.wolt.android com.whatsapp

As a library:
    from play_whatsnew import fetch_whatsnew
    rec = fetch_whatsnew("com.wolt.android", expected_epoch=1789643120)
    # -> {"whatsnew": "...", "date": "Sep 17, 2026", "epoch": 1789643120} or None

Honest limits: the text is usually generic ("bug fixes and improvements"). It's
a triage hint, not the changed code — that only comes from an APK diff.
"""

from __future__ import annotations

import re
import sys
import urllib.request

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
# The "What's new" string sits immediately before the update stamp in the page's
# embedded data:  "<whatsnew>"]],[["<Mon DD, YYYY>",[<epoch>
_PAT = re.compile(
    r'"((?:[^"\\]|\\.){1,6000})"\]\],\[\["([A-Z][a-z]{2} \d{1,2}, \d{4})",\[(\d{10})')


def _clean(s: str) -> str:
    """Decode \\uXXXX + common escapes, strip HTML, collapse spaces."""
    s = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s)
    for a, b in (("\\/", "/"), ('\\"', '"'), ("\\n", "\n"), ("\\t", " "), ("\\r", "")):
        s = s.replace(a, b)
    s = re.sub(r"<[^>]+>", " ", s)
    return re.sub(r"[ \t]+", " ", s).strip()


def fetch_whatsnew(pkg: str, lang: str = "en", country: str = "us",
                   timeout: int = 30, expected_epoch: int | None = None) -> dict | None:
    """Return {whatsnew, date, epoch} for pkg, or None if not found.

    If expected_epoch is given, prefer the match whose stamp equals it (guards
    against picking up an unrelated date/epoch pair elsewhere on the page).
    """
    url = f"https://play.google.com/store/apps/details?id={pkg}&hl={lang}&gl={country}"
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    html = urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", "replace")
    best = None
    for m in _PAT.finditer(html):
        rec = {"whatsnew": _clean(m.group(1)), "date": m.group(2), "epoch": int(m.group(3))}
        if expected_epoch and rec["epoch"] == expected_epoch:
            return rec
        if best is None:
            best = rec
    return best


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: play_whatsnew.py <package> [package ...]", file=sys.stderr)
        return 2
    for pkg in argv:
        try:
            rec = fetch_whatsnew(pkg)
        except Exception as e:
            print(f"{pkg}: ERROR {e!r}")
            continue
        if not rec:
            print(f"{pkg}: (no What's new found)")
            continue
        print(f"\n=== {pkg} — updated {rec['date']} ===")
        print(rec["whatsnew"] or "(empty)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
