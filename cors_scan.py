#!/usr/bin/env python3
"""
cors_scan.py

apk-drill — CORS & Host-header misconfiguration scanner.

Off the per-host endpoint inventory, tests each in-scope URL for:
  * reflective CORS  — server echoes an attacker Origin into
    Access-Control-Allow-Origin, worse with Allow-Credentials:true (cross-site
    data theft for authenticated endpoints).
  * null-origin trust and naive suffix/prefix Origin matching.
  * Host / X-Forwarded-Host injection — attacker host reflected into a redirect
    or body (password-reset poisoning, cache poisoning).

Shares probe_authz's scope model: a URL is only touched if its host matches a
target's allow_hosts AND that target has active_testing_permitted:true. Sends
nothing without --live (default: dry-run plan). Read-only GETs.

Usage:
  cors_scan.py --endpoints-dir endpoints/ --config probe_targets.json
  cors_scan.py --endpoints-dir endpoints/ --config probe_targets.json --live -o cors.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from probe_authz import Target, load_config, HostThrottle, parse_path_line, log

ATTACKER = "evil-apkdrill.example.org"


def get_resp(url: str, extra_headers: dict[str, str], timeout: int) -> dict:
    headers = {"User-Agent": "apk-drill-cors/1.0", **extra_headers}
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(400).decode("utf-8", "replace")
            h = r.headers
            return {"status": r.status, "acao": h.get("Access-Control-Allow-Origin"),
                    "acac": h.get("Access-Control-Allow-Credentials"),
                    "location": h.get("Location"), "body": body}
    except urllib.error.HTTPError as e:
        h = e.headers
        return {"status": e.code, "acao": h.get("Access-Control-Allow-Origin") if h else None,
                "acac": h.get("Access-Control-Allow-Credentials") if h else None,
                "location": h.get("Location") if h else None, "body": ""}
    except Exception as e:
        return {"status": None, "error": type(e).__name__}


def classify_cors(sent_origin: str, acao: str | None, acac: str | None) -> tuple[str, str] | None:
    """Return (severity, note) or None."""
    if not acao:
        return None
    creds = (acac or "").lower() == "true"
    if acao == sent_origin:
        if creds:
            return "high", f"reflects attacker Origin {sent_origin} with Allow-Credentials:true (cross-site data theft)"
        return "medium", f"reflects attacker Origin {sent_origin} (no creds — data exposure if endpoint is unauthenticated)"
    if acao.lower() == "null" and sent_origin == "null":
        sev = "high" if creds else "medium"
        return sev, f"trusts Origin: null (creds={creds}) — reachable from sandboxed iframe"
    if acao == "*" and creds:
        return "low", "ACAO:* with Allow-Credentials:true (browsers reject, but a misconfig signal)"
    return None


def classify_host(reflected_where: str | None) -> tuple[str, str] | None:
    if reflected_where:
        return "medium", f"attacker Host reflected in {reflected_where} (host-header injection candidate)"
    return None


def cors_probes(host: str) -> list[tuple[str, str]]:
    return [("arbitrary", f"https://{ATTACKER}"),
            ("null", "null"),
            ("subdomain-suffix", f"https://{host}.{ATTACKER}"),
            ("sibling-prefix", f"https://{host}-{ATTACKER}")]


def scan_url(url: str, host: str, timeout: int) -> list[dict]:
    findings = []
    for label, origin in cors_probes(host):
        r = get_resp(url, {"Origin": origin}, timeout)
        if r.get("status") is None:
            continue
        verdict = classify_cors(origin, r.get("acao"), r.get("acac"))
        if verdict:
            findings.append({"url": url, "bug_class": "CORS_MISCONFIG", "probe": label,
                             "origin_sent": origin, "severity": verdict[0], "note": verdict[1],
                             "acao": r.get("acao"), "acac": r.get("acac")})
    # Host-header injection
    r = get_resp(url, {"X-Forwarded-Host": ATTACKER}, timeout)
    where = None
    if r.get("location") and ATTACKER in (r["location"] or ""):
        where = "Location header"
    elif r.get("body") and ATTACKER in (r["body"] or ""):
        where = "response body"
    hv = classify_host(where)
    if hv:
        findings.append({"url": url, "bug_class": "HOST_HEADER_INJECTION", "probe": "x-forwarded-host",
                         "severity": hv[0], "note": hv[1]})
    return findings


def build_plan(targets: list[Target], endpoints_dir: Path):
    plan, skipped = [], 0
    for f in sorted(p for p in endpoints_dir.iterdir() if p.is_file()):
        host = f.name
        tgt = next((t for t in targets if t.host_allowed(host) and t.active_testing_permitted), None)
        for raw in f.read_text(encoding="utf-8", errors="replace").splitlines():
            parsed = parse_path_line(raw)
            if not parsed:
                continue
            _m, path = parsed
            if tgt is None:
                skipped += 1
                continue
            plan.append((f"{tgt.scheme}://{host}{path}", host, tgt))
    return plan, skipped


def self_test() -> int:
    assert classify_cors("https://evil.x", "https://evil.x", "true")[0] == "high"
    assert classify_cors("https://evil.x", "https://evil.x", None)[0] == "medium"
    assert classify_cors("null", "null", "true")[0] == "high"
    assert classify_cors("https://evil.x", "https://api.legit.com", "true") is None
    assert classify_cors("https://evil.x", None, None) is None
    assert classify_host("Location header")[0] == "medium"
    assert classify_host(None) is None
    assert cors_probes("api.x.com")[0][1] == "https://evil-apkdrill.example.org"
    print("self-test OK")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="apk-drill CORS & Host-header scanner")
    ap.add_argument("--endpoints-dir", help="per-host inventory dir")
    ap.add_argument("--config", help="probe_authz targets config (scope)")
    ap.add_argument("-o", "--output", default="cors_findings.jsonl")
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--timeout", type=int, default=12)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    if not args.endpoints_dir or not args.config:
        ap.error("--endpoints-dir and --config required (or --self-test)")

    targets = load_config(Path(args.config))
    if not any(t.active_testing_permitted for t in targets):
        log("no target permits active testing — nothing to do.")
        return 0
    plan, skipped = build_plan(targets, Path(args.endpoints_dir))
    log(f"plan: {len(plan)} in-scope URL(s); {skipped} skipped (out of scope / no permission)")
    if not args.live:
        log("DRY-RUN (no requests sent). Re-run with --live.")
        for url, _h, tgt in plan[:40]:
            print(f"  [{tgt.program}] CORS+HostHeader probes -> {url}")
        return 0

    throttle, findings = HostThrottle(), 0
    with open(args.output, "a", encoding="utf-8") as out_f:
        for url, host, tgt in plan:
            throttle.wait(host, tgt.rps, tgt.jitter_ms)
            for res in scan_url(url, host, args.timeout):
                res.update(program=tgt.program, at=datetime.now(timezone.utc).isoformat())
                out_f.write(json.dumps(res) + "\n")
                out_f.flush()
                findings += 1
                log(f"  {res['severity'].upper():6s} {res['bug_class']} {res['probe']} {url}")
    log(f"done. findings={findings} -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
