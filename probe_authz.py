#!/usr/bin/env python3
"""
probe_authz.py

apk-drill — authorization-differential endpoint prober.

Replays each IN-SCOPE endpoint under up to three caller identities —
none / A / B — and diffs the responses to surface the top mobile bug classes:

  * MISSING_AUTH  — endpoint returns data-shaped 2xx with NO credentials.
  * BROKEN_AUTHZ  — B reads a resource scoped to A (IDOR candidate; needs a
                    human to confirm object ownership).

Two input modes:
  1. --endpoints-dir DIR : the canonical endpoint inventory recon produces —
       one file per host (filename == host), one path per line. See
       docs/ENDPOINT-INVENTORY-RULE.md.
  2. a surface_map JSONL : harvest concrete URLs straight from apk_surface_map.

Read-only by design; sends NOTHING without --live.

SCOPE / AUTHORIZATION  (read before every run)
----------------------------------------------
Run only against programs whose policy permits active/dynamic testing, and only
against hosts listed in a target's allow_hosts. Credentials must come from
accounts YOU created for testing. Guard rails enforced here:
  * --live required to send anything (default: dry-run plan).
  * a target must declare "active_testing_permitted": true or it is skipped.
  * host must match a target's allow_hosts glob, else skipped (and a built-in
    third-party denylist blocks shared infra even if broadly allowlisted).
  * GET/HEAD only, unless a target opts into more AND you pass --allow-mutating.
  * credential VALUES come from environment variables named in the config,
    never the CLI or the config file, and are never written to output.
  * per-host rate limit + jitter; response bodies captured only up to --max-body.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

UA = "apk-drill-authz/1.1"

THIRD_PARTY_DENY = (
    "googleapis.com", "gstatic.com", "google.com", "googlesource.com",
    "crashlytics.com", "firebaseio.com", "firebase.com", "doubleclick.net",
    "facebook.com", "fbcdn.net", "amazonaws.com", "cloudfront.net",
    "cloudflare.com", "sentry.io", "bugsnag.com", "appsflyer.com",
    "adjust.com", "branch.io", "onesignal.com", "mixpanel.com",
    "segment.com", "newrelic.com", "nr-data.net", "braze.com", "onetrust.io",
    "gvt1.com", "schemas.android.com", "w3.org", "opensource.org",
    "apache.org", "github.com", "githubusercontent.com",
)

TEMPLATE_MARKERS = ("%s", "%d", "%@", "{", "}", "<", ">", " ", "\\", "$")
_ID_SEG_RE = re.compile(r"/(\d{2,}|[0-9a-fA-F]{8}-[0-9a-fA-F\-]{8,}|[0-9a-fA-F]{16,})(?:/|$)")
_LOGIN_HINT_RE = re.compile(r"(?i)\b(log ?in|sign ?in|password|authenticate|unauthori[sz]ed|forbidden|access denied)\b")
_HTTP_VERBS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}


def log(msg: str) -> None:
    print(f"[{datetime.now(timezone.utc):%H:%M:%S}] {msg}", flush=True)


# --------------------------------------------------------------------------- #
# Config: identities are lists of credential injections (header / query / cookie)
# --------------------------------------------------------------------------- #
@dataclass
class Injection:
    where: str            # "header" | "query" | "cookie"
    name: str
    env: str = ""         # env var holding the secret value (preferred)
    value: str = ""       # static non-secret value (e.g. a client-id)
    prefix: str = ""      # e.g. "Bearer " or "Basic "

    def resolve(self) -> str | None:
        raw = os.environ.get(self.env) if self.env else self.value
        if not raw:
            return None
        return self.prefix + raw


@dataclass
class Target:
    program: str
    active_testing_permitted: bool
    allow_hosts: list[str]
    methods: list[str] = field(default_factory=lambda: ["GET"])
    identities: dict[str, list[Injection]] = field(default_factory=dict)
    scheme: str = "https"
    rps: float = 1.0
    jitter_ms: int = 400

    def host_allowed(self, host: str) -> bool:
        host = host.lower()
        if any(host == d or host.endswith("." + d) for d in THIRD_PARTY_DENY):
            return False
        return any(fnmatch.fnmatch(host, pat.lower()) for pat in self.allow_hosts)


def load_config(path: Path) -> list[Target]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    targets: list[Target] = []
    for t in raw.get("targets", []):
        ids: dict[str, list[Injection]] = {}
        for name, injs in (t.get("identities") or {}).items():
            ids[name] = [Injection(where=i.get("where", "header"), name=i["name"],
                                   env=i.get("env", ""), value=i.get("value", ""),
                                   prefix=i.get("prefix", "")) for i in injs]
        targets.append(Target(
            program=t["program"],
            active_testing_permitted=bool(t.get("active_testing_permitted", False)),
            allow_hosts=list(t.get("allow_hosts") or []),
            methods=[m.upper() for m in (t.get("methods") or ["GET"])],
            identities=ids,
            scheme=t.get("scheme", "https"),
            rps=float(t.get("rate", {}).get("rps", 1.0)),
            jitter_ms=int(t.get("rate", {}).get("jitter_ms", 400)),
        ))
    return targets


def apply_identity(url: str, injs: list[Injection]) -> tuple[str, dict[str, str]] | None:
    """Return (url, headers) with credentials injected, or None if a required
    secret is missing (identity unusable -> caller skips it)."""
    headers = {"User-Agent": UA}
    cookies: list[str] = []
    p = urlparse(url)
    query = p.query
    for inj in injs:
        val = inj.resolve()
        if val is None:
            return None
        if inj.where == "header":
            headers[inj.name] = val
        elif inj.where == "query":
            add = urllib.parse.quote(inj.name) + "=" + urllib.parse.quote(val, safe="")
            query = (query + "&" + add) if query else add
        elif inj.where == "cookie":
            cookies.append(f"{inj.name}={val}")
        else:
            raise ValueError(f"unknown injection target: {inj.where}")
    if cookies:
        headers["Cookie"] = "; ".join(cookies)
    return p._replace(query=query).geturl(), headers


# --------------------------------------------------------------------------- #
# Endpoint harvesting
# --------------------------------------------------------------------------- #
def is_concrete_url(u: str) -> bool:
    if not u.startswith(("http://", "https://")):
        return False
    if any(m in u for m in TEMPLATE_MARKERS):
        return False
    p = urlparse(u)
    return bool(p.netloc) and "." in p.netloc


def harvest_from_surface(rec: dict) -> list[str]:
    ep = rec.get("endpoints", {}) or {}
    urls: set[str] = set()
    for key in ("api", "graphql"):
        for u in ep.get(key, []) or []:
            if isinstance(u, str) and is_concrete_url(u):
                urls.add(u.rstrip("/") or u)
    return sorted(urls)


def parse_path_line(line: str) -> tuple[str | None, str] | None:
    """A host-file line -> (method_or_None, path). '#' comments and blanks -> None."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split()
    if len(parts) >= 2 and parts[0].upper() in _HTTP_VERBS:
        method, path = parts[0].upper(), parts[1]
    else:
        method, path = None, parts[0]
    if not path.startswith("/"):
        path = "/" + path
    return method, path


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
@dataclass
class Resp:
    status: int | None
    length: int
    ctype: str
    body_sha1: str
    snippet: str
    error: str = ""


class HostThrottle:
    def __init__(self) -> None:
        self._last: dict[str, float] = {}

    def wait(self, host: str, rps: float, jitter_ms: int) -> None:
        min_gap = 1.0 / max(rps, 0.05)
        gap = time.monotonic() - self._last.get(host, 0.0)
        sleep = max(0.0, min_gap - gap) + random.uniform(0, jitter_ms / 1000.0)
        if sleep > 0:
            time.sleep(sleep)
        self._last[host] = time.monotonic()


def do_request(url: str, method: str, headers: dict[str, str], timeout: int, max_body: int) -> Resp:
    req = urllib.request.Request(url, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return _resp(r.status, r.headers.get("Content-Type", ""), r.read(max_body))
    except urllib.error.HTTPError as e:
        try:
            body = e.read(max_body)
        except Exception:
            body = b""
        return _resp(e.code, e.headers.get("Content-Type", "") if e.headers else "", body)
    except Exception as e:
        return Resp(None, 0, "", "", "", error=type(e).__name__)


def _resp(status: int, ctype: str, body: bytes) -> Resp:
    text = body.decode("utf-8", "replace")
    return Resp(status=status, length=len(body), ctype=ctype.split(";")[0].strip(),
                body_sha1=hashlib.sha1(body).hexdigest()[:12],
                snippet=text[:200].replace("\n", " "))


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #
def looks_like_data(r: Resp) -> bool:
    if r.status is None or not (200 <= r.status < 300):
        return False
    ct = r.ctype.lower()
    if any(x in ct for x in ("json", "xml", "csv", "protobuf")):
        return not _LOGIN_HINT_RE.search(r.snippet or "")
    if r.snippet and ("{" in r.snippet or "<" in r.snippet):
        return not _LOGIN_HINT_RE.search(r.snippet)
    return False


def classify(url: str, states: dict[str, Resp], has_pair: bool) -> dict | None:
    none, a, b = states.get("none"), states.get("A"), states.get("B")
    finding, sev, conf, reasons = None, "info", "low", []

    if none and looks_like_data(none):
        finding, sev, conf = "MISSING_AUTH", "medium", "medium"
        reasons.append(f"unauth {none.status} {none.ctype} {none.length}B data-shaped")
        if a and a.status and none.body_sha1 == a.body_sha1:
            reasons.append("byte-identical to identity-A response (auth ignored)")
            conf = "high"

    if has_pair and a and b and a.status and b.status:
        if 200 <= a.status < 300 and 200 <= b.status < 300 and a.body_sha1 != b.body_sha1:
            if _ID_SEG_RE.search(urlparse(url).path):
                if finding is None:
                    finding, sev, conf = "BROKEN_AUTHZ", "high", "low"
                reasons.append("A and B both 2xx on id-scoped path, bodies differ (confirm ownership)")

    if finding is None:
        return None
    return {"url": url, "finding": finding, "severity": sev, "confidence": conf, "reasons": reasons,
            "states": {k: {"status": v.status, "len": v.length, "ctype": v.ctype, "sha1": v.body_sha1,
                           "snippet": v.snippet[:120], "err": v.error} for k, v in states.items()}}


# --------------------------------------------------------------------------- #
# Plan building + runner
# --------------------------------------------------------------------------- #
def _pick_methods(target: Target, line_method: str | None, allow_mutating: bool) -> list[str]:
    methods = [line_method] if line_method else list(target.methods)
    return [m for m in methods if m in ("GET", "HEAD") or allow_mutating]


def build_plan(targets: list[Target], *, endpoints_dir: Path | None, surface: Path | None,
               allow_mutating: bool):
    plan, skipped = [], 0

    def match(host: str) -> Target | None:
        t = next((t for t in targets if t.host_allowed(host)), None)
        return t if (t and t.active_testing_permitted) else None

    if endpoints_dir:
        for f in sorted(p for p in endpoints_dir.iterdir() if p.is_file()):
            host = f.name
            tgt = match(host)
            for raw in f.read_text(encoding="utf-8", errors="replace").splitlines():
                parsed = parse_path_line(raw)
                if not parsed:
                    continue
                m, path = parsed
                if tgt is None:
                    skipped += 1
                    continue
                methods = _pick_methods(tgt, m, allow_mutating)
                if methods:
                    plan.append((f"{tgt.scheme}://{host}{path}", host, methods, tgt))
    if surface:
        for line in surface.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            for url in harvest_from_surface(rec):
                host = urlparse(url).netloc.lower()
                tgt = match(host)
                if tgt is None:
                    skipped += 1
                    continue
                methods = _pick_methods(tgt, None, allow_mutating)
                if methods:
                    plan.append((url, host, methods, tgt))
    return plan, skipped


def run(plan, skipped, out_path: Path, *, live: bool, timeout: int, max_body: int) -> None:
    log(f"plan: {len(plan)} in-scope request-groups; {skipped} skipped (out of scope / no permission)")
    if not live:
        log("DRY-RUN (no requests sent). Re-run with --live to execute.")
        for url, _host, methods, tgt in plan[:60]:
            ids = ["none"] + [n for n in tgt.identities]
            print(f"  [{tgt.program}] {','.join(methods)} {url}  identities={ids}")
        if len(plan) > 60:
            print(f"  ... and {len(plan) - 60} more")
        return

    throttle, findings, probed = HostThrottle(), 0, 0
    warned: set[str] = set()
    with out_path.open("a", encoding="utf-8") as out_f:
        for url, host, methods, tgt in plan:
            for method in methods:
                states: dict[str, Resp] = {}
                throttle.wait(host, tgt.rps, tgt.jitter_ms)
                states["none"] = do_request(url, method, {"User-Agent": UA}, timeout, max_body)
                for name, injs in tgt.identities.items():
                    built = apply_identity(url, injs)
                    if built is None:
                        if name not in warned:
                            log(f"  identity {name!r} unusable (missing env secret) — skipping it")
                            warned.add(name)
                        continue
                    turl, headers = built
                    throttle.wait(host, tgt.rps, tgt.jitter_ms)
                    states[name] = do_request(turl, method, headers, timeout, max_body)
                probed += 1
                res = classify(url, states, has_pair=("A" in tgt.identities and "B" in tgt.identities))
                if res:
                    res.update(program=tgt.program, method=method, at=datetime.now(timezone.utc).isoformat())
                    out_f.write(json.dumps(res) + "\n")
                    out_f.flush()
                    findings += 1
                    log(f"  {res['severity'].upper():6s} {res['finding']} {method} {url}")
    log(f"done. probed={probed} findings={findings} -> {out_path}")


# --------------------------------------------------------------------------- #
def self_test() -> int:
    assert is_concrete_url("https://api.example.com/v1/orders")
    assert not is_concrete_url("https://%sadrevenue.%s/api/v2")
    assert parse_path_line("# comment") is None
    assert parse_path_line("/users") == (None, "/users")
    assert parse_path_line("POST /users/create") == ("POST", "/users/create")
    assert parse_path_line("users") == (None, "/users")
    # identity injection: header/bearer, query, cookie, missing-secret
    u, h = apply_identity("https://h/x", [Injection("header", "Authorization", value="tok", prefix="Bearer ")])
    assert h["Authorization"] == "Bearer tok"
    u2, _ = apply_identity("https://h/x?a=1", [Injection("query", "access_token", value="Q")])
    assert "access_token=Q" in u2 and u2.startswith("https://h/x?a=1&")
    _, h3 = apply_identity("https://h/x", [Injection("cookie", "session", value="S"),
                                           Injection("header", "X-Client-Id", value="mobile")])
    assert h3["Cookie"] == "session=S" and h3["X-Client-Id"] == "mobile"
    assert apply_identity("https://h/x", [Injection("header", "Authorization", env="DEFINITELY_MISSING_ENV")]) is None
    # classifiers
    assert looks_like_data(_resp(200, "application/json", b'{"orders":[1]}'))
    assert not looks_like_data(_resp(200, "text/html", b"<form>please log in</form>"))
    r = classify("https://api.x/v1/users/12345/card",
                 {"none": _resp(401, "application/json", b'{"error":"unauthorized"}'),
                  "A": _resp(200, "application/json", b'{"card":"A"}'),
                  "B": _resp(200, "application/json", b'{"card":"B"}')}, has_pair=True)
    assert r and r["finding"] == "BROKEN_AUTHZ", r
    r2 = classify("https://api.x/v1/catalog",
                  {"none": _resp(200, "application/json", b'{"items":[1,2,3]}')}, has_pair=False)
    assert r2 and r2["finding"] == "MISSING_AUTH", r2
    print("self-test OK")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="apk-drill authorization-differential endpoint prober")
    ap.add_argument("surface", nargs="?", help="surface_map JSONL (alternative to --endpoints-dir)")
    ap.add_argument("--endpoints-dir", help="dir of per-host inventory files (filename == host)")
    ap.add_argument("--config", help="targets config JSON (scope + identities)")
    ap.add_argument("-o", "--output", default="authz_findings.jsonl")
    ap.add_argument("--live", action="store_true", help="actually send requests (default: dry-run)")
    ap.add_argument("--allow-mutating", action="store_true", help="permit non-GET/HEAD methods (dangerous)")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--max-body", type=int, default=2048)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()
    if not args.config or not (args.surface or args.endpoints_dir):
        ap.error("need --config and one of: SURFACE jsonl | --endpoints-dir DIR (or --self-test)")

    targets = load_config(Path(args.config))
    permitted = [t for t in targets if t.active_testing_permitted]
    log(f"loaded {len(targets)} target(s); {len(permitted)} permit active testing")
    if not permitted:
        log("no target permits active testing — nothing to do.")
        return 0
    plan, skipped = build_plan(
        targets,
        endpoints_dir=Path(args.endpoints_dir) if args.endpoints_dir else None,
        surface=Path(args.surface) if args.surface else None,
        allow_mutating=args.allow_mutating,
    )
    run(plan, skipped, Path(args.output), live=args.live, timeout=args.timeout, max_body=args.max_body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
