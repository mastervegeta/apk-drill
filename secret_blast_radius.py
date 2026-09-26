#!/usr/bin/env python3
"""
secret_blast_radius.py

apk-drill — secret impact / blast-radius resolver.

trufflehog tells you a secret is LIVE. A triager pays for what it can DO. This
runs the minimal, read-only capability check per secret type and turns
"verified secret" into a severity-justified impact statement.

Safety:
  * the secret VALUE is read only from an environment variable you name, never
    the CLI or a file, and is NEVER printed or written to output.
  * checks are benign and read-only (identity / scope / enabled-API probes) —
    never a state-changing call.
  * nothing runs without --live (default prints the plan).
  * this uses a found third-party credential; run it only to establish impact
    on an engagement whose rules permit it, and report — never use — the key.

Usage:
  export SECRET=...            # the found key, from your notes
  secret_blast_radius.py --type google_api_key  --secret-env SECRET
  secret_blast_radius.py --type google_api_key  --secret-env SECRET --live
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

# Benign, read-only Google endpoints used only to see whether a key is accepted
# (which reveals enabled + billable APIs). Minimal, harmless query params.
GOOGLE_PROBES = {
    "Geocoding":      "https://maps.googleapis.com/maps/api/geocode/json?address=1600+Amphitheatre&key={K}",
    "Static Maps":    "https://maps.googleapis.com/maps/api/staticmap?center=0,0&zoom=1&size=1x1&key={K}",
    "Directions":     "https://maps.googleapis.com/maps/api/directions/json?origin=0,0&destination=1,1&key={K}",
    "Places Details": "https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&key={K}",
    "Timezone":       "https://maps.googleapis.com/maps/api/timezone/json?location=0,0&timestamp=0&key={K}",
}


def _get(url: str, timeout: int = 12) -> tuple[int | None, str]:
    try:
        with urllib.request.urlopen(urllib.request.Request(url), timeout=timeout) as r:
            return r.status, r.read(400).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(400).decode("utf-8", "replace")
        except Exception:
            return e.code, ""
    except Exception as e:
        return None, type(e).__name__


def classify_google(api: str, status: int | None, body: str) -> str:
    """Map a probe response to a verdict WITHOUT echoing the key."""
    b = body.lower().replace(" ", "").replace("\n", "")
    if "request_denied" in b or "apinotactivated" in b or status == 403:
        return "denied/restricted"
    if "over_query_limit" in b:
        return "ENABLED (quota hit)"
    if '"status":"ok"' in b or ('"results":' in b and "error_message" not in b):
        return "ENABLED"
    if status == 200:
        return "ENABLED"
    return f"unclear (HTTP {status})"


def run_google(secret: str, live: bool) -> dict:
    result = {"type": "google_api_key", "checks": [], "impact": "", "severity": "low"}
    enabled = []
    for api, tmpl in GOOGLE_PROBES.items():
        if not live:
            result["checks"].append({"api": api, "verdict": "PLANNED (dry-run)"})
            continue
        status, body = _get(tmpl.format(K=urllib.parse.quote(secret, safe="")))
        verdict = classify_google(api, status, body)
        result["checks"].append({"api": api, "verdict": verdict})
        if verdict.startswith("ENABLED"):
            enabled.append(api)
    if enabled:
        result["impact"] = ("Unrestricted Google Maps key: attacker can call "
                            + ", ".join(enabled) + " on the victim's billing account "
                            "(financial DoS via quota drain / cost inflation).")
        result["severity"] = "medium"
    elif live:
        result["impact"] = "Key appears application/referrer-restricted; server-side abuse limited."
    return result


def run_newrelic(secret: str, live: bool) -> dict:
    # A New Relic *license/ingest* key can send telemetry into the org account;
    # it is not a data-read key. Impact = telemetry/log injection + ingest-cost abuse.
    r = {"type": "newrelic_license_key", "checks": [], "severity": "low",
         "impact": ("New Relic ingest/license key: an attacker can inject arbitrary "
                    "telemetry/logs into the org's New Relic account (data poisoning, "
                    "alert noise, ingest-cost abuse). It is NOT a data-read key, so most "
                    "programs rate this low/informational — state that honestly.")}
    if live:
        # Benign: POST an empty metric batch; 202 == accepted (key valid), no data planted.
        r["checks"].append({"note": "run a single empty-metric POST to metric-api.newrelic.com "
                                    "to confirm 202 acceptance; omitted here to avoid writing data."})
    else:
        r["checks"].append({"verdict": "PLANNED (dry-run)"})
    return r


def run_manual(kind: str) -> dict:
    guides = {
        "aws_access_key": "Run `aws sts get-caller-identity` with the key pair exported to AWS_ACCESS_KEY_ID/"
                          "AWS_SECRET_ACCESS_KEY (benign, read-only) to get the principal ARN; then "
                          "`aws iam get-account-authorization-details`/simulate to bound permissions.",
        "generic": "No automated capability check for this type. Identify the provider, find its "
                   "identity/whoami or scope endpoint, and make ONE read-only call to bound impact.",
    }
    return {"type": kind, "severity": "unknown",
            "impact": "manual capability check required",
            "checks": [{"guidance": guides.get(kind, guides["generic"])}]}


HANDLERS = {"google_api_key": run_google, "newrelic_license_key": run_newrelic}


def self_test() -> int:
    ok = classify_google("Geocoding", 200, '{ "results" : [ ], "status" : "OK" }')
    assert ok == "ENABLED", ok
    denied = classify_google("Geocoding", 200, '{ "error_message": "...", "status": "REQUEST_DENIED" }')
    assert denied == "denied/restricted", denied
    g = run_google("FAKEKEY", live=False)
    assert all(c["verdict"].startswith("PLANNED") for c in g["checks"])
    nr = run_newrelic("FAKE", live=False)
    assert nr["severity"] == "low" and "ingest" in nr["impact"].lower()
    assert run_manual("aws_access_key")["type"] == "aws_access_key"
    print("self-test OK")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="apk-drill secret blast-radius resolver")
    ap.add_argument("--type", help="secret type",
                    choices=["google_api_key", "newrelic_license_key", "aws_access_key", "generic"])
    ap.add_argument("--secret-env", help="env var holding the secret value (never printed)")
    ap.add_argument("--live", action="store_true", help="actually perform the capability checks")
    ap.add_argument("-o", "--output")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    if not args.type:
        ap.error("--type required (or --self-test)")

    if args.type in ("aws_access_key", "generic"):
        result = run_manual(args.type)
    else:
        secret = os.environ.get(args.secret_env or "")
        if args.live and not secret:
            ap.error(f"--live needs the secret in env var {args.secret_env!r} (it is never printed)")
        result = HANDLERS[args.type](secret or "", args.live)

    blob = json.dumps(result, indent=2)
    print(blob)
    if args.output:
        open(args.output, "a", encoding="utf-8").write(json.dumps(result) + "\n")
    if not args.live and args.type in HANDLERS:
        print("\n(dry-run — re-run with --live to execute the capability checks)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
