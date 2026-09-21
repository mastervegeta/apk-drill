#!/usr/bin/env python3
"""
report.py

Turn results_latest.jsonl (from apk_secret_scan.py) into a readable Markdown
report: findings grouped by package and detector type, severity assigned by
whether the secret verified live, plus a remediation / fix plan.

Usage:
    python3 report.py results_latest.jsonl -o report.md
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


# Rough severity model: a *verified* (live) credential is the real problem.
# Unverified hits are still worth triage but are frequently false positives or
# dead keys. Some detector families are higher-impact when live.
HIGH_IMPACT_DETECTORS = {
    "AWS", "GCP", "Azure", "PrivateKey", "Stripe", "Twilio",
    "GitHub", "GitLab", "SlackWebhook", "Slack", "Mailgun", "SendGrid",
    "Firebase", "Gemini", "OpenAI", "Anthropic",
}

# Detectors that are *designed* to ship in a client app: telemetry, analytics,
# attribution, crash-reporting, search-only keys. "Verified live" for these
# usually means "working as intended", not "leak" — most programs close them as
# informational. We still list them; we just flag them so you assess impact
# before spending a report on one.
LOW_VALUE_IN_CLIENT = {
    "NewRelicLicenseKey", "NewRelic", "SentryToken", "Sentry", "Bugsnag",
    "Instabug", "Datadog", "Mixpanel", "Segment", "Amplitude", "Algolia",
    "Branch", "Adjust", "AppsFlyer", "Intercom", "Pendo", "Iterable",
    "GoogleApiKey", "Firebase", "Mapbox", "Pusher", "OneSignal",
}
LOW_VALUE_NOTE = ("designed to ship in a client app (telemetry / analytics / "
                  "attribution) — usually informational; confirm what it "
                  "actually authorizes before reporting")


def severity(detector: str | None, verified: bool) -> str:
    if verified:
        return "CRITICAL" if (detector in HIGH_IMPACT_DETECTORS) else "HIGH"
    return "MEDIUM" if (detector in HIGH_IMPACT_DETECTORS) else "LOW"


SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def load(path: Path) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    status_counts: dict[str, int] = defaultdict(int)
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "status" in rec and "detector" not in rec:
            status_counts[rec["status"]] += 1
        else:
            findings.append(rec)
    return findings, dict(status_counts)


def build_report(findings: list[dict], status_counts: dict, source_name: str) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # tag each finding with severity
    for f in findings:
        f["_sev"] = severity(f.get("detector"), bool(f.get("verified")))

    by_pkg: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        by_pkg[f.get("package", "?")].append(f)

    sev_totals: dict[str, int] = defaultdict(int)
    for f in findings:
        sev_totals[f["_sev"]] += 1

    verified_total = sum(1 for f in findings if f.get("verified"))
    distinct = len({(f.get("package"), f.get("detector"),
                     (f.get("raw_secret_redacted") or "").strip()) for f in findings})
    low_value_verified = sum(
        1 for f in findings
        if f.get("verified") and f.get("detector") in LOW_VALUE_IN_CLIENT)

    lines: list[str] = []
    lines.append("# APK Secret Scan Report\n")
    lines.append(f"_Generated {now} from `{source_name}`_\n")

    # ---- summary ----
    lines.append("## Summary\n")
    lines.append(f"- **Packages with findings:** {len(by_pkg)}")
    lines.append(f"- **Total findings:** {len(findings)} ({distinct} distinct secret(s) after dedupe)")
    lines.append(f"- **Verified (live) secrets:** {verified_total}"
                 + (f" — of which {low_value_verified} are client-side "
                    "telemetry/analytics keys (⚑ usually informational)"
                    if low_value_verified else ""))
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if sev_totals.get(sev):
            lines.append(f"- **{sev}:** {sev_totals[sev]}")
    if status_counts:
        extra = ", ".join(f"{k}={v}" for k, v in sorted(status_counts.items()))
        lines.append(f"- **Scan outcomes:** {extra}")
    lines.append("")

    if verified_total:
        lines.append("> ⚠️ **Live credentials were found.** These are the priority — "
                     "treat every verified secret as compromised and rotate it. "
                     "See the fix plan below.\n")

    # ---- findings by package ----
    lines.append("## Findings by package\n")
    if not findings:
        lines.append("_No secrets detected._\n")
    else:
        # packages sorted by their worst severity, then by count
        def pkg_rank(item):
            pkg, fs = item
            worst = min(SEV_ORDER[f["_sev"]] for f in fs)
            return (worst, -len(fs), pkg)

        for pkg, fs in sorted(by_pkg.items(), key=pkg_rank):
            # Collapse duplicates: the same key turns up once per file it lives
            # in (raw .apk + extracted classes.dex, split bundles, etc.). Group
            # on (detector, verified, redacted secret) and count occurrences so
            # a report shows distinct secrets, not scan artifacts.
            groups: dict[tuple, dict] = {}
            for f in fs:
                key = (f.get("detector"), bool(f.get("verified")),
                       (f.get("raw_secret_redacted") or "").strip())
                g = groups.setdefault(key, {"sev": f["_sev"], "files": set(), "n": 0})
                g["n"] += 1
                if f.get("file"):
                    g["files"].add("/".join(Path(f["file"]).parts[-3:]))

            uniq = sorted(groups.items(),
                          key=lambda kv: (SEV_ORDER[kv[1]["sev"]], kv[0][0] or ""))
            worst = min(g["sev"] for _, g in uniq)
            low_val = {k[0] for k, _ in uniq if k[0] in LOW_VALUE_IN_CLIENT}

            lines.append(f"### `{pkg}` — worst: {worst} "
                         f"({len(uniq)} distinct secret(s), {len(fs)} raw hit(s))\n")
            if low_val:
                lines.append(f"> ⚑ Contains **{', '.join(sorted(low_val))}** — {LOW_VALUE_NOTE}.\n")
            lines.append("| Severity | Detector | Verified | Redacted | Seen in |")
            lines.append("|---|---|---|---|---|")
            for (detector, verified, redacted), g in uniq:
                flag = " ⚑" if detector in LOW_VALUE_IN_CLIENT else ""
                seen = "; ".join(f"`.../{p}`" for p in sorted(g["files"])[:2]) or "—"
                if len(g["files"]) > 2:
                    seen += f" +{len(g['files']) - 2}"
                lines.append(
                    f"| {g['sev']} "
                    f"| {detector or '?'}{flag} "
                    f"| {'✅' if verified else '—'} "
                    f"| `{redacted}` "
                    f"| {seen} |"
                )
            lines.append("")

    # ---- fix plan ----
    lines.append(build_fix_plan(findings, verified_total))
    return "\n".join(lines)


def build_fix_plan(findings: list[dict], verified_total: int) -> str:
    detectors = sorted({f.get("detector") for f in findings if f.get("detector")})
    p: list[str] = []
    p.append("## Remediation / fix plan\n")

    p.append("### 1. Triage (first, before anything else)\n")
    p.append("- Confirm each package is **in authorized scope** before actioning or reporting.")
    p.append("- Sort by severity: verified CRITICAL/HIGH first — those are live keys with "
             "real blast radius.")
    p.append("- For each verified key, identify **what it unlocks** (read-only? billable? "
             "admin?) to gauge impact before you report or rotate.\n")

    p.append("### 2. Rotate & revoke (the actual fix for a leaked secret)\n")
    p.append("A secret committed into a shipped APK is exposed to everyone who has the app — "
             "you cannot un-ship it. The only real fix is to **invalidate the leaked value and "
             "issue a new one that never ships client-side.**\n")
    if detectors:
        p.append("Per detector type found in this scan:\n")
        hints = {
            "AWS": "Deactivate the IAM access key in AWS IAM, issue a new one, and move it "
                   "server-side. Check CloudTrail for use of the leaked key.",
            "GCP": "Revoke the service-account key in IAM & Admin → Service Accounts, rotate, "
                   "and audit usage in Cloud Logging.",
            "Gemini": "Revoke the API key in Google AI Studio / Cloud console and regenerate. "
                      "Restrict the new key by API and referrer; keep it off the client.",
            "OpenAI": "Revoke the key in the OpenAI dashboard and regenerate. Proxy calls "
                      "through your backend so the key never ships in the app.",
            "Firebase": "Rotate the config; lock down with Security Rules and App Check. A raw "
                        "Firebase API key isn't always sensitive — verify what it grants.",
            "GitHub": "Revoke the token in GitHub settings, rotate, and scope the replacement "
                      "to least privilege (fine-grained PAT).",
            "Stripe": "Roll the key in the Stripe dashboard immediately; only publishable keys "
                      "belong client-side, never secret keys.",
            "PrivateKey": "Treat the private key as fully compromised. Generate a new keypair "
                          "and rotate anything that trusted the old one.",
            "SlackWebhook": "Delete the incoming webhook in Slack and recreate it; webhook URLs "
                            "are effectively passwords.",
        }
        for d in detectors:
            tip = hints.get(d, "Revoke the credential at its provider, regenerate, and move it "
                                "off the client.")
            p.append(f"- **{d}:** {tip}")
        p.append("")

    p.append("### 3. Prevent recurrence\n")
    p.append("- Move all secrets **server-side**; the app should call your backend, which holds "
             "the key. Client-side keys are always extractable.")
    p.append("- If a value must live on the device, scope it to the minimum (API restrictions, "
             "referrer/bundle allowlists, short TTL).")
    p.append("- Add secret scanning to CI (TruffleHog / gitleaks) so a key can't reach a build.")
    p.append("- Add a pre-release APK scan step (this pipeline) to the release checklist.")
    p.append("- Store build-time secrets in a secrets manager or CI secret store, not in "
             "source, `local.properties`, `strings.xml`, or `BuildConfig`.\n")

    if verified_total:
        p.append("### 4. If reporting to a bug bounty program\n")
        p.append("- Include the package, the detector, proof the key is **live** (a minimal, "
                 "non-destructive verification), and the concrete impact.")
        p.append("- Do **not** exfiltrate data, rack up billing, or pivot beyond what's needed "
                 "to demonstrate impact — stay within program rules.")
        p.append("- Redact the full secret in the report; show enough to prove it, not enough "
                 "to abuse it.\n")

    return "\n".join(p)


def main() -> int:
    ap = argparse.ArgumentParser(description="Build a Markdown report + fix plan from JSONL findings.")
    ap.add_argument("results", type=Path, help="results_latest.jsonl from the scanner.")
    ap.add_argument("-o", "--output", type=Path, default=Path("report.md"))
    args = ap.parse_args()

    if not args.results.exists():
        print(f"FATAL: results file not found: {args.results}")
        return 1

    findings, status_counts = load(args.results)
    md = build_report(findings, status_counts, args.results.name)
    args.output.write_text(md, encoding="utf-8")
    print(f"Wrote {args.output} — {len(findings)} finding(s), "
          f"{sum(1 for f in findings if f.get('verified'))} verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
