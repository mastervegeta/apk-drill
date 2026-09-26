#!/usr/bin/env python3
"""
report_forge.py

apk-drill — bug-bounty report drafter.

Takes one normalized Finding (bug class + where it was found + evidence) and
renders a submission for each platform FIELD BY FIELD — the exact value to paste
into every free-text box and the exact option to pick in every dropdown — so a
report is 90% written before you open the form.

Per-platform shaping is real, not cosmetic:
  * HackerOne keeps Description and Impact as separate fields; severity is a
    CVSS 3.1 vector (this tool computes the vector AND the base score).
  * Bugcrowd merges summary + impact + PoC into ONE Description field and takes
    severity from the VRT category you pick.
  * Intigriti / YesWeHack: renderers stubbed until their form layouts are added.

Taxonomy note: CWE ids and VRT category paths are best-effort defaults per bug
class. Dropdown wording changes over time — the sheet prints the intended value
so you can match it to the live option.

Usage:
  report_forge.py finding.json --platform hackerone
  report_forge.py finding.json --platform all -o report_sheet.md
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

# --------------------------------------------------------------------------- #
# CVSS 3.1 base score
# --------------------------------------------------------------------------- #
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def cvss31(m: dict) -> tuple[str, float, str]:
    """Return (vector, base_score, severity_label) for a CVSS 3.1 metric dict."""
    scope_changed = m["S"] == "C"
    pr = (_PR_C if scope_changed else _PR_U)[m["PR"]]
    isc_base = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base
    expl = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    if impact <= 0:
        score = 0.0
    elif scope_changed:
        score = _roundup(min(1.08 * (impact + expl), 10))
    else:
        score = _roundup(min(impact + expl, 10))
    vector = ("CVSS:3.1/AV:%(AV)s/AC:%(AC)s/PR:%(PR)s/UI:%(UI)s/"
              "S:%(S)s/C:%(C)s/I:%(I)s/A:%(A)s") % m
    label = ("None" if score == 0 else "Low" if score < 4 else "Medium"
             if score < 7 else "High" if score < 9 else "Critical")
    return vector, score, label


# --------------------------------------------------------------------------- #
# Bug-class taxonomy: internal enum -> per-platform mapping + CVSS default
# --------------------------------------------------------------------------- #
BUG_CLASSES: dict[str, dict] = {
    "MISSING_AUTH": {
        "title": "Unauthenticated access to {host} endpoint {path}",
        "cwe": "CWE-306: Missing Authentication for Critical Function",
        "vrt": "Broken Access Control (BAC)",
        "intigriti": "CWE-306 Missing Authentication for Critical Function (Broken Authentication)",
        "ywh_type": "Improper Authentication / Missing Authentication (CWE-306)",
        "ywh_part": "URL path",
        "fix": "Require and verify authentication server-side before this endpoint returns data.",
        "cvss": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
    },
    "BROKEN_AUTHZ": {
        "title": "IDOR: cross-user access to {path} on {host}",
        "cwe": "CWE-639: Authorization Bypass Through User-Controlled Key",
        "vrt": "Broken Access Control (BAC) > Insecure Direct Object References (IDOR)",
        "intigriti": "CWE-639 Insecure Direct Object Reference (Broken Access Control)",
        "ywh_type": "Insecure Direct Object Reference (CWE-639)",
        "ywh_part": "URL path",
        "fix": "Enforce per-object authorization tying each resource to the authenticated user.",
        "cvss": {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
    },
    "HARDCODED_SECRET": {
        "title": "Hardcoded live credential in {host} app package",
        "cwe": "CWE-798: Use of Hard-coded Credentials",
        "vrt": "Sensitive Data Exposure > Disclosure of Secrets > In Client-Side Code",
        "intigriti": "CWE-798 Use of Hard-coded Credentials (Mobile)",
        "ywh_type": "Use of Hard-coded Credentials (CWE-798)",
        "ywh_part": "Other (application binary)",
        "fix": "Revoke and rotate the key; move secrets to a server-side broker, never ship them in the client.",
        "cvss": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
    },
    "KNOWN_VULN_COMPONENT": {
        "title": "Bundled component with known CVE(s) in {host} app",
        "cwe": "CWE-1104: Use of Unmaintained Third Party Components",
        "vrt": "Using Components with Known Vulnerabilities",
        "intigriti": "CWE-657 Violation of Secure Design Principles (Vulnerable components)",
        "ywh_type": "Use of a vulnerable component (CWE-1104)",
        "ywh_part": "Other (bundled library)",
        "fix": "Upgrade the affected component to a fixed release.",
        "cvss": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "L", "A": "N"},
    },
    "EXPORTED_COMPONENT": {
        "title": "Unprotected exported component in {host} app",
        "cwe": "CWE-926: Improper Export of Android Application Components",
        "vrt": "Mobile Security Misconfiguration > Tapjacking",
        "intigriti": "CAPEC-499 Android Intent Intercept (Mobile)",
        "ywh_type": "Mobile Security Misconfiguration (exported component)",
        "ywh_part": "Other (Android component)",
        "fix": "Set android:exported=false or protect the component with a signature-level permission.",
        "cvss": {"AV": "L", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"},
    },
    "CLEARTEXT_TRAFFIC": {
        "title": "Cleartext HTTP traffic permitted in {host} app",
        "cwe": "CWE-319: Cleartext Transmission of Sensitive Information",
        "vrt": "Insecure Data Transport > Cleartext Transmission of Sensitive Data",
        "intigriti": "CWE-319 Cleartext Transmission of Sensitive Information (Mobile)",
        "ywh_type": "Cleartext Transmission of Sensitive Information (CWE-319)",
        "ywh_part": "Other (network config)",
        "fix": "Disable cleartext traffic (usesCleartextTraffic=false) and enforce TLS via network-security-config.",
        "cvss": {"AV": "A", "AC": "H", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"},
    },
    "CORS_MISCONFIG": {
        "title": "CORS misconfiguration on {host}",
        "cwe": "CWE-942: Permissive Cross-domain Policy with Untrusted Domains",
        "vrt": "Server Security Misconfiguration > Misconfigured CORS",
        "intigriti": "CWE-16 Misconfiguration (Misconfiguration)",
        "ywh_type": "CORS Misconfiguration (CWE-942)",
        "ywh_part": "HTTP Request Header (Origin)",
        "fix": "Validate Origin against an allowlist; never reflect arbitrary origins with Allow-Credentials:true.",
        "cvss": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "H", "I": "N", "A": "N"},
    },
    "HOST_HEADER_INJECTION": {
        "title": "Host header injection on {host}",
        "cwe": "CWE-20: Improper Input Validation (Host header)",
        "vrt": "Server Security Misconfiguration",
        "intigriti": "Host Header Injection (Other)",
        "ywh_type": "Host Header Injection",
        "ywh_part": "HTTP Request Header (Host)",
        "fix": "Use a server-configured canonical host; never build URLs/redirects from client-supplied Host/X-Forwarded-Host.",
        "cvss": {"AV": "N", "AC": "H", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "L", "A": "N"},
    },
    "OPEN_FIREBASE": {
        "title": "Publicly readable Firebase datastore behind {host} app",
        "cwe": "CWE-284: Improper Access Control",
        "vrt": "Server Security Misconfiguration > Firebase Misconfiguration",
        "intigriti": "CWE-284 Improper Access Control (Generic) (Broken Access Control)",
        "ywh_type": "Improper Access Control (CWE-284)",
        "ywh_part": "Other (backend datastore)",
        "fix": "Apply Firebase security rules requiring authentication/authorization for reads and writes.",
        "cvss": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
    },
}


# --------------------------------------------------------------------------- #
# Description assembly
# --------------------------------------------------------------------------- #
def _steps_block(steps: list[str]) -> str:
    if not steps:
        return "_(add reproduction steps)_"
    return "\n".join(f"{i}. {s}" for i, s in enumerate(steps, 1))


def _evidence_block(evidence: list[str]) -> str:
    if not evidence:
        return "_(attach screenshots / request-response captures)_"
    return "\n".join(f"- `{e}`" for e in evidence)


def description_md(f: dict) -> str:
    parts = [
        "## Summary", f.get("summary", "_(summary)_"), "",
        "## Affected endpoint",
        f"`{f.get('url') or f.get('host','')}`" + (f"  (path `{f['path']}`)" if f.get("path") else ""), "",
        "## Steps to reproduce", _steps_block(f.get("steps", [])), "",
        "## Evidence", _evidence_block(f.get("evidence", [])),
    ]
    return "\n".join(parts)


def impact_md(f: dict) -> str:
    return f.get("impact", "_(describe who is affected and what an attacker gains)_")


# --------------------------------------------------------------------------- #
# Renderers
# --------------------------------------------------------------------------- #
def _resolve(f: dict) -> tuple[dict, str, str, float, str]:
    cls = BUG_CLASSES.get(f["bug_class"])
    if not cls:
        raise SystemExit(f"unknown bug_class {f['bug_class']!r}; known: {', '.join(BUG_CLASSES)}")
    ctx = {"host": f.get("host", ""), "path": f.get("path", "")}
    title = f.get("title") or cls["title"].format(**ctx)
    metrics = {**cls["cvss"], **(f.get("cvss") or {})}
    vector, score, label = cvss31(metrics)
    return cls, title, vector, score, label


def render_hackerone(f: dict) -> str:
    cls, title, vector, score, label = _resolve(f)
    asset = f.get("asset") or f.get("host", "")
    return "\n".join([
        f"# HackerOne — {f.get('program','<program>')}",
        "",
        f"**Title:** {title}",
        f"**Asset** *(select):* `{asset}`  _(match to the in-scope asset dropdown)_",
        f"**Weakness** *(select):* {cls['cwe']}",
        f"**Severity:** Submit with severity — `{vector}`  →  **{score} ({label})**",
        "",
        "**Description:**",
        "",
        description_md(f),
        "",
        "**Impact:**",
        "",
        impact_md(f),
        "",
        f"**Attachments:** {', '.join(f.get('evidence', [])) or '_(none)_'}",
    ])


def render_bugcrowd(f: dict) -> str:
    cls, title, vector, score, label = _resolve(f)
    target = f.get("asset") or f.get("host", "")
    combined = "\n".join([description_md(f), "", "## Impact", impact_md(f)])
    if len(combined) > 25000:
        combined = combined[:24950] + "\n\n_(truncated to 25000-char limit)_"
    return "\n".join([
        f"# Bugcrowd — {f.get('program','<program>')}",
        "",
        f"**Submission title:** {title}",
        f"**Target** *(select):* `{target}`  _(must match an in-scope target)_",
        f"**VRT Category** *(select):* {cls['vrt']}",
        f"  _(suggested severity for reference: {score} {label} — `{vector}`)_",
        f"**URL / Location** *(optional):* {f.get('url','') or '_(n/a)_'}",
        "",
        "**Description** *(single field — vuln + impact + PoC, ≤25000 chars):*",
        "",
        combined,
        "",
        f"**Attachments** *(optional):* {', '.join(f.get('evidence', [])) or '_(none)_'}",
        "**Confirmation:** ☑ I have followed the brief and agree to Bugcrowd's terms & conditions",
    ])


def render_intigriti(f: dict) -> str:
    cls, title, vector, score, label = _resolve(f)
    asset = f.get("asset") or f.get("host", "")
    endpoint = f.get("endpoint") or f.get("url") or f.get("host", "")
    return "\n".join([
        f"# Intigriti — {f.get('program','<program>')}",
        "",
        f"**Title:** {title}",
        f"**Select asset:** `{asset}`  _(match the asset/tier in the dropdown)_",
        f"**Endpoint / vulnerable component:** {endpoint}",
        f"**Type** *(select):* {cls['intigriti']}",
        f"**Severity** *(CVSS calculator):* `{vector}`  →  **{score} ({label})**",
        "",
        "**Proof of Concept / description** *(≤30000):*",
        "",
        description_md(f),
        "",
        "**Impact** *(≤15000):*",
        "",
        impact_md(f),
        "",
        "**Recommended solution** *(≤15000):*",
        "",
        f.get("recommended_solution") or cls["fix"],
        "",
        f"**IP address used for testing:** {f.get('ips','') or '_(fill in / Fetch my IP)_'}",
        f"**Attachments:** {', '.join(f.get('evidence', [])) or '_(none)_'}",
    ])


def render_yeswehack(f: dict) -> str:
    cls, title, vector, score, label = _resolve(f)
    scope = f.get("asset") or f.get("host", "")
    endpoint = f.get("endpoint") or f.get("url") or f.get("host", "")
    return "\n".join([
        f"# YesWeHack — {f.get('program','<program>')}",
        "",
        f"**Bug type** *(select):* {cls['ywh_type']}  _(match to the closest bug-type option)_",
        f"**Scope** *(select):* `{scope}`",
        f"**Endpoint:** {endpoint}",
        f"**Vulnerable part** *(select):* {cls['ywh_part']}",
        f"**Part name:** {f.get('part_name','') or '_(e.g. Authorization header / id path segment)_'}",
        f"**Payload:** {f.get('payload','') or '_(n/a)_'}",
        f"**Technical environment:** {f.get('tech_env','') or '_(app version / OS / device)_'}",
        f"**Application fingerprint:** {f.get('app_fingerprint','') or '_(n/a)_'}",
        f"**CVE:** {f.get('cve','') or '_(n/a)_'}",
        f"**Impact:** {impact_md(f)}",
        f"**IPs used:** {f.get('ips','') or '_(Get my IP)_'}",
        f"**CVSS vector:** `{vector}`  →  **{score} ({label})**",
        f"**Report title:** {title}",
        "",
        "**Description** *(markdown):*",
        "",
        description_md(f),
        "",
        f"**Recommended fix:** {f.get('recommended_solution') or cls['fix']}",
        f"**Attachments:** {', '.join(f.get('evidence', [])) or '_(none)_'}",
    ])


RENDERERS = {
    "hackerone": render_hackerone,
    "bugcrowd": render_bugcrowd,
    "intigriti": render_intigriti,
    "yeswehack": render_yeswehack,
}


# --------------------------------------------------------------------------- #
def self_test() -> int:
    # CVSS reference vectors
    v, s, lab = cvss31({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"})
    assert s == 7.5 and lab == "High", (v, s, lab)
    _, s2, _ = cvss31({"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"})
    assert s2 == 6.5, s2
    _, s3, lab3 = cvss31({"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"})
    assert lab3 == "Critical", (s3, lab3)
    f = {"bug_class": "MISSING_AUTH", "program": "bookbeat", "host": "api.bookbeat.com",
         "path": "/api/bookbot/chats", "url": "https://api.bookbeat.com/api/bookbot/chats",
         "summary": "The endpoint returns chat data without any Authorization header.",
         "steps": ["curl the URL with no token", "observe 200 + JSON chat data"],
         "impact": "Any unauthenticated party can read users' chatbot conversations.",
         "evidence": ["noauth_200.png"]}
    h1 = render_hackerone(f)
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" in h1 and "7.5 (High)" in h1
    assert "CWE-306" in h1 and "**Impact:**" in h1
    bc = render_bugcrowd(f)
    assert "Insecure Direct Object" not in bc  # MISSING_AUTH != IDOR
    assert "Submission title:" in bc and "single field" in bc
    intg = render_intigriti(f)
    assert "CWE-306 Missing Authentication for Critical Function (Broken Authentication)" in intg
    assert "Recommended solution" in intg and "≤30000" in intg
    ywh = render_yeswehack(f)
    assert "Bug type" in ywh and "Vulnerable part" in ywh and "URL path" in ywh
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" in ywh
    # IDOR maps to the right Intigriti taxonomy string
    idor = render_intigriti({**f, "bug_class": "BROKEN_AUTHZ"})
    assert "CWE-639 Insecure Direct Object Reference (Broken Access Control)" in idor
    print("self-test OK")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="apk-drill bug-bounty report drafter")
    ap.add_argument("finding", nargs="?", help="finding JSON")
    ap.add_argument("--platform", choices=list(RENDERERS) + ["all"], default="all")
    ap.add_argument("-o", "--output")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--list-classes", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()
    if args.list_classes:
        for k, v in BUG_CLASSES.items():
            print(f"  {k:22s} {v['cwe']}")
        return 0
    if not args.finding:
        ap.error("finding JSON required (or --self-test / --list-classes)")

    f = json.loads(Path(args.finding).read_text(encoding="utf-8"))
    platforms = list(RENDERERS) if args.platform == "all" else [args.platform]
    out = "\n\n---\n\n".join(RENDERERS[p](f) for p in platforms)
    if args.output:
        Path(args.output).write_text(out + "\n", encoding="utf-8")
        print(f"wrote {args.output}")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
