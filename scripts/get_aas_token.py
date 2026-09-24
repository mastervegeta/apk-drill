#!/usr/bin/env python3
"""
get_aas_token.py

One-time helper: exchange a fresh Google OAuth token for a long-lived AAS token
(the credential apkeep/gpapi use for authenticated Google Play downloads).

Why you need this: Google OAuth tokens are single-use and expire in minutes, so
they can't drive a daily job. The AAS token is long-lived — get it once, store
it as GPLAY_AAS_TOKEN in .gplay.env, and the pipeline runs unattended.

STEPS (spare/throwaway account only — bulk Play use can get an account banned):
  1. In a browser, open:  https://accounts.google.com/EmbeddedSetup
     (or https://accounts.google.com/embedded/setup/v2/android )
  2. Sign in with the throwaway Google account. Accept the prompt.
  3. Open DevTools -> Application -> Cookies -> https://accounts.google.com and
     copy the value of the `oauth_token` cookie (starts with `oauth2_4/...`).
  4. IMMEDIATELY (within a minute or two) run:
        python3 scripts/get_aas_token.py --email you@gmail.com --oauth-token 'oauth2_4/...'
  5. Paste the printed `GPLAY_AAS_TOKEN=aas_et/...` line into .gplay.env,
     replacing the old GPLAY_OAUTH_TOKEN line.

Pure stdlib. The token is read from --oauth-token or stdin; it is not logged.
"""

from __future__ import annotations

import argparse
import sys
import urllib.parse
import urllib.request

AUTH_URL = "https://android.googleapis.com/auth"
# Public GMS client signature used by the standard oauth->aas exchange.
CLIENT_SIG = "38918a453d07199354f8b19af05ec6562ced5788"


def exchange(email: str, oauth_token: str, country: str = "us") -> dict:
    body = urllib.parse.urlencode({
        "Email": email,
        "Token": oauth_token,
        "service": "ac2dm",
        "accountType": "HOSTED_OR_GOOGLE",
        "has_permission": "1",
        "add_account": "1",
        "source": "android",
        "app": "com.google.android.gms",
        "client_sig": CLIENT_SIG,
        "device_country": country.lower(),
        "operatorCountry": country.lower(),
        "lang": "en",
        "sdk_version": "17",
    }).encode()
    req = urllib.request.Request(
        AUTH_URL, data=body,
        headers={"User-Agent": "GoogleAuth/1.4",
                 "Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=30) as r:
        text = r.read().decode("utf-8", "replace")
    out = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Exchange a Google OAuth token for an AAS token.")
    ap.add_argument("--email", required=True, help="The throwaway account email.")
    ap.add_argument("--oauth-token", help="Fresh oauth2_4/... token (or pass via stdin).")
    ap.add_argument("--country", default="us", help="Account region (default us).")
    args = ap.parse_args()

    token = args.oauth_token or sys.stdin.readline().strip()
    if not token.startswith("oauth2_4/"):
        print("WARNING: token doesn't start with 'oauth2_4/' — did you copy the right cookie?",
              file=sys.stderr)

    try:
        res = exchange(args.email, token, args.country)
    except Exception as e:
        print(f"Exchange request failed: {e!r}", file=sys.stderr)
        return 1

    aas = res.get("Token")
    if not aas:
        print("No AAS token returned. Google said:", file=sys.stderr)
        for k, v in res.items():
            print(f"  {k}={v if k not in ('Token','Auth') else '<redacted>'}", file=sys.stderr)
        print("\nUsual cause: the OAuth token was already used or expired. "
              "Get a fresh one and retry within a minute.", file=sys.stderr)
        return 1

    print("# Success. Put this line in .gplay.env (replace any GPLAY_OAUTH_TOKEN line):")
    print(f"GPLAY_AAS_TOKEN={aas}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
