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

Needs gpsoauth (in the venv). The token is read from --oauth-token or stdin; not logged.
"""

from __future__ import annotations

import argparse
import sys

import gpsoauth  # maintained lib; sends the device-shaped request Google requires

# A stable 16-hex device id for the exchange. Keep it constant so the account
# stays associated with one "device"; also store it as GPLAY_DEVICE if you like.
DEFAULT_ANDROID_ID = "3232f4a1b0c9d8e7"


def exchange(email: str, oauth_token: str, android_id: str, country: str = "us") -> dict:
    return gpsoauth.exchange_token(
        email, oauth_token, android_id,
        device_country=country.lower(), operator_country=country.lower())


def main() -> int:
    ap = argparse.ArgumentParser(description="Exchange a Google OAuth token for an AAS token.")
    ap.add_argument("--email", required=True, help="The throwaway account email.")
    ap.add_argument("--oauth-token", help="Fresh oauth2_4/... token (or pass via stdin).")
    ap.add_argument("--android-id", default=DEFAULT_ANDROID_ID,
                    help="16-hex device id for the exchange (default is fine; keep it stable).")
    ap.add_argument("--country", default="us", help="Account region (default us).")
    args = ap.parse_args()

    token = args.oauth_token or sys.stdin.readline().strip()
    if not token.startswith("oauth2_4/"):
        print("WARNING: token doesn't start with 'oauth2_4/' — did you copy the right cookie?",
              file=sys.stderr)

    try:
        res = exchange(args.email, token, args.android_id, args.country)
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
