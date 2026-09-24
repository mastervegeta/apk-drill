#!/usr/bin/env python3
"""
recon_subdomains.py

Step 3 of the web recon pipeline: given a domain (or a list of apex domains),
find subdomains and report which are live — so the live ones can be fed to
js_pull.py.

    python3 scripts/recon_subdomains.py wolt.com
    python3 scripts/recon_subdomains.py --list hosts.txt -o recon_out
    python3 scripts/recon_subdomains.py wolt.com --brute --wordlist words.txt

Stages (each degrades gracefully with zero external tools):
  1. PASSIVE enum  — subfinder if installed, else crt.sh (CT logs). Always on;
     no traffic to the target.
  2. ACTIVE brute  — OFF by default (--brute). puredns if installed, else a
     builtin threaded DNS resolve over a wordlist. Sends DNS queries — only
     enable on programs whose policy permits active scanning.
  3. LIVENESS      — httpx if installed, else a builtin HTTP(S) probe. Touches
     the target lightly; --passive-only skips it.

Outputs under <out>/<domain>/: all_subdomains.txt, live_hosts.txt.

IMPORTANT — a scope listing is not authorization. Confirm the program permits
this (and active scanning, for --brute) before running.
"""

from __future__ import annotations

import argparse
import json
import shutil
import socket
import subprocess
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Small builtin wordlist so --brute works with no external file. Supply a real
# one with --wordlist for serious brute forcing.
BUILTIN_WORDS = """
www api api-dev dev staging stage test qa uat prod app apps admin portal
auth login sso account accounts secure vpn mail smtp imap webmail m mobile
static assets cdn img images media files download downloads docs help support
status blog shop store checkout pay payment payments billing dashboard console
internal intranet corp corporate partner partners merchant restaurant ops
graphql gateway proxy edge beta demo sandbox git gitlab jenkins ci grafana
kibana jira confluence vault s3 storage backup db data analytics metrics
""".split()


def run(cmd: list[str], inp: str | None = None, timeout: int = 300) -> str:
    try:
        r = subprocess.run(cmd, input=inp, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception as e:
        print(f"  {cmd[0]} failed: {e!r}", file=sys.stderr)
        return ""


def passive_crtsh(domain: str, timeout: int = 60) -> set[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        data = json.loads(urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", "replace"))
    except Exception as e:
        print(f"  crt.sh failed for {domain}: {e!r}", file=sys.stderr)
        return set()
    out: set[str] = set()
    for row in data:
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lstrip("*.").lower()
            if name.endswith("." + domain) or name == domain:
                out.add(name)
    return out


def passive_enum(domain: str) -> set[str]:
    if shutil.which("subfinder"):
        print("  passive: subfinder")
        out = run(["subfinder", "-silent", "-d", domain], timeout=300)
        subs = {l.strip().lower() for l in out.splitlines() if l.strip()}
        if subs:
            return subs
        print("  subfinder returned nothing; falling back to crt.sh", file=sys.stderr)
    else:
        print("  passive: crt.sh (subfinder not installed)")
    return passive_crtsh(domain)


def brute_enum(domain: str, wordlist: list[str], resolvers: Path | None,
               threads: int) -> set[str]:
    if shutil.which("puredns"):
        print("  brute: puredns")
        # write candidate names, let puredns resolve/validate
        names = "\n".join(f"{w}.{domain}" for w in wordlist)
        cmd = ["puredns", "resolve", "--quiet"]
        if resolvers:
            cmd += ["-r", str(resolvers)]
        out = run(cmd, inp=names, timeout=600)
        return {l.strip().lower() for l in out.splitlines() if l.strip()}
    # builtin fallback: threaded system-resolver lookups
    print(f"  brute: builtin resolver ({len(wordlist)} words, puredns not installed)")
    found: set[str] = set()

    def resolve(name: str) -> str | None:
        try:
            socket.getaddrinfo(name, None)
            return name
        except OSError:
            return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(resolve, f"{w}.{domain}"): w for w in wordlist}
        for fut in as_completed(futs):
            r = fut.result()
            if r:
                found.add(r)
    return found


def live_httpx(hosts: list[str]) -> dict[str, str]:
    """Return {url: status_label}. httpx -sc adds [status] we split off."""
    print("  liveness: httpx")
    out = run(["httpx", "-silent", "-no-color", "-sc"], inp="\n".join(hosts), timeout=600)
    live: dict[str, str] = {}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        url, _, rest = line.partition(" ")
        live[url] = rest.strip()
    return live


def live_builtin(hosts: list[str], threads: int, timeout: int) -> dict[str, str]:
    print(f"  liveness: builtin probe ({len(hosts)} hosts, httpx not installed)")
    live: dict[str, str] = {}

    def probe(host: str):
        for scheme in ("https", "http"):
            try:
                req = urllib.request.Request(f"{scheme}://{host}/",
                                             headers={"User-Agent": _UA}, method="GET")
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    return f"{scheme}://{host}", f"[{r.status}]"
            except urllib.error.HTTPError as e:
                return f"{scheme}://{host}", f"[{e.code}]"  # responded, just an error status
            except Exception:
                continue
        return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(probe, h): h for h in hosts}
        for fut in as_completed(futs):
            r = fut.result()
            if r:
                live[r[0]] = r[1]
    return live


def process(domain: str, args) -> None:
    domain = domain.strip().lower().lstrip("*.")
    if not domain:
        return
    print(f"[{domain}]")
    subs = passive_enum(domain)
    print(f"  passive: {len(subs)} name(s)")
    if args.brute:
        words = (Path(args.wordlist).read_text().split() if args.wordlist else BUILTIN_WORDS)
        b = brute_enum(domain, words, args.resolvers, args.threads)
        new = b - subs
        subs |= b
        print(f"  brute: +{len(new)} new (total {len(subs)})")

    outdir = args.out / domain
    outdir.mkdir(parents=True, exist_ok=True)
    all_sorted = sorted(subs)
    (outdir / "all_subdomains.txt").write_text("\n".join(all_sorted) + "\n", encoding="utf-8")

    if args.passive_only:
        print(f"  wrote {len(all_sorted)} subdomains (liveness skipped) -> {outdir}/")
        return

    live = (live_httpx(all_sorted) if shutil.which("httpx")
            else live_builtin(all_sorted, args.threads, args.timeout))
    # clean URLs (feed straight into js_pull) + a detail file with statuses
    (outdir / "live_hosts.txt").write_text("\n".join(sorted(live)) + "\n", encoding="utf-8")
    (outdir / "live_detail.txt").write_text(
        "\n".join(f"{u} {live[u]}".strip() for u in sorted(live)) + "\n", encoding="utf-8")
    print(f"  live: {len(live)}/{len(all_sorted)} -> {outdir}/live_hosts.txt")


def main() -> int:
    ap = argparse.ArgumentParser(description="Find subdomains and probe which are live.")
    ap.add_argument("domain", nargs="?", help="Apex domain, e.g. wolt.com")
    ap.add_argument("--list", type=Path, help="File of apex domains (one per line).")
    ap.add_argument("-o", "--out", type=Path, default=Path("recon_out"))
    ap.add_argument("--brute", action="store_true",
                    help="Also active DNS brute (OFF by default; needs policy permission).")
    ap.add_argument("--wordlist", help="Wordlist for --brute (default: small builtin list).")
    ap.add_argument("--resolvers", type=Path, help="Resolvers file for puredns.")
    ap.add_argument("--passive-only", action="store_true", help="Skip the liveness probe.")
    ap.add_argument("--threads", type=int, default=40)
    ap.add_argument("--timeout", type=int, default=8)
    args = ap.parse_args()

    domains: list[str] = []
    if args.domain:
        domains.append(args.domain)
    if args.list:
        domains += [l.strip() for l in args.list.read_text().splitlines()
                    if l.strip() and not l.startswith("#")]
    if not domains:
        ap.error("give a domain or --list")

    for d in dict.fromkeys(domains):  # dedupe, keep order
        process(d, args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
