# Rule: the per-host endpoint inventory

The endpoint inventory is the single source of truth that connects **recon** to
**active testing**. Recon writes it; the prober reads it. Every AI or script
doing recon on a project MUST maintain it in this exact shape.

## Layout — one directory per project, one file per host

```
projects/<program>/
  endpoints/
    api.example.live          # filename == the host, literally
    search-api.example.live
    portal.example.live
  probe_targets.json          # scope + identities for probe_authz.py
  authz_findings.jsonl        # prober output
```

## File format — one path per line

A host file is named **exactly** after the host (no scheme, no port unless the
service actually uses one, e.g. `api.example.live:8443`). Each line is a request
path beginning with `/`:

```
# api.example.live
/users
/users/create
/users/{id}          # keep template segments as-is; the prober skips {..} but they document surface
/orders
/orders/{id}/invoice
POST /users/create   # optional leading METHOD; default is the target's methods (GET)
```

Rules:
- **Path only** — no host, no scheme, no query string. One path per line.
- A line may start with an HTTP method (`GET` `POST` …); without one, the
  prober uses the target's configured methods (GET by default).
- Lines starting with `#` are comments; blank lines are ignored.
- The **filename is the authority**: never put a path under a host it doesn't
  belong to.

## Who writes it

Any recon source appends to the right host file:
- **APK surface** — `endpoints_from_surface.py surface.jsonl -o endpoints/`
- **JS pulls, mitmproxy/Burp logs, crawlers** — normalize each observed request
  to `(host, path)` and merge it in the same way.

Writes are **additive and de-duplicated**: re-running recon merges new paths
into existing files and keeps them sorted-unique. Nothing is lost between runs,
so the inventory only grows as you learn more surface.

## Who reads it

`probe_authz.py --endpoints-dir projects/<program>/endpoints --config projects/<program>/probe_targets.json`

The prober reconstructs `https://<host><path>` for each in-scope host and
replays it under `none / A / B`. Scope is still enforced at probe time: a host
is only touched if it matches an `allow_hosts` glob of a target whose
`active_testing_permitted` is `true`. So the inventory can be broad; the config
decides what is actually hit.

## Why this shape

- **Decoupled** — discovery and testing evolve independently; add a new recon
  source without touching the prober.
- **Diffable** — the inventory is plain text under version control, so
  newly-appeared paths after an app update stand out in a `git diff` (feeds the
  n-day workflow).
- **Reviewable** — a human can read `endpoints/api.example.live` and instantly
  see the attack surface before anything is sent.
