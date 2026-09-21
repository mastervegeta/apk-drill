# Running apk-drill on a shared server

Notes for running scans on a box that already has other workloads (a home
server, a VPS you also use for something else). Nothing here is required for a
laptop run.

## Resource shape of a scan

Per package, roughly:

| Phase | Cost |
|---|---|
| `apkeep` download | network-bound, tens of MB to a few hundred MB |
| unzip/extract | disk-bound; extracted tree is typically 1.5–3× the APK |
| `trufflehog` | **CPU-bound and parallel by default** — it will happily use every core |

Packages are processed **one at a time** and the scratch directory is deleted
after each one (unless `--keep-files`), so peak disk is one package, not the
whole list. CPU is the contended resource, not disk.

## Keep it off the other workload's cores

TruffleHog fans out across all cores. On a box running something latency- or
thermally-sensitive, cap it:

```bash
systemd-run --user --scope -p CPUQuota=400% -p MemoryMax=4G \
    nice -n 15 python3 apk_secret_scan.py packages.txt -o results_latest.jsonl --only-verified
```

`CPUQuota=400%` is four cores' worth. Add `ionice -c3` in front of `nice` if the
extract phase is competing with a database for disk.

Simplest version, if you just want it deprioritized:

```bash
nice -n 19 ionice -c3 python3 apk_secret_scan.py packages.txt -o results_latest.jsonl --only-verified
```

## Put the scratch dir where there's room

`--workdir` defaults to `._apk_work` next to the script. Point it at whatever
volume has space:

```bash
python3 apk_secret_scan.py packages.txt --workdir /var/tmp/apk-drill -o results_latest.jsonl --only-verified
```

## Long runs: detach

A list of any size outlives an SSH session. Use tmux or screen:

```bash
tmux new -s apkdrill
```

Run the scan inside, then detach with `ctrl-b d` and reattach later with
`tmux attach -t apkdrill`. The results file is append-mode and flushed per
package, so a dropped connection or a `ctrl-c` loses at most the package in
flight — rerunning the same list just appends.

## Watching it

```bash
tail -f results_latest.jsonl | python3 -c "import sys,json;[print(json.loads(l).get('package'), json.loads(l).get('detector') or json.loads(l).get('status')) for l in sys.stdin]"
```

## Don't leave findings lying around

`results_latest.jsonl` and `report.md` contain redacted secrets, package names,
and your scan history. They're gitignored, but on a shared box also consider:

- keeping them in a mode-700 directory
- deleting them once the report is filed
- never committing a real `packages.txt` — only `packages.example.txt` ships

## Scheduling

If you scan the same in-scope list periodically, a user-level timer beats cron
for portability and logging:

```bash
systemd-run --user --on-calendar='weekly' --unit=apk-drill \
    /path/to/venv-or-python3 /path/to/apk_secret_scan.py /path/to/packages.txt \
    -o /path/to/results_latest.jsonl --only-verified
```

Check it with `systemctl --user list-timers apk-drill` and read output with
`journalctl --user -u apk-drill`.

Re-confirm scope before every scheduled run — bug-bounty program scope changes,
and an automated scan doesn't notice that a target left the program.
