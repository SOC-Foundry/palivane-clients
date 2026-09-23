#!/usr/bin/env python3
"""Palivane git capture plane — scan changed files for secrets & PII before they reach a repo.

One script, two uses:
  • pre-commit hook   — scans staged files, blocks the commit on a secret/PII finding.
  • CI (GitHub Action) — scans a PR's changed files, fails the check.

It calls the Palivane backend's `POST /api/scan/code` (the detection engine; no secrets
logic lives here). Stdlib only — no pip install.

Config (env):
  PALIVANE_URL    Palivane backend base URL          (or --url)
  PALIVANE_TOKEN  a per-tenant API key (ak_…)       (env only, never a CLI flag)

Usage:
  palivane_git_scan.py --staged                 # default: staged changes (pre-commit)
  palivane_git_scan.py --range origin/main..HEAD  # a diff range (CI)
  palivane_git_scan.py path/a.py path/b.env       # explicit files

Exit codes: 0 = clean/allowed (warns by default), 1 = a blocking finding (or any
finding with --strict). On a backend/network error it fails OPEN (exit 0) unless
--fail-closed is given (recommended for CI).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

MAX_BYTES = 1_000_000   # skip files larger than this (likely data/blobs, not source)


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout


def _changed(mode: str, rng: str) -> list[str]:
    if mode == "staged":
        out = _git("diff", "--cached", "--name-only", "--diff-filter=ACM", "-z")
    elif mode == "all":
        out = _git("ls-files", "-z")          # every tracked file — whole-repo sweep
    else:
        out = _git("diff", "--name-only", "--diff-filter=ACM", "-z", *rng.split())
    return [p for p in out.split("\0") if p]


def _content(path: str, mode: str) -> str | None:
    """Read a file's content: the staged blob in staged mode, else the working tree."""
    try:
        if mode == "staged":
            raw = subprocess.run(["git", "show", f":{path}"], capture_output=True, check=True).stdout
        else:
            with open(path, "rb") as fh:
                raw = fh.read()
    except (subprocess.CalledProcessError, OSError):
        return None
    if len(raw) > MAX_BYTES:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None    # binary — skip


def main() -> int:
    ap = argparse.ArgumentParser(description="Scan changed files for secrets & PII via Palivane.")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--staged", action="store_true", help="scan staged changes (default)")
    g.add_argument("--range", dest="rng", help="scan a git diff range, e.g. origin/main..HEAD")
    g.add_argument("--all", action="store_true", help="scan every tracked file (whole repo)")
    ap.add_argument("files", nargs="*", help="explicit files to scan")
    ap.add_argument("--url", default=os.getenv("PALIVANE_URL", "http://localhost:8088"))
    ap.add_argument("--strict", action="store_true", help="fail on warn findings too")
    ap.add_argument("--fail-closed", action="store_true", help="fail if the backend is unreachable")
    ap.add_argument("--record", action="store_true", help="persist findings in Palivane")
    args = ap.parse_args()

    token = os.getenv("PALIVANE_TOKEN", "")
    if not token:
        print("palivane: PALIVANE_TOKEN is not set — skipping scan.", file=sys.stderr)
        return 1 if args.fail_closed else 0

    mode = "all" if args.all else ("range" if args.rng else "staged")
    paths = args.files or _changed(mode, args.rng or "")
    files = [{"path": p, "content": c} for p in paths if (c := _content(p, mode)) is not None]
    if not files:
        return 0

    payload = json.dumps({"files": files, "record": args.record}).encode()
    req = urllib.request.Request(
        args.url.rstrip("/") + "/api/scan/code", data=payload, method="POST",
        headers={"content-type": "application/json", "X-Palivane-Token": token},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            result = json.loads(r.read())
    except urllib.error.HTTPError as e:
        print(f"palivane: backend returned HTTP {e.code} — {e.read().decode('utf-8', 'replace')[:200]}",
              file=sys.stderr)
        return 1 if args.fail_closed else 0
    except (urllib.error.URLError, OSError, ValueError) as e:
        print(f"palivane: could not reach backend ({e}). {'Failing closed.' if args.fail_closed else 'Failing open.'}",
              file=sys.stderr)
        return 1 if args.fail_closed else 0

    flagged = result.get("files", [])
    if not flagged:
        print(f"palivane: scanned {result.get('scanned', len(files))} file(s) — clean ✓")
        return 0

    blocking = False
    print(f"\n  ⚠ Palivane found sensitive data in {len(flagged)} file(s):\n")
    for f in flagged:
        mark = "🔴 BLOCK" if f["action"] == "block" else "🟠 WARN "
        cats = ", ".join(dict.fromkeys(s["category"] for s in f.get("signals", [])))
        ev = "; ".join(s.get("evidence", "") for s in f.get("signals", []) if s.get("evidence"))
        print(f"  {mark}  {f['path']}  [{cats}]  {('— ' + ev) if ev else ''}")
        if f["action"] == "block" or args.strict:
            blocking = True
    print()

    if blocking:
        print("  Commit blocked. Remove the secret/PII (and rotate any exposed key), or override\n"
              "  with `git commit --no-verify` if this is a false positive.\n", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
