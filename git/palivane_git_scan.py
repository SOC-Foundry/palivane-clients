#!/usr/bin/env python3
"""Palivane git capture plane — scan changed files for secrets & PII before they reach a repo.

One script, two uses:
  • pre-commit hook   — scans staged files, blocks the commit on a secret/PII finding.
  • CI (GitHub Action) — scans a PR's changed files, fails the check.

It calls the Palivane backend's `POST /api/scan/code` (the detection engine; no secrets
logic lives here), and — when a dependency manifest changed (package.json,
requirements*.txt) — `POST /api/scan/deps` for supply-chain risk: install-script abuse,
non-registry sources, known-bad packages. `--no-deps` skips that. Stdlib only.

Config (env):
  PALIVANE_URL    Palivane backend base URL          (or --url)
  PALIVANE_TOKEN  a per-tenant API key (ak_…)       (env only, never a CLI flag)

Usage:
  palivane_git_scan.py --staged                 # default: staged changes (pre-commit)
  palivane_git_scan.py --range origin/main..HEAD  # a diff range (CI)
  palivane_git_scan.py path/a.py path/b.env       # explicit files

Exit codes: 0 = clean/allowed (warns by default), 1 = a blocking finding (or any
finding with --strict). On a backend/network error it fails OPEN (exit 0) unless
--fail-closed is given (recommended for CI). Renamed files are scanned; binary files
are skipped; a file over 1 MB is scanned up to 1 MB with a warning. With --fail-closed,
a file that could not be read or was only partly scanned also fails the run.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

MAX_BYTES = 1_000_000   # scan at most this much of a file; larger files are truncated (with a warning)
_BINARY_SNIFF = 8192    # a NUL byte in this prefix marks a file as binary (images, archives, ...)
# The manifests /api/scan/deps understands (dep_guard): npm's package.json and pip's
# requirements files. Matched on the file name, in any directory.
_MANIFEST = re.compile(r"(?:^|/)(?:package\.json|requirements[\w.-]*\.txt)$", re.I)


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout


def _changed(mode: str, rng: str) -> list[str]:
    if mode == "staged":
        out = _git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
    elif mode == "all":
        out = _git("ls-files", "-z")          # every tracked file — whole-repo sweep
    else:
        out = _git("diff", "--name-only", "--diff-filter=ACMR", "-z", *rng.split())
    return [p for p in out.split("\0") if p]


def _content(path: str, mode: str) -> tuple[str | None, str | None]:
    """Read a file's content: the staged blob in staged mode, else the working tree.

    Returns (content, problem). content is None when the file is skipped; problem is a
    human-readable reason when the file was skipped or only partly scanned, None otherwise.
    Binary files (a NUL byte near the start) are skipped without a problem: they are not
    source. Non-UTF-8 text is decoded with replacement characters rather than dropped, and an
    oversized file is scanned up to MAX_BYTES rather than skipped.
    """
    try:
        if mode == "staged":
            raw = subprocess.run(["git", "show", f":{path}"], capture_output=True, check=True).stdout
        else:
            with open(path, "rb") as fh:
                raw = fh.read()
    except (subprocess.CalledProcessError, OSError) as e:
        return None, f"could not read ({e.__class__.__name__})"
    if b"\0" in raw[:_BINARY_SNIFF]:
        return None, None    # binary — not source, nothing to scan
    problem = None
    if len(raw) > MAX_BYTES:
        problem = f"larger than {MAX_BYTES:,} bytes ({len(raw):,}); only the first {MAX_BYTES:,} were scanned"
        raw = raw[:MAX_BYTES]
    return raw.decode("utf-8", errors="replace"), problem


def _post(url: str, endpoint: str, token: str, body: dict, fail_closed: bool):
    """(result, None) on success, or (None, exit_code) after printing why it failed."""
    req = urllib.request.Request(
        url.rstrip("/") + endpoint, data=json.dumps(body).encode(), method="POST",
        headers={"content-type": "application/json", "X-Palivane-Token": token},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read()), None
    except urllib.error.HTTPError as e:
        print(f"palivane: backend returned HTTP {e.code} — {e.read().decode('utf-8', 'replace')[:200]}",
              file=sys.stderr)
    except (urllib.error.URLError, OSError, ValueError) as e:
        print(f"palivane: could not reach backend ({e}). {'Failing closed.' if fail_closed else 'Failing open.'}",
              file=sys.stderr)
    return None, (1 if fail_closed else 0)


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
    ap.add_argument("--no-deps", action="store_true",
                    help="don't vet changed dependency manifests (package.json, requirements*.txt)")
    args = ap.parse_args()

    token = os.getenv("PALIVANE_TOKEN", "")
    if not token:
        print("palivane: PALIVANE_TOKEN is not set — skipping scan.", file=sys.stderr)
        return 1 if args.fail_closed else 0

    mode = "all" if args.all else ("range" if args.rng else "staged")
    paths = args.files or _changed(mode, args.rng or "")
    files, incomplete = [], []
    for p in paths:
        content, problem = _content(p, mode)
        if problem:
            incomplete.append(p)
            print(f"palivane: WARNING {p}: {problem}.", file=sys.stderr)
        if content is not None:
            files.append({"path": p, "content": content})
    # With --fail-closed a file that was not (fully) scanned is a failure, never a silent pass.
    gap = 1 if (incomplete and args.fail_closed) else 0
    if gap:
        print(f"palivane: {len(incomplete)} file(s) could not be fully scanned. Failing closed.",
              file=sys.stderr)
    if not files:
        return gap

    result, rc = _post(args.url, "/api/scan/code", token,
                       {"files": files, "record": args.record}, args.fail_closed)
    if result is None:
        return rc
    flagged = list(result.get("files", []))

    # Dependency manifests among the changed files also get the supply-chain check.
    manifests = [] if args.no_deps else [f for f in files if _MANIFEST.search(f["path"])]
    if manifests:
        deps, rc = _post(args.url, "/api/scan/deps", token,
                         {"files": manifests, "record": args.record}, args.fail_closed)
        if deps is None:
            return rc
        flagged += deps.get("files", [])

    if not flagged:
        extra = f", {len(manifests)} dependency manifest(s) vetted" if manifests else ""
        print(f"palivane: scanned {result.get('scanned', len(files))} file(s){extra} — clean ✓")
        return gap

    blocking = False
    print(f"\n  ⚠ Palivane flagged {len(flagged)} file(s):\n")
    for f in flagged:
        mark = "🔴 BLOCK" if f["action"] == "block" else "🟠 WARN "
        cats = ", ".join(dict.fromkeys(s["category"] for s in f.get("signals", [])))
        ev = "; ".join(s.get("evidence", "") for s in f.get("signals", []) if s.get("evidence"))
        print(f"  {mark}  {f['path']}  [{cats}]  {('— ' + ev) if ev else ''}")
        if f["action"] == "block" or args.strict:
            blocking = True
    print()

    if blocking:
        print("  Commit blocked. Remove the secret/PII (and rotate any exposed key) or the risky\n"
              "  dependency, or override with `git commit --no-verify` if this is a false positive.\n",
              file=sys.stderr)
        return 1
    return gap


if __name__ == "__main__":
    sys.exit(main())
