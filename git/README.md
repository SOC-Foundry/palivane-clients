# Palivane git capture plane (pre-commit + CI)

Stops **secrets and PII from reaching your repos** — the boundary the gateway/extension/
proxy don't cover. One scanner script ([`palivane_git_scan.py`](./palivane_git_scan.py),
stdlib only) runs two ways:

- **pre-commit hook** — scans *staged* files, blocks the commit on a secret/PII finding.
- **GitHub Action** — scans a PR's changed files, fails the check (the enforceable gate).

Both call the backend's `POST /api/scan/code`, which reuses Palivane's detection engine but
**ignores `source_code_leak`** (a repo is meant to hold code) and keeps **secrets + PII**.
Findings can optionally be recorded to the console (`--record`).

> This **complements** GitHub's native Secret Scanning push protection — use that as the
> primary secrets gate; Palivane adds your custom patterns, PII coverage, and one policy/
> console across AI egress *and* commits.

## Credentials

Mint a per-tenant **API key** (`ak_…`) in the console's **Connect** page and expose it to
the scanner:

```bash
export PALIVANE_URL=https://palivane.corp.example.com
export PALIVANE_TOKEN=ak_xxx          # never hard-code; use a secret store / CI secret
```

## Pre-commit hook

**With the [pre-commit](https://pre-commit.com) framework** — in the repo you want to
protect, add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/SOC-Foundry/palivane-clients
    rev: main                       # pin to a tag/SHA in real use
    hooks:
      - id: palivane-secret-scan
```

```bash
pre-commit install
```

**Or a plain git hook** — copy the scanner and call it from `.git/hooks/pre-commit`:

```bash
#!/usr/bin/env bash
exec python3 /path/to/palivane_git_scan.py --staged
```

A blocked commit prints the offending files and exits non-zero. Override a false positive
with `git commit --no-verify` (and consider tuning patterns instead). Local hooks **fail
open** if the backend is unreachable (pass `--fail-closed` to change that).

## GitHub Action (the enforceable gate)

Add a workflow to the repo you want to protect — pairs with branch protection so a
failing scan blocks merge:

```yaml
# .github/workflows/palivane-secret-scan.yml
name: Palivane secret & PII scan
on: pull_request
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }        # full history so the PR range diffs correctly
      - uses: SOC-Foundry/Palivane/git@main
        with:
          palivane-url: https://palivane.corp.example.com
          palivane-token: ${{ secrets.PALIVANE_TOKEN }}
          # strict: "true"               # also fail on warn-level findings
```

The Action scans `base..head` of the PR and **fails closed** (a backend outage fails the
check rather than letting a secret through).

## Using your existing scanner in CI (TruffleHog / Gitleaks / GitGuardian)

Already run TruffleHog, Gitleaks, or GitGuardian in CI? Keep them — pipe their JSON to
[`palivane-import`](../cli/README.md) and the findings land in the **same Palivane console**,
scored and deduped alongside every other plane, with alerts + SIEM export. The raw secret
is masked at ingest (never persisted), and TruffleHog's **live verification** escalates a
confirmed-working credential to critical. `palivane-import` exits non-zero when any
verified-live secret is found, so it fails the build:

```yaml
# .github/workflows/palivane-scanner-import.yml
name: Secret scan → Palivane
on: pull_request
jobs:
  scan:
    runs-on: ubuntu-latest
    env:
      PALIVANE_URL: https://palivane.corp.example.com
      PALIVANE_TOKEN: ${{ secrets.PALIVANE_TOKEN }}
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      # bring palivane-import onto PATH (from this repo, or vendor cli/palivane-import)
      - run: curl -sSL https://raw.githubusercontent.com/SOC-Foundry/Palivane/main/cli/palivane-import -o /usr/local/bin/palivane-import && chmod +x /usr/local/bin/palivane-import
      - uses: trufflesecurity/trufflehog@main
        with: { extra_args: --json }          # or run any scanner that emits JSON
      # pipe the scanner's JSON to Palivane (trufflehog | gitleaks | gitguardian)
      - run: trufflehog git file://. --json | palivane-import trufflehog
```

This is complementary to the native Action above: use `SOC-Foundry/Palivane/git@main`
for a Palivane-engine gate, and `palivane-import` to fold in whatever scanners you already run.
On endpoints (not CI), the same integration is `palivane-secrets --engine trufflehog`, which
the MDM pack schedules for you.

## One-time history sweep (secrets already committed)

The pre-commit hook and the PR Action catch secrets going **forward** (staged / changed
files). To find what's **already buried in a repo's history**, do a one-off sweep — a
history scanner walks every commit and blob, and `palivane-import` lands the hits in the
console:

```bash
export PALIVANE_URL=https://palivane.corp.example.com PALIVANE_TOKEN=ak_…

# TruffleHog (scans full git history + verifies live credentials):
trufflehog git file://. --json                     | palivane-import trufflehog

# or Gitleaks (scans history by default):
gitleaks detect --report-format json -o /dev/stdout . | palivane-import gitleaks

# sweep every repo under a directory:
for r in ~/src/*/.git; do (cd "$r/.." && trufflehog git file://. --json | palivane-import trufflehog); done
```

> **A secret found in history is already compromised** — it was pushed to a remote, so
> rewriting history (`git filter-repo`, BFG) is *cleanup*, not remediation. **Rotate and
> revoke the credential first**; the console finding's "How to fix" says the same.

## Whole-repo, org-wide & S3 sweeps

The hook and PR Action scan **what changes**. To sweep **existing contents** at rest:

```bash
export PALIVANE_URL=https://palivane.corp.example.com PALIVANE_TOKEN=ak_…

# Every tracked file in the current checkout (not just the diff):
palivane_git_scan.py --all --record

# Every repo in a GitHub org (or --user, or explicit --repo owner/name), via the API —
# no local clone needed. Skips archived/fork repos by default.
GITHUB_TOKEN=ghp_… palivane-github-scan --org acme --record
GITHUB_TOKEN=ghp_… palivane-github-scan --repo acme/api --repo acme/web

# An S3 bucket's objects, plus whether the bucket is publicly reachable (public + sensitive
# is escalated to a hard block). AWS creds come from the standard boto3 chain.
palivane-s3-scan my-data-bucket --prefix exports/ --record
```

`palivane-github-scan` and `palivane-s3-scan` are ops/admin tools — run them from CI or a
security box (download from `<console>/cli/<name>`); they aren't installed on every
developer machine. Both fail **open** by default; add `--fail-closed` in a pipeline.

**Run them on a schedule** (they don't auto-run — nothing triggers them until you do):

- **Org sweep, scheduled GitHub Action** — copy [`palivane-org-scan.yml`](./palivane-org-scan.yml)
  into a repo as `.github/workflows/palivane-org-scan.yml`. It runs `palivane-github-scan --org`
  on a cron (weekly by default) + on demand. Set `PALIVANE_TOKEN` and an org-repo-read
  `PALIVANE_ORG_READ_TOKEN` as secrets (the built-in `GITHUB_TOKEN` only sees the current repo).
- **CI-runner posture scan** — copy [`palivane-ci-scan.yml`](./palivane-ci-scan.yml) into a repo
  as `.github/workflows/palivane-ci-scan.yml`. It runs `palivane-ci-scan` against the repo's own
  workflows (PR gate on workflow changes + weekly), flagging pwn-request triggers, unpinned
  third-party actions, `write-all` permissions, `secrets: inherit`, self-hosted runners on PR
  triggers, and AI agents running in CI (plus non-model secrets handed to them). It can
  authenticate with the runner's **OIDC token** (`--github-oidc`, needs `id-token: write`) —
  no long-lived Palivane secret in the repo. `palivane-ci-scan --org acme` sweeps a whole org.
- **S3 sweep, systemd timer** — the instanced unit
  [`deploy/palivane-s3-scan@.timer`](../deploy/palivane-s3-scan@.timer) runs one scan per bucket
  daily. Enable per bucket: `systemctl enable --now palivane-s3-scan@my-bucket.timer`. See
  [`deploy/README.md`](../deploy/README.md#scheduled-s3-scanning).

> These are **content** sweeps (secrets/PII in current files & objects), complementary to
> the git-**history** sweep above. For secrets buried in old commits, use the history
> scanners in the previous section.

## Other CI systems (GitLab / Bitbucket / Jenkins / …)

The GitHub Action is GitHub-specific, but the scanner is host-agnostic — run
`palivane_git_scan.py --range` in any pipeline (it needs Python 3 and the repo checked out
with history). Fail the job closed so a leak blocks the merge.

**GitLab CI** (`.gitlab-ci.yml`):
```yaml
palivane-secret-scan:
  image: python:3.12-slim
  variables: { PALIVANE_URL: "https://palivane.corp.example.com" }   # PALIVANE_TOKEN via a masked CI variable
  script:
    - curl -sSL https://raw.githubusercontent.com/SOC-Foundry/Palivane/main/git/palivane_git_scan.py -o palivane_git_scan.py
    - python3 palivane_git_scan.py --range "origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME...HEAD" --fail-closed --record
```

**Generic / Bitbucket / Jenkins** — same idea, adjust the diff range to your platform's
base ref:
```bash
python3 palivane_git_scan.py --range "origin/main...HEAD" --fail-closed --record
```

## Scanner CLI

```
palivane_git_scan.py [--staged | --range A..B | <files…>] [--strict] [--fail-closed] [--record]
```

| Flag | Meaning |
| --- | --- |
| `--staged` | Scan staged changes (default; pre-commit). |
| `--range A..B` | Scan files changed in a diff range (CI). |
| `--strict` | Exit non-zero on **warn** findings too, not just blocks. |
| `--fail-closed` | Treat a backend/network error as a failure (recommended for CI). |
| `--record` | Persist findings to the Palivane console. |

Exit `0` = clean/allowed, `1` = blocking finding (or any finding with `--strict`). Binary
and >1 MB files are skipped.
