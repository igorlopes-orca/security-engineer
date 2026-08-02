# security-engineer

A Claude Code plugin that autonomously remediates Orca security alerts — from detection to merged PR.

## What it does

Fetches open Orca alerts, then for each one: creates an isolated git branch, invokes a Claude subprocess to apply the fix, runs a 4-phase validation chain, assesses production impact, opens a PR with the impact summary, and notifies via console, log, and optional webhook.

```
Orca alerts
    └─► [for each alert, parallel]
            create worktree
                └─► fix agent (Claude)
                        └─► validate: sanity → LLM → build → CI
                                └─► impact agent (Claude)
                                        └─► commit → PR → notify
    └─► summary table
```

## Installation

### Prerequisites

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) v1.0.33+
- [GitHub CLI](https://cli.github.com/) (`gh`) — authenticated
- Python 3.10+
- An [Orca Security](https://orca.security/) API token

### Install the plugin

```bash
curl -sL https://raw.githubusercontent.com/igorlopes-orca/security-engineer/main/install.sh | bash
```

Or manually:

```bash
claude plugin marketplace add igorlopes-orca/security-engineer
claude plugin install security-engineer@orca-security
```

### Set your Orca API token

```bash
export ORCA_API_TOKEN="<your-token>"
```

Optionally, for Slack/Teams notifications:

```bash
export NOTIFY_WEBHOOK_URL="https://hooks.slack.com/..."
```

## Usage

After installing, the skill is namespaced under `security-engineer:`:

```
# Fix mode — remediate alerts
/security-engineer:run                              → all fixable alerts
/security-engineer:run high,cve                     → high+ CVEs only
/security-engineer:run --alert orca-270453          → fix a single alert
/security-engineer:run --dry-run cve                → plan only, no git ops
/security-engineer:run --remote owner/repo          → clone and fix a remote repo
/security-engineer:run --remote all                 → fix all Orca-discovered repos

# Scan mode — list risks without fixing
/security-engineer:run --scan                       → list all risks for current repo
/security-engineer:run --scan high                  → list high+ risks only
/security-engineer:run --scan --remote owner/repo   → list risks for a remote repo
/security-engineer:run --scan --remote all          → list risks across all repos
```

## CVE version decisions

For a package CVE the target version is resolved before the fix agent runs, from
[OSV.dev](https://osv.dev) advisory ranges plus the published version list from
[deps.dev](https://deps.dev) — both free, unauthenticated, and cached on disk. The
agent is told which version to apply rather than asked to find it.

Policy is **minimum safe at any distance**: the lowest published release that
clears every advisory affecting the installed version, queried package-wide so a
bump cannot land on a different known CVE. A major-version jump is not refused —
some packages have no safe release inside the current major — but the distance is
measured and passed to the production-impact assessment.

Inspect any decision without a token, an alert, or a pipeline run:

```bash
python3 skills/security-engineer/run_agent.py resolve-version pypi pillow 8.3.1
```

Ecosystems: PyPI, npm, Go, Maven, Cargo, RubyGems, NuGet. See
`skills/security-engineer/SKILL.md` for the `version_data:` config keys.

## Language coverage

Each finding type runs through a pipeline (`skills/security-engineer/pipelines/`)
that owns its own post-fix check.

**CVE:** the manifest must pin the resolved version, a lockfile beside it must
agree, and the applied version must carry no known advisory. Plus `go build ./...`
(Go) or `cargo metadata --locked` (Cargo) where the toolchain is present.

**sast / iac / secret:** a local build check, with the build root detected from the
alert's source file path (from Orca), so subdirectory apps and monorepos are
handled correctly.

| Language | Build check | Root detection |
|---|---|---|
| Go | `go build ./...` | walks up to nearest `go.mod` |
| JavaScript / TypeScript | `npm run build --if-present` | walks up to nearest `package.json` |
| Python | `python3 -m py_compile` per file | per-file, no root needed |
| Terraform | `terraform validate` | directory of the changed `.tf` file |
| Other (YAML, Dockerfile, …) | skipped | — |

If the build tool isn't installed the check is skipped (not failed) — the Orca
check and CI gates catch regressions.

## Plugin layout

```
.claude-plugin/plugin.json   → plugin manifest
skills/
  security-engineer/         → orchestrator, validator, agents, notifier
    fix-agents/              → fix instructions per vulnerability type (cve, sast, iac, secret)
  lib/                       → shared Orca API client
docs/                        → design plans
examples/                    → usage examples
```

## Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `ORCA_API_TOKEN` | Yes | Orca API token (base64 string from Orca config) |
| `NOTIFY_WEBHOOK_URL` | No | Webhook URL for Slack/Teams notifications |

## Developing

Unit tests cover argument parsing and mocked branches; the pipeline that matters
— worktree lifecycle, what the validation gates actually see, whether the Orca
check gate fires — only exists in a live run. `devloop/` makes that one command:

```bash
cp devloop/.env.example devloop/.env   # fill in ORCA_API_TOKEN
make test                               # unit tests, no token or network
make fast                               # test → reset sandbox → fix one alert → report
make loop ARGS="--dry-run cve"          # plan only, no writes
```

`make fast` runs the orchestrator against a disposable sandbox repo and prints
per-alert state, PR URLs, Orca check conclusions, and the annotations behind any
failure. See [`devloop/README.md`](devloop/README.md). Nothing in `devloop/` ships
with the plugin.
