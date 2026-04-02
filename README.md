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
claude /plugin install github:igorlopes-orca/security-engineer
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

After installing, skills are namespaced under `security-engineer:`:

```
/security-engineer:security-engineer                        → all fixable alerts
/security-engineer:security-engineer high,cve               → high+ CVEs only
/security-engineer:security-engineer --alert orca-270453    → single alert
/security-engineer:security-engineer --dry-run cve          → plan only, no git ops
/security-engineer:security-engineer --remote owner/repo    → clone and fix a remote repo
/security-engineer:security-engineer --remote all           → fix all Orca-discovered repos
/security-engineer:orca-repo-risks                          → list all risks for repo
/security-engineer:orca-fix-alert orca-270453               → fix a single alert interactively
```

## Language coverage

Phase 3 of the validation pipeline runs a local build check. Build root detection uses the alert's source file path (from Orca), so subdirectory apps and monorepos are handled correctly.

| Language | Build check | Root detection |
|---|---|---|
| Go | `go build ./...` | walks up to nearest `go.mod` |
| JavaScript / TypeScript | `npm run build --if-present` | walks up to nearest `package.json` |
| Python | `python3 -m py_compile` per file | per-file, no root needed |
| Terraform | `terraform validate` | directory of the changed `.tf` file |
| Other (YAML, Dockerfile, …) | skipped | — |

If the build tool isn't installed the check is skipped (not failed) — CI in Phase 4 catches regressions.

## Plugin layout

```
.claude-plugin/plugin.json   → plugin manifest
skills/
  security-engineer/         → orchestrator, validator, agents, notifier
  fix-agents/                → fix instructions per vulnerability type (cve, sast, iac, secret)
  lib/                       → shared Orca API client
  orca-fix-alert/            → single-alert fix skill
  orca-repo-risks/           → repo risk summary skill
docs/                        → design plans
examples/                    → usage examples
```

## Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `ORCA_API_TOKEN` | Yes | Orca API token (base64 string from Orca config) |
| `NOTIFY_WEBHOOK_URL` | No | Webhook URL for Slack/Teams notifications |
