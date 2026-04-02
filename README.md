# security-engineer

A Claude Code skill that autonomously remediates Orca security alerts — from detection to merged PR.

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

## Usage

```
/security-engineer                        → all fixable alerts
/security-engineer high,cve               → high+ CVEs only
/security-engineer --alert orca-270453    → single alert
/security-engineer --dry-run cve          → plan only, no git ops
```

See `.claude/skills/security-engineer/SKILL.md` for the full reference.

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

## Repository layout

```
.claude/skills/security-engineer/   → orchestrator, validator, agents, notifier
.claude/skills/fix-agents/          → fix instructions per vulnerability type (cve, sast, iac, secret)
.claude/skills/orca-fix-alert/      → single-alert fix skill
.claude/skills/orca-repo-risks/     → repo risk summary skill
examples/                           → usage examples
k8s-cloudcamp/                      → unrelated workload (to be moved out)
```
