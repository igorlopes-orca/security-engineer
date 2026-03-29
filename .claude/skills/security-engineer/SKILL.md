---
name: security-engineer
description: Autonomous security agent — Python orchestrator fixes Orca alerts with validation, impact analysis, and notifications
argument-hint: "[risk_levels,feature_types] [--alert <id>] [--max N] [--dry-run] [owner/repo]"
allowed-tools: Bash
---

# Security Engineer Agent

```bash
python3 .claude/skills/security-engineer/orchestrator.py $ARGUMENTS
```

Return the output verbatim.

---

## Usage Reference

```
/security-engineer                             → all fixable alerts, all severities
/security-engineer cve                         → CVE alerts only, all severities
/security-engineer high                        → high+ severity, all types
/security-engineer high,cve                    → high+ severity AND CVE type only
/security-engineer critical,sast               → critical+ AND SAST only
/security-engineer --dry-run cve               → plan CVE fixes — read-only, no git ops
/security-engineer --dry-run high,sast         → plan high+ SAST fixes — no edits
/security-engineer --alert orca-270453         → fix one specific alert (live)
/security-engineer --alert orca-270453 --dry-run → plan one specific alert
/security-engineer --max 3 cve                 → cap at 3 CVE fixes
/security-engineer cve owner/repo              → target explicit repo
```

## Filter Rules

**Risk levels** (cumulative — specifying `high` includes `critical` too):
- `critical` → critical only
- `high` → critical + high
- `medium` → critical + high + medium
- `low` → everything except informational

**Feature types** (exact match — only alerts of those types):
- `cve` → package/dependency CVEs (category "Vulnerabilities")
- `sast` → source code vulnerabilities
- `iac` → Dockerfiles, K8s YAML, Terraform
- `secret` → hardcoded credentials

Combine with comma: `high,cve` = high+ severity AND CVE type. Both conditions must match.

## --dry-run Guarantees

Three independent enforcement layers:
1. **Tool restriction** — claude subprocess receives `--allowedTools Read` only; Edit/Write/Bash are physically unavailable
2. **Orchestrator gate** — returns immediately after fix plan; validation, commit, and PR steps are never reached
3. **Commit guard** — `_commit_and_pr()` also checks dry_run as defense in depth

Run `python3 .claude/skills/security-engineer/tests/test_orchestrator.py` to verify all flags are enforced correctly.

## Pipeline (Live Mode)

```
For each alert (parallel, isolated git worktree per alert):

  1. create_worktree        → /tmp/orca-fix-<id>  (isolated branch)
  2. invoke_fix_agent       → claude subprocess, --allowedTools Read,Edit,Write,Bash
                              timeout: sast=180s, iac/secret=120s, cve=240s
                              retries: up to 2 on json_parse / subprocess errors
  3. validate (Phase 1)     → Python: diff non-empty, diff size, no new secrets
  4. validate (Phase 2)     → LLM: does the fix address the vulnerability?
  5. validate (Phase 3)     → Local build: go build / py_compile / npm build
  6. impact_agent           → claude subprocess: analyze diff → production risk JSON
  7. git-commit             → run_agent.py git-commit
  8. open-pr                → run_agent.py open-pr (includes impact in PR body)
  9. validate (Phase 4)     → CI gate: gh pr checks --watch (timeout: 10min)
 10. notify                 → console + log file + GitHub PR comment
 11. remove_worktree        → cleanup /tmp/orca-fix-<id> + local branch
```

## Notifications

Always active:
- Console output (`[OK]`, `[FAIL]`, `[TOUT]`, etc.)
- `security-engineer-run.json` — newline-delimited JSON log of all events

Opt-in:
- `NOTIFY_WEBHOOK_URL=https://...` → HTTP POST on every event (Slack, Teams, etc.)
- GitHub PR comment with impact assessment (posted automatically after PR is opened)

## Environment Variables

| Variable | Required | Purpose |
|---|---|---|
| `ORCA_API_TOKEN` | Yes | Orca API token (base64 string from Orca config) |
| `NOTIFY_WEBHOOK_URL` | No | Webhook for Slack/Teams notifications |
