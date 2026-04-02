---
name: run
description: Autonomous security agent — Python orchestrator fixes Orca alerts with validation, impact analysis, and notifications
argument-hint: "[risk_levels,feature_types] [--scan] [--alert <id>] [--max N] [--dry-run] | --remote <owner/repo|all> [filters]"
allowed-tools: Bash
---

# Security Engineer Agent

```bash
python3 ${CLAUDE_SKILL_DIR}/orchestrator.py $ARGUMENTS
```

Return the output verbatim. If the script exits with a non-zero exit code, print the error and STOP — do not retry, do not correct arguments, do not attempt to fix the command on the user's behalf.

---

## Usage Reference

Two modes: **fix** (default) and **scan** (`--scan`).

### Fix mode — remediate alerts

```
# Local mode — operates on the repo you're already inside
/security-engineer:run                             -> all fixable alerts, all severities
/security-engineer:run cve                         -> CVE alerts only, all severities
/security-engineer:run high                        -> high+ severity, all types
/security-engineer:run high,cve                    -> high+ severity AND CVE type only
/security-engineer:run critical,sast               -> critical+ AND SAST only
/security-engineer:run --dry-run cve               -> plan CVE fixes — read-only, no git ops
/security-engineer:run --dry-run high,sast         -> plan high+ SAST fixes — no edits
/security-engineer:run --alert orca-270453         -> fix one specific alert (live)
/security-engineer:run --alert orca-270453 --dry-run -> plan one specific alert
/security-engineer:run --max 3 cve                 -> cap at 3 CVE fixes

# Remote mode — clones repos, runs full pipeline, cleans up
/security-engineer:run --remote owner/repo              -> clone owner/repo, fix all alerts
/security-engineer:run --remote owner/repo high,cve     -> clone, fix high+ CVEs only
/security-engineer:run --remote --dry-run owner/repo    -> clone, plan only, no edits
/security-engineer:run --remote all                     -> all Orca-discovered repos (clone each)
/security-engineer:run --remote all high,cve            -> all repos, high+ CVEs only
/security-engineer:run --remote all --dry-run sast      -> plan SAST fixes across all repos
/security-engineer:run --remote all --max 2 cve         -> cap at 2 CVE fixes per repo
```

### Scan mode — list risks without fixing

```
/security-engineer:run --scan                           -> list all risks, local repo
/security-engineer:run --scan high                      -> list high+ risks only
/security-engineer:run --scan sast,iac                  -> list SAST and IaC risks
/security-engineer:run --scan --remote owner/repo       -> list risks for a remote repo
/security-engineer:run --scan --remote all              -> list risks across all repos
```

## Flag Compatibility

| Flag | Fix mode | Scan mode | Notes |
|---|---|---|---|
| `filters` (positional) | Yes | Yes | `high,cve`, `sast`, etc. |
| `--dry-run` | Yes | **Error** | Scan is inherently read-only |
| `--alert <id>` | Yes | **Error** | Use `--alert` without `--scan` to fix it |
| `--max N` | Yes | **Error** | No fixing = no cap needed |
| `--remote <repo\|all>` | Yes | Yes | In scan mode: API query only, no clone |

Invalid combinations produce a clear error:
```
Error: --scan and --dry-run cannot be combined. --scan already lists alerts without fixing.
Error: --scan and --alert cannot be combined. To fix a single alert, drop --scan.
Error: --scan and --max cannot be combined. --scan lists all matching alerts.
```

## Filter Rules

**Risk levels** (cumulative — specifying `high` includes `critical` too):
- `critical` -> critical only
- `high` -> critical + high
- `medium` -> critical + high + medium
- `low` -> everything except informational

**Feature types** (exact match — only alerts of those types):
- `cve` -> package/dependency CVEs (category "Vulnerabilities")
- `sast` -> source code vulnerabilities
- `iac` -> Dockerfiles, K8s YAML, Terraform
- `secret` -> hardcoded credentials

Combine with comma: `high,cve` = high+ severity AND CVE type. Both conditions must match.

## --dry-run Guarantees

Three independent enforcement layers:
1. **Tool restriction** — claude subprocess receives `--allowedTools Read` only; Edit/Write/Bash are physically unavailable
2. **Orchestrator gate** — returns immediately after fix plan; validation, commit, and PR steps are never reached
3. **Commit guard** — `_commit_and_pr()` also checks dry_run as defense in depth

Run `python3 ${CLAUDE_SKILL_DIR}/tests/test_orchestrator.py` to verify all flags are enforced correctly.

## Pipeline (Live Mode)

### Local mode (default)

Operates on the repo you're already inside — no cloning.

```
For each alert (up to 4 in parallel, isolated git worktree per alert):

  1. create_worktree        -> /tmp/orca-fix-<id>  (isolated branch)
  2. invoke_fix_agent       -> claude subprocess, --allowedTools Read,Edit,Write,Bash
                              timeout: sast=180s, iac/secret=120s, cve=240s
                              retries: up to 2 on json_parse / subprocess errors
  3. validate (Phase 1)     -> Python: diff non-empty, diff size, no new secrets
  4. validate (Phase 2)     -> LLM: does the fix address the vulnerability?
  5. validate (Phase 3)     -> Local build (see Language Coverage below)
  6. validate (Phase 3b)    -> orca-cli before/after scan (see Orca CLI Validation below)
  7. impact_agent           -> claude subprocess: analyze diff -> production risk JSON
  8. git-commit             -> run_agent.py git-commit
  9. open-pr                -> run_agent.py open-pr (includes impact in PR body)
 10. validate (Phase 4)     -> CI gate: gh pr checks --watch (timeout: 10min)
 11. notify                 -> console + log file + GitHub PR comment
 12. remove_worktree        -> cleanup /tmp/orca-fix-<id> + local branch
```

### Remote mode (`--remote owner/repo` or `--remote all`)

Adds a repo-level wrapper around the per-alert pipeline above.

```
--remote owner/repo:
  1. gh repo clone -> /tmp/orca-global-<owner>-<repo>/  (shallow, --depth=1)
  2. fetch alerts for that repo (via Orca API)
  3. per-alert pipeline (same 11 steps above, git ops run inside the clone)
  4. shutil.rmtree -> cleanup clone (always, even on failure)

--remote all:
  1. list_repositories(token)  -> Orca CodeRepository query -> list of repos with open alerts
  2. For each repo (up to 3 in parallel):
       same 4 steps as --remote owner/repo
  3. global summary table (per-repo breakdown + totals)

Max concurrent Claude subprocesses: 3 repos x 4 alerts = 12
```

## Orca CLI Validation

Phase 3b runs a before/after `orca-cli` scan to verify the fix and detect regressions:

1. **Stash** the fix (revert to pre-fix state)
2. **Scan baseline** with the appropriate scanner
3. **Pop** the fix (re-apply)
4. **Scan again** with fix applied
5. **Compare fingerprints**: findings that disappeared = fix verified; new findings = regression

| Alert type | Scanner | Command |
|---|---|---|
| sast | SAST | `orca-cli sast scan --path <worktree>` |
| iac | IaC | `orca-cli iac scan --path <worktree>` |
| cve | SCA | `orca-cli sca scan --path <worktree>` |
| secret | Secrets | `orca-cli secrets scan --path <worktree>` |

**Pass conditions:**
- No new findings introduced by the fix
- If no findings disappeared, the PR is flagged `needs-review` (the scanner may not cover the exact alert)

**Skip conditions** (validation passes, flagged for review):
- `orca-cli` not installed
- `ORCA_SECURITY_API_TOKEN` / `ORCA_API_TOKEN` not set
- No diff to compare

**Environment:** Uses `ORCA_SECURITY_API_TOKEN` or falls back to `ORCA_API_TOKEN`. Scans use `--skip-scan-log` to avoid polluting the Orca platform.

## Language Coverage

Phase 3 (local build) runs a language-appropriate check after each fix. The build root is detected by walking up from the affected file — the path comes from the Orca alert (`source` field), so monorepos and subdirectory apps are handled correctly.

| Language | Detection | Build command | Notes |
|---|---|---|---|
| Go | nearest `go.mod` | `go build ./...` | Skipped if `go` not installed |
| JavaScript / TypeScript | nearest `package.json` | `npm run build --if-present` | Skipped if `npm` not installed; `--if-present` means no `build` script = pass |
| Python | per-file | `python3 -m py_compile <file>` | Syntax-only; no project root needed |
| Terraform | directory of `.tf` file | `terraform validate` | Skipped if `terraform` not installed |
| Dockerfile / YAML / other | — | skipped | No build check |

If the build tool is not installed, the check passes (skip, not fail) — CI in Phase 4 catches regressions.

## Notifications

Always active:
- Console output (`[OK]`, `[FAIL]`, `[TOUT]`, etc.)
- `security-engineer-run.json` — newline-delimited JSON log of all events

Opt-in:
- `NOTIFY_WEBHOOK_URL=https://...` -> HTTP POST on every event (Slack, Teams, etc.)
- GitHub PR comment with impact assessment (posted automatically after PR is opened)

## Environment Variables

| Variable | Required | Purpose |
|---|---|---|
| `ORCA_API_TOKEN` | Yes | Orca API token (base64 string from Orca config) |
| `NOTIFY_WEBHOOK_URL` | No | Webhook for Slack/Teams notifications |
