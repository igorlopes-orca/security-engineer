---
name: security-engineer
description: Autonomous security agent — filters Orca alerts and dispatches specialist fix agents in parallel
argument-hint: "[risk_levels,feature_types] [--alert <id>] [--max N] [--dry-run] [owner/repo]"
allowed-tools: Bash, Agent
---

# Security Engineer Agent

Autonomous security remediation loop. Fetches Orca alerts, dispatches parallel specialist subagents per alert, collects results, and reports a summary.

In **live mode**: agents fix code and open PRs.
In **dry-run mode**: agents read files and describe the planned fix — but have no write tools available, so they cannot modify anything even if they try.

## Usage

```
/security-engineer                    → all open fixable alerts
/security-engineer high               → high and above, all types
/security-engineer critical,sast      → critical severity, sast type only
/security-engineer high,sast,iac      → high+, sast and iac types only
/security-engineer --dry-run high     → plan only — agents read files but cannot edit
/security-engineer --alert orca-270453        → fix one specific alert
/security-engineer --alert orca-270453 --dry-run  → plan fix for one alert
/security-engineer --max 3 high       → cap at 3 fixes
/security-engineer high igorlopes-orca/se-lab  → explicit repo
```

---

## Workflow

### Step 1: Parse arguments

Arguments: **$ARGUMENTS**

Scan $ARGUMENTS for:
- **`--dry-run`** — present or absent
- **`--alert <id>`** — specific alert ID (e.g. `orca-270453`); bypasses bulk fetch when present
- **`--max N`** — integer N, or absent
- **filter tokens** — comma-separated risk levels / feature types (e.g. `high,sast,cve`)
- **repo** — explicit `owner/repo` if present; otherwise detect with `git remote get-url origin`

Set `DRY_RUN = true` if `--dry-run` appears anywhere in $ARGUMENTS.

If `DRY_RUN == true`, announce at the start:
```
Mode: DRY-RUN — agents will read files and plan fixes, but cannot edit or create PRs.
```

### Step 2: Fetch and categorize alerts

Run:
```bash
python3 .claude/skills/security-engineer/run_agent.py list-alerts [repo] \
  [--alert <id>] [--filter <tokens>] [--max <N>] --fixable-only
```

When `--alert` is provided, pass it directly and omit `--filter` and `--max` — the script fetches only that alert by ID.

The output is a JSON object: `{"dry_run": bool, "alerts": [...]}`.

From `alerts`, bucket each item:
- **to_fix**: `is_fixable == true` AND `branch_exists == false`
- **skipped**: `is_fixable == true` AND `branch_exists == true`
- **scm_posture**: `feature_type == "scm_posture"`
- **unfixable**: other non-fixable types

Print the plan table:
```
Repository: owner/repo
Filter: <tokens or "all">

Found N alerts:
  ✓ X to fix
  ⟳ Y skipped (branch exists)
  ℹ Z scm_posture (manual action)
  ✗ W other unfixable

Planned fixes:
  1. orca-270453 — SQL Injection (high, sast) — k8s-cloudcamp/main.go:88
  2. orca-270452 — Dockerfile root user (low, iac) — k8s-cloudcamp/Dockerfile
```

If `to_fix` is empty, skip to Step 5.

### Step 3: Fetch full alert details

For each alert in `to_fix`, run:
```bash
python3 .claude/skills/security-engineer/run_agent.py get-alert <alert_id>
```

Collect the full alert JSON. This is passed to the fix agents.

### Step 4: Dispatch fix agents IN PARALLEL

Read the specialist instruction file for each alert type:
- `sast` → `.claude/skills/fix-agents/sast.md`
- `iac` → `.claude/skills/fix-agents/iac.md`
- `secret` → `.claude/skills/fix-agents/secret.md`
- `cve` → `.claude/skills/fix-agents/cve.md`

**Spawn all fix agents simultaneously** — one Agent tool call per alert, all in the same message.

**Tools to grant each agent:**
- Live mode (`DRY_RUN == false`): `Read, Edit, Write, Bash`
- Dry-run mode (`DRY_RUN == true`): `Read` only

**Agent prompt structure:**

For **live mode**:
```
You are fixing a security vulnerability. Alert details:

<full alert JSON>

Instructions:

<full contents of fix-agents/<type>.md>
```

For **dry-run mode**:
```
DRY RUN — you may only read files, not edit them.

You are planning a fix for a security vulnerability. Alert details:

<full alert JSON>

Instructions (for reference — do NOT execute any steps that write files or run git/PR commands):

<full contents of fix-agents/<type>.md>

Your task:
1. Read the source file at the path in "source" (strip the line number).
2. Identify the exact lines that need to change.
3. Show the before/after diff of what the fix would look like.
4. Explain why this fixes the vulnerability.
5. List any manual follow-up steps.
6. Return your response as a structured plan — NOT a PR URL.
```

### Step 5: Collect results and print summary

**Live mode** — each agent returns a PR URL or failure reason:

```markdown
## Security Engineer — Run Summary

**Repo:** owner/repo  |  **Mode:** Live

### Fixed — PRs Opened (N)
| Alert ID | Title | Risk | Type | PR |
|---|---|---|---|---|
| orca-270453 | SQL Injection | high | sast | https://... |

### Skipped — Branch Already Exists (N)
| Alert ID | Branch |
|---|---|

### Fix Failed (N)
| Alert ID | Reason |
|---|---|

### SCM Posture — Manual Action Required (N)
| Alert ID | Title | Risk | Action |
|---|---|---|---|
```

**Dry-run mode** — each agent returns a structured plan:

```markdown
## Security Engineer — Dry-run Plan

**Repo:** owner/repo  |  **Mode:** DRY-RUN (no files were modified)

### Planned Fixes (N)
For each alert, show the agent's planned fix:

#### orca-270453 — SQL Injection (high, sast)
**File:** k8s-cloudcamp/main.go  |  **Lines:** 88–89
**Before:**
  query := "SELECT ... WHERE username = '" + username + "'"
**After:**
  rows, err := db.Query("SELECT ... WHERE username = ?", username)
**Why:** Eliminates string concatenation that allows SQL injection.

...

### SCM Posture — Manual Action Required (N)
| Alert ID | Title | Risk | Action |
|---|---|---|---|
```

If more alerts remain past `--max`: `N more fixable alerts exist. Re-run to process more.`
