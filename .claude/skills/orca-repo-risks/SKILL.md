---
name: orca-repo-risks
description: Identify all Orca security risks for a GitHub repository
argument-hint: "[owner/repo] [--level high] [--types sast,iac]"
disable-model-invocation: true
allowed-tools: Bash
---

# Orca Repo Risks Skill

Identify all Orca security risks for a GitHub repository via the Orca API.

## Usage
- `/orca-repo-risks` — auto-detect repo from current git remote
- `/orca-repo-risks owner/repo` — explicit target
- `/orca-repo-risks --level high` — high and above only
- `/orca-repo-risks --types sast,cve` — filter by feature type

## Workflow

### Step 1: Run the alerts script

Pass all arguments directly to the script — it handles repo detection automatically:

```bash
python3 .claude/skills/orca-repo-risks/orca_alerts.py $ARGUMENTS
```

The script reads `ORCA_API_TOKEN` or `ORCA_AUTH_TOKEN` from the environment.

### Step 2: Present the output

Return the script output as-is. It is a formatted markdown report with alert counts and tables grouped by risk level, including a Type column showing feature type (sast/iac/cve/scm_posture).

If the script exits with an error (missing token, HTTP error), report the message to the user.

Suggest `/orca-fix-alert <alert-id>` for individual fixes or `/security-engineer` for automated bulk fixes.
