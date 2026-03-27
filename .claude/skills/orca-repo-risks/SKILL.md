---
name: orca-repo-risks
description: Identify all Orca security risks for a GitHub repository
argument-hint: "[owner/repo]"
disable-model-invocation: true
context: fork
allowed-tools: Bash
---

# Orca Repo Risks Skill

Identify all Orca security risks for a GitHub repository by calling the Orca API directly.

## Usage
- `/orca-repo-risks` — auto-detect repo from current git remote
- `/orca-repo-risks owner/repo` — explicit target

## Workflow

### Step 1: Determine the repo name

If an argument was provided, use it directly as `<owner/repo>`.

Otherwise run:
```bash
git remote get-url origin
```
Extract `owner/repo` from the URL:
- `https://github.com/owner/repo.git` → `owner/repo`
- `git@github.com:owner/repo.git` → `owner/repo`

### Step 2: Run the alerts script

The script reads `ORCA_API_TOKEN` from the environment (plain API key), or falls back to `ORCA_AUTH_TOKEN` (base64 `url||token` format). Run:

```bash
python3 .claude/skills/orca-repo-risks/orca_alerts.py <owner/repo>
```

The script calls the Orca API and prints a formatted markdown report grouped by risk level.

### Step 3: Present the output

Return the script output as-is. It already contains the formatted report with alert counts and tables grouped by risk level.

If the script exits with an error (e.g. missing token, HTTP error), report the error message to the user.
