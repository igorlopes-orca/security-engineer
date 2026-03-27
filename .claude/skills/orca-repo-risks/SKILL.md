---
name: orca-repo-risks
description: Identify all Orca security risks for a GitHub repository
argument-hint: "[owner/repo]"
disable-model-invocation: true
context: fork
allowed-tools: Bash
---

# Orca Repo Risks Skill

Identify all Orca security risks for a GitHub repository by querying the Orca API directly.

## Usage
- `/orca-repo-risks` — auto-detect repo from current git remote
- `/orca-repo-risks owner/repo` — explicit target

## Workflow

### Step 1: Determine the repo name

If an argument was provided (e.g. `/orca-repo-risks igorlopes-orca/se-lab`), use it directly as `<owner/repo>`.

Otherwise, run:
```bash
git remote get-url origin
```
Extract the `owner/repo` portion from the URL:
- `https://github.com/owner/repo.git` → `owner/repo`
- `git@github.com:owner/repo.git` → `owner/repo`

### Step 2: Fetch alerts

Run:
```bash
python3 .claude/skills/orca-repo-risks/orca_get_repo_risks.py <owner/repo>
```

The script reads `ORCA_API_TOKEN` or `ORCA_AUTH_TOKEN` from the environment, calls the Orca serving-layer API, and prints the alerts grouped by risk level.

### Step 3: Parse and present

The script output already groups alerts by risk level (Critical → Informational) with counts and a summary line. Present this output to the user as-is, and add:

1. A brief header noting the repository name and total alert count
2. If any Critical or High alerts exist, highlight the top 3 by OrcaScore with a short note on what they are
3. A footer suggesting `/orca-fix-alert <alert-id>` to fix a specific alert
