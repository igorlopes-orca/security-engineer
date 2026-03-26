---
name: orca-repo-risks
description: Identify all Orca security risks for a GitHub repository
argument-hint: "[owner/repo]"
disable-model-invocation: true
context: fork
agent: Explore
allowed-tools: Bash(git remote get-url origin), mcp__orca-remote__get_asset_by_name, mcp__orca-remote__discovery_search, mcp__orca-remote__get_asset_alerts_count_grouped_by_risk_level, mcp__orca-remote__get_asset_related_alerts_summary
---

# Orca Repo Risks Skill

Identify all Orca security risks for a GitHub repository using the Orca MCP server.

## Usage
- `/orca-repo-risks` — auto-detect repo from current git remote
- `/orca-repo-risks owner/repo` — explicit target

## Workflow

Follow these exact steps. Do NOT deviate — previous attempts without this guide wasted 15 tool calls.

### Step 1: Determine the repo name

If an argument was provided (e.g. `/orca-repo-risks igorlopes-orca/se-lab`), use it directly as `<owner/repo>`.

Otherwise, run:
```bash
git remote get-url origin
```
Extract the `owner/repo` portion from the URL:
- `https://github.com/owner/repo.git` → `owner/repo`
- `git@github.com:owner/repo.git` → `owner/repo`

### Step 2: Find the asset in Orca (run in parallel)

Make these two calls simultaneously:

**A)** `mcp__orca-remote__discovery_search` with **exactly** this phrase:
```
"alerts for asset <owner/repo>"
```
Example: `"alerts for asset igorlopes-orca/se-lab"` with `limit=1`

**IMPORTANT:** Do NOT use vague terms like "se-lab" or "GitHub repository se-lab" — they return empty results. The `owner/repo` format is required.

From this response, note the `app_url` for the final output link.

**B)** `mcp__orca-remote__get_asset_by_name` with:
- `asset_name = <owner/repo>` (e.g. `"igorlopes-orca/se-lab"`)
- `model_type = "CodeRepository"`
- `name_match_limit = 1`

From **this** response, extract `asset_id` — it is the top-level `id` field (a short UUID, e.g. `"3281ec1f-3050-2666-5912-7e567b99bf04"`).

**Do NOT use** `asset_unique_id` (the long `CodeRepository_...` string inside `.data`) — it will cause validation errors.

### Step 3: Fetch alerts (run in parallel)

Make these two calls simultaneously using the `asset_id` from Step 2B:

1. `mcp__orca-remote__get_asset_alerts_count_grouped_by_risk_level(asset_id=<id>)`
   → Returns counts per risk level (Critical / High / Medium / Low / Informational)

2. `mcp__orca-remote__get_asset_related_alerts_summary(asset_id=<id>)`
   → Returns full alert list (up to 50; total_items shows the real count)

### Step 4: Parse and present

Parse the alerts summary response. Each alert has these top-level fields:
- `name` — alert ID (e.g. `orca-270453`)
- `alert_title` — human-readable name
- `risk_level` — `critical` / `high` / `medium` / `low` / `informational`
- `orca_score` — numeric score
- `status` — `open` / `in_progress` / `dismissed`
- `ui_url` — direct link to alert in Orca platform

Present results as:
1. Header: asset name, Orca score, risk level, last scan date
2. Alert counts summary (from Step 3 result)
3. Grouped table by risk level (Critical first, Informational last)
4. Footer: link to full results in Orca platform (use `app_url` from discovery_search response)

Only show `open` and `in_progress` alerts unless the user asks for dismissed ones.
