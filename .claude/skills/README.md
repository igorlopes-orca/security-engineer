# Orca Security Skills for Claude Code

Two Claude Code skills that integrate with the Orca Security MCP server to surface and fix vulnerabilities directly from your terminal.

## Skills

### `/orca-repo-risks [owner/repo]`

Lists all open security alerts for a GitHub repository, grouped by risk level.

- Auto-detects the repo from `git remote get-url origin` if no argument is given
- Returns a formatted report: alert counts by severity, grouped alert table, and link to Orca platform
- Large MCP responses (~20k tokens) stay isolated in a forked subagent — only the formatted report (~1–2k tokens) lands in your main conversation

**Example:**
```
/orca-repo-risks
/orca-repo-risks igorlopes-orca/se-lab
```

---

### `/orca-fix-alert <alert-id>`

Fetches a specific Orca alert and applies a code fix to the repository.

- Reads the alert details (description, recommendation, code snippet, file path)
- Reads the affected source file and applies the fix using `Edit`
- Handles: SAST vulnerabilities, IaC misconfigurations, hardcoded secrets, CVE dependency updates
- For `scm_posture` alerts (branch protection, etc.) — explains the setting and where to configure it in GitHub instead of trying to fix in code

**Example:**
```
/orca-fix-alert orca-270453
```

---

## Prerequisites

### 1. Claude Code CLI

Install via:
```bash
npm install -g @anthropic-ai/claude-code
```

### 2. Orca MCP Server (`orca-remote`)

The skills use a remote MCP server that proxies to `https://api.orcasecurity.io/mcp`.

**Add to `~/.claude.json`** (global Claude Code config) so it's available in all sessions including forked subagents:

```json
{
  "mcpServers": {
    "orca-remote": {
      "command": "uvx",
      "args": [
        "mcp-proxy",
        "https://api.orcasecurity.io/mcp",
        "--transport",
        "streamablehttp",
        "-H",
        "Authorization",
        "Token <YOUR_ORCA_API_TOKEN>"
      ]
    }
  }
}
```

Replace `<YOUR_ORCA_API_TOKEN>` with a valid Orca API token from your organization.

> **Why `~/.claude.json` and not Claude Desktop config?**
> Skills with `context: fork` run in isolated subagents. Subagents only load MCP servers from the **global (user-level) `mcpServers`** key at the root of `~/.claude.json`. Two things will break the skill:
> 1. `orca-remote` is only in Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`) — forks never read that file.
> 2. `orca-remote` is only in the **project-scoped** section of `~/.claude.json` (under a specific project path key) — this shows as "Local MCPs" in `/mcp`, but forks don't inherit project context and won't see it.
>
> It must be in the root-level `mcpServers` object (shown as "User MCPs" in `/mcp`). Verify with `/mcp` after setup: `orca-remote` must appear under **User MCPs ✔ connected**.

You also need `uvx` (part of `uv`) and `mcp-proxy`:
```bash
pip install uv
uvx mcp-proxy --help   # verifies mcp-proxy is available via uvx
```

---

## Installation

1. Copy the `.claude/` directory (or just `.claude/skills/`) into your target repository root.

2. Ensure `.claude/settings.local.json` exists with the required permissions:

```json
{
  "permissions": {
    "allow": [
      "mcp__orca-remote__get_asset_by_name",
      "mcp__orca-remote__discovery_search",
      "mcp__orca-remote__get_asset_related_alerts_summary",
      "mcp__orca-remote__get_asset_alerts_count_grouped_by_risk_level",
      "mcp__orca-remote__get_scm_posture_alerts_on_asset",
      "mcp__orca-remote__get_alert",
      "Bash(git remote get-url origin)",
      "Bash(python3:*)"
    ]
  }
}
```

3. Verify the MCP server is reachable — start a Claude Code session and run `/mcp`. You should see `orca-remote` listed with a green status.

4. Run `/orca-repo-risks` from within any repo that has been scanned by Orca.

---

## Architecture Notes

### Why `context: fork`?

The Orca MCP tools return large payloads (20k+ tokens). Without isolation, each call would consume a large portion of the main conversation context window, making long sessions expensive and slow.

`context: fork` runs the entire skill in a subagent with its own context. The MCP responses stay there; only the final formatted text (1–2k tokens) is returned to your main session.

### Why `disable-model-invocation: true`?

Prevents Claude from trying to answer the skill using its own knowledge before running the workflow. All answers must come from live Orca data.

### Skill directory structure

Claude Code requires skills to be in a subdirectory, not a flat `.md` file:

```
.claude/
  skills/
    orca-repo-risks/
      SKILL.md        ✓ correct
    orca-fix-alert/
      SKILL.md        ✓ correct
    my-skill.md       ✗ will not be recognized
```

---

## Common Pitfalls

| Symptom | Cause | Fix |
|---|---|---|
| Skill not listed in `/skills` | Flat `.md` file instead of `<name>/SKILL.md` | Move to subdirectory |
| Skill not listed in `/skills` | Parentheses in `allowed-tools` (e.g. `Bash(git...)`) | Use bare tool names in frontmatter; put restrictions in `settings.local.json` |
| MCP tools not available in fork | `orca-remote` only in Claude Desktop config | Add to `~/.claude.json` |
| "I don't have bash access" / no MCP calls | `agent: Explore` in frontmatter | Remove `agent:` line; default agent has full tool access |
| Skill doesn't receive argument | `$ARGUMENTS` inside a fenced code block | Place `$ARGUMENTS` outside code blocks in the skill body |
| Validation error on asset queries | Using `asset_unique_id` (long string) instead of `asset_id` (short UUID) | Use top-level `id` from `get_asset_by_name` response |
| Empty results from discovery search | Vague search term (e.g. "se-lab") | Use exact format: `"alerts for asset owner/repo"` |

---

## Token Budget Reference

| Operation | Approx. tokens |
|---|---|
| `get_asset_related_alerts_summary` response | ~20,000 |
| Formatted risk report returned to main context | ~1,200 |
| `get_alert` response (single alert) | ~3,000–8,000 |

Running these skills without `context: fork` would consume 20k+ tokens of your main context per invocation.
