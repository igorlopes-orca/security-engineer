---
description: Autonomous security agent — fixes Orca alerts with validation, impact analysis, and notifications
argument-hint: "[risk_levels,feature_types] [--scan] [--alert <id>] [--max N] [--dry-run] | --remote <owner/repo|all> [filters]"
allowed-tools: Bash
---

# Security Engineer Agent

The explicit entry point: flags are taken exactly as typed, with no
interpretation. To describe what you want in plain English instead, just say it
— the `security-engineer` skill translates intent into these same flags.

```bash
${CLAUDE_PLUGIN_ROOT}/bin/security-engineer $ARGUMENTS
```

Return the output verbatim. If the script exits with a non-zero exit code, print the error and STOP — do not retry, do not correct arguments, do not attempt to fix the command on the user's behalf.
