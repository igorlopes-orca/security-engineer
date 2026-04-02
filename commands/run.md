---
description: Autonomous security agent — fixes Orca alerts with validation, impact analysis, and notifications
argument-hint: "[risk_levels,feature_types] [--scan] [--alert <id>] [--max N] [--dry-run] | --remote <owner/repo|all> [filters]"
allowed-tools: Bash
---

# Security Engineer Agent

```bash
python3 -u ${CLAUDE_PLUGIN_ROOT}/skills/security-engineer/orchestrator.py $ARGUMENTS
```

Return the output verbatim. If the script exits with a non-zero exit code, print the error and STOP — do not retry, do not correct arguments, do not attempt to fix the command on the user's behalf.
