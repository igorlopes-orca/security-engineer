#!/bin/bash
set -e

# Install the Orca Security Engineer plugin for Claude Code
if ! command -v claude &> /dev/null; then
  echo "Error: Claude Code is not installed. See https://docs.anthropic.com/en/docs/claude-code" >&2
  exit 1
fi

if ! command -v gh &> /dev/null; then
  echo "Error: GitHub CLI (gh) is required. Install from https://cli.github.com/" >&2
  exit 1
fi

echo "Adding Orca Security marketplace..."
claude plugin marketplace add igorlopes-orca/security-engineer

echo "Installing security-engineer plugin..."
claude plugin install security-engineer@orca-security

echo ""
echo "Done! Restart Claude Code or run /reload-plugins, then use:"
echo "  /security-engineer:run                — fix all alerts"
echo "  /security-engineer:run --dry-run      — plan only"
echo "  /security-engineer:run --scan         — list risks"
