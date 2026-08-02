#!/usr/bin/env bash
# Shared configuration for the dev loop. Sourced by reset.sh and run.sh.
#
# Single source of truth for which repo the loop is allowed to touch. Every
# destructive action downstream is scoped by SANDBOX_REPO + BRANCH_PREFIX, so
# those two values are the safety boundary — keep them here, not inlined.

set -euo pipefail

DEVLOOP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$DEVLOOP_DIR/.." && pwd)"

# Sandbox: the repo the orchestrator runs --remote against. Must NOT be the
# plugin repo itself — a loop that opens fix PRs against its own source would
# collide with in-flight work.
SANDBOX_REPO="${SANDBOX_REPO:-igorlopes-orca/vulnerable-apps}"

# Every branch the orchestrator creates starts with this (alert_branch_name()).
# reset.sh will only ever close/delete things matching it.
BRANCH_PREFIX="${BRANCH_PREFIX:-fix/orca-}"

RUNS_DIR="$REPO_ROOT/devloop/runs"
ORCHESTRATOR="$REPO_ROOT/skills/security-engineer/orchestrator.py"
DEVLOOP_CONFIG_YAML="$DEVLOOP_DIR/orca-check.yaml"

# Secrets live in a gitignored .env, never in this file.
if [[ -f "$DEVLOOP_DIR/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$DEVLOOP_DIR/.env"
  set +a
fi

devloop::die() {
  echo "error: $*" >&2
  exit 1
}

devloop::require_token() {
  if [[ -z "${ORCA_API_TOKEN:-}" ]]; then
    devloop::die "ORCA_API_TOKEN is not set.
  Copy devloop/.env.example to devloop/.env and fill it in, or export it in your shell."
  fi
}

devloop::require_gh() {
  command -v gh >/dev/null 2>&1 || devloop::die "gh CLI not found — install it and run 'gh auth login'."
  gh auth status >/dev/null 2>&1 || devloop::die "gh is not authenticated — run 'gh auth login'."
}

# Refuse to point the loop at the plugin repo itself, however SANDBOX_REPO was set.
devloop::guard_sandbox() {
  local origin
  origin="$(git -C "$REPO_ROOT" remote get-url origin 2>/dev/null || true)"
  if [[ -n "$origin" && "$origin" == *"$SANDBOX_REPO"* ]]; then
    devloop::die "SANDBOX_REPO ($SANDBOX_REPO) is this repo. Point it at a throwaway repo."
  fi
  [[ "$SANDBOX_REPO" == */* ]] || devloop::die "SANDBOX_REPO must be owner/repo, got '$SANDBOX_REPO'."
}
