#!/usr/bin/env bash
# One live orchestrator run against the sandbox, fully captured.
#
# Usage:  devloop/run.sh [orchestrator flags...]
#   devloop/run.sh                          all alerts on the sandbox
#   devloop/run.sh cve --max 1              one CVE (fast path)
#   devloop/run.sh --dry-run cve            plan only, no writes
#   devloop/run.sh --scan                   list risks and live alert IDs
#
# Prefer filters over --alert <id>: Orca mints new alert IDs on every rescan,
# so a hardcoded ID goes stale and the run dies with "Alert <id> not found".
#
# --remote $SANDBOX_REPO is always injected; don't pass it yourself.

set -euo pipefail

# shellcheck source=./config.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/config.sh"

devloop::require_token
devloop::require_gh
devloop::guard_sandbox

for arg in "$@"; do
  [[ "$arg" == "--remote" || "$arg" == --remote=* ]] && \
    devloop::die "--remote is injected by run.sh — drop it from your arguments."
done

# config.py silently falls back to defaults without PyYAML, which would give a
# 600s Orca timeout and the non-matching default check name. Say so up front
# rather than letting the run behave differently than the yaml claims.
if python3 -c "import yaml" >/dev/null 2>&1; then
  export SECURITY_ENGINEER_CONFIG="$DEVLOOP_CONFIG_YAML"
else
  echo "warning: PyYAML not installed — devloop/orca-check.yaml will be ignored" >&2
  echo "         (pip3 install pyyaml) Falling back to shipped defaults." >&2
fi

# Skip git hooks for this run — the devloop equivalent of --no-verify.
#
# The sandbox is a private throwaway repo full of deliberately vulnerable code,
# and no real secrets are ever pushed to it, so a personal secret-scanning
# pre-commit hook has nothing useful to say about these commits. What it can do
# is fail: a global core.hooksPath (Orca's own `orca-cli secrets pre-commit
# scan` is a common one) breaks `git commit` whenever its token or region goes
# stale, and the orchestrator then reports the hook's stderr as the *fix's*
# failure reason — so a local environment problem reads as a broken fix agent.
#
# Done with GIT_CONFIG_* rather than `git commit --no-verify` for two reasons:
# it is inherited by every child git process, so it covers all four commit/push
# sites in run_agent.py and orchestrator.py at once (--no-verify on commit would
# still leave pre-push hooks live); and it needs no change to shipped code, so
# real users keep running their own hooks. A `git -c` here would not reach the
# orchestrator's own git calls.
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0=core.hooksPath
export GIT_CONFIG_VALUE_0=/dev/null

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$RUNS_DIR/$STAMP"
mkdir -p "$RUN_DIR"
ln -sfn "$STAMP" "$RUNS_DIR/latest"

# Provenance: a report is only useful if you can tie it to the tree that made it.
{
  echo "timestamp   $STAMP"
  echo "sandbox     $SANDBOX_REPO"
  echo "args        ${*:-<none>}"
  echo "head        $(git -C "$REPO_ROOT" rev-parse HEAD)"
  echo "branch      $(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD)"
  echo "config      ${SECURITY_ENGINEER_CONFIG:-<defaults>}"
  echo
  echo "--- git status ---"
  git -C "$REPO_ROOT" status --short
  echo
  echo "--- uncommitted diff ---"
  git -C "$REPO_ROOT" diff
} > "$RUN_DIR/run-meta.txt" 2>&1

echo "run:  $SANDBOX_REPO  args: ${*:-<none>}"
echo "dir:  $RUN_DIR"
echo

# cd into the run dir: build_notifiers(repo, Path.cwd()) writes
# security-engineer-run.json relative to cwd, so the NDJSON event log lands
# beside the console log with no extra plumbing.
cd "$RUN_DIR"

set +e
python3 -u "$ORCHESTRATOR" --remote "$SANDBOX_REPO" "$@" 2>&1 | tee "$RUN_DIR/console.log"
status="${PIPESTATUS[0]}"
set -e

echo "$status" > "$RUN_DIR/exit-code"
echo
echo "run:  orchestrator exited $status"
echo "next: python3 devloop/observe.py"
exit "$status"
