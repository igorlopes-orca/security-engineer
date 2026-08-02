#!/usr/bin/env bash
# Return the sandbox to a known-clean state so the next run is meaningful.
#
# Why this exists: _fetch_and_plan() drops any alert whose fix branch already
# exists on the remote (branch_exists_remote, skills/lib/orca_client.py). One
# completed run therefore poisons every run after it — alerts land in the
# "skipped — branch exists" bucket and nothing is actually exercised.
#
# Scope is deliberately narrow: only PRs whose head branch starts with
# BRANCH_PREFIX, and only refs with that same prefix. main and human branches
# are unreachable from here by construction.

set -euo pipefail

# shellcheck source=./config.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/config.sh"

devloop::require_gh
devloop::guard_sandbox

DRY=""
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY="1" ;;
    *) devloop::die "unknown argument: $arg (only --dry-run is supported)" ;;
  esac
done

say() { echo "  $*"; }
act() {
  if [[ -n "$DRY" ]]; then
    say "would: $*"
  else
    say "$*"
  fi
}

echo "reset: $SANDBOX_REPO (branches matching '$BRANCH_PREFIX*')"
[[ -n "$DRY" ]] && echo "       DRY RUN — nothing will be changed"

# --- 1. Close open fix PRs ------------------------------------------------
pr_rows="$(gh pr list --repo "$SANDBOX_REPO" --state open \
             --json number,headRefName --jq \
             ".[] | select(.headRefName | startswith(\"$BRANCH_PREFIX\")) | \"\(.number)\t\(.headRefName)\"")"

if [[ -z "$pr_rows" ]]; then
  say "no open $BRANCH_PREFIX* PRs"
else
  while IFS=$'\t' read -r num branch; do
    [[ -z "$num" ]] && continue
    act "close PR #$num ($branch)"
    if [[ -z "$DRY" ]]; then
      gh pr close "$num" --repo "$SANDBOX_REPO" \
        --comment "Closed by devloop reset — sandbox state cleanup." >/dev/null
    fi
  done <<< "$pr_rows"
fi

# --- 2. Delete the remote branches ---------------------------------------
# Covers branches with no PR too (a run that committed but died before open-pr).
branches="$(gh api "repos/$SANDBOX_REPO/branches" --paginate \
              --jq ".[].name | select(startswith(\"$BRANCH_PREFIX\"))" 2>/dev/null || true)"

if [[ -z "$branches" ]]; then
  say "no remote $BRANCH_PREFIX* branches"
else
  while read -r branch; do
    [[ -z "$branch" ]] && continue
    act "delete remote branch $branch"
    if [[ -z "$DRY" ]]; then
      gh api -X DELETE "repos/$SANDBOX_REPO/git/refs/heads/$branch" >/dev/null 2>&1 \
        || say "  (already gone)"
    fi
  done <<< "$branches"
fi

# --- 3. Ensure the labels the orchestrator applies exist ------------------
# `gh pr edit --add-label` fails outright on a label the repo does not define,
# so without these every run ends with three "'impact:high' not found" warnings
# and the labelling path is never actually exercised.
for spec in "ci-failed:d73a4a" "needs-review:fbca04" \
            "impact:low:0e8a16" "impact:medium:fbca04" "impact:high:d73a4a"; do
  colour="${spec##*:}"
  label="${spec%:*}"
  if ! gh label list --repo "$SANDBOX_REPO" --search "$label" \
        --json name --jq '.[].name' 2>/dev/null | grep -qx "$label"; then
    act "create label $label"
    if [[ -z "$DRY" ]]; then
      gh label create "$label" --repo "$SANDBOX_REPO" --color "$colour" \
        --description "Applied by security-engineer" >/dev/null 2>&1 || true
    fi
  fi
done

# --- 4. Clear local scratch state ----------------------------------------
# Stale /tmp/orca-fix-* directories make `git worktree add` fail, which older
# orchestrator code reported as "branch already exists" — a leak that made
# every later run skip the alert.
shopt -s nullglob
stale=(/tmp/orca-fix-* /tmp/orca-global-*)
shopt -u nullglob
if (( ${#stale[@]} == 0 )); then
  say "no stale /tmp worktrees"
else
  for d in "${stale[@]}"; do
    act "remove $d"
    [[ -z "$DRY" ]] && rm -rf "$d"
  done
fi

act "git worktree prune"
[[ -z "$DRY" ]] && git -C "$REPO_ROOT" worktree prune

# Drop local fix branches left behind in the plugin repo itself (local-mode runs).
local_branches="$(git -C "$REPO_ROOT" for-each-ref --format='%(refname:short)' \
                    "refs/heads/$BRANCH_PREFIX*" 2>/dev/null || true)"
if [[ -n "$local_branches" ]]; then
  while read -r b; do
    [[ -z "$b" ]] && continue
    act "delete local branch $b"
    [[ -z "$DRY" ]] && git -C "$REPO_ROOT" branch -D "$b" >/dev/null
  done <<< "$local_branches"
fi

# --- 5. Truncate the in-repo run log -------------------------------------
# Per-run logs live under devloop/runs/; this one only accumulates when the
# orchestrator is invoked directly from the repo root.
stray_log="$REPO_ROOT/skills/security-engineer/security-engineer-run.json"
if [[ -s "$stray_log" ]]; then
  act "truncate $(basename "$stray_log")"
  [[ -z "$DRY" ]] && : > "$stray_log"
fi

echo "reset: done"
