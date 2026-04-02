#!/usr/bin/env python3
"""
Security Engineer Orchestrator — Python state machine.

Replaces the LLM coordinator. Fetches Orca alerts, dispatches Claude fix agents
as subprocesses with timeouts, validates fixes, assesses production impact,
opens PRs, polls CI, and notifies.

Usage: python3 orchestrator.py [filter_tokens] [--scan] [--dry-run] [--alert ID] [--max N] [--remote REPO]
"""
import argparse
import copy
import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_THIS_DIR = Path(__file__).parent
_SKILLS_DIR = _THIS_DIR.parent
sys.path.insert(0, str(_SKILLS_DIR / "lib"))
sys.path.insert(0, str(_THIS_DIR))

from orca_client import (RISK_ORDER, alert_branch_name, Repository,
                         list_repositories, get_token, fetch_alerts,
                         _resolve_feature_type)

from _json_util import find_last_json_with_key
from notifier import build_notifiers, NotificationPayload
from validator import sanity_check, llm_validate, local_build_check, ci_gate
from orca_cli_validator import orca_cli_validate
from impact_agent import analyze_impact, ImpactResult

_RUN_AGENT = str(_THIS_DIR / "run_agent.py")

MAX_WORKERS = 4
REPO_WORKERS = 3    # concurrent repos in --all-repos mode (total agents = REPO_WORKERS × MAX_WORKERS)
MAX_RETRIES = 2
RETRYABLE_ERRORS = {"json_parse_failure", "subprocess_error"}
TIMEOUTS = {"sast": 180, "iac": 120, "secret": 120, "cve": 240}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class FixAgentResult:
    success: bool
    skipped: bool = False
    files_changed: list[str] = field(default_factory=list)
    diff_summary: str = ""
    manual_steps: list[str] = field(default_factory=list)
    failure_reason: Optional[str] = None
    failed_step: Optional[str] = None
    error_code: Optional[str] = None
    timed_out: bool = False


@dataclass
class AlertTask:
    alert_id: str
    title: str
    risk_level: str
    feature_type: str
    source: str
    alert_json: dict
    state: str = "PENDING"
    pr_url: Optional[str] = None
    failure_reason: Optional[str] = None
    worktree_path: Optional[Path] = None
    fix_result: Optional[FixAgentResult] = None
    impact: Optional[ImpactResult] = None
    needs_review: bool = False
    attempts: int = 0


# ---------------------------------------------------------------------------
# Subprocess helper
# ---------------------------------------------------------------------------

def _run(cmd: list[str], check: bool = True, cwd: Optional[Path] = None) -> tuple[str, str, int]:
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    if check and r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or f"Command failed: {' '.join(str(c) for c in cmd)}")
    return r.stdout.strip(), r.stderr.strip(), r.returncode


# ---------------------------------------------------------------------------
# Git worktree helpers
# ---------------------------------------------------------------------------

def _create_worktree(alert_id: str, branch: str, repo: Optional[Repository] = None) -> Path:
    """Create an isolated git worktree with a new branch checked out from main.

    repo: when set (multi-repo mode) all git commands run inside repo.clone_path.
          When None, uses the current working directory (single-repo mode).
    """
    path = Path(f"/tmp/orca-fix-{alert_id}")
    cwd = str(repo.clone_path) if (repo and repo.clone_path) else None
    if path.exists():
        subprocess.run(["git", "worktree", "remove", "--force", str(path)],
                       capture_output=True, cwd=cwd)
    subprocess.run(["git", "branch", "-D", branch], capture_output=True, cwd=cwd)
    _run(["git", "worktree", "add", "-b", branch, str(path), "main"], cwd=cwd)
    return path


def _remove_worktree(path: Optional[Path], branch: Optional[str] = None,
                     repo: Optional[Repository] = None) -> None:
    """Remove worktree and clean up local branch.

    repo: when set (multi-repo mode) git commands run inside repo.clone_path.
    """
    cwd = str(repo.clone_path) if (repo and repo.clone_path) else None
    if path and path.exists():
        subprocess.run(["git", "worktree", "remove", "--force", str(path)],
                       capture_output=True, cwd=cwd)
    if branch:
        subprocess.run(["git", "branch", "-D", branch], capture_output=True, cwd=cwd)


def _get_diff(worktree_path: Path) -> str:
    r = subprocess.run(["git", "diff"], cwd=worktree_path, capture_output=True, text=True)
    return r.stdout


# ---------------------------------------------------------------------------
# Fix agent invocation
# ---------------------------------------------------------------------------

_FIX_PROMPT_LIVE = """\
You are a specialist security fix agent. Fix ONE specific vulnerability.

## Vulnerability
**Alert:** {alert_id}  |  **Severity:** {risk_level}  |  **Type:** {feature_type}
**Title:** {title}

## Location
**File:** {file_path}
**Lines:** {lines}

## Vulnerable Code
{code_snippet}

## Why It's Vulnerable
{description}
{ai_triage_explanation}

## Recommended Fix
{recommendation}

## Instructions
{instructions}

## Important
- Your branch is already created and checked out. Do NOT run git-setup.
- Do NOT run git commit or git push. The orchestrator handles those after validation.
- Apply the fix, then verify the change was applied correctly.
- Print ONLY the JSON block below as your very last output (nothing after it).

## Full Alert Data (reference)
{alert_json}

## Required Final Output
Success:
{{"status": "success", "alert_id": "{alert_id}", "files_changed": ["path/to/file"], "diff_summary": "<one sentence>", "manual_steps": ["step if needed"]}}

Failure:
{{"status": "failed", "alert_id": "{alert_id}", "reason": "<what went wrong>", "step": "file_read|fix_apply|verify"}}
"""

_FIX_PROMPT_DRY = """\
DRY RUN — read files only, do not edit anything.

You are reviewing what a fix would look like for this vulnerability.

## Vulnerability
**Alert:** {alert_id}  |  **Severity:** {risk_level}  |  **Type:** {feature_type}
**Title:** {title}

## Location
**File:** {file_path}
**Lines:** {lines}

## Vulnerable Code
{code_snippet}

## Why It's Vulnerable
{description}
{ai_triage_explanation}

## Recommended Fix
{recommendation}

## Instructions (reference only — do not execute git or edit commands)
{instructions}

Describe the planned fix:
1. Read the file at {file_path}.
2. Show before/after of what the fix would look like.
3. Explain why this addresses the vulnerability.

## Full Alert Data (reference)
{alert_json}

Print ONLY this JSON as your very last output:
{{"status": "success", "alert_id": "{alert_id}", "files_changed": ["{file_path}"], "diff_summary": "<planned change>", "manual_steps": []}}
"""


def _build_prompt_context(alert: dict) -> dict:
    """Extract structured fields from alert JSON for fix agent prompts."""
    position = alert.get("position", {}) or {}
    start_line = position.get("start_line")
    end_line = position.get("end_line")
    if start_line and end_line and start_line != end_line:
        lines = f"{start_line}–{end_line}"
    elif start_line:
        lines = str(start_line)
    else:
        lines = "see recommendation"

    raw_snippet = alert.get("code_snippet", [])
    code_snippet = (
        "\n".join(str(s) for s in raw_snippet) if isinstance(raw_snippet, list)
        else str(raw_snippet)
    ) or "(not available)"

    ai_triage = alert.get("ai_triage", {}) or {}
    ai_explanation = ai_triage.get("explanation", "")

    return {
        "file_path":            alert.get("file_path") or alert.get("source", "(unknown)"),
        "lines":                lines,
        "code_snippet":         code_snippet,
        "description":          alert.get("description", ""),
        "ai_triage_explanation": ai_explanation,
        "recommendation":       alert.get("recommendation", ""),
    }


def _invoke_fix_agent(task: AlertTask, dry_run: bool, timeout_sec: int) -> FixAgentResult:
    instructions_path = _THIS_DIR / "fix-agents" / f"{task.feature_type}.md"
    if not instructions_path.exists():
        return FixAgentResult(
            success=False,
            failure_reason=f"No fix instructions for type: {task.feature_type}",
            error_code="no_instructions",
        )
    instructions = instructions_path.read_text()

    if dry_run:
        tmpl = _FIX_PROMPT_DRY
        tools = "Read"
    else:
        tmpl = _FIX_PROMPT_LIVE
        tools = "Read,Edit,Write,Bash"

    ctx = _build_prompt_context(task.alert_json)
    prompt = tmpl.format(
        alert_json=json.dumps(task.alert_json, indent=2),
        instructions=instructions,
        alert_id=task.alert_id,
        title=task.title,
        risk_level=task.risk_level,
        feature_type=task.feature_type,
        **ctx,
    )

    cmd = [
        "claude", "-p", prompt,
        "--allowedTools", tools,
        "--output-format", "json",
        "--max-turns", "20",
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout_sec,
            cwd=task.worktree_path,
        )
    except subprocess.TimeoutExpired:
        return FixAgentResult(
            success=False, timed_out=True,
            failure_reason=f"fix agent timed out after {timeout_sec}s",
            error_code="timeout",
        )

    if result.returncode != 0:
        return FixAgentResult(
            success=False,
            failure_reason=result.stderr[:300],
            error_code="subprocess_error",
        )

    return _parse_fix_result(result.stdout)


def _parse_fix_result(raw: str) -> FixAgentResult:
    try:
        envelope = json.loads(raw)
        text = envelope.get("result", "") or raw
    except json.JSONDecodeError:
        text = raw

    data = find_last_json_with_key(text, "status")
    if not data:
        return FixAgentResult(
            success=False, error_code="json_parse_failure",
            failure_reason="No structured output from fix agent",
        )

    status = data.get("status", "failed")
    if status == "success":
        return FixAgentResult(
            success=True,
            files_changed=data.get("files_changed") or [],
            diff_summary=data.get("diff_summary", ""),
            manual_steps=data.get("manual_steps") or [],
        )
    else:
        return FixAgentResult(
            success=False,
            failure_reason=data.get("reason", "unknown failure"),
            failed_step=data.get("step"),
        )


# ---------------------------------------------------------------------------
# Commit + PR
# ---------------------------------------------------------------------------

def _commit_and_pr(task: AlertTask, impact: Optional[ImpactResult], dry_run: bool) -> Optional[str]:
    """Stage, commit, and open PR. Returns PR URL or None (dry-run)."""
    if dry_run:
        print(f"  [dry-run] would commit and open PR for {task.alert_id}")
        return None

    commit_msg = f"fix(security): {task.title} ({task.alert_id})"

    impact_level = impact.level if impact else "unknown"
    impact_desc = impact.description if impact else ""
    downtime = " ⚠️ Possible downtime." if (impact and impact.downtime_risk) else ""
    steps_md = ""
    if impact and impact.manual_steps:
        steps_md = "\n\n### Required Manual Steps\n" + "\n".join(
            f"- [ ] {s}" for s in impact.manual_steps
        )
    concerns_md = ""
    if impact and impact.concerns:
        concerns_md = "\n\n### Reviewer Concerns\n" + "\n".join(
            f"- {c}" for c in impact.concerns
        )

    pr_body = (
        f"## Security Fix: {task.title}\n\n"
        f"**Alert:** `{task.alert_id}`  |  "
        f"**Risk:** {task.risk_level}  |  "
        f"**Type:** {task.feature_type}  |  "
        f"**Impact:** {impact_level}{downtime}\n\n"
        f"{impact_desc}\n\n"
        f"### What Changed\n"
        f"{task.fix_result.diff_summary if task.fix_result else 'See diff'}"
        f"{steps_md}{concerns_md}\n\n"
        f"---\n*Auto-generated by `/security-engineer` orchestrator*"
    )
    pr_title = f"fix(security): {task.title[:60]} [{task.alert_id}]"

    _run(["python3", _RUN_AGENT, "git-commit", task.alert_id, commit_msg],
         cwd=task.worktree_path)

    stdout, _, _ = _run([
        "python3", _RUN_AGENT, "open-pr", task.alert_id,
        "--title", pr_title,
        "--body", pr_body,
    ], cwd=task.worktree_path)

    pr_url = stdout.strip().split("\n")[-1].strip()
    if not pr_url.startswith("http"):
        raise RuntimeError(f"Unexpected open-pr output: {stdout[:200]}")
    return pr_url


# ---------------------------------------------------------------------------
# Per-alert state machine
# ---------------------------------------------------------------------------

def _revert(worktree_path: Path) -> None:
    subprocess.run(["git", "checkout", "--", "."], cwd=worktree_path, capture_output=True)


def _notify_payload(task: AlertTask) -> NotificationPayload:
    return NotificationPayload(
        event="",
        alert_id=task.alert_id,
        feature_type=task.feature_type,
        risk_level=task.risk_level,
        repo="",
        pr_url=task.pr_url,
        reason=task.failure_reason,
        impact_level=task.impact.level if task.impact else None,
        manual_steps=task.impact.manual_steps if task.impact else [],
        concerns=task.impact.concerns if task.impact else [],
    )


def run_one(task: AlertTask, dry_run: bool, notifier, repo: Repository) -> AlertTask:
    """Drive a single alert through the full fix pipeline.

    repo.clone_path controls where git operations run:
      None  → current working directory (single-repo mode, existing behaviour)
      Path  → inside the cloned repo (multi-repo mode)
    """
    branch = alert_branch_name(task.alert_id)

    # Create worktree
    try:
        task.worktree_path = _create_worktree(task.alert_id, branch, repo=repo)
    except RuntimeError as e:
        if "already exists" in str(e):
            task.state = "SKIPPED"
            task.failure_reason = "branch already exists"
            return task
        task.state = "FAILED"
        task.failure_reason = f"worktree creation failed: {e}"
        return task

    p = _notify_payload(task)
    p.repo = repo.name
    notifier.notify("fix_started", p)

    # Fix agent with retries
    task.state = "FIX_RUNNING"
    timeout = TIMEOUTS.get(task.feature_type, 180)
    fix_result = None

    while task.attempts < MAX_RETRIES:
        task.attempts += 1
        fix_result = _invoke_fix_agent(task, dry_run, timeout)

        if fix_result.timed_out:
            task.state = "TIMED_OUT"
            task.failure_reason = fix_result.failure_reason
            p = _notify_payload(task)
            p.repo = repo.name
            notifier.notify("timeout", p)
            _remove_worktree(task.worktree_path, branch, repo=repo)
            return task

        if fix_result.success:
            break

        if fix_result.error_code not in RETRYABLE_ERRORS:
            break

        # Retryable: reset and retry
        _revert(task.worktree_path)

    if not fix_result or not fix_result.success:
        task.state = "FAILED"
        task.failure_reason = (fix_result.failure_reason if fix_result else "unknown")
        p = _notify_payload(task)
        p.repo = repo.name
        notifier.notify("fix_failed", p)
        _remove_worktree(task.worktree_path, branch, repo=repo)
        return task

    task.fix_result = fix_result

    # Dry-run: done after fix agent describes the plan
    if dry_run:
        task.state = "DONE"
        p = _notify_payload(task)
        p.repo = repo.name
        p.detail = fix_result.diff_summary or ""
        notifier.notify("fix_planned", p)
        _remove_worktree(task.worktree_path, branch, repo=repo)
        return task

    # Phase 1: sanity
    task.state = "VALIDATE_LOCAL"
    sanity = sanity_check(task.alert_json, task.worktree_path)
    if not sanity.passed:
        task.state = "FAILED"
        task.failure_reason = "; ".join(sanity.failures)
        p = _notify_payload(task)
        p.repo = repo.name
        notifier.notify("validation_failed", p)
        _revert(task.worktree_path)
        _remove_worktree(task.worktree_path, branch, repo=repo)
        return task

    # Phase 2: LLM validation
    llm_val = llm_validate(task.alert_json, task.worktree_path)
    if not llm_val.passed:
        task.state = "FAILED"
        task.failure_reason = "; ".join(llm_val.failures)
        p = _notify_payload(task)
        p.repo = repo.name
        notifier.notify("validation_failed", p)
        _revert(task.worktree_path)
        _remove_worktree(task.worktree_path, branch, repo=repo)
        return task
    if llm_val.needs_review:
        task.needs_review = True

    # Phase 3: local build
    local_val = local_build_check(
        fix_result.files_changed, task.worktree_path,
        source_file=task.alert_json.get("file_path") or task.alert_json.get("source", ""),
    )
    if not local_val.passed:
        task.state = "FAILED"
        task.failure_reason = "; ".join(local_val.failures)
        p = _notify_payload(task)
        p.repo = repo.name
        notifier.notify("validation_failed", p)
        _revert(task.worktree_path)
        _remove_worktree(task.worktree_path, branch, repo=repo)
        return task

    # Phase 3b: orca-cli validation (before/after scan)
    task.state = "VALIDATE_ORCA_CLI"
    orca_val = orca_cli_validate(
        task.alert_json, task.worktree_path, task.feature_type)
    if not orca_val.passed:
        task.state = "FAILED"
        task.failure_reason = "; ".join(orca_val.failures)
        p = _notify_payload(task)
        p.repo = repo.name
        notifier.notify("validation_failed", p)
        _revert(task.worktree_path)
        _remove_worktree(task.worktree_path, branch, repo=repo)
        return task
    if orca_val.needs_review:
        task.needs_review = True

    # Impact analysis
    task.state = "IMPACT_ANALYSIS"
    diff_text = _get_diff(task.worktree_path)
    task.impact = analyze_impact(task.alert_json, diff_text)

    # Commit + PR
    task.state = "COMMITTING"
    try:
        pr_url = _commit_and_pr(task, task.impact, dry_run)
    except RuntimeError as e:
        task.state = "FAILED"
        task.failure_reason = str(e)
        p = _notify_payload(task)
        p.repo = repo.name
        notifier.notify("fix_failed", p)
        _remove_worktree(task.worktree_path, branch, repo=repo)
        return task

    task.pr_url = pr_url

    p = _notify_payload(task)
    p.repo = repo.name
    notifier.notify("committed", p)

    if pr_url:
        p = _notify_payload(task)
        p.repo = repo.name
        notifier.notify("pr_opened", p)

    task.state = "PR_OPENING"

    # Phase 4: CI gate
    if pr_url:
        task.state = "VALIDATE_CI"
        ci = ci_gate(pr_url, timeout_sec=600)
        if not ci.passed:
            task.state = "CI_FAILED"
            task.failure_reason = "; ".join(ci.failures)
            subprocess.run(
                ["gh", "pr", "edit", pr_url, "--add-label", "ci-failed"],
                capture_output=True
            )
            p = _notify_payload(task)
            p.repo = repo.name
            notifier.notify("ci_failed", p)
        else:
            task.state = "DONE"
    else:
        task.state = "DONE"

    # Add needs-review label
    if task.needs_review and pr_url:
        subprocess.run(
            ["gh", "pr", "edit", pr_url, "--add-label", "needs-review"],
            capture_output=True
        )

    # Add impact label
    if task.impact and pr_url:
        subprocess.run(
            ["gh", "pr", "edit", pr_url, "--add-label", f"impact:{task.impact.level}"],
            capture_output=True
        )

    p = _notify_payload(task)
    p.repo = repo.name
    notifier.notify("fix_succeeded", p)
    _remove_worktree(task.worktree_path, branch, repo=repo)
    return task


# ---------------------------------------------------------------------------
# Fetch and plan
# ---------------------------------------------------------------------------

def _detect_repo() -> Optional[Repository]:
    """Auto-detect the current repo from git remote and return a Repository object."""
    try:
        stdout, _, _ = _run(["git", "remote", "get-url", "origin"], check=False)
        url = stdout.strip()
        for sep in ("github.com/", "github.com:"):
            if sep in url:
                name = url.split(sep)[-1].removesuffix(".git").strip("/")
                return Repository(name=name, url=url)
    except Exception:
        pass
    return None


def _fetch_and_plan(args, repo: Repository) -> tuple[list[AlertTask], list[dict], list[dict], list[dict]]:
    """Fetch alerts for a repo and partition them into fix/skip/scm/unfixable buckets.

    repo.clone_path: when set, passes --repo-dir to run_agent.py so git ops
                     (detect_repo, branch_exists_remote) run inside the clone.
    """
    cmd = ["python3", _RUN_AGENT, "list-alerts", repo.name]
    if args.alert:
        cmd += ["--alert", args.alert]
    else:
        if args.filter_tokens:
            cmd += ["--filter", args.filter_tokens]
        if args.max:
            cmd += ["--max", str(args.max)]
    cmd.append("--fixable-only")
    if repo.clone_path:
        cmd += ["--repo-dir", str(repo.clone_path)]

    stdout, _, _ = _run(cmd)
    data = json.loads(stdout)
    alerts = data.get("alerts", [])

    to_fix: list[AlertTask] = []
    skipped: list[dict] = []
    scm_posture: list[dict] = []
    unfixable: list[dict] = []

    for a in alerts:
        ft = a.get("feature_type", "")
        if ft == "scm_posture":
            scm_posture.append(a)
        elif not a.get("is_fixable"):
            unfixable.append(a)
        elif a.get("branch_exists"):
            skipped.append(a)
        else:
            stdout2, _, _ = _run(["python3", _RUN_AGENT, "get-alert", a["alert_id"]])
            full = json.loads(stdout2)
            to_fix.append(AlertTask(
                alert_id=a["alert_id"],
                title=a["title"],
                risk_level=a["risk_level"],
                feature_type=ft,
                source=a.get("source", ""),
                alert_json=full,
            ))

    return to_fix, skipped, scm_posture, unfixable


# ---------------------------------------------------------------------------
# Flag validation
# ---------------------------------------------------------------------------

def _validate_flags(args):
    """Reject invalid flag combinations. Called immediately after argparse."""
    if not args.scan:
        return
    if args.dry_run:
        sys.exit("Error: --scan and --dry-run cannot be combined. "
                 "--scan already lists alerts without fixing.")
    if args.alert:
        sys.exit("Error: --scan and --alert cannot be combined. "
                 "To fix a single alert, drop --scan.")
    if args.max:
        sys.exit("Error: --scan and --max cannot be combined. "
                 "--scan lists all matching alerts.")


# ---------------------------------------------------------------------------
# Scan mode
# ---------------------------------------------------------------------------

_RISK_BADGE = {"critical": "\U0001f534", "high": "\U0001f7e0",
               "medium": "\U0001f7e1", "low": "\U0001f535",
               "informational": "\u26aa"}


def _print_scan_report(repo_name, alerts):
    """Print a risk report grouped by severity — no fixes, no git ops."""
    grouped = {lvl: [] for lvl in RISK_ORDER}
    for a in alerts:
        lvl = a["risk_level"] if a["risk_level"] in grouped else "informational"
        grouped[lvl].append(a)

    total = sum(len(v) for v in grouped.values())
    print(f"# Orca Alerts — {repo_name}")
    print(f"\nTotal open/in-progress: **{total}**\n")

    print("| Risk Level | Count |")
    print("|---|---|")
    for lvl in RISK_ORDER:
        n = len(grouped[lvl])
        if n:
            print(f"| {_RISK_BADGE.get(lvl, '')} {lvl.capitalize()} | {n} |")

    for lvl in RISK_ORDER:
        items = grouped[lvl]
        if not items:
            continue
        print(f"\n## {_RISK_BADGE.get(lvl, '')} {lvl.capitalize()} ({len(items)})\n")
        print("| Alert ID | Title | Category | Score | Type |")
        print("|---|---|---|---|---|")
        for a in items:
            ftype = _resolve_feature_type(a)
            print(f"| {a['alert_id']} | {a['title']} | {a['category']} | {a['score']} | {ftype} |")


def _run_scan(args):
    """Execute scan mode: fetch alerts and print risk report, then exit."""
    from run_agent import parse_filter, min_level_from_list

    levels, types = parse_filter(args.filter_tokens) if args.filter_tokens else (None, None)
    min_level = min_level_from_list(levels)
    token = get_token()

    if args.remote is not None:
        if args.remote == "all":
            repos = list_repositories(token)
            if not repos:
                sys.exit("No repositories found in Orca.")
            for repo in repos:
                try:
                    alerts = fetch_alerts(repo.name, token,
                                          min_level=min_level, feature_types=types)
                except RuntimeError as e:
                    print(f"\nError fetching alerts for {repo.name}: {e}",
                          file=sys.stderr)
                    continue
                if alerts:
                    _print_scan_report(repo.name, alerts)
                    print()
        elif "/" in args.remote:
            try:
                alerts = fetch_alerts(args.remote, token,
                                      min_level=min_level, feature_types=types)
            except RuntimeError as e:
                sys.exit(f"Error fetching alerts for {args.remote}: {e}")
            if not alerts:
                print(f"No alerts found for {args.remote}.")
                return
            _print_scan_report(args.remote, alerts)
        else:
            sys.exit("Error: --remote requires 'all' or 'owner/repo'")
    else:
        repo = _detect_repo()
        if not repo:
            sys.exit("Error: could not detect repo from git remote. "
                     "Run from inside a git repo or use --scan --remote owner/repo.")
        try:
            alerts = fetch_alerts(repo.name, token,
                                  min_level=min_level, feature_types=types)
        except RuntimeError as e:
            sys.exit(f"Error fetching alerts: {e}")
        if not alerts:
            print(f"No alerts found for {repo.name}.")
            return
        _print_scan_report(repo.name, alerts)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def _print_plan(to_fix, skipped, scm_posture, unfixable, repo, dry_run):
    mode = "DRY-RUN" if dry_run else "LIVE"
    total = len(to_fix) + len(skipped) + len(scm_posture) + len(unfixable)
    print(f"\nRepository: {repo}  |  Mode: {mode}")
    print(f"\nFound {total} alerts:")
    print(f"  ✓  {len(to_fix)} to fix")
    print(f"  ⟳  {len(skipped)} skipped (branch exists)")
    print(f"  ℹ  {len(scm_posture)} scm_posture (manual action)")
    print(f"  ✗  {len(unfixable)} other unfixable")
    if to_fix:
        print("\nPlanned fixes:")
        for i, t in enumerate(to_fix, 1):
            print(f"  {i}. {t.alert_id} — {t.title} ({t.risk_level}, {t.feature_type}) — {t.source}")


def _print_summary(tasks: list[AlertTask], skipped: list[dict], scm_posture: list[dict],
                   repo: str, dry_run: bool):
    mode = "DRY-RUN" if dry_run else "Live"
    print(f"\n## Security Engineer — Run Summary")
    print(f"\n**Repo:** {repo}  |  **Mode:** {mode}\n")

    done = [t for t in tasks if t.state in ("DONE", "CI_FAILED")]
    failed = [t for t in tasks if t.state in ("FAILED", "TIMED_OUT")]
    all_skipped = [t for t in tasks if t.state == "SKIPPED"] + skipped

    if done:
        print(f"### Fixed — PRs Opened ({len(done)})")
        print("| Alert | Title | Risk | Type | Impact | PR |")
        print("|---|---|---|---|---|---|")
        for t in done:
            impact = t.impact.level if t.impact else "-"
            ci_note = " ⚠️" if t.state == "CI_FAILED" else ""
            review_note = " 👁" if t.needs_review else ""
            print(f"| {t.alert_id} | {t.title} | {t.risk_level} | {t.feature_type} "
                  f"| {impact}{ci_note}{review_note} | {t.pr_url or '-'} |")

    if failed:
        print(f"\n### Fix Failed ({len(failed)})")
        print("| Alert | State | Reason |")
        print("|---|---|---|")
        for t in failed:
            print(f"| {t.alert_id} | {t.state} | {t.failure_reason or '-'} |")

    if all_skipped:
        print(f"\n### Skipped — Branch Exists ({len(all_skipped)})")
        print("| Alert | Title |")
        print("|---|---|")
        for item in all_skipped:
            if isinstance(item, AlertTask):
                print(f"| {item.alert_id} | {item.title} |")
            else:
                print(f"| {item.get('alert_id', '-')} | {item.get('title', '-')} |")

    if scm_posture:
        print(f"\n### SCM Posture — Manual Action Required ({len(scm_posture)})")
        print("| Alert | Title | Risk |")
        print("|---|---|---|")
        for a in scm_posture:
            print(f"| {a['alert_id']} | {a['title']} | {a['risk_level']} |")


# ---------------------------------------------------------------------------
# Multi-repo pipeline
# ---------------------------------------------------------------------------

def _clone_repo(repo: Repository) -> Repository:
    """Shallow-clone a GitHub repo into /tmp. Fills repo.clone_path in-place."""
    safe = repo.name.replace("/", "-")
    path = Path(f"/tmp/orca-global-{safe}")
    if path.exists():
        shutil.rmtree(path)
    _run(["gh", "repo", "clone", repo.url, str(path), "--", "--depth=1"])
    repo.clone_path = path
    return repo


def _repo_notif(repo: Repository) -> NotificationPayload:
    """Bare payload for repo-level events (no alert context)."""
    return NotificationPayload(event="", alert_id="", feature_type="", risk_level="", repo=repo.name)


def _run_repo_pipeline(repo: Repository, args) -> dict:
    """Clone a repo, run the full fix pipeline against it, clean up the clone.

    Returns a dict with keys: results, skipped, scm_posture, unfixable, error.
    """
    notifier = build_notifiers(repo.name, _THIS_DIR)

    p = _repo_notif(repo)
    notifier.notify("clone_started", p)
    try:
        _clone_repo(repo)
    except RuntimeError as e:
        p = _repo_notif(repo)
        p.reason = str(e)
        notifier.notify("clone_failed", p)
        return {"results": [], "skipped": [], "scm_posture": [], "unfixable": [],
                "error": f"clone failed: {e}"}

    p = _repo_notif(repo)
    p.detail = str(repo.clone_path)
    notifier.notify("clone_succeeded", p)

    try:
        local_args = copy.copy(args)
        local_args.repo = repo.name  # ensure filter uses this repo, not auto-detect

        to_fix, skipped, scm_posture, unfixable = _fetch_and_plan(local_args, repo)

        p = _repo_notif(repo)
        p.detail = f"{len(to_fix)} to fix, {len(skipped)} skipped, {len(unfixable)} unfixable"
        notifier.notify("alerts_fetched", p)

        _print_plan(to_fix, skipped, scm_posture, unfixable, repo.name, args.dry_run)

        results: list[AlertTask] = []
        if to_fix:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
                futures = {
                    pool.submit(run_one, task, args.dry_run, notifier, repo): task
                    for task in to_fix
                }
                for future in as_completed(futures):
                    try:
                        results.append(future.result())
                    except Exception as e:
                        task = futures[future]
                        task.state = "FAILED"
                        task.failure_reason = str(e)
                        results.append(task)

        return {"results": results, "skipped": skipped,
                "scm_posture": scm_posture, "unfixable": unfixable, "error": None}
    finally:
        if repo.clone_path and repo.clone_path.exists():
            shutil.rmtree(repo.clone_path, ignore_errors=True)
            repo.clone_path = None


def _print_global_summary(all_results: dict, dry_run: bool = False) -> None:
    """Print a per-repo breakdown and aggregate totals for --all-repos runs."""
    total_done = total_failed = total_skipped = 0

    print("\n## Security Engineer — Global Run Summary\n")
    for repo_name, data in sorted(all_results.items()):
        if data.get("error"):
            print(f"### {repo_name} — ERROR: {data['error']}")
            continue
        results = data.get("results", [])
        skipped = data.get("skipped", [])
        scm = data.get("scm_posture", [])
        _print_summary(results, skipped, scm, repo_name, dry_run)
        done = sum(1 for t in results if t.state in ("DONE", "CI_FAILED"))
        failed = sum(1 for t in results if t.state in ("FAILED", "TIMED_OUT"))
        total_done += done
        total_failed += failed
        total_skipped += len(skipped)

    print(f"\n---\n**Totals** — Fixed: {total_done}  |  Failed: {total_failed}  |  Skipped: {total_skipped}")


def _get_repo_url(repo_name: str) -> str:
    """Resolve the clone URL for an owner/repo via gh CLI."""
    stdout, _, _ = _run(["gh", "repo", "view", repo_name, "--json", "url", "--jq", ".url"])
    return stdout.strip()


def run_all_repos(args) -> None:
    """Discover all repos with open Orca alerts and run the fix pipeline on each."""
    token = get_token()
    repos = list_repositories(token)
    if not repos:
        print("No repositories with open alerts found in Orca.")
        return

    mode = "DRY-RUN" if args.dry_run else "LIVE"
    print(f"\nFound {len(repos)} repositories with open alerts. Mode: {mode}")
    print(f"Processing up to {REPO_WORKERS} repos concurrently "
          f"(up to {REPO_WORKERS * MAX_WORKERS} parallel fix agents).\n")
    for r in repos:
        print(f"  {r.name}  [{r.risk_level or 'unknown'}]  {r.url}")

    all_results: dict = {}
    with ThreadPoolExecutor(max_workers=REPO_WORKERS) as executor:
        futures = {
            executor.submit(_run_repo_pipeline, r, args): r
            for r in repos
        }
        for future in as_completed(futures):
            r = futures[future]
            try:
                all_results[r.name] = future.result()
            except Exception as e:
                all_results[r.name] = {
                    "results": [], "skipped": [], "scm_posture": [], "unfixable": [],
                    "error": str(e),
                }

    _print_global_summary(all_results, dry_run=args.dry_run)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(description="Security Engineer Orchestrator")
    parser.add_argument("--scan", action="store_true",
                        help="List alerts without fixing (risk report)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Plan only — fix agents read files but cannot edit")
    parser.add_argument("--remote", default=None, metavar="REPO",
                        help="Clone and fix: 'all' for all Orca repos, 'owner/repo' for one")
    parser.add_argument("--alert", default=None,
                        help="Target a single alert ID")
    parser.add_argument("--max", type=int, default=None,
                        help="Cap number of fixes")
    parser.add_argument("positional", nargs="*",
                        help="[filter_tokens] e.g. 'high,sast' or 'cve'")
    args = parser.parse_args(argv)

    # All positional tokens are filter tokens — repo is always auto-detected from git remote
    args.repo = None
    args.filter_tokens = None
    for p in args.positional:
        args.filter_tokens = p

    _validate_flags(args)

    # --scan: risk report only, no fixes
    if args.scan:
        _run_scan(args)
        return

    # --remote: clone-based pipeline (single repo or all Orca repos)
    if args.remote is not None:
        if args.dry_run:
            print("Mode: DRY-RUN — fix agents will read files and plan fixes, cannot edit.")
        if args.remote == "all":
            run_all_repos(args)
        elif "/" in args.remote:
            try:
                url = _get_repo_url(args.remote)
            except RuntimeError as e:
                sys.exit(f"Error: could not resolve URL for {args.remote}: {e}")
            repo = Repository(name=args.remote, url=url)
            data = _run_repo_pipeline(repo, args)
            if data.get("error"):
                sys.exit(f"Pipeline failed: {data['error']}")
            _print_summary(data["results"], data["skipped"], data["scm_posture"],
                           args.remote, args.dry_run)
        else:
            sys.exit("Error: --remote requires 'all' or 'owner/repo'")
        return

    # Local mode — repo always auto-detected from git remote origin
    repo = _detect_repo()
    if not repo:
        sys.exit("Error: could not detect repo from git remote. "
                 "Run from inside a git repo or use --remote owner/repo.")

    notifier = build_notifiers(repo.name, _THIS_DIR)

    if args.dry_run:
        print("Mode: DRY-RUN — fix agents will read files and plan fixes, cannot edit.")

    to_fix, skipped, scm_posture, unfixable = _fetch_and_plan(args, repo)
    _print_plan(to_fix, skipped, scm_posture, unfixable, repo.name, args.dry_run)

    if not to_fix:
        notifier.notify("run_complete", NotificationPayload(
            event="run_complete", alert_id="-", feature_type="-", risk_level="-",
            repo=repo.name, succeeded=0, failed=0, skipped=len(skipped),
        ))
        return

    results: list[AlertTask] = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(run_one, task, args.dry_run, notifier, repo): task
            for task in to_fix
        }
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                task = futures[future]
                task.state = "FAILED"
                task.failure_reason = str(e)
                results.append(task)

    _print_summary(results, skipped, scm_posture, repo.name, args.dry_run)

    succeeded = sum(1 for t in results if t.state in ("DONE", "CI_FAILED"))
    failed = sum(1 for t in results if t.state in ("FAILED", "TIMED_OUT"))
    notifier.notify("run_complete", NotificationPayload(
        event="run_complete", alert_id="-", feature_type="-", risk_level="-",
        repo=repo.name, succeeded=succeeded, failed=failed, skipped=len(skipped),
    ))


if __name__ == "__main__":
    main()
