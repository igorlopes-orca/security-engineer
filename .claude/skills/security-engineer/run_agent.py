#!/usr/bin/env python3
"""
Security Engineer Agent — mechanical operations CLI.
Handles: alert fetching/filtering, git branch management, PR creation.
Claude handles the code fixes; this script handles everything else.

Usage: python3 run_agent.py <subcommand> [options]
"""
import sys
import os
import json
import argparse
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
from orca_client import (
    get_token, fetch_alerts, fetch_alert_by_id,
    is_fixable, alert_branch_name, branch_exists_remote,
    RISK_ORDER, _resolve_feature_type
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(cmd, check=True, capture=True, cwd=None):
    """Run a shell command. Returns (stdout, stderr, returncode)."""
    result = subprocess.run(
        cmd, shell=isinstance(cmd, str),
        capture_output=capture, text=True, cwd=cwd
    )
    if check and result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"Command failed: {cmd}")
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def detect_repo():
    """Detect owner/repo from git remote."""
    try:
        url, _, _ = run(["git", "remote", "get-url", "origin"])
        if "github.com/" in url:
            return url.split("github.com/")[-1].removesuffix(".git")
        elif "github.com:" in url:
            return url.split("github.com:")[-1].removesuffix(".git")
    except Exception:
        pass
    return None


def parse_filter(filter_str):
    """Parse comma-separated risk levels and feature types from a filter string."""
    valid_levels = set(RISK_ORDER)
    valid_types = {"sast", "iac", "secret", "cve", "scm_posture"}

    levels = []
    types = []
    unknown = []

    for token in filter_str.split(","):
        token = token.strip().lower()
        if token in valid_levels:
            levels.append(token)
        elif token in valid_types:
            types.append(token)
        elif token:
            unknown.append(token)

    if unknown:
        print(f"Warning: ignoring unknown filter tokens: {unknown}", file=sys.stderr)

    return levels or None, types or None


def min_level_from_list(levels):
    """Return the lowest-ranked (most inclusive) level from a list."""
    if not levels:
        return None
    indices = [RISK_ORDER.index(l) for l in levels if l in RISK_ORDER]
    return RISK_ORDER[max(indices)] if indices else None


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def _alert_to_entry(a):
    """Convert a normalized alert dict to a list-alerts entry."""
    branch = alert_branch_name(a["alert_id"])
    return {
        "alert_id":      a["alert_id"],
        "title":         a["title"],
        "risk_level":    a["risk_level"],
        "score":         a["score"],
        "feature_type":  _resolve_feature_type(a),
        "source":        a["source"],
        "is_fixable":    is_fixable(a),
        "branch_exists": branch_exists_remote(branch),
        "branch_name":   branch,
    }


def cmd_list_alerts(args):
    token = get_token()

    # Single-alert mode: bypass bulk fetch
    if args.alert:
        try:
            a = fetch_alert_by_id(args.alert, token)
        except RuntimeError as e:
            print(json.dumps({"error": str(e)}))
            sys.exit(1)
        if not a:
            print(json.dumps({"error": f"Alert {args.alert} not found"}))
            sys.exit(1)
        result = [_alert_to_entry(a)]
        print(json.dumps({"dry_run": getattr(args, "dry_run", False), "alerts": result}, indent=2))
        return

    # Bulk mode
    repo = args.repo or detect_repo()
    if not repo:
        sys.exit("Error: could not detect repo. Pass repo as argument.")

    levels, types = parse_filter(args.filter) if args.filter else (None, None)
    min_level = min_level_from_list(levels)

    try:
        alerts = fetch_alerts(repo, token, min_level=min_level, feature_types=types)
    except RuntimeError as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

    if args.fixable_only:
        alerts = [a for a in alerts if is_fixable(a)]

    result = [_alert_to_entry(a) for a in alerts]

    if args.max:
        result = result[:args.max]

    output = {
        "dry_run": getattr(args, "dry_run", False),
        "alerts": result,
    }
    print(json.dumps(output, indent=2))


def cmd_get_alert(args):
    token = get_token()
    try:
        alert = fetch_alert_by_id(args.alert_id, token)
    except RuntimeError as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

    if not alert:
        print(json.dumps({"error": f"Alert {args.alert_id} not found"}))
        sys.exit(1)

    print(json.dumps(alert, indent=2))


def cmd_git_setup(args):
    branch = alert_branch_name(args.alert_id)

    if args.dry_run:
        print(f"dry-run: would create branch {branch} from main")
        return

    try:
        run(["git", "checkout", "main"])
        run(["git", "pull", "origin", "main"])
        stdout, stderr, rc = run(["git", "checkout", "-b", branch], check=False)
        if rc != 0:
            if "already exists" in stderr:
                print("branch_exists_locally")
                sys.exit(1)
            raise RuntimeError(stderr)
        print(f"ok: {branch}")
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_git_commit(args):
    if args.dry_run:
        print(f"dry-run: would commit with message: {args.message}")
        return

    try:
        run(["git", "add", "-A"])
        stdout, _, _ = run(["git", "commit", "-m", args.message])
        # Extract SHA from "1 file changed" line or git log
        sha, _, _ = run(["git", "rev-parse", "--short", "HEAD"])
        print(sha)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_open_pr(args):
    branch = alert_branch_name(args.alert_id)

    if args.dry_run:
        print(f"dry-run: would push {branch} and open PR: {args.title}")
        return

    try:
        run(["git", "push", "-u", "origin", branch])
        pr_url, _, _ = run([
            "gh", "pr", "create",
            "--title", args.title,
            "--body", args.body,
            "--base", "main",
            "--head", branch
        ])
        print(pr_url)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Security Engineer Agent — mechanical ops")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without executing")
    sub = parser.add_subparsers(dest="command", required=True)

    # list-alerts
    p_list = sub.add_parser("list-alerts", help="Fetch and filter alerts as JSON")
    p_list.add_argument("repo", nargs="?", help="owner/repo (auto-detected if omitted)")
    p_list.add_argument("--filter", default=None,
                        help="Comma-separated risk levels and/or feature types (e.g. 'high,sast')")
    p_list.add_argument("--alert", default=None, help="Target a single alert ID instead of bulk fetch")
    p_list.add_argument("--max", type=int, default=None, help="Max number of alerts to return")
    p_list.add_argument("--fixable-only", action="store_true", help="Only return fixable alerts")
    p_list.add_argument("--dry-run", action="store_true", help="Signal dry-run mode in output")

    # get-alert
    p_get = sub.add_parser("get-alert", help="Fetch single alert as JSON")
    p_get.add_argument("alert_id")

    # git-setup
    p_git = sub.add_parser("git-setup", help="Create fix branch from main")
    p_git.add_argument("alert_id")

    # git-commit
    p_commit = sub.add_parser("git-commit", help="Stage all and commit")
    p_commit.add_argument("alert_id")
    p_commit.add_argument("message")

    # open-pr
    p_pr = sub.add_parser("open-pr", help="Push branch and open PR")
    p_pr.add_argument("alert_id")
    p_pr.add_argument("--title", required=True)
    p_pr.add_argument("--body", required=True)

    args = parser.parse_args()

    # Propagate --dry-run into subcommand args
    if not hasattr(args, "dry_run"):
        args.dry_run = False

    dispatch = {
        "list-alerts": cmd_list_alerts,
        "get-alert":   cmd_get_alert,
        "git-setup":   cmd_git_setup,
        "git-commit":  cmd_git_commit,
        "open-pr":     cmd_open_pr,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
