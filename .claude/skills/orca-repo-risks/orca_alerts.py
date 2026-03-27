#!/usr/bin/env python3
"""
Fetch Orca Security alerts for a GitHub repository.
Usage: python3 orca_alerts.py [owner/repo] [--json] [--level high]
Token: ORCA_API_TOKEN env var
"""
import sys
import json
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
from orca_client import get_token, fetch_alerts, RISK_ORDER, is_fixable, _resolve_feature_type

RISK_BADGE = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "informational": "⚪"}


def print_report(repo, alerts):
    grouped = {lvl: [] for lvl in RISK_ORDER}
    for a in alerts:
        lvl = a["risk_level"] if a["risk_level"] in grouped else "informational"
        grouped[lvl].append(a)

    total = sum(len(v) for v in grouped.values())
    print(f"# Orca Alerts — {repo}")
    print(f"\nTotal open/in-progress: **{total}**\n")

    print("| Risk Level | Count |")
    print("|---|---|")
    for lvl in RISK_ORDER:
        n = len(grouped[lvl])
        if n:
            print(f"| {RISK_BADGE.get(lvl, '')} {lvl.capitalize()} | {n} |")

    for lvl in RISK_ORDER:
        items = grouped[lvl]
        if not items:
            continue
        print(f"\n## {RISK_BADGE.get(lvl, '')} {lvl.capitalize()} ({len(items)})\n")
        print("| Alert ID | Title | Category | Score | Type |")
        print("|---|---|---|---|---|")
        for a in items:
            ftype = _resolve_feature_type(a)
            print(f"| {a['alert_id']} | {a['title']} | {a['category']} | {a['score']} | {ftype} |")


def main():
    parser = argparse.ArgumentParser(description="Fetch Orca alerts for a repo")
    parser.add_argument("repo", nargs="?", help="owner/repo (auto-detected from git remote if omitted)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of markdown")
    parser.add_argument("--level", default=None, help="Minimum risk level (critical/high/medium/low)")
    parser.add_argument("--types", default=None, help="Comma-separated feature types (sast,iac,secret,cve)")
    args = parser.parse_args()

    # Auto-detect repo if not provided
    repo = args.repo
    if not repo:
        import subprocess
        try:
            url = subprocess.check_output(["git", "remote", "get-url", "origin"], text=True).strip()
            # https://github.com/owner/repo.git or git@github.com:owner/repo.git
            if "github.com/" in url:
                repo = url.split("github.com/")[-1].removesuffix(".git")
            elif "github.com:" in url:
                repo = url.split("github.com:")[-1].removesuffix(".git")
        except Exception:
            pass
    if not repo:
        sys.exit("Error: could not detect repo. Pass owner/repo as argument.")

    feature_types = [t.strip() for t in args.types.split(",")] if args.types else None
    token = get_token()

    try:
        alerts = fetch_alerts(repo, token, min_level=args.level, feature_types=feature_types)
    except RuntimeError as e:
        sys.exit(str(e))

    if not alerts:
        print(f"No alerts found for {repo}.", file=sys.stderr)
        if args.json:
            print("[]")
        return

    if args.json:
        print(json.dumps(alerts, indent=2))
    else:
        print_report(repo, alerts)


if __name__ == "__main__":
    main()
