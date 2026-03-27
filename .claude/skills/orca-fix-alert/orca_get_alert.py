#!/usr/bin/env python3
"""
Fetch a single Orca Security alert by ID.
Usage: python3 orca_get_alert.py <alert-id> [--json]
Token: ORCA_API_TOKEN env var
"""
import sys
import json
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
from orca_client import get_token, fetch_alert_by_id


def print_alert(a):
    print(f"# Alert: {a['alert_id']}")
    print(f"\n**Title:** {a['title']}")
    print(f"**Risk Level:** {a['risk_level']}  |  **Score:** {a['score']}")
    print(f"**Category:** {a['category']}  |  **Status:** {a['status']}")
    print(f"**Feature Type:** {a['feature_type']}")
    print(f"**Source:** {a['source']}")
    if a["labels"]:
        print(f"**Labels:** {', '.join(str(l) for l in a['labels'])}")

    print(f"\n## Description\n\n{a['description']}")
    print(f"\n## Recommendation\n\n{a['recommendation']}")

    triage = a.get("ai_triage", {})
    if triage.get("explanation"):
        print(f"\n## AI Triage\n")
        print(triage["explanation"])
        print(f"\n**Verdict:** {triage.get('verdict', '')}  |  **Confidence:** {triage.get('confidence', '')}")

    pos = a.get("position", {})
    if pos.get("start_line") is not None:
        print(f"\n## Vulnerable Lines\n\nstart_line: {pos['start_line']}  end_line: {pos['end_line']}")

    snippet = a.get("code_snippet", [])
    if snippet:
        print(f"\n## Code Snippet\n")
        print("```")
        for entry in snippet:
            print(f"{entry.get('position', ''):>4}  {entry.get('line', '')}")
        print("```")


def main():
    parser = argparse.ArgumentParser(description="Fetch a single Orca alert")
    parser.add_argument("alert_id", help="Alert ID (e.g. orca-270453)")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of markdown")
    args = parser.parse_args()

    token = get_token()
    try:
        alert = fetch_alert_by_id(args.alert_id, token)
    except RuntimeError as e:
        sys.exit(str(e))

    if not alert:
        sys.exit(f"Alert {args.alert_id} not found.")

    if args.json:
        print(json.dumps(alert, indent=2))
    else:
        print_alert(alert)


if __name__ == "__main__":
    main()
