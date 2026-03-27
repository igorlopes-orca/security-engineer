#!/usr/bin/env python3
"""
Fetch a single Orca Security alert by ID.
Usage: python3 orca_get_alert.py <alert-id>
Token: ORCA_API_TOKEN env var (base64 token string from Orca MCP server config)
       or ORCA_AUTH_TOKEN env var
"""
import sys
import os
import json
import urllib.request
import urllib.error

ORCA_API = "https://api.orcasecurity.io/api/serving-layer/query"


def get_token():
    token = os.environ.get("ORCA_API_TOKEN") or os.environ.get("ORCA_AUTH_TOKEN")
    if not token:
        sys.exit("Error: set ORCA_API_TOKEN env var")
    return token


def val(item, key, default=""):
    """Extract from item['data'][key]['value'] or item[key]."""
    data = item.get("data", item)
    v = data.get(key, default)
    if isinstance(v, dict):
        return v.get("value", default)
    return v if v is not None else default


def fetch_alert(alert_id, token):
    payload = {
        "query": {
            "models": ["Alert"],
            "type": "object_set",
            "with": {
                "key": "AlertId",
                "values": [alert_id],
                "type": "str",
                "operator": "in"
            }
        },
        "limit": 1,
        "select": [
            "AlertId", "AlertType", "OrcaScore", "RiskLevel", "Category",
            "Source", "Status", "Description", "Recommendation", "RiskFindings",
            "Labels", "AssetData"
        ],
        "get_results_and_count": False,
        "full_graph_fetch": {"enabled": True},
        "debug_enable_bu_tags": True,
        "max_tier": 2
    }

    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        ORCA_API,
        data=data,
        headers={
            "Authorization": f"TOKEN {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        sys.exit(f"HTTP {e.code}: {e.read().decode(errors='replace')}")


def print_alert(item):
    alert_id   = val(item, "AlertId") or item.get("name", "")
    title      = val(item, "AlertType")
    risk_level = val(item, "RiskLevel")
    score      = val(item, "OrcaScore")
    category   = val(item, "Category")
    status     = val(item, "Status")
    description    = val(item, "Description")
    recommendation = val(item, "Recommendation")
    source     = val(item, "Source")
    labels     = val(item, "Labels", [])
    findings   = val(item, "RiskFindings", {})

    feature_type  = findings.get("feature_type", "")
    code_snippet  = findings.get("code_snippet", [])
    ai_triage     = findings.get("ai_triage", {})
    position      = findings.get("position", {})

    print(f"# Alert: {alert_id}")
    print(f"\n**Title:** {title}")
    print(f"**Risk Level:** {risk_level}  |  **Score:** {score}")
    print(f"**Category:** {category}  |  **Status:** {status}")
    print(f"**Feature Type:** {feature_type}")
    print(f"**Source:** {source}")
    if labels:
        print(f"**Labels:** {', '.join(str(l) for l in labels)}")

    print(f"\n## Description\n\n{description}")
    print(f"\n## Recommendation\n\n{recommendation}")

    if ai_triage:
        print(f"\n## AI Triage\n")
        print(ai_triage.get("explanation", ""))
        print(f"\n**Verdict:** {ai_triage.get('verdict', '')}  |  **Confidence:** {ai_triage.get('confidence', '')}")

    if position:
        start = position.get("start_line", "")
        end   = position.get("end_line", "")
        print(f"\n## Vulnerable Lines\n\nstart_line: {start}  end_line: {end}")

    if code_snippet:
        print(f"\n## Code Snippet\n")
        print("```")
        for entry in code_snippet:
            print(f"{entry.get('position', ''):>4}  {entry.get('line', '')}")
        print("```")


def main():
    if len(sys.argv) < 2:
        sys.exit("Usage: python3 orca_get_alert.py <alert-id>")

    alert_id = sys.argv[1]
    token = get_token()
    result = fetch_alert(alert_id, token)
    items = result.get("data", [])

    if not items:
        print(f"Alert {alert_id} not found.")
        print(f"Raw response: {json.dumps(result)[:1000]}")
        return

    print_alert(items[0])


if __name__ == "__main__":
    main()
