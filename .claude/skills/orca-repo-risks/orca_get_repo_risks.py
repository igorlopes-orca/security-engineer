#!/usr/bin/env python3
"""
Fetch Orca Security alerts for a GitHub repository.
Usage: python3 orca_get_repo_risks.py <owner/repo>
Token: ORCA_API_TOKEN env var or ORCA_AUTH_TOKEN env var
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


def fetch_repo_alerts(repo_name, token):
    payload = {
        "query": {
            "models": ["Alert"],
            "type": "object_set",
            "with": {
                "operator": "and",
                "type": "operation",
                "values": [
                    {
                        "keys": ["Inventories"],
                        "models": ["Inventory"],
                        "type": "object_set",
                        "operator": "has",
                        "with": {
                            "key": "Name",
                            "values": [repo_name],
                            "type": "str",
                            "operator": "in"
                        }
                    },
                    {
                        "key": "Status",
                        "values": ["in_progress", "open"],
                        "type": "str",
                        "operator": "in"
                    }
                ]
            }
        },
        "limit": 100,
        "start_at_index": 0,
        "order_by[]": ["-OrcaScore"],
        "select": [
            "AlertId", "AlertType", "OrcaScore", "RiskLevel", "RuleSource",
            "RuleType", "ScoreVector", "Title", "AssetData",
            "AutoRemediationActions", "Category", "Inventory.Name",
            "Inventory.CiSource", "CloudAccount.Name",
            "CloudAccount.CloudProvider", "Source", "Status", "CreatedAt",
            "LastSeen", "Inventories.Name", "Labels", "Jira", "AzureDevops",
            "ServiceNowIncidents", "ServiceNowSiIncidents", "Monday", "Linear"
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


def print_alerts(repo_name, items):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for item in items:
        risk = val(item, "RiskLevel", "informational").lower()
        counts[risk] = counts.get(risk, 0) + 1

    print(f"# Orca Alerts: {repo_name}\n")
    print(f"**Total alerts:** {len(items)}")
    print(f"Critical: {counts['critical']}  |  High: {counts['high']}  |  "
          f"Medium: {counts['medium']}  |  Low: {counts['low']}  |  "
          f"Informational: {counts['informational']}\n")

    level_order = ["critical", "high", "medium", "low", "informational"]
    grouped = {lvl: [] for lvl in level_order}
    for item in items:
        risk = val(item, "RiskLevel", "informational").lower()
        grouped.setdefault(risk, []).append(item)

    for level in level_order:
        group = grouped.get(level, [])
        if not group:
            continue
        print(f"## {level.capitalize()} ({len(group)})\n")
        print(f"{'Alert ID':<20} {'Score':>6}  {'Category':<25}  Title")
        print("-" * 90)
        for item in group:
            alert_id = val(item, "AlertId") or item.get("name", "")
            score    = val(item, "OrcaScore")
            category = val(item, "Category", "")
            title    = val(item, "AlertType") or val(item, "Title", "")
            status   = val(item, "Status", "")
            source   = val(item, "Source", "")
            print(f"{alert_id:<20} {score:>6}  {category:<25}  {title}")
            if source:
                print(f"{'':20}         Source: {source}")
        print()


def main():
    if len(sys.argv) < 2:
        sys.exit("Usage: python3 orca_get_repo_risks.py <owner/repo>")

    repo_name = sys.argv[1]
    token = get_token()
    result = fetch_repo_alerts(repo_name, token)
    items = result.get("data", [])

    if not items:
        print(f"No open alerts found for repository: {repo_name}")
        print(f"Raw response: {json.dumps(result)[:500]}")
        return

    print_alerts(repo_name, items)


if __name__ == "__main__":
    main()
