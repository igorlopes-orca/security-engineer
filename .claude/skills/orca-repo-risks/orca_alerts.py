#!/usr/bin/env python3
"""
Fetch Orca Security alerts for a GitHub repository.
Usage: python3 orca_alerts.py <owner/repo>
Token: ORCA_API_TOKEN env var (plain API key)
       or ORCA_AUTH_TOKEN env var (base64 "url||token" format used by orca-mcp-server)
"""
import sys
import os
import json
import base64
import urllib.request
import urllib.error

ORCA_API = "https://api.orcasecurity.io/api/serving-layer/query"
RISK_ORDER = ["critical", "high", "medium", "low", "informational"]

ALL_CATEGORIES = [
    "Neglected assets", "Vendor services misconfigurations",
    "Workload misconfigurations", "Best practices",
    "Data protection", "Data at risk", "IAM misconfigurations",
    "Network misconfigurations", "Logging and monitoring",
    "Authentication", "Lateral movement", "Vulnerabilities",
    "Malware", "Malicious activity", "System integrity",
    "Suspicious activity", "Source code vulnerabilities"
]


def get_token():
    # ORCA_API_TOKEN: full base64 token string (same format used by orca-remote MCP proxy)
    token = os.environ.get("ORCA_API_TOKEN")
    if token:
        return token
    # ORCA_AUTH_TOKEN: same format, set by orca-mcp-server config — use as-is
    token = os.environ.get("ORCA_AUTH_TOKEN")
    if token:
        return token
    sys.exit("Error: set ORCA_API_TOKEN env var (the base64 token string from your Orca MCP server config)")


def val(obj, key, default=""):
    """Extract a value from item['data'][key]['value'] or item[key]."""
    data = obj.get("data", obj)  # fields live in item["data"]
    v = data.get(key, default)
    if isinstance(v, dict):
        return v.get("value", default)
    return v if v is not None else default


def fetch_alerts(repo, token):
    payload = {
        "query": {
            "models": ["Alert"],
            "type": "object_set",
            "with": {
                "operator": "and",
                "type": "operation",
                "values": [
                    {
                        "key": "Category",
                        "values": ALL_CATEGORIES,
                        "type": "str",
                        "operator": "in"
                    },
                    {
                        "key": "Status",
                        "values": ["open", "in_progress"],
                        "type": "str",
                        "operator": "in"
                    },
                    {
                        "keys": ["Inventories"],
                        "models": ["Inventory"],
                        "type": "object_set",
                        "operator": "has",
                        "with": {
                            "key": "Name",
                            "values": [repo],
                            "type": "str",
                            "operator": "in"
                        }
                    }
                ]
            }
        },
        "limit": 100,
        "start_at_index": 0,
        "order_by[]": ["-OrcaScore"],
        "select": [
            "AlertId", "AlertType", "OrcaScore", "RiskLevel",
            "Category", "Source", "Status", "CreatedAt", "Labels"
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


def parse_alerts(result):
    if isinstance(result, list):
        return result
    if "data" in result:
        return result["data"]
    # {"model_data": {"Alert": {"objects": [...]}}}
    md = result.get("model_data", {})
    if "Alert" in md:
        return md["Alert"].get("objects", [])
    return []


def print_report(repo, alerts):
    grouped = {lvl: [] for lvl in RISK_ORDER}
    for a in alerts:
        lvl = val(a, "RiskLevel", "informational").lower()
        if lvl not in grouped:
            lvl = "informational"
        grouped[lvl].append(a)

    total = sum(len(v) for v in grouped.values())
    print(f"# Orca Alerts — {repo}")
    print(f"\nTotal open/in-progress: **{total}**\n")

    print("| Risk Level | Count |")
    print("|---|---|")
    for lvl in RISK_ORDER:
        n = len(grouped[lvl])
        if n:
            print(f"| {lvl.capitalize()} | {n} |")

    for lvl in RISK_ORDER:
        items = grouped[lvl]
        if not items:
            continue
        print(f"\n## {lvl.capitalize()} ({len(items)})\n")
        print("| Alert ID | Title | Category | Score |")
        print("|---|---|---|---|")
        for a in items:
            aid = val(a, "AlertId") or a.get("name", "")
            title = val(a, "AlertType")
            cat = val(a, "Category")
            score = val(a, "OrcaScore")
            print(f"| {aid} | {title} | {cat} | {score} |")


def main():
    if len(sys.argv) < 2:
        sys.exit("Usage: python3 orca_alerts.py owner/repo")

    repo = sys.argv[1]
    token = get_token()
    result = fetch_alerts(repo, token)
    alerts = parse_alerts(result)

    if not alerts:
        print("No alerts found. Raw response (first 2000 chars):")
        print(json.dumps(result)[:2000])
        return

    print_report(repo, alerts)


if __name__ == "__main__":
    main()
