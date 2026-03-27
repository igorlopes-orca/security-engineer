"""
Shared Orca Security API client.
Used by orca_alerts.py, orca_get_alert.py, and run_agent.py.

Token: ORCA_API_TOKEN env var (base64 token string from Orca config)
       or ORCA_AUTH_TOKEN env var (same format)
"""
import sys
import os
import json
import re
import subprocess
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
    """Read ORCA_API_TOKEN or ORCA_AUTH_TOKEN from environment."""
    token = os.environ.get("ORCA_API_TOKEN") or os.environ.get("ORCA_AUTH_TOKEN")
    if not token:
        sys.exit("Error: set ORCA_API_TOKEN env var (base64 token from your Orca config)")
    return token


def val(item, key, default=None):
    """Extract from item['data'][key]['value'], item[key], or default."""
    data = item.get("data", item)
    v = data.get(key, default)
    if isinstance(v, dict):
        return v.get("value", default)
    return v if v is not None else default


def _post(payload, token):
    """POST to ORCA_API. Raises RuntimeError on HTTP error."""
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
        body = e.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {e.code}: {body}")


def _normalize_alert(item):
    """Convert a raw API item into a clean dict."""
    findings = val(item, "RiskFindings", {}) or {}
    position = findings.get("position", {}) or {}
    ai_triage = findings.get("ai_triage", {}) or {}

    return {
        "alert_id":       val(item, "AlertId") or item.get("name", ""),
        "title":          val(item, "AlertType", ""),
        "risk_level":     (val(item, "RiskLevel", "") or "").lower(),
        "score":          val(item, "OrcaScore"),
        "category":       val(item, "Category", ""),
        "status":         val(item, "Status", ""),
        "source":         val(item, "Source", ""),
        "labels":         val(item, "Labels", []) or [],
        "description":    val(item, "Description", ""),
        "recommendation": val(item, "Recommendation", ""),
        "feature_type":   findings.get("feature_type", ""),
        "code_snippet":   findings.get("code_snippet", []),
        "position": {
            "start_line": position.get("start_line"),
            "end_line":   position.get("end_line"),
        },
        "ai_triage": {
            "explanation": ai_triage.get("explanation", ""),
            "verdict":     ai_triage.get("verdict", ""),
            "confidence":  ai_triage.get("confidence"),
        },
    }


def fetch_alert_by_id(alert_id, token):
    """Fetch a single alert by ID. Returns normalized dict or None."""
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
            "Source", "Status", "Description", "Recommendation",
            "RiskFindings", "Labels", "AssetData"
        ],
        "get_results_and_count": False,
        "full_graph_fetch": {"enabled": True},
        "debug_enable_bu_tags": True,
        "max_tier": 2
    }
    result = _post(payload, token)
    items = result.get("data", [])
    if not items:
        return None
    return _normalize_alert(items[0])


def fetch_alerts(repo, token, min_level=None, feature_types=None, statuses=None):
    """
    Fetch open alerts for a repo.

    repo          - "owner/repo" string
    min_level     - minimum risk level (inclusive); None means all
    feature_types - list of feature_type strings to include; None means all
    statuses      - list of statuses; defaults to ["open", "in_progress"]
    """
    if statuses is None:
        statuses = ["open", "in_progress"]

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
                        "values": statuses,
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
            "Category", "Source", "Status", "Description",
            "Recommendation", "RiskFindings", "Labels"
        ],
        "get_results_and_count": False,
        "full_graph_fetch": {"enabled": True},
        "debug_enable_bu_tags": True,
        "max_tier": 2
    }

    result = _post(payload, token)
    items = result.get("data", [])
    alerts = [_normalize_alert(item) for item in items]

    # Filter by min_level
    if min_level and min_level in RISK_ORDER:
        cutoff = RISK_ORDER.index(min_level)
        alerts = [a for a in alerts if a["risk_level"] in RISK_ORDER and RISK_ORDER.index(a["risk_level"]) <= cutoff]

    # Filter by feature_types
    if feature_types:
        ft_set = set(ft.lower() for ft in feature_types)
        alerts = [a for a in alerts if _resolve_feature_type(a) in ft_set]

    return alerts


def _resolve_feature_type(alert):
    """Normalize feature_type.
    Package CVEs have empty feature_type but category 'Vulnerabilities'.
    SAST CVEs have feature_type 'sast' and a CVE-* label.
    """
    ft = (alert.get("feature_type") or "").lower()
    category = (alert.get("category") or "").lower()
    labels = alert.get("labels") or []
    has_cve_label = any(re.match(r"CVE-\d{4}-\d+", str(l)) for l in labels)

    # Package vulnerabilities: category "Vulnerabilities" with no feature_type
    if "vulnerabilit" in category and not ft:
        return "cve"
    # SAST alerts with explicit CVE labels
    if has_cve_label and ft == "sast":
        return "cve"
    return ft or "unknown"


def is_fixable(alert):
    """True for sast/iac/secret/cve. False for scm_posture and unknown."""
    return _resolve_feature_type(alert) in {"sast", "iac", "secret", "cve"}


def alert_branch_name(alert_id):
    return f"fix/orca-{alert_id.replace('/', '-')}"


def branch_exists_remote(branch_name):
    """Check if branch exists on remote origin."""
    try:
        result = subprocess.run(
            ["git", "ls-remote", "--heads", "origin", branch_name],
            capture_output=True, text=True, timeout=10
        )
        return bool(result.stdout.strip())
    except Exception:
        return False
