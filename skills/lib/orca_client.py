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
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class Repository:
    """A code repository with Orca metadata and an optional local clone path.

    clone_path = None  → single-repo mode: all git ops use cwd (existing behaviour)
    clone_path = Path  → multi-repo mode: all git ops run inside the cloned directory
    """
    name: str                           # "owner/repo" (derived from URL)
    url: str                            # "https://github.com/owner/repo" (for cloning)
    clone_path: Optional[Path] = None   # set by _clone_repo() in multi-repo mode
    orca_score: float = 0.0
    risk_level: str = ""

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


def _extract_file_path(source: str) -> str:
    """Extract a clean relative file path from the Orca Source field.

    Handles three formats:
    - GitHub blob URL: https://github.com/owner/repo/blob/<sha>/path/to/file.js
    - Path with line suffix: path/to/file.js:40
    - Plain path: path/to/file.js
    """
    if not source:
        return ""
    if "github.com" in source and "/blob/" in source:
        parts = source.split("/blob/")
        if len(parts) > 1:
            # Drop the sha/branch component (first segment after /blob/)
            path = "/".join(parts[1].split("/")[1:])
            return path.split("#")[0].strip("/")  # strip GitHub line anchor (#L40)
    return source.split(":")[0].strip()


def _normalize_code_snippet(raw_snippet):
    """Normalize code_snippet to a list of code lines.

    Orca returns different formats depending on alert type:
    - Secret/SAST: list of dicts [{"line": "code...", "position": 3}, ...]
    - Other:       list of strings ["code line 1", "code line 2"]
    """
    if not raw_snippet:
        return [], None, None
    lines = []
    first_line = None
    last_line = None
    for entry in raw_snippet:
        if isinstance(entry, dict):
            lines.append(entry.get("line", "").rstrip("\n"))
            pos = entry.get("position")
            if pos is not None:
                if first_line is None or pos < first_line:
                    first_line = pos
                if last_line is None or pos > last_line:
                    last_line = pos
        else:
            lines.append(str(entry))
    return lines, first_line, last_line


def _normalize_alert(item):
    """Convert a raw API item into a clean dict."""
    findings = val(item, "RiskFindings", {}) or {}
    position = findings.get("position", {}) or {}
    ai_triage = findings.get("ai_triage", {}) or {}
    source = val(item, "Source", "") or ""

    # Normalize code_snippet and extract line numbers from it
    raw_snippet = findings.get("code_snippet", [])
    snippet_lines, snippet_start, snippet_end = _normalize_code_snippet(raw_snippet)

    # Position: prefer explicit position dict, fall back to code_snippet positions
    start_line = position.get("start_line") or snippet_start
    end_line = position.get("end_line") or snippet_end

    return {
        "alert_id":       val(item, "AlertId") or item.get("name", ""),
        "title":          val(item, "AlertType", ""),
        "risk_level":     (val(item, "RiskLevel", "") or "").lower(),
        "score":          val(item, "OrcaScore"),
        "category":       val(item, "Category", ""),
        "status":         val(item, "Status", ""),
        "source":         source,
        "file_path":      _extract_file_path(source),
        "labels":         val(item, "Labels", []) or [],
        "description":    val(item, "Description", ""),
        "recommendation": val(item, "Recommendation", ""),
        "feature_type":   findings.get("feature_type", ""),
        "code_snippet":   snippet_lines,            # always list[str] now
        "position": {
            "start_line": start_line,
            "end_line":   end_line,
        },
        "ai_triage": {
            "explanation": ai_triage.get("explanation", ""),
            "verdict":     ai_triage.get("verdict", ""),
            "confidence":  ai_triage.get("confidence"),
        },
        # Rich context from RiskFindings (available for fix agents)
        "origin_url":     findings.get("origin_url", ""),
        "verification":   findings.get("active_verification_status", ""),
        "first_commit":   findings.get("first_commit", {}),
        "is_test_file":   findings.get("is_test_file", False),
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


def list_repositories(token: str) -> list:
    """Fetch all code repositories that have open/in-progress alerts in Orca.

    Returns a list of Repository objects ordered by OrcaScore descending.
    """
    payload = {
        "query": {
            "models": ["CodeRepository"],
            "type": "object_set",
            "with": {
                "keys": ["Alerts"],
                "models": ["Alert"],
                "type": "object_set",
                "operator": "has",
                "with": {
                    "key": "Status",
                    "values": ["open", "in_progress"],
                    "type": "str",
                    "operator": "in"
                }
            }
        },
        "limit": 100,
        "start_at_index": 0,
        "order_by[]": ["-OrcaScore"],
        "select": [
            "CiSource", "Name", "OrcaScore", "RiskLevel", "group_unique_id",
            "Exposure", "State", "Observations", "Tags",
            "ShiftleftProject.Name", "CodeLanguages", "Url"
        ],
        "get_results_and_count": False,
        "full_graph_fetch": {"enabled": True},
        "debug_enable_bu_tags": True,
        "max_tier": 2,
    }
    result = _post(payload, token)
    repos = []
    seen_urls: set = set()
    for item in result.get("data", []):
        url = (val(item, "Url", "") or "").strip()
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        # Derive owner/repo from the clone URL
        name = None
        for sep in ("github.com/", "github.com:"):
            if sep in url:
                name = url.split(sep)[-1].removesuffix(".git").strip("/")
                break
        if not name:
            # Fall back to the Orca Name field
            name = (val(item, "Name", "") or url)
        repos.append(Repository(
            name=name,
            url=url,
            orca_score=float(val(item, "OrcaScore") or 0),
            risk_level=(val(item, "RiskLevel", "") or "").lower(),
        ))
    return repos


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


def branch_exists_remote(branch_name, cwd=None):
    """Check if branch exists on remote origin.

    cwd: working directory for the git command (None = inherit from caller).
         Pass repo.clone_path in multi-repo mode.
    """
    try:
        result = subprocess.run(
            ["git", "ls-remote", "--heads", "origin", branch_name],
            capture_output=True, text=True, timeout=10, cwd=cwd
        )
        return bool(result.stdout.strip())
    except Exception:
        return False
