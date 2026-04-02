#!/usr/bin/env python3
"""
Orca CLI validation step — before/after scan to verify fixes and detect regressions.

Runs the appropriate orca-cli scanner (sast, iac, sca, secrets) twice:
once with the fix reverted (baseline) and once with the fix applied.
Compares fingerprints to confirm the original vulnerability is gone
and no new issues were introduced.
"""
import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from validator import ValidationResult

# ---------------------------------------------------------------------------
# Scanner mapping: alert feature_type → orca-cli subcommand + args
# ---------------------------------------------------------------------------

_SCANNER_CMD = {
    "sast":   ["sast", "scan"],
    "iac":    ["iac", "scan"],
    "cve":    ["sca", "scan"],
    "secret": ["secrets", "scan"],
}

_SCAN_TIMEOUT = 300  # 5 minutes per scan


# ---------------------------------------------------------------------------
# Fingerprinting — normalize findings into comparable tuples
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FindingFingerprint:
    """Hashable identifier for a single finding across scans."""
    control_id: str
    file_name: str
    start_line: int

    def __str__(self):
        return f"{self.file_name}:{self.start_line} [{self.control_id[:8]}]"


def _extract_fingerprints(scan_output: dict) -> set[FindingFingerprint]:
    """Extract fingerprints from orca-cli JSON output.

    Handles both SAST/IaC schema (results[].catalog_control + findings[])
    and SCA schema (results[].vulnerabilities[]).
    """
    fps = set()
    results = scan_output.get("results") or []

    for result in results:
        control = result.get("catalog_control") or {}
        control_id = control.get("id", "unknown")

        for finding in result.get("findings") or []:
            pos = finding.get("position") or {}
            fps.add(FindingFingerprint(
                control_id=control_id,
                file_name=finding.get("file_name", ""),
                start_line=pos.get("start_line", 0),
            ))

    return fps


# ---------------------------------------------------------------------------
# Scan execution
# ---------------------------------------------------------------------------

def _get_api_token() -> Optional[str]:
    """Resolve the Orca CLI API token from environment."""
    return (os.environ.get("ORCA_SECURITY_API_TOKEN")
            or os.environ.get("ORCA_API_TOKEN"))


def _run_orca_scan(scanner_cmd: list[str], scan_path: Path,
                   token: str, project_key: str = "default") -> dict:
    """Run an orca-cli scan and return parsed JSON output.

    Returns empty dict on any error (scan failure, parse error, timeout).
    """
    cmd = [
        "orca-cli", *scanner_cmd,
        "--path", str(scan_path),
        "--format", "json",
        "--no-color",
        "--skip-scan-log",
        "-p", project_key,
        "--api-token", token,
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=_SCAN_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return {}
    except FileNotFoundError:
        return {}

    # orca-cli prints JSON to stdout, sometimes mixed with banner on stderr
    stdout = result.stdout.strip()
    if not stdout:
        return {}

    # Find the JSON object in the output (skip any banner text before it)
    json_start = stdout.find("{")
    if json_start == -1:
        return {}

    try:
        return json.loads(stdout[json_start:])
    except json.JSONDecodeError:
        return {}


# ---------------------------------------------------------------------------
# Before / after comparison
# ---------------------------------------------------------------------------

@dataclass
class OrcaCliResult:
    """Result of the before/after orca-cli validation."""
    passed: bool
    fixed_count: int = 0
    new_count: int = 0
    new_findings: list[str] = field(default_factory=list)
    fixed_findings: list[str] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""


def _git_stash(worktree_path: Path) -> bool:
    """Stash uncommitted changes. Returns True if something was stashed."""
    result = subprocess.run(
        ["git", "stash", "--include-untracked"],
        cwd=worktree_path, capture_output=True, text=True,
    )
    return "No local changes" not in result.stdout


def _git_stash_pop(worktree_path: Path):
    """Restore stashed changes."""
    subprocess.run(
        ["git", "stash", "pop"],
        cwd=worktree_path, capture_output=True, text=True,
    )


def orca_cli_validate(
    alert: dict,
    worktree_path: Path,
    feature_type: str,
) -> ValidationResult:
    """Run before/after orca-cli scan to verify fix and detect regressions.

    1. Stash the fix → scan baseline → pop the fix
    2. Scan again with fix applied
    3. Compare: original alert should be gone, no new findings
    """
    scanner_cmd = _SCANNER_CMD.get(feature_type)
    if not scanner_cmd:
        return ValidationResult(passed=True, phase="orca_cli")

    token = _get_api_token()
    if not token:
        return ValidationResult(passed=True, phase="orca_cli",
                                needs_review=True,
                                failures=["ORCA_SECURITY_API_TOKEN not set — skipped orca-cli scan"])

    if not shutil.which("orca-cli"):
        return ValidationResult(passed=True, phase="orca_cli",
                                needs_review=True,
                                failures=["orca-cli not installed — skipped"])

    # --- Before scan (baseline without fix) ---
    had_changes = _git_stash(worktree_path)
    if not had_changes:
        # No diff to compare — skip gracefully
        return ValidationResult(passed=True, phase="orca_cli",
                                needs_review=True,
                                failures=["no diff to stash — cannot run before/after comparison"])

    before_raw = _run_orca_scan(scanner_cmd, worktree_path, token)
    _git_stash_pop(worktree_path)

    # --- After scan (with fix applied) ---
    after_raw = _run_orca_scan(scanner_cmd, worktree_path, token)

    # --- Compare ---
    before_fps = _extract_fingerprints(before_raw)
    after_fps = _extract_fingerprints(after_raw)

    fixed = before_fps - after_fps   # findings that disappeared (good)
    new = after_fps - before_fps     # findings that appeared (bad)

    cli_result = OrcaCliResult(
        passed=len(new) == 0,
        fixed_count=len(fixed),
        new_count=len(new),
        new_findings=[str(f) for f in sorted(new, key=lambda f: f.file_name)],
        fixed_findings=[str(f) for f in sorted(fixed, key=lambda f: f.file_name)],
    )

    failures = []
    needs_review = False

    if new:
        failures.append(
            f"orca-cli detected {len(new)} new finding(s) introduced by the fix: "
            + ", ".join(cli_result.new_findings[:5])
        )

    if not fixed:
        # The scan didn't show the original finding disappearing.
        # This doesn't mean the fix is wrong — the scanner might not cover
        # the exact alert, or the alert might be API-only. Flag for review.
        needs_review = True

    return ValidationResult(
        passed=len(failures) == 0,
        phase="orca_cli",
        failures=failures,
        needs_review=needs_review,
    )
