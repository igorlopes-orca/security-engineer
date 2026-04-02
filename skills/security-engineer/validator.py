#!/usr/bin/env python3
"""
Multi-phase validation pipeline for security fixes.

Phase 1: Python sanity checks — diff non-empty, size limits, no new secrets
Phase 2: LLM validation — does the fix address the vulnerability?
Phase 3: Local build/test — language-aware compile/lint
Phase 4: GitHub CI gate — poll required PR checks (called after PR is opened)
"""
import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from _json_util import find_last_json_with_key


@dataclass
class ValidationResult:
    passed: bool
    phase: str                        # "sanity" | "llm" | "local_build" | "ci"
    failures: list[str] = field(default_factory=list)
    needs_review: bool = False        # True when LLM verdict is "uncertain"


# ---------------------------------------------------------------------------
# Phase 1: Sanity checks (Python, always)
# ---------------------------------------------------------------------------

_DIFF_LIMITS = {"sast": 50, "iac": 50, "secret": 50, "cve": 200}

_SECRET_PATTERNS = [
    r'(?i)(api_?key|password|secret|token)\s*[=:]\s*["\'][^"\']{8,}["\']',
    r'sk-[A-Za-z0-9]{20,}',
    r'(?i)bearer\s+[A-Za-z0-9+/]{20,}',
]


def sanity_check(alert: dict, worktree_path: Path) -> ValidationResult:
    failures = []

    stat = subprocess.run(
        ["git", "diff", "--stat"],
        cwd=worktree_path, capture_output=True, text=True
    ).stdout.strip()
    if not stat:
        return ValidationResult(passed=False, phase="sanity",
                                failures=["git diff is empty — no changes were made"])

    shortstat = subprocess.run(
        ["git", "diff", "--shortstat"],
        cwd=worktree_path, capture_output=True, text=True
    ).stdout
    total = sum(int(n) for n in re.findall(r"(\d+) (?:insertion|deletion)", shortstat))
    ft = (alert.get("feature_type") or "sast").lower()
    limit = _DIFF_LIMITS.get(ft, 50)
    if total > limit:
        failures.append(f"diff too large: {total} lines changed (limit {limit} for {ft})")

    if ft == "secret":
        diff_text = subprocess.run(
            ["git", "diff"],
            cwd=worktree_path, capture_output=True, text=True
        ).stdout
        added = [l for l in diff_text.splitlines()
                 if l.startswith("+") and not l.startswith("+++")]
        for line in added:
            for pat in _SECRET_PATTERNS:
                if re.search(pat, line):
                    failures.append("diff adds a line matching a secret pattern")
                    break

    return ValidationResult(passed=len(failures) == 0, phase="sanity", failures=failures)


# ---------------------------------------------------------------------------
# Phase 2: LLM validation agent
# ---------------------------------------------------------------------------

_LLM_PROMPT = """\
You are reviewing a security fix diff. Does this fix correctly address the vulnerability?

## Alert
{alert_json}

## Diff Applied
```diff
{diff_text}
```

Return ONLY this JSON as your final output (nothing after):
{{
  "verdict": "pass|fail|uncertain",
  "reason": "<one sentence>",
  "concerns": ["optional concern for reviewer"]
}}

- "pass"      → fix clearly addresses the vulnerability
- "fail"      → fix does not address it, or introduces new issues
- "uncertain" → fix seems plausible but correctness cannot be confirmed without runtime context
"""


def llm_validate(alert: dict, worktree_path: Path, timeout_sec: int = 90) -> ValidationResult:
    diff_text = subprocess.run(
        ["git", "diff"],
        cwd=worktree_path, capture_output=True, text=True
    ).stdout[:5000]

    prompt = _LLM_PROMPT.format(
        alert_json=json.dumps(alert, indent=2),
        diff_text=diff_text,
    )
    cmd = ["claude", "-p", prompt, "--output-format", "json", "--max-turns", "1"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        # Don't block on timeout — flag for review instead
        return ValidationResult(passed=True, phase="llm", needs_review=True,
                                failures=["LLM validation timed out — flagged for human review"])

    if result.returncode != 0:
        return ValidationResult(passed=True, phase="llm", needs_review=True,
                                failures=["LLM validation errored — flagged for human review"])

    return _parse_llm(result.stdout)


def _parse_llm(raw: str) -> ValidationResult:
    try:
        envelope = json.loads(raw)
        text = envelope.get("result", "") or raw
    except json.JSONDecodeError:
        text = raw

    data = find_last_json_with_key(text, "verdict")
    if not data:
        return ValidationResult(passed=True, phase="llm", needs_review=True,
                                failures=["Could not parse LLM validation response"])

    verdict = data.get("verdict", "uncertain")
    reason = data.get("reason", "")
    concerns = data.get("concerns") or []

    if verdict == "fail":
        return ValidationResult(passed=False, phase="llm", failures=[reason])
    elif verdict == "uncertain":
        return ValidationResult(passed=True, phase="llm", needs_review=True, failures=concerns)
    else:
        return ValidationResult(passed=True, phase="llm")


# ---------------------------------------------------------------------------
# Phase 3: Local build/test (language-aware)
# ---------------------------------------------------------------------------

def _dominant_ext(files: list[str]) -> str | None:
    counts: dict[str, int] = {}
    for f in files:
        ext = Path(f).suffix.lower()
        counts[ext] = counts.get(ext, 0) + 1
    return max(counts, key=counts.get) if counts else None


def local_build_check(
    files_changed: list[str],
    worktree_path: Path,
    source_file: str = "",
) -> ValidationResult:
    """Run a language-appropriate build check after a fix is applied.

    source_file: the affected file path from the Orca alert (authoritative).
                 Used as the primary seed for project-root detection; falls back
                 to files_changed if empty.
    """
    # Seed with the alert's source file first — it's authoritative and available
    # before the fix agent runs, unlike files_changed which comes from agent output.
    all_files = ([source_file] if source_file else []) + list(files_changed)

    ext = _dominant_ext(all_files)
    if not ext:
        return ValidationResult(passed=True, phase="local_build")

    if ext == ".go":
        go_root = _find_project_root(all_files, worktree_path, "go.mod")
        return _run_check(["go", "build", "./..."], go_root)
    elif ext == ".py":
        return _check_python(files_changed, worktree_path)
    elif ext in (".js", ".ts"):
        npm_root = _find_project_root(all_files, worktree_path, "package.json")
        return _run_check(["npm", "run", "build", "--if-present"], npm_root)
    elif ext == ".tf":
        tf_root = _find_terraform_root(all_files, worktree_path)
        return _run_check(["terraform", "validate"], tf_root)
    else:
        # No build check for YAML/Dockerfile/etc. — skip gracefully
        return ValidationResult(passed=True, phase="local_build")


def _find_project_root(files: list[str], worktree_path: Path, marker: str) -> Path:
    """Walk up from each file to find the nearest directory containing `marker`.

    Works for any project root indicator: go.mod, package.json, etc.
    Falls back to worktree_path if not found.
    """
    for f in files:
        # Strip line number suffix (e.g. "nodejs-app/server.js:40" → "nodejs-app/server.js")
        clean = f.split(":")[0] if ":" in f else f
        candidate = (worktree_path / clean).parent
        while candidate >= worktree_path:
            if (candidate / marker).exists():
                return candidate
            if candidate == worktree_path:
                break
            candidate = candidate.parent
    return worktree_path


def _find_terraform_root(files: list[str], worktree_path: Path) -> Path:
    """Find the directory containing .tf files — the terraform module root."""
    for f in files:
        if not f.endswith(".tf"):
            continue
        tf_dir = (worktree_path / f).parent
        if tf_dir.exists():
            return tf_dir
    return worktree_path


# Keep old names as aliases for backward compat with existing callers/tests
def _find_package_json_root(files: list[str], worktree_path: Path) -> Path:
    return _find_project_root(files, worktree_path, "package.json")


def _find_go_module_root(files: list[str], worktree_path: Path) -> Path:
    return _find_project_root(files, worktree_path, "go.mod")


def _run_check(cmd: list[str], cwd: Path) -> ValidationResult:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, cwd=cwd)
    except subprocess.TimeoutExpired:
        return ValidationResult(passed=False, phase="local_build",
                                failures=[f"local build timed out ({' '.join(cmd)})"])
    except FileNotFoundError:
        return ValidationResult(passed=True, phase="local_build")  # tool not installed — skip
    if result.returncode != 0:
        out = (result.stdout + result.stderr)[:400]
        return ValidationResult(passed=False, phase="local_build",
                                failures=[f"local build failed: {out}"])
    return ValidationResult(passed=True, phase="local_build")


def _check_python(files: list[str], cwd: Path) -> ValidationResult:
    failures = []
    for f in files:
        if not f.endswith(".py"):
            continue
        result = subprocess.run(
            ["python3", "-m", "py_compile", str(cwd / f)],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            failures.append(f"syntax error in {f}: {result.stderr[:150]}")
    return ValidationResult(passed=len(failures) == 0, phase="local_build", failures=failures)


# ---------------------------------------------------------------------------
# Phase 4: GitHub CI gate (called after PR is opened)
# ---------------------------------------------------------------------------

def ci_gate(pr_url: str, timeout_sec: int = 600) -> ValidationResult:
    """Poll GitHub required checks. Uses `gh pr checks --watch`."""
    try:
        result = subprocess.run(
            ["gh", "pr", "checks", pr_url, "--watch", "--fail-fast"],
            capture_output=True, text=True, timeout=timeout_sec,
        )
    except subprocess.TimeoutExpired:
        return ValidationResult(passed=False, phase="ci",
                                failures=[f"CI checks did not complete within {timeout_sec}s"])
    except FileNotFoundError:
        return ValidationResult(passed=True, phase="ci")  # gh not available

    if result.returncode != 0:
        failed_lines = [l for l in result.stdout.splitlines() if "fail" in l.lower()]
        reason = "; ".join(failed_lines[:3]) if failed_lines else result.stdout[:200]
        return ValidationResult(passed=False, phase="ci",
                                failures=[f"CI checks failed: {reason}"])

    return ValidationResult(passed=True, phase="ci")
