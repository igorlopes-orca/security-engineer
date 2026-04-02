#!/usr/bin/env python3
"""
Impact analysis agent — invokes Claude to analyze a security fix diff
and produce a structured production risk assessment.

Not a lookup table. Claude reads the actual diff and alert context.
"""
import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from _json_util import find_last_json_with_key


@dataclass
class ImpactResult:
    level: str                        # "low" | "medium" | "high"
    description: str
    downtime_risk: bool
    requires_deploy: bool
    manual_steps: list[str] = field(default_factory=list)
    concerns: list[str] = field(default_factory=list)
    error: str | None = None


_PROMPT = """\
You are assessing the production risk of a security fix before it is deployed.

## Alert Details
{alert_json}

## Git Diff
```diff
{diff_text}
```

Analyze the diff in the context of the vulnerability and answer:
1. What is the production risk of deploying this change?
2. Is there a risk of downtime or service disruption?
3. Does this require a redeployment or infrastructure action after merge?
4. What manual steps must an operator take before or after deploying?
5. Are there concerns a code reviewer should know?

Return ONLY this JSON as your final output (nothing after this block):
{{
  "level": "low|medium|high",
  "description": "<one sentence: what is the production risk>",
  "downtime_risk": true|false,
  "requires_deploy": true|false,
  "manual_steps": ["step 1", "step 2"],
  "concerns": ["optional reviewer concern"]
}}

Guidelines:
- "low"   → code logic change only, no infra impact, no redeploy needed
- "medium" → rebuild/redeploy required, dep version bump, possible brief disruption
- "high"  → secret rotation required, env var must be set before deploy, significant breaking risk
"""


def analyze_impact(
    alert_json: dict,
    diff_text: str,
    timeout_sec: int = 90,
) -> ImpactResult:
    """Invoke claude subprocess to assess production impact. Returns ImpactResult."""
    prompt = _PROMPT.format(
        alert_json=json.dumps(alert_json, indent=2),
        diff_text=diff_text[:6000],
    )
    cmd = [
        "claude", "-p", prompt,
        "--output-format", "json",
        "--max-turns", "1",
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_sec
        )
    except subprocess.TimeoutExpired:
        print(f"[WARN] impact analysis timed out after {timeout_sec}s")
        return ImpactResult(
            level="medium",
            description="Impact analysis timed out — treating as medium risk",
            downtime_risk=False, requires_deploy=True,
            error=f"timeout after {timeout_sec}s",
        )

    if result.returncode != 0:
        stderr = result.stderr[:500]
        print(f"[WARN] impact analysis failed (exit={result.returncode}): {stderr}")
        return ImpactResult(
            level="medium",
            description="Impact analysis failed — treating as medium risk",
            downtime_risk=False, requires_deploy=True,
            error=f"exit_code={result.returncode}: {stderr}",
        )

    return _parse(result.stdout)


def _parse(raw: str) -> ImpactResult:
    try:
        envelope = json.loads(raw)
        text = envelope.get("result", "") or raw
    except json.JSONDecodeError:
        text = raw

    data = find_last_json_with_key(text, "level")
    if not data:
        snippet = text[:200] if text else "(empty)"
        print(f"[WARN] could not parse impact analysis output: {snippet}")
        return ImpactResult(
            level="medium",
            description="Could not parse impact analysis — treating as medium risk",
            downtime_risk=False, requires_deploy=True,
            error=f"no_json_output: {snippet}",
        )

    return ImpactResult(
        level=data.get("level", "medium"),
        description=data.get("description", ""),
        downtime_risk=bool(data.get("downtime_risk", False)),
        requires_deploy=bool(data.get("requires_deploy", True)),
        manual_steps=data.get("manual_steps") or [],
        concerns=data.get("concerns") or [],
    )
