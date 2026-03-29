#!/usr/bin/env python3
"""
Notification system for the Security Engineer orchestrator.
Pluggable backends: log file (always), webhook (opt-in), GitHub PR comment (auto).

Add new backends by implementing NotifierBackend and registering in build_notifiers().
"""
import json
import os
import subprocess
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# Payload
# ---------------------------------------------------------------------------

@dataclass
class NotificationPayload:
    event: str
    alert_id: str
    feature_type: str
    risk_level: str
    repo: str
    pr_url: str | None = None
    reason: str | None = None
    impact_level: str | None = None
    manual_steps: list[str] = field(default_factory=list)
    concerns: list[str] = field(default_factory=list)
    succeeded: int = 0
    failed: int = 0
    skipped: int = 0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# Backend protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class NotifierBackend(Protocol):
    def send(self, payload: NotificationPayload) -> None: ...


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------

_CONSOLE_PREFIX = {
    "fix_started":       "[START]",
    "fix_succeeded":     "[OK]   ",
    "fix_failed":        "[FAIL] ",
    "timeout":           "[TOUT] ",
    "validation_failed": "[INVL] ",
    "ci_failed":         "[CI]   ",
    "run_complete":      "[DONE] ",
}

_CONSOLE_MSG = {
    "fix_started":       "Fix started for {alert_id} ({feature_type}, {risk_level})",
    "fix_succeeded":     "{alert_id} fixed — PR: {pr_url}",
    "fix_failed":        "{alert_id} failed: {reason}",
    "timeout":           "{alert_id} timed out",
    "validation_failed": "{alert_id} validation failed: {reason}",
    "ci_failed":         "{alert_id} CI failed on {pr_url}",
    "run_complete":      "{succeeded} fixed, {failed} failed, {skipped} skipped",
}


class ConsoleNotifier:
    def send(self, payload: NotificationPayload) -> None:
        prefix = _CONSOLE_PREFIX.get(payload.event, "[INFO] ")
        tmpl = _CONSOLE_MSG.get(payload.event, payload.event)
        msg = tmpl.format(**vars(payload))
        print(f"{prefix} {msg}")


class LogFileNotifier:
    """Always active. Appends newline-delimited JSON to security-engineer-run.json."""

    def __init__(self, log_path: Path):
        self.log_path = log_path

    def send(self, payload: NotificationPayload) -> None:
        entry = {k: v for k, v in vars(payload).items() if v is not None and v != [] and v != 0}
        with open(self.log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")


class WebhookNotifier:
    """Active when NOTIFY_WEBHOOK_URL is set. Generic HTTP POST — works with Slack, Teams, etc."""

    def __init__(self, url: str):
        self.url = url

    def send(self, payload: NotificationPayload) -> None:
        body = json.dumps({
            "event": payload.event,
            "alert_id": payload.alert_id,
            "repo": payload.repo,
            "impact_level": payload.impact_level,
            "pr_url": payload.pr_url,
            "reason": payload.reason,
            "manual_steps": payload.manual_steps,
            "timestamp": payload.timestamp,
        }).encode()
        req = urllib.request.Request(
            self.url, data=body,
            headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            print(f"[WARN] webhook failed: {e}")


class GitHubPRCommentNotifier:
    """Posts a production impact assessment comment to the PR on fix_succeeded."""

    def send(self, payload: NotificationPayload) -> None:
        if payload.event != "fix_succeeded" or not payload.pr_url:
            return
        body = self._build_comment(payload)
        try:
            subprocess.run(
                ["gh", "pr", "comment", payload.pr_url, "--body", body],
                check=True, capture_output=True, timeout=30
            )
        except Exception as e:
            print(f"[WARN] GitHub PR comment failed: {e}")

    def _build_comment(self, payload: NotificationPayload) -> str:
        level = payload.impact_level or "unknown"
        emoji = {"low": "🟢", "medium": "🟡", "high": "🔴"}.get(level, "⚪")
        lines = [
            "## 🔒 Security Fix — Production Impact",
            "",
            f"**Impact:** {emoji} `{level.upper()}`  |  "
            f"**Alert:** `{payload.alert_id}`  |  "
            f"**Risk:** {payload.risk_level} `{payload.feature_type}`",
            "",
        ]
        if payload.concerns:
            lines += ["**⚠️ Reviewer concerns:**"]
            for c in payload.concerns:
                lines.append(f"- {c}")
            lines.append("")
        if payload.manual_steps:
            lines += ["**Required steps before/after deploying:**"]
            for step in payload.manual_steps:
                lines.append(f"- [ ] {step}")
            lines.append("")
        lines += ["---", "_Auto-generated by `/security-engineer` orchestrator_"]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Composite notifier
# ---------------------------------------------------------------------------

class Notifier:
    def __init__(self, backends: list[NotifierBackend]):
        self.backends = backends

    def notify(self, event: str, payload: NotificationPayload) -> None:
        payload.event = event
        for backend in self.backends:
            try:
                backend.send(payload)
            except Exception as e:
                print(f"[WARN] notifier {type(backend).__name__} failed: {e}")


def build_notifiers(repo: str, log_dir: Path) -> Notifier:
    """Build active backends from environment. Extend here to add new channels."""
    backends: list[NotifierBackend] = [
        ConsoleNotifier(),
        LogFileNotifier(log_dir / "security-engineer-run.json"),
        GitHubPRCommentNotifier(),
    ]
    webhook_url = os.environ.get("NOTIFY_WEBHOOK_URL")
    if webhook_url:
        backends.append(WebhookNotifier(webhook_url))
    return Notifier(backends)
