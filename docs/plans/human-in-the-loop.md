# Plan: Provider Abstraction + Human-in-the-Loop Design

## Context

The agent is tightly coupled to Orca's API — `orca_client.py` mixes Orca-specific auth, query payloads, field names, and normalization with generic helpers (`RISK_ORDER`, `Repository`, `branch_exists_remote`). The goal is to introduce a `SecurityProvider` protocol + `SecurityFinding` canonical type so Orca can be swapped for Snyk, GHAS, Semgrep, or any other tool without touching the orchestrator. This is the foundational step toward open source multi-provider support.

---

## Part 1: Provider Abstraction

### New file: `.claude/skills/lib/provider.py`

Single source of truth for provider-agnostic types and the protocol.

```python
RISK_ORDER = ["critical", "high", "medium", "low", "informational"]

@dataclass
class Repository:
    name: str           # "owner/repo"
    url: str            # "https://github.com/owner/repo"
    clone_path: Optional[Path] = None
    score: float = 0.0
    risk_level: str = ""

@dataclass
class SecurityFinding:
    id: str             # provider's native alert/finding ID
    title: str
    severity: str       # critical/high/medium/low/informational
    type: str           # cve/sast/iac/secret/scm_posture
    is_fixable: bool
    source: str = ""
    description: str = ""
    recommendation: str = ""
    score: float = 0.0
    status: str = ""
    category: str = ""
    labels: list[str] = field(default_factory=list)
    code_snippet: list = field(default_factory=list)
    position: dict = field(default_factory=dict)
    ai_triage: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)  # full provider-specific response

class SecurityProvider(Protocol):
    def list_repositories(self) -> list[Repository]: ...
    def list_findings(self, repo: str, min_level=None, feature_types=None) -> list[SecurityFinding]: ...
    def get_finding(self, finding_id: str) -> Optional[SecurityFinding]: ...

def finding_branch_name(finding_id: str) -> str:
    return f"fix/{finding_id.replace('/', '-').replace(' ', '-').lower()}"

def branch_exists_remote(branch: str, cwd=None) -> bool:
    # Pure git — moved from orca_client, same implementation
```

### Refactor: `.claude/skills/lib/orca_client.py`

- Import `SecurityFinding`, `Repository`, `RISK_ORDER`, `finding_branch_name`, `branch_exists_remote` from `provider.py`
- `_normalize_alert()` → returns `SecurityFinding` (mapping: `id` ← `AlertId`, `severity` ← `RiskLevel`, `type` ← resolved feature_type)
- `fetch_alerts()` → returns `list[SecurityFinding]`
- `fetch_alert_by_id()` → returns `Optional[SecurityFinding]`
- `_resolve_feature_type()` and `is_fixable()` remain as internal Orca-specific helpers
- Add `OrcaProvider` class implementing `SecurityProvider`:

```python
class OrcaProvider:
    def __init__(self, token: str): self._token = token
    def list_repositories(self): return list_repositories(self._token)
    def list_findings(self, repo, min_level=None, feature_types=None):
        return fetch_alerts(repo, self._token, min_level=min_level, feature_types=feature_types)
    def get_finding(self, finding_id): return fetch_alert_by_id(finding_id, self._token)
```

- Re-export `alert_branch_name = finding_branch_name` for backward compat during transition

### Update: `.claude/skills/security-engineer/run_agent.py`

- Import `SecurityFinding`, `finding_branch_name`, `branch_exists_remote`, `RISK_ORDER` from `provider`
- `_alert_to_entry()`: use `finding.id`, `finding.severity`, `finding.type`, `finding_branch_name(finding.id)`
- Serialize `SecurityFinding` via `dataclasses.asdict()` in both `cmd_list_alerts` and `cmd_get_alert`

### Update: `.claude/skills/security-engineer/orchestrator.py`

- Import `Repository`, `RISK_ORDER`, `finding_branch_name`, `SecurityFinding` from `provider`
- Refactor `AlertTask` — replace the 5 separate fields + `alert_json: dict` with a single `finding: SecurityFinding`:

```python
@dataclass
class AlertTask:
    finding: SecurityFinding
    state: str = "PENDING"
    pr_url: Optional[str] = None
    failure_reason: Optional[str] = None
    worktree_path: Optional[Path] = None
    fix_result: Optional[FixAgentResult] = None
    impact: Optional[ImpactResult] = None
    needs_review: bool = False
    attempts: int = 0
```

- `task.alert_id` → `task.finding.id`
- `task.risk_level` → `task.finding.severity`
- `task.feature_type` → `task.finding.type`
- `task.alert_json` → `dataclasses.asdict(task.finding)` when serializing for prompts/validators
- `alert_branch_name(task.alert_id)` → `finding_branch_name(task.finding.id)`
- `_fetch_and_plan()`: reconstruct `SecurityFinding` from subprocess JSON via `SecurityFinding(**data)`
- `_notify_payload()`: update field references

### Update: `.claude/skills/security-engineer/tests/test_orchestrator.py`

- Import `SecurityFinding` from `provider`
- Update `AlertTask` construction in all tests to use `finding=SecurityFinding(...)`
- Add `TestProviderProtocol`: verify `OrcaProvider` satisfies `SecurityProvider` via `isinstance` check
- Add `TestSecurityFindingFields`: table-driven tests for field mapping in `_normalize_alert`

---

## Part 2: Human-in-the-Loop Design

User specs:
1. Meet humans where they are (Slack, Telegram, Teams) — stop and wait for response
2. Pre-flight analysis before starting fixes
3. Balance: since fixes open PRs (already human-reviewed), HiTL targets only external action

### Two distinct interaction patterns

**Notifier** (already exists): fire-and-forget progress events. Already pluggable.

**ApprovalGate** (new concept): request-response. Blocks the pipeline until a human decides. Separate from the notifier — it's a decision point, not a broadcast.

```python
class ApprovalGate(Protocol):
    def request(self, report: PreflightReport) -> ApprovalDecision: ...

@dataclass
class ApprovalDecision:
    approved: bool
    excluded_finding_ids: list[str]  # human can exclude specific findings
    notes: str = ""
```

Implementations: `AutoApprovalGate` (default, current behavior), `ConsoleApprovalGate` (stdin y/n), `SlackApprovalGate` (post message + wait for button), `TelegramApprovalGate`.

### Phase 0: Pre-flight analysis

Before any fix agents run, a single Claude analysis agent reviews all findings holistically:
- Classifies each finding: `auto_fixable` (PR is sufficient) vs `needs_external_action`
- `needs_external_action` examples: secret requires vault rotation, IaC change needs deployment, auth changes need security team sign-off
- Returns a `PreflightReport` with a plain-language summary

If `needs_external_action` is non-empty AND an `ApprovalGate` is configured → pipeline pauses and waits. Otherwise auto-proceeds.

### When HiTL actually triggers

Since PRs always need human code review, the gate is specifically for findings where the code change alone is insufficient — something external must happen. Configurable via `--require-approval` flag (or env var) to gate everything through a human regardless.

Default (no flag): `AutoApprovalGate` — fully autonomous, current behavior preserved.

### Notifier events to add when implementing HiTL

Two new events: `preflight_complete` (analysis report ready), `approval_requested` (pipeline paused, waiting).

---

## Files to Modify

| File | Change |
|---|---|
| `.claude/skills/lib/provider.py` | **New** — protocol, `SecurityFinding`, `Repository`, `RISK_ORDER`, generic helpers |
| `.claude/skills/lib/orca_client.py` | Add `OrcaProvider`, `_normalize_alert` returns `SecurityFinding`, re-export compat aliases |
| `.claude/skills/security-engineer/run_agent.py` | Use `SecurityFinding`, update imports |
| `.claude/skills/security-engineer/orchestrator.py` | `AlertTask.finding: SecurityFinding`, update all field references |
| `.claude/skills/security-engineer/tests/test_orchestrator.py` | Update helpers, add `TestProviderProtocol` + `TestSecurityFindingFields` |

---

## Verification

```bash
# All existing tests must pass
python3 .claude/skills/security-engineer/tests/test_orchestrator.py

# Provider protocol satisfied at runtime
python3 -c "
import sys; sys.path.insert(0, '.claude/skills/lib')
from orca_client import OrcaProvider
from provider import SecurityProvider
print(isinstance(OrcaProvider('tok'), SecurityProvider))  # True
"

# Smoke test: dry-run still works end-to-end
python3 .claude/skills/security-engineer/orchestrator.py --dry-run --max 1
```
