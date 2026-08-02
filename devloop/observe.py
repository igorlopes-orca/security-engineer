#!/usr/bin/env python3
"""
Turn a dev-loop run into one readable verdict.

Joins two sources the orchestrator already produces or depends on:

  1. security-engineer-run.json — newline-delimited NotificationPayload events
     written by LogFileNotifier into the run directory.
  2. Live GitHub state for any PR the run opened — PR status, the Orca App's
     check runs, and the annotations behind a failing one.

The annotations matter most: they are exactly what orca_check_gate feeds back
to the fix agent on retry, so seeing them here tells you whether the retry got
usable input or garbage.

Deliberately self-contained — it imports nothing from skills/, so it keeps
working while the pipeline code is being rewritten underneath it.

Usage:
    python3 devloop/observe.py                  # newest run
    python3 devloop/observe.py --run 20260801T101500Z
    python3 devloop/observe.py --watch          # poll until every alert settles
    python3 devloop/observe.py --json           # machine-readable

Exit codes:
    0  every alert reached a good terminal state
    1  at least one alert failed, timed out, or is still running
    2  the run exercised no alerts at all (usually: sandbox needed a reset)
"""
import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

_DEVLOOP = Path(__file__).resolve().parent
_RUNS = _DEVLOOP / "runs"

LOG_NAME = "security-engineer-run.json"
CONSOLE_NAME = "console.log"

# Ordered highest precedence first. A single alert can emit several of these —
# the orchestrator notifies ci_failed and *then* fix_succeeded on the same
# alert, so "last event wins" would report a CI failure as a success.
_STATE_PRECEDENCE = [
    ("timeout",           "TIMED_OUT"),
    ("fix_failed",        "FAILED"),
    ("validation_failed", "FAILED"),
    ("ci_failed",         "CI_FAILED"),
    ("fix_succeeded",     "DONE"),
    ("fix_planned",       "PLANNED"),
    ("pr_opened",         "RUNNING"),
    ("committed",         "RUNNING"),
    ("fix_started",       "RUNNING"),
]

# Planned by the orchestrator but no events yet. Terminal only once the run has
# exited — at that point it means the alert was dropped without explanation.
NOT_STARTED = "NOT_STARTED"

# States that mean the alert is finished, good or bad. Anything else is still
# moving, which --watch keeps polling on.
TERMINAL_STATES = {"TIMED_OUT", "FAILED", "CI_FAILED", "DONE", "PLANNED", "SKIPPED"}
GOOD_STATES = {"DONE", "PLANNED"}

_PR_URL_RE = re.compile(r"github\.com/([^/]+)/([^/]+)/pull/(\d+)")
_PHASE_RE = re.compile(r"^\[PHASE\]\s+(\S+)\s+(.*)$")
# "  1. orca-4060654 — Potential SQL Injection … (high, sast) — webhook-service/db.js:22"
_PLANNED_RE = re.compile(r"^\s*\d+\.\s+(\S+)\s+[—-]")


# ---------------------------------------------------------------------------
# Pure parsing — no network, no filesystem
# ---------------------------------------------------------------------------

def parse_events(text: str) -> list[dict]:
    """Parse NDJSON, skipping malformed lines.

    A run that is still in flight can leave a half-written final line, and one
    bad line should never cost you the whole report.
    """
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            events.append(obj)
    return events


def alert_events(events: list[dict]) -> dict[str, list[dict]]:
    """Group events by alert, dropping repo-level ones.

    LogFileNotifier omits empty fields, so repo-level events (clone_started,
    alerts_fetched) simply have no alert_id. run_complete carries the "-"
    placeholder.
    """
    grouped: dict[str, list[dict]] = {}
    for e in events:
        aid = e.get("alert_id")
        if not aid or aid == "-":
            continue
        grouped.setdefault(aid, []).append(e)
    return grouped


def derive_state(events: list[dict]) -> str:
    """Collapse one alert's event stream into a single state."""
    seen = {e.get("event") for e in events}
    for event_name, state in _STATE_PRECEDENCE:
        if event_name in seen:
            return state
    return "UNKNOWN"


def last_value(events: list[dict], key: str) -> str | None:
    """Most recent non-empty value of `key` across an alert's events."""
    for e in reversed(events):
        v = e.get(key)
        if v:
            return v
    return None


def parse_pr_url(url: str) -> tuple[str, str, int] | None:
    """('owner', 'repo', number) from a PR URL, or None if it isn't one."""
    m = _PR_URL_RE.search(url or "")
    if not m:
        return None
    return m.group(1), m.group(2), int(m.group(3))


def last_phase(console_text: str) -> dict[str, str]:
    """Latest `[PHASE] <alert> <description>` line per alert.

    The orchestrator prints these as it goes, so this is the only signal for
    where an alert currently is while a run is still executing.
    """
    phases: dict[str, str] = {}
    for line in console_text.splitlines():
        m = _PHASE_RE.match(line.strip())
        if m:
            phases[m.group(1)] = m.group(2).strip()
    return phases


def planned_alerts(console_text: str) -> list[str]:
    """Alert IDs the orchestrator said it would fix, from its "Planned fixes:" block.

    The event log only knows about alerts that have already started, so it
    cannot distinguish "not reached yet" from "never ran at all". An alert that
    is planned and then silently never starts is exactly the kind of gap this
    report exists to catch, so take the denominator from the plan.
    """
    ids: list[str] = []
    in_block = False
    for line in console_text.splitlines():
        if line.strip().startswith("Planned fixes:"):
            in_block = True
            continue
        if in_block:
            m = _PLANNED_RE.match(line)
            if m:
                ids.append(m.group(1))
            elif line.strip():
                break  # first non-matching, non-blank line ends the block
    return ids


def classify_checks(check_runs: list[dict], orca_marker: str = "orca") -> dict:
    """Split a commit's check runs into Orca App checks and everything else.

    Returns {"orca": [...], "other": [...]}; each entry is normalized to
    name/status/conclusion/id/duration so the renderer and the tests agree on
    one shape.
    """
    out: dict[str, list[dict]] = {"orca": [], "other": []}
    for run in check_runs or []:
        name = run.get("name", "")
        entry = {
            "name": name,
            "status": run.get("status", ""),
            "conclusion": run.get("conclusion") or "",
            "id": run.get("id"),
            "duration": _duration(run.get("started_at"), run.get("completed_at")),
        }
        bucket = "orca" if orca_marker in name.lower() else "other"
        out[bucket].append(entry)
    return out


def _duration(started: str | None, completed: str | None) -> str:
    """Human duration between two ISO-8601 timestamps, '' if unavailable."""
    if not started or not completed:
        return ""
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    try:
        t0 = time.mktime(time.strptime(started, fmt))
        t1 = time.mktime(time.strptime(completed, fmt))
    except ValueError:
        return ""
    secs = int(t1 - t0)
    if secs < 0:
        return ""
    return f"{secs}s" if secs < 60 else f"{secs // 60}m{secs % 60:02d}s"


def verdict(alerts: list[dict], finished: bool = True) -> tuple[str, int]:
    """One-line summary plus the process exit code.

    finished: whether the orchestrator process has exited (run.sh writes an
              exit-code file when it does). A report taken mid-run must never
              read as a final answer — an agent polling every minute would
              otherwise see "no alerts exercised" thirty seconds in and
              conclude the loop is broken.
    """
    if not finished:
        if not alerts:
            return "VERDICT: run in progress — no alerts started yet", 1
        pending = [a for a in alerts if not a["terminal"]]
        done = len(alerts) - len(pending)
        if pending:
            where = "; ".join(
                f"{a['alert_id']} ({a['phase'] or a['state'].lower()})" for a in pending
            )
            return ((f"VERDICT: run in progress — {done}/{len(alerts)} settled, "
                     f"waiting on {where}"), 1)
        return ((f"VERDICT: run in progress — all {len(alerts)} alerts settled, "
                 f"orchestrator still wrapping up"), 1)

    if not alerts:
        # Two common causes, and the console tail printed above distinguishes
        # them: the run errored before fetching, or every alert was skipped
        # because its fix branch still existed on the remote.
        return (("VERDICT: no alerts exercised — check the console lines above; "
                 "if the run reached the planning stage, the sandbox needs "
                 "`devloop/reset.sh`"), 2)

    counts: dict[str, int] = {}
    for a in alerts:
        counts[a["state"]] = counts.get(a["state"], 0) + 1

    parts = ", ".join(f"{n} {s.lower()}" for s, n in sorted(counts.items()))
    bad = [a for a in alerts if a["state"] not in GOOD_STATES]
    if not bad:
        return f"VERDICT: {parts} — all good", 0

    detail = "; ".join(
        f"{a['alert_id']} ({a['state']}{': ' + a['reason'] if a.get('reason') else ''})"
        for a in bad
    )
    return f"VERDICT: {parts} — see {detail}", 1


# ---------------------------------------------------------------------------
# GitHub lookups
# ---------------------------------------------------------------------------

def _gh_json(args: list[str]) -> object | None:
    """Run a gh command expecting JSON. None on any failure — GitHub being
    unreachable should degrade the report, not abort it."""
    try:
        r = subprocess.run(["gh", *args], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0 or not r.stdout.strip():
        return None
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return None


def fetch_pr(owner: str, repo: str, number: int) -> dict | None:
    return _gh_json(["pr", "view", str(number), "--repo", f"{owner}/{repo}",
                     "--json", "number,state,url,title,headRefOid,headRefName,labels"])


def fetch_check_runs(owner: str, repo: str, sha: str) -> list[dict]:
    data = _gh_json(["api", f"repos/{owner}/{repo}/commits/{sha}/check-runs",
                     "--paginate"])
    if isinstance(data, dict):
        return data.get("check_runs", []) or []
    return []


def fetch_annotations(owner: str, repo: str, check_id: int) -> list[dict]:
    data = _gh_json(["api", f"repos/{owner}/{repo}/check-runs/{check_id}/annotations"])
    return data if isinstance(data, list) else []


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------

def build_report(run_dir: Path, online: bool = True) -> dict:
    """Everything the renderer needs, as plain data."""
    log_path = run_dir / LOG_NAME
    console_path = run_dir / CONSOLE_NAME

    events = parse_events(log_path.read_text()) if log_path.exists() else []
    console = console_path.read_text() if console_path.exists() else ""
    phases = last_phase(console)

    grouped = alert_events(events)
    # Planned-but-never-started alerts still get a row, so the count in the
    # verdict matches what the orchestrator said it would do.
    for aid in planned_alerts(console):
        grouped.setdefault(aid, [])

    # run.sh writes exit-code only once the orchestrator has exited. Needed here
    # because NOT_STARTED means "queued" mid-run but "silently dropped" after.
    exit_code_path = run_dir / "exit-code"
    finished = exit_code_path.exists()

    alerts = []
    for aid, evs in sorted(grouped.items()):
        state = derive_state(evs) if evs else NOT_STARTED
        entry = {
            "alert_id": aid,
            "state": state,
            "terminal": state in TERMINAL_STATES or (state == NOT_STARTED and finished),
            "feature_type": last_value(evs, "feature_type") or "",
            "risk_level": last_value(evs, "risk_level") or "",
            "impact_level": last_value(evs, "impact_level") or "",
            "reason": last_value(evs, "reason") or "",
            "pr_url": last_value(evs, "pr_url") or "",
            "events": [e.get("event", "") for e in evs],
            "phase": phases.get(aid, ""),
            "pr": None,
            "checks": {"orca": [], "other": []},
            "annotations": [],
        }

        parsed = parse_pr_url(entry["pr_url"])
        if parsed and online:
            owner, repo, number = parsed
            pr = fetch_pr(owner, repo, number)
            if pr:
                entry["pr"] = {
                    "number": pr.get("number"),
                    "state": pr.get("state"),
                    "url": pr.get("url"),
                    "title": pr.get("title"),
                    "branch": pr.get("headRefName"),
                    "labels": [lb.get("name") for lb in pr.get("labels") or []],
                }
                sha = pr.get("headRefOid")
                if sha:
                    runs = fetch_check_runs(owner, repo, sha)
                    entry["checks"] = classify_checks(runs)
                    for c in entry["checks"]["orca"] + entry["checks"]["other"]:
                        if c["conclusion"] in ("failure", "action_required") and c["id"]:
                            for a in fetch_annotations(owner, repo, c["id"]):
                                entry["annotations"].append({
                                    "check": c["name"],
                                    "path": a.get("path", ""),
                                    "line": a.get("start_line", ""),
                                    "level": a.get("annotation_level", ""),
                                    "message": (a.get("message") or "").strip(),
                                })
        alerts.append(entry)

    text, code = verdict(alerts, finished=finished)
    meta_path = run_dir / "run-meta.txt"
    return {
        "run_dir": str(run_dir),
        "meta": meta_path.read_text() if meta_path.exists() else "",
        "offline": not online,
        "finished": finished,
        "run_exit_code": exit_code_path.read_text().strip() if finished else None,
        "alerts": alerts,
        "verdict": text,
        "exit_code": code,
        "settled": finished and all(a["terminal"] for a in alerts),
    }


def render(report: dict) -> str:
    status = (f"finished (orchestrator exit {report['run_exit_code']})"
              if report["finished"] else "IN PROGRESS")
    lines = [f"run: {report['run_dir']}", f"     {status}", ""]

    if not report["alerts"]:
        lines.append("  (no alert events yet)" if not report["finished"]
                     else "  (no alert events in this run)")
        console = Path(report["run_dir"]) / CONSOLE_NAME
        if console.exists():
            tail = console.read_text().splitlines()[-15:]
            lines += ["", "  last console lines:"] + [f"    {t}" for t in tail]
    for a in report["alerts"]:
        head = f"{a['alert_id']}  {a['feature_type']}/{a['risk_level']}  →  {a['state']}"
        lines.append(head)
        if a["events"]:
            lines.append(f"  events   {' → '.join(a['events'])}")
        if a["phase"] and not a["terminal"]:
            lines.append(f"  phase    {a['phase']}")
        if a["reason"]:
            lines.append(f"  reason   {a['reason']}")
        if a["impact_level"]:
            lines.append(f"  impact   {a['impact_level']}")

        pr = a["pr"]
        if pr:
            labels = f"  [{', '.join(pr['labels'])}]" if pr["labels"] else ""
            lines.append(f"  pr       #{pr['number']} {pr['state']}{labels}  {pr['url']}")
        elif a["pr_url"]:
            note = "GitHub lookups skipped" if report["offline"] else "could not read from GitHub"
            lines.append(f"  pr       {a['pr_url']} ({note})")

        orca = a["checks"]["orca"]
        if orca:
            for i, c in enumerate(orca):
                label = "  orca     " if i == 0 else "           "
                state = c["conclusion"] or c["status"]
                lines.append(f"{label}{c['name']:<40} {state:<10} {c['duration']}")
        elif pr:
            # The whole point of Phase 4 — call it out rather than staying silent.
            lines.append("  orca     (no Orca checks on this commit)")

        other = a["checks"]["other"]
        if other:
            for i, c in enumerate(other):
                label = "  ci       " if i == 0 else "           "
                state = c["conclusion"] or c["status"]
                lines.append(f"{label}{c['name']:<40} {state:<10} {c['duration']}")

        for an in a["annotations"]:
            loc = f"{an['path']}:{an['line']}" if an["path"] else an["check"]
            lines.append(f"  finding  {loc} — {an['message'][:160]}")
        lines.append("")

    lines.append(report["verdict"])
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def resolve_run_dir(name: str | None) -> Path:
    if name:
        p = Path(name)
        if p.is_dir():
            return p.resolve()
        p = _RUNS / name
        if p.is_dir():
            return p.resolve()
        sys.exit(f"error: no such run: {name}")
    latest = _RUNS / "latest"
    if latest.exists():
        return latest.resolve()
    if not _RUNS.is_dir():
        sys.exit("error: no runs yet — start one with devloop/run.sh")
    dirs = sorted((d for d in _RUNS.iterdir() if d.is_dir()), key=lambda d: d.name)
    if not dirs:
        sys.exit("error: no runs yet — start one with devloop/run.sh")
    return dirs[-1].resolve()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Report on a dev-loop run")
    ap.add_argument("--run", default=None,
                    help="Run directory or timestamp name (default: latest)")
    ap.add_argument("--json", action="store_true", help="Machine-readable output")
    ap.add_argument("--watch", action="store_true",
                    help="Re-poll until every alert reaches a terminal state")
    ap.add_argument("--interval", type=int, default=15,
                    help="Seconds between polls with --watch (default 15)")
    ap.add_argument("--timeout", type=int, default=1800,
                    help="Give up watching after N seconds (default 1800)")
    ap.add_argument("--offline", action="store_true",
                    help="Skip GitHub lookups — parse the event log only")
    args = ap.parse_args(argv)

    run_dir = resolve_run_dir(args.run)
    deadline = time.time() + args.timeout

    while True:
        report = build_report(run_dir, online=not args.offline)
        if not args.watch or report["settled"] or time.time() > deadline:
            break
        print(render(report))
        print(f"\n… still running, re-checking in {args.interval}s\n")
        time.sleep(args.interval)

    print(json.dumps(report, indent=2) if args.json else render(report))
    return report["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
