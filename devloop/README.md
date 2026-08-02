# Dev loop

A one-command develop → test → observe cycle for the orchestrator.

## Why

Unit tests cover argument parsing and mocked branches. Everything the plugin is
actually for only happens in a live `--remote` run: worktree lifecycle, whether
the diff the gates judge is the diff that gets committed, whether the Orca
GitHub App check gate fires at all, whether annotation feedback reaches the fix
agent on retry. Assembling that run by hand is slow enough that changes get
shipped unverified.

`make loop` does the whole thing and prints one verdict.

## Setup (once)

```bash
cp devloop/.env.example devloop/.env    # then fill in ORCA_API_TOKEN
pip3 install pyyaml                      # optional but recommended, see below
gh auth login                            # needs access to the sandbox repo
```

`devloop/.env` and `devloop/runs/` are gitignored.

## Use

```bash
make fast                        # test → reset → fix one CVE → report
make fast ALERT=orca-4060654     # a specific alert
make loop                        # same, but all alerts on the sandbox
make loop ARGS="--dry-run cve"   # plan only, no writes, no PRs
make loop ARGS="sast --max 2"    # any orchestrator filter

make reset                       # sandbox back to clean, on its own
make run ARGS="--scan"           # a run without the reset/report wrapper
make observe                     # re-report on the newest run, any time

make install                     # install this working tree as the plugin
make uninstall                   # remove it; marketplace goes back to GitHub
make plugin-status               # is the installed plugin this code?
```

## The dev loop and the skill test the same code

Two entry points reach the orchestrator, and they do not share a copy of it:

| Entry point | Runs |
|---|---|
| `devloop/run.sh`, `make run` | `skills/run/orchestrator.py` in this repo — uncommitted edits included |
| `/security-engineer:run` | the copy in `~/.claude/plugins/cache/`, made when the plugin was installed |

Nothing refreshes that copy on its own. `claude plugin update` short-circuits
while `plugin.json`'s version is unchanged, and installing over an existing
install is a no-op — so the installed skill keeps running the commit it went in
at. On 2026-08-02 that was twelve commits back, and the dev loop was green the
whole time, because the dev loop was never testing it.

`make install` closes the gap: it points the `orca-security` marketplace at this
directory, drops the old install, and copies the working tree in. `make loop`
and `make fast` run it as a step, so the two entry points cannot silently
diverge. A bare `devloop/run.sh` only warns — that run still tests the working
tree, which is what the dev loop is for; only the skill is stale.

`make uninstall` removes the plugin and puts the marketplace back on GitHub, so
`./install.sh` reinstalls the published version. Use that before tagging a
release, to check the packaged form the way a fresh clone would get it.

Changes to Python take effect on the next invocation. Changes to `SKILL.md`
frontmatter need a Claude Code restart to re-register.

**Alert IDs are not stable.** Orca mints new ones every time it rescans, so a
hardcoded ID eventually fails with `Alert <id> not found`. That is why `make
fast` defaults to the filter `cve --max 1` rather than a fixed ID. To target one
alert, get a live ID first:

```bash
make run ARGS="--scan"           # then read devloop/runs/latest/console.log
```

Long runs: start `make run` in the background and poll with
`python3 devloop/observe.py --watch`. `observe.py` is read-only and idempotent,
so it is safe to call repeatedly while a run is still going.

## Driving it from an agent

`/devloop` (`.claude/commands/devloop.md`) is the runbook — it encodes the step
order, the background/poll pattern, what a correct run looks like, and a table
mapping failure signatures to causes.

```
/devloop                 # one CVE, the fast path
/devloop orca-4060654    # a specific alert
/devloop sast --max 1    # any orchestrator filter
/devloop --all           # every alert on the sandbox
/devloop --dry-run       # plumbing check, no PRs
```

The shape that matters, if you are writing your own driver:

1. `make test` and `make reset` in the foreground — both take seconds.
2. `devloop/run.sh --alert <id>` **in the background**. A live run takes 5–15
   minutes (Orca gate polls up to 300s, CI gate up to 600s), so a foreground
   call hits the command timeout and reports nothing useful.
3. Poll `python3 devloop/observe.py` every 60–90s. Faster gains nothing — the
   gates themselves move on 15s and 10s cadences.

`observe.py` distinguishes a mid-run report from a final one. Until the
orchestrator exits, the header reads `IN PROGRESS`, the verdict names the phase
each alert is sitting in, and the exit code is 1 — never 0 or 2. That matters
for an automated driver: without it, a poll thirty seconds in would see zero
alerts, exit 2, and look like a broken loop.

Use `make loop` / `make fast` for interactive use, where blocking is fine and
you are watching the output scroll by.

## The four pieces

| File | Role |
|---|---|
| `config.sh` | Sandbox repo, branch prefix, token loading, safety guards. Sourced by the others. |
| `reset.sh` | Sandbox back to a known-clean state. |
| `run.sh` | One live run, fully captured into `runs/<timestamp>/`. |
| `observe.py` | Run + live GitHub state → one verdict. |

### `reset.sh` — why a reset is mandatory

`_fetch_and_plan()` drops any alert whose fix branch already exists on the
remote (`branch_exists_remote`, `skills/lib/orca_client.py`). One completed run
therefore poisons every run after it: alerts land in the "skipped — branch
exists" bucket and the next run exercises nothing. Reset closes open
`fix/orca-*` PRs, deletes those remote branches, clears `/tmp/orca-fix-*` and
`/tmp/orca-global-*`, and prunes stale worktrees.

Scope is the safety boundary: only refs matching `BRANCH_PREFIX`. `main` and
human branches are unreachable from it. `devloop/reset.sh --dry-run` prints
what it would do without doing it.

### `run.sh` — what gets captured

Each run creates `devloop/runs/<UTC-timestamp>/`, with `runs/latest`
symlinked to the newest:

```
console.log                   full orchestrator stdout+stderr
security-engineer-run.json    NDJSON event log (LogFileNotifier)
run-meta.txt                  HEAD, branch, git status, full uncommitted diff
exit-code                     orchestrator's exit status
```

`run-meta.txt` exists so a report is always traceable to the exact working tree
that produced it — the diff is captured, not just the commit.

The script `cd`s into the run directory before invoking the orchestrator,
because `build_notifiers(repo, Path.cwd())` writes the event log relative to
cwd. That is why each run gets its own log with no extra plumbing.

### `orca-check.yaml` — the test config

Passed via `SECURITY_ENGINEER_CONFIG`, which `config.py:load_config()` already
supports. **It does not change what ships.** Two overrides matter:

- `check_name: "Orca Security"`. The Orca App posts checks named
  `Orca Security - SAST`, `Orca Security - Vulnerabilities`, `Orca Security - IaC`,
  `Orca Security - Secrets`, `Orca Security - OSS Licenses`. The shipped default
  (`orca-security-us`) matches none of them as a substring, so Phase 4 silently
  takes the `on_not_found` path and the gate never runs. Matching the common
  prefix is what makes the gate testable here.
- `timeout_sec: 300`, `poll_interval_sec: 10` instead of 600/15, so an
  iteration finishes in minutes.

Plus `on_not_found: fail` — in production a missing check should not block the
PR, but in the loop it means the thing under test did not happen, so it should
be loud.

Without PyYAML installed, `config.py` warns and falls back to defaults; `run.sh`
detects this and tells you the yaml is being ignored.

### `observe.py` — the report

Joins the NDJSON event log with live GitHub state:

```
orca-385591  sast/high  →  DONE
  events   fix_started → committed → pr_opened → fix_succeeded
  impact   medium
  pr       #8 OPEN  [impact:medium]  https://github.com/.../pull/8
  orca     Orca Security - SAST                 success    34s
           Orca Security - Vulnerabilities      success    11s
  ci       build                                success    1m12s

VERDICT: 1 done — all good
```

On a failing check it also fetches the annotations and prints them as
`finding  path:line — message`. Those annotations are exactly what
`orca_check_gate` feeds back to the fix agent on retry, so this is how you tell
whether the retry got usable input.

Exit codes — meaningful, so the loop chain stops on its own:

| Code | Meaning |
|---|---|
| 0 | every alert reached `DONE` or `PLANNED` |
| 1 | something failed, timed out, or is still running |
| 2 | no alerts exercised at all — the sandbox needs a reset |

Flags: `--run <dir|timestamp>`, `--json`, `--watch [--interval N] [--timeout N]`,
`--offline` (parse the log, skip GitHub).

`observe.py` imports nothing from `skills/`, so it keeps working while the
pipeline code is being rewritten underneath it.

## Single-shot subprocesses: `--tools ""`, not `--allowedTools ""`

Phase 2 (LLM validation) and the impact agent are pure text-in/JSON-out calls —
the alert and diff are already in the prompt, so neither needs a tool. Getting
that restriction right turned out to matter a lot, and the two flags are not
interchangeable:

| Flags | Success | Turns used | Cost / 5 calls |
|---|---|---|---|
| `--allowedTools "" --max-turns 6` | 5/5 | 3, 3, 3, 3, 3 | $0.569 |
| `--tools "" --max-turns 1` | 5/5 | 1, 1, 1, 1, 1 | $0.092 |

`--allowedTools ""` only *denies* tool calls. The definitions stay in the
model's context, so it emits a `tool_use` block anyway, gets refused, and tries
again — two wasted round trips that re-send the whole prompt, hence 6.2x the
cost. Occasionally the tail ran longer (7 turns observed), blew past the cap,
and exited `subtype=error_max_turns` with an empty stderr. Both callers then
took their silent error path: validation passed everything with `needs_review`
and every PR was labelled `impact:medium`. Roughly 1 call in 15 before the fix.

`--tools ""` removes the definitions, so there is nothing to attempt. One turn,
every time. Raising `--max-turns` never fixed this — the turn cap was never the
lever.

The fix agent is unaffected and still gets real tools; it needs them.

## Known environment gotchas

Two things about this machine and this sandbox, both found by the loop's first
live run rather than by reading code:

**A failing global pre-commit hook takes the whole pipeline down with it.**
A global `core.hooksPath` pointing at a hook that exits non-zero makes the
orchestrator's `git commit` fail, and the hook's stderr is then reported as the
*fix's* failure reason — so it reads like the fix agent broke rather than like a
local environment problem. That is why `run.sh` neutralises hooks for its own
sandbox runs via `GIT_CONFIG_*`.

Observed on this machine 2026-08-01: `~/.git/hooks/pre-commit` runs
`orca-cli secrets pre-commit scan` and exits 1 with
`Failed to retrieve scan configuration via Orca Cloud [error_code=21]`,
which blocked a devloop run at the commit step. Note that a normal commit
succeeded ~40 minutes earlier the same day, so treat this as "broken from some
point onward", not "always broken" — if commits start failing, run the hook
directly to check before suspecting the orchestrator.

**The Orca App is not posting checks on the sandbox.** It posted five checks on
PR #7 in April 2026 and posts none today, so Phase 4 cannot be exercised
end-to-end until that integration is reconnected. `observe.py` reports this as
`(no Orca checks on this commit)` rather than letting the gate pass silently.

## Changing the sandbox

Set `SANDBOX_REPO` in `devloop/.env` (or the environment). Requirements: Orca
must already discover and scan it, the Orca GitHub App must be installed on it,
and it must be disposable. `config.sh` refuses to point the loop at this repo.

`igorlopes-orca/vulnerable-apps` is the default — around 100 open alerts across
SAST, CVE, IaC, and secrets, so there is always something to exercise. Run
`make run ARGS="--scan"` for the current inventory.

## Adding to the loop

`observe.py`'s parsing layer is pure and table-driven-tested in
`devloop/tests/test_observe.py` (`CASES` + `self.subTest`, per `CLAUDE.md`).
Keep GitHub access in the thin `fetch_*` wrappers so the logic stays testable
offline.
