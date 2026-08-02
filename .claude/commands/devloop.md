---
description: Run the security-engineer dev loop against the sandbox repo and report whether the pipeline behaved correctly
argument-hint: "[alert-id | --all | --dry-run]"
allowed-tools: Bash, Read
---

# Drive the dev loop

Run the orchestrator live against the sandbox repo, watch it, and judge whether
the pipeline did the right thing. `$ARGUMENTS` selects scope:

| Argument | Meaning |
|---|---|
| *(empty)* | one CVE — `cve --max 1` (fast path) |
| `orca-4060654` | that specific alert |
| `sast --max 1` | any filter the orchestrator accepts, passed through |
| `--all` | every alert on the sandbox |
| `--dry-run` | plan only, no PRs — use to check plumbing after refactors |

**Never hardcode an alert ID.** Orca mints new IDs whenever it rescans, so
yesterday's ID fails with `Alert <id> not found`. Use a filter (`cve --max 1`),
or run `devloop/run.sh --scan` first and pick a live one.

## Why this needs a procedure

A live run takes 5–15 minutes: the Orca check gate polls for up to 300s and the
CI gate for up to 600s. A foreground `make fast` will hit the command timeout
and tell you nothing. Always background the run and poll the report.

## Steps

**1. Preflight** — cheap, fails fast:
```bash
python3 -c "import yaml" && gh auth status >/dev/null \
  && { [ -f devloop/.env ] || [ -n "$ORCA_API_TOKEN" ]; } && echo preflight-ok
```
The token can come from `devloop/.env` or the environment; `config.sh` accepts
either. If neither is present, stop and tell the user to create `devloop/.env`
from `devloop/.env.example` — you cannot supply the token yourself.

**2. Unit tests** (foreground, seconds):
```bash
make test
```
Stop if red. Never start a live run on a broken tree — you will spend fifteen
minutes proving something you already knew.

**3. Reset the sandbox** (foreground, seconds):
```bash
make reset
```
Expect either a list of closed PRs and deleted branches, or "no open …". Both
are fine. Skipping this step is the single most common way to waste a run:
`_fetch_and_plan()` drops alerts whose fix branch still exists on the remote, so
an unreset sandbox exercises nothing.

**4. Start the run in the background**:
```bash
devloop/run.sh cve --max 1     # run_in_background: true
```
Use the Bash tool's `run_in_background` flag, not a trailing `&`. The harness
re-invokes you when it exits, so you do not need to guess a duration.

**5. Poll while it runs.** `observe.py` is read-only and idempotent — safe to
call as often as you like:
```bash
python3 devloop/observe.py
```
Poll roughly every 60–90s. Anything faster just burns tokens; the gates move on
15-second and 10-second cadences. While the run is live the report is headed
`IN PROGRESS` and the verdict names the phase each alert is sitting in — quote
that to the user rather than saying "still waiting".

**6. Final report** once the background command reports exit:
```bash
python3 devloop/observe.py
```

## Reading the verdict

Exit codes: `0` all alerts good · `1` failure or still running · `2` no alerts
exercised at all.

A correct run should show, per alert:

- `events` reaching `fix_succeeded`, with `committed` and `pr_opened` in between
- `pr` — a real PR number in `OPEN` state
- `orca` — Orca App checks with a real `success`/`failure` conclusion.
  **This line is the point of the exercise.** `(no Orca checks on this commit)`
  means Phase 4 never actually gated anything.
- `impact` — a level, meaning the impact agent ran

## Failure signatures

| What you see | What it means |
|---|---|
| exit 2, console shows an API error | the run died before fetching alerts — read `console.log` |
| exit 2, `RuntimeError: … Alert <id> not found` | a stale alert ID — Orca reminted them. Use a filter or `--scan` for a live one. |
| `[WARN] LLM validation failed` / `impact analysis failed` | a `claude -p` subprocess errored; the message carries the cause. `error_max_turns` means something restored `--allowedTools ""` in place of `--tools ""` — the former only denies tool calls, so the model keeps emitting them and each refusal burns a turn. See `_SINGLE_SHOT_TOOL_FLAGS` in validator.py. |
| `(no Orca checks on this commit)` | the Orca GitHub App is not posting on the sandbox. Not a code bug — check the integration on the repo. Known broken on `vulnerable-apps` since April 2026. |
| `state=FAILED`, reason `Orca check … not found on PR` | `on_not_found: fail` is set and the App did not post. Retrying cannot help — a re-fix will not make an App appear. |
| exit 2, console reached the plan stage | every alert was skipped; the reset did not take |
| `state=FAILED`, reason `diff too large` | the diff-size limit for that feature type rejected the fix |
| `state=FAILED`, reason mentions empty diff | the fix agent produced nothing, or the diff the gate read is not the diff that was written |
| `state=CI_FAILED` | the fix landed but GitHub checks went red — read the `finding` lines |
| `(no Orca checks on this commit)` | check-name matching, or the Orca App is not installed on the sandbox |
| `finding path:line — …` lines present | these are exactly what the retry feeds back to the fix agent; judge whether that feedback is usable |

## Reporting back

Give the user: the verdict line, per-alert states, PR links, and — if anything
failed — the specific `reason` or `finding` lines plus your read on the root
cause. Point at `devloop/runs/latest/console.log` for detail rather than pasting
it wholesale.

Do not fix code as part of this command. Report, then let the user decide.
