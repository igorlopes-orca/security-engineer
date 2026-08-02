---
name: run
description: Autonomous security agent that fixes Orca security alerts (CVE/SCA, SAST, IaC, secrets) — validates each fix, analyzes production impact, opens PRs, and notifies. Use whenever the user wants to fix, remediate, patch, or triage Orca alerts or vulnerabilities, or scan a repo for security findings — including phrases like "fix the sast issues", "remediate one CVE", "patch the high-severity alerts", "scan this repo", or "run the security engineer". Translates natural-language intent (severity, finding type, count, dry-run, remote repo) into orchestrator flags.
argument-hint: "[risk_levels,feature_types] [--scan] [--alert <id>] [--max N] [--dry-run] | --remote <owner/repo|all> [filters]"
allowed-tools: Bash
---

# Security Engineer Agent

```bash
python3 ${CLAUDE_SKILL_DIR}/orchestrator.py $ARGUMENTS
```

Return the output verbatim. If the script exits with a non-zero exit code, print the error and STOP — do not retry, do not correct arguments, do not attempt to fix the command on the user's behalf.

## Translating natural language to flags

When invoked from plain English (not a `/security-engineer:run` slash command), build
`$ARGUMENTS` from the request using this mapping, then run the orchestrator exactly once:

| User says… | Flags |
|---|---|
| "fix one sast alert", "fix a single SAST issue" | `sast --max 1` |
| "remediate one CVE" | `cve --max 1` |
| "patch the high-severity alerts" | `high` |
| "fix critical SAST findings" | `critical,sast` |
| "fix the secrets" / "fix IaC issues" | `secret` / `iac` |
| "just show me what it would do" / "dry run" | append `--dry-run` |
| "scan this repo" / "don't fix, just report" | `--scan` |
| "fix alert orca-385591" | `--alert orca-385591` |
| "fix alerts in owner/repo" | `--remote owner/repo` |
| "fix everything" / no qualifier | (no flags) |

Rules:
- Severity words (`critical`/`high`/`medium`/`low`) and types (`sast`/`iac`/`cve`/`secret`)
  combine comma-separated with no spaces: `critical,sast`.
- "one" / "a single" / "just one" → `--max 1`; "two", "three" → `--max 2`, `--max 3`.
- If the request is ambiguous about scope (which severity/type), ask before running —
  do not guess and launch a broad fix run.
- Echo the resolved command to the user before executing, e.g. `→ orchestrator.py sast --max 1`.

---

## Usage Reference

Two modes: **fix** (default) and **scan** (`--scan`).

### Fix mode — remediate alerts

```
# Local mode — operates on the repo you're already inside
/security-engineer:run                             -> all fixable alerts, all severities
/security-engineer:run cve                         -> CVE alerts only, all severities
/security-engineer:run high                        -> high+ severity, all types
/security-engineer:run high,cve                    -> high+ severity AND CVE type only
/security-engineer:run critical,sast               -> critical+ AND SAST only
/security-engineer:run --dry-run cve               -> plan CVE fixes — read-only, no git ops
/security-engineer:run --dry-run high,sast         -> plan high+ SAST fixes — no edits
/security-engineer:run --alert orca-270453         -> fix one specific alert (live)
/security-engineer:run --alert orca-270453 --dry-run -> plan one specific alert
/security-engineer:run --max 3 cve                 -> cap at 3 CVE fixes

# Remote mode — clones repos, runs full pipeline, cleans up
/security-engineer:run --remote owner/repo              -> clone owner/repo, fix all alerts
/security-engineer:run --remote owner/repo high,cve     -> clone, fix high+ CVEs only
/security-engineer:run --remote --dry-run owner/repo    -> clone, plan only, no edits
/security-engineer:run --remote all                     -> all Orca-discovered repos (clone each)
/security-engineer:run --remote all high,cve            -> all repos, high+ CVEs only
/security-engineer:run --remote all --dry-run sast      -> plan SAST fixes across all repos
/security-engineer:run --remote all --max 2 cve         -> cap at 2 CVE fixes per repo
```

### Scan mode — list risks without fixing

```
/security-engineer:run --scan                           -> list all risks, local repo
/security-engineer:run --scan high                      -> list high+ risks only
/security-engineer:run --scan sast,iac                  -> list SAST and IaC risks
/security-engineer:run --scan --remote owner/repo       -> list risks for a remote repo
/security-engineer:run --scan --remote all              -> list risks across all repos
```

## Flag Compatibility

| Flag | Fix mode | Scan mode | Notes |
|---|---|---|---|
| `filters` (positional) | Yes | Yes | `high,cve`, `sast`, etc. |
| `--dry-run` | Yes | **Error** | Scan is inherently read-only |
| `--alert <id>` | Yes | **Error** | Use `--alert` without `--scan` to fix it |
| `--max N` | Yes | **Error** | No fixing = no cap needed |
| `--remote <repo\|all>` | Yes | Yes | In scan mode: API query only, no clone |

Invalid combinations produce a clear error:
```
Error: --scan and --dry-run cannot be combined. --scan already lists alerts without fixing.
Error: --scan and --alert cannot be combined. To fix a single alert, drop --scan.
Error: --scan and --max cannot be combined. --scan lists all matching alerts.
```

## Filter Rules

**Risk levels** (cumulative — specifying `high` includes `critical` too):
- `critical` -> critical only
- `high` -> critical + high
- `medium` -> critical + high + medium
- `low` -> everything except informational

**Feature types** (exact match — only alerts of those types):
- `cve` -> package/dependency CVEs (category "Vulnerabilities")
- `sast` -> source code vulnerabilities
- `iac` -> Dockerfiles, K8s YAML, Terraform
- `secret` -> hardcoded credentials

Combine with comma: `high,cve` = high+ severity AND CVE type. Both conditions must match.

## --dry-run Guarantees

Three independent enforcement layers:
1. **Tool restriction** — claude subprocess receives `--allowedTools Read` only; Edit/Write/Bash are physically unavailable
2. **Orchestrator gate** — returns immediately after fix plan; validation, commit, and PR steps are never reached
3. **Commit guard** — `_commit_and_pr()` also checks dry_run as defense in depth

Run `python3 ${CLAUDE_SKILL_DIR}/tests/test_orchestrator.py` to verify all flags are enforced correctly.

## Pipeline (Live Mode)

### Local mode (default)

Operates on the repo you're already inside — no cloning.

Each finding type runs through a **FixPipeline** (`pipelines/`) that owns its
timeout, diff budget, pre-fix `prepare()` and post-fix `verify()`. `cve` has a
specialist; `sast`, `iac` and `secret` use the generic pipeline, which behaves
exactly as the orchestrator did before pipelines existed.

```
For each alert (up to 4 in parallel, isolated git worktree per alert):

  1. create_worktree        -> /tmp/orca-fix-<owner>-<repo>-<id>  (isolated branch)
                              clears leftovers from a crashed run; refuses to
                              delete a branch holding commits (skips instead)
  2. pipeline.prepare       -> Phase 0. CVE only: resolve the package and the
                              target version from OSV + deps.dev (see CVE
                              Version Decisions). A failure here is not fatal —
                              the fix proceeds unguided, flagged needs-review.
  3. invoke_fix_agent       -> claude subprocess, --allowedTools Read,Edit,Write,Bash
                              timeout from the pipeline (sast=180s,
                              iac/secret=120s, cve=240s)
                              prompt = fix-agents/<type>.md + prepare() directive
                              retries: up to 2 on json_parse / subprocess errors
  4. validate (Phase 1)     -> Python: diff non-empty, diff size, no new secrets,
                              and the agent's diff_summary must not name a
                              version its own diff never added
                              diff = `git add -A -N` + `git diff`, so created
                              files count; size limit from the pipeline
  5. validate (Phase 2)     -> LLM: does the fix address the vulnerability?
  6. pipeline.verify        -> Phase 3. CVE: the manifest actually pins the
                              resolved version, the lockfile agrees, and the
                              applied version carries no known advisory.
                              Other types: local build (see Language Coverage)
  7. impact_agent           -> claude subprocess: diff + the resolved bump
                              distance -> production risk JSON
  8. git-commit             -> run_agent.py git-commit
  9. open-pr                -> run_agent.py open-pr (impact + version rationale
                              in the PR body)
 10. validate (Phase 4)     -> Orca check gate (see Orca Check Gate below)
 11. validate (Phase 5)     -> CI gate: gh pr checks --watch (timeout: 10min)
 12. notify                 -> console + log file (+ webhook if configured)
 13. remove_worktree        -> cleanup worktree + local branch (runs in a finally,
                              so it happens on every exit path incl. exceptions)
```

### Remote mode (`--remote owner/repo` or `--remote all`)

Adds a repo-level wrapper around the per-alert pipeline above.

```
--remote owner/repo:
  1. gh repo clone -> /tmp/orca-global-<owner>-<repo>/  (shallow, --depth=1)
  2. fetch alerts for that repo (via Orca API)
  3. per-alert pipeline (same 11 steps above, git ops run inside the clone)
  4. shutil.rmtree -> cleanup clone (always, even on failure)

--remote all:
  1. list_repositories(token)  -> Orca CodeRepository query -> list of repos with open alerts
  2. For each repo (up to 3 in parallel):
       same 4 steps as --remote owner/repo
  3. global summary table (per-repo breakdown + totals)

Max concurrent Claude subprocesses: 3 repos x 4 alerts = 12
```

## Orca Check Gate

Phase 4 runs **after the PR is opened**: it polls the Orca GitHub App check (default
`orca-security-us`) on the PR head commit via the `gh` CLI and treats new findings the
App reports as regressions introduced by the fix.

1. **Resolve** the PR head SHA (`gh pr view`)
2. **Find** the Orca check run among the commit's check-runs (case-insensitive name match)
3. **Poll** until the check completes or `timeout_sec` elapses
4. **On failure**, fetch the check annotations (file, line, message, severity) as findings

**Retry on failure:** when the check reports findings, the orchestrator reverts the fix,
re-invokes the fix agent with the annotations as feedback, re-validates locally
(sanity + build), and pushes the new fix to the same PR branch — up to `max_retries`
times. After retries are exhausted, behavior follows `on_failure` (`retry`/`fail`/`skip`).

**Pass conditions:**
- Check concludes `success` or `neutral`
- Check `skipped` or not found after the grace period → passes, flagged `needs-review`

**Configuration** (`orca_check:` section of `config.py`, overridable via
`SECURITY_ENGINEER_CONFIG` YAML — see also `version_data:` under CVE Version
Decisions):

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Run the gate at all |
| `check_name` | `orca-security-us` | Substring matched against check-run names |
| `timeout_sec` | `600` | Max time to wait for the check to complete |
| `poll_interval_sec` | `15` | Delay between polls |
| `max_retries` | `1` | Fix-agent re-invocations on failure |
| `on_failure` | `retry` | `retry` \| `fail` \| `skip` after retries exhausted |
| `on_not_found` | `skip` | `skip` \| `fail` when the check never appears |

**Environment:** Relies on `gh` being authenticated for the target repo; no `orca-cli`
binary or API token is needed on the runner.

## CVE Version Decisions

For a package CVE, the target version is resolved **before** the fix agent runs,
by `skills/lib/version_data.py`. The agent is told which version to apply rather
than asked to work it out.

**Sources** (both free, unauthenticated, and cached on disk):

| Source | Supplies |
|---|---|
| OSV.dev `POST /v1/query` | advisory ranges — which versions each advisory affects |
| deps.dev v3 | which versions were actually published |

**Policy: minimum safe at any distance.** The target is the lowest published
release that clears *every* advisory affecting the installed version — queried
package-wide, not just for the alert's own CVE, so a bump cannot land on a
different known vulnerability. Crossing a major boundary is not refused, because
some packages have no safe release inside the current major; instead the distance
is classified (`bump_class`, `majors_crossed`) and handed to impact analysis.

**Ecosystems:** PyPI, npm, Go, Maven, Cargo, RubyGems, NuGet. The ecosystem comes
from the manifest filename in the alert's `source`; the package name is whichever
manifest entry the alert's prose names, cross-checked against the manifest, which
is the authority. Per-ecosystem agent instructions live in `fix-agents/cve/`.

**Inspect a decision by hand** — no Orca token or alert needed:

```bash
python3 ${CLAUDE_SKILL_DIR}/run_agent.py resolve-version pypi pillow 8.3.1
python3 ${CLAUDE_SKILL_DIR}/run_agent.py resolve-version ./app/requirements.txt requests 2.20.0
```

The same rationale, cleared advisories and reproduce command appear in the PR body.

**Configuration** (`version_data:` section):

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | `false` reverts CVEs to the generic pipeline entirely |
| `cache_dir` | `~/.cache/security-engineer/version-data` | On-disk cache location |
| `cache_ttl_sec` | `21600` (6h) | Cache lifetime; `0` forces a refetch |
| `timeout_sec` | `20` | Per-request HTTP timeout |
| `offline` | `false` | Serve from cache only; never call out |
| `osv_url` / `deps_dev_url` | upstream defaults | Override the endpoints |

**Degradation:** every failure — unknown ecosystem, unparsed manifest, API
outage, no safe version — leaves the fix running on the agent's own judgement
with the alert flagged `needs-review`. A data-layer problem costs determinism,
not the fix.

## Language Coverage

Phase 3 is the type's `pipeline.verify()`.

**CVE** does not use the build-command table below. A dependency bump touches
manifests and lockfiles, whose extensions (`.txt`, `.mod`, `.json`) never matched
any entry, so this table silently did nothing for CVE fixes. Instead the CVE
pipeline asserts the manifest pins the resolved version, that a lockfile beside it
agrees, and that the applied version carries no known advisory — then runs an
ecosystem resolve check where one is cheap and offline (`go build ./...` for Go,
`cargo metadata --locked` for Cargo). `pip install` / `npm install` / `mvn` are
deliberately not run: they are slow, need the network, and rewrite lockfiles,
which is the fix agent's job. CI covers what is left.

**sast / iac / secret** use the generic pipeline, which runs the language check
below. The build root is detected by walking up from the affected file — the path
comes from the Orca alert (`source` field), so monorepos and subdirectory apps are
handled correctly.

| Language | Detection | Build command | Notes |
|---|---|---|---|
| Go | nearest `go.mod` | `go build ./...` | Skipped if `go` not installed |
| JavaScript / TypeScript | nearest `package.json` | `npm run build --if-present` | Skipped if `npm` not installed; `--if-present` means no `build` script = pass |
| Python | per-file | `python3 -m py_compile <file>` | Syntax-only; no project root needed |
| Terraform | directory of `.tf` file | `terraform validate` | Skipped if `terraform` not installed |
| Dockerfile / YAML / other | — | skipped | No build check |

If the build tool is not installed, the check passes (skip, not fail) — the Orca
check and CI gates catch regressions.

## Notifications

Always active:
- Console output (`[OK]`, `[FAIL]`, `[TOUT]`, etc.)
- `security-engineer-run.json` — newline-delimited JSON log of all events

Opt-in:
- `NOTIFY_WEBHOOK_URL=https://...` -> HTTP POST on every event (Slack, Teams, etc.)
The impact assessment goes into the **PR body** at creation time (step 8), not a
separate comment — impact is computed before the PR is opened, so a comment could
only repeat it.

## Environment Variables

| Variable | Required | Purpose |
|---|---|---|
| `ORCA_API_TOKEN` | Yes | Orca API token (base64 string from Orca config) |
| `NOTIFY_WEBHOOK_URL` | No | Webhook for Slack/Teams notifications |
