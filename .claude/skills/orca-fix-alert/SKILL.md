---
name: orca-fix-alert
description: Fetch an Orca alert by ID and apply a code fix to resolve the vulnerability
argument-hint: "<alert-id>"
disable-model-invocation: true
context: fork
allowed-tools: Read, Edit, Write, mcp__orca__get_alert
---

# Orca Fix Alert Skill

Fetch an Orca alert and fix the vulnerability in the repository code.

## Usage
```
/orca-fix-alert orca-270453
```

## Workflow

The alert ID to fix is: **$ARGUMENTS**

### Step 1: Fetch the alert

Call `mcp__orca__get_alert(alert_id="$ARGUMENTS")`.

From the response (`data[0].data`), extract these fields:

| Field | Path in response |
|---|---|
| Alert title | `AlertType.value` |
| Category | `Category.value` |
| Description | `Description.value` |
| Recommendation | `Recommendation.value` |
| Source file + line | `Source.value` (e.g. `k8s-cloudcamp/main.go:88`) |
| Feature type | `RiskFindings.value.feature_type` (`sast`, `iac`, `scm_posture`) |
| Code snippet | `RiskFindings.value.code_snippet` (array of `{line, position}`) |
| AI triage | `RiskFindings.value.ai_triage.explanation` (if present) |
| Start line | `RiskFindings.value.position.start_line` |
| End line | `RiskFindings.value.position.end_line` |
| Alert URL | `ui_url` (top-level field) |

### Step 2: Determine fixability

Check `RiskFindings.value.feature_type`:

- **`sast`** — source code vulnerability → fix the source file
- **`iac`** — infrastructure as code (Dockerfile, K8s YAML, Terraform) → fix the config file
- **`scm_posture`** — repository settings (branch protection, etc.) → **cannot be fixed in code**. Inform the user: explain what the setting is, where to configure it in GitHub, and stop.
- **`secret`** — hardcoded secret → remove/rotate the secret and replace with env var or secret manager reference
- For package CVEs (Labels contain `shiftleft:sast:lang:*` and CveIds is non-empty) → update the dependency version in the relevant module file (`go.mod`, `package.json`, etc.)

### Step 3: Read the file

Extract the file path from `Source.value` — it's in the format `path/to/file.go:linenum`. Strip the line number.

Read the full file using the Read tool. The `code_snippet` array gives you surrounding context to locate the exact region.

### Step 4: Apply the fix

Use the Edit tool to fix the vulnerability. Base your fix on:
1. `Recommendation.value` — the prescribed fix
2. `ai_triage.explanation` — detailed analysis of source/sink (for SAST)
3. `code_snippet` — the exact code to replace
4. Your understanding of the language/framework

**Fix guidelines by type:**

**SQL Injection (CWE-89):** Replace string concatenation with parameterized queries.
```go
// Before
query := "SELECT ... WHERE username = '" + username + "'"
rows, err := db.Query(query)

// After
rows, err := db.Query("SELECT ... WHERE username = ?", username)
```

**Path Traversal (CWE-22):** Validate and sanitize the path before use. Use `filepath.Clean` and verify it stays within allowed base directories.

**HTTP timeouts:** Add `ReadTimeout`, `WriteTimeout`, `IdleTimeout` to the `http.Server` struct.

**HTTP without TLS:** Replace `http.ListenAndServe` with `http.ListenAndServeTLS`, or note if TLS termination happens at infra level.

**Dockerfile root user:** Add `USER nonroot` (or a named non-root user) before `CMD`/`ENTRYPOINT`. If no non-root user exists in the image, add:
```dockerfile
RUN useradd -r -u 1001 appuser
USER appuser
```

**Missing HEALTHCHECK:** Add an appropriate `HEALTHCHECK` instruction before `CMD`.

**Hardcoded secrets:** Replace inline value with `os.Getenv("SECRET_NAME")` and document which env var is needed.

**Go module CVEs:** Update the vulnerable package version in `go.mod` to the patched version, then note that `go mod tidy` should be run.

### Step 5: Summarize

After applying the fix, output:
1. What was changed (file, line range, before/after)
2. Why this fixes the vulnerability (brief explanation)
3. Any manual follow-up needed (e.g., run `go mod tidy`, rotate secrets, set env vars)
4. Link to the alert: `ui_url`

Do NOT mark the alert as resolved in Orca — leave that for the user after they verify and merge the fix.
