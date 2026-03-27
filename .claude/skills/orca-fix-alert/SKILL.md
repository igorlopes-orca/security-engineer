---
name: orca-fix-alert
description: Fetch an Orca alert by ID and apply a code fix to resolve the vulnerability
argument-hint: "<alert-id>"
disable-model-invocation: true
context: fork
allowed-tools: Read, Edit, Write, mcp__orca__ask_orca
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

Call `mcp__orca__ask_orca` with this query (substitute the actual alert ID):

"Get full details for Orca alert $ARGUMENTS. Include: alert title, category, full description, recommendation for how to fix it, the affected source file path and line number, the vulnerable code snippet with surrounding context, the feature type (sast/iac/scm_posture/secret), any CVE IDs if present, and any AI triage analysis explaining the vulnerability source and sink. Also include the direct URL to this alert."

Extract from the response:
- Alert title, description, recommendation
- Source file path + line number (e.g. `app/main.go:88`)
- Feature type: `sast`, `iac`, `scm_posture`, or `secret`
- Vulnerable code snippet
- AI triage explanation (if present)
- Alert URL

### Step 2: Determine fixability

Based on feature type:

- **`sast`** — source code vulnerability → fix the source file
- **`iac`** — infrastructure as code (Dockerfile, K8s YAML, Terraform) → fix the config file
- **`scm_posture`** — repository/branch settings → **cannot be fixed in code**. Explain the setting to the user and where to configure it in GitHub, then stop.
- **`secret`** — hardcoded secret → remove and replace with `os.Getenv("SECRET_NAME")`
- **CVE** (CveIds non-empty) → update the dependency version in `go.mod`, `package.json`, etc.

### Step 3: Read the file

Strip the line number from the source path (e.g. `app/main.go:88` → `app/main.go`) and read the full file using the Read tool.

### Step 4: Apply the fix

Use the Edit tool. Fix guidelines by vulnerability type:

**SQL Injection (CWE-89):** Replace string concatenation with parameterized queries.
```go
// Before
rows, err := db.Query("SELECT ... WHERE id = '" + id + "'")
// After
rows, err := db.Query("SELECT ... WHERE id = ?", id)
```

**Path Traversal (CWE-22):** Use `filepath.Clean` and verify the result stays within the allowed base directory.

**HTTP timeouts:** Add `ReadTimeout`, `WriteTimeout`, `IdleTimeout` to the `http.Server` struct.

**HTTP without TLS:** Replace `http.ListenAndServe` with `http.ListenAndServeTLS`, or note if TLS terminates at infra level.

**Dockerfile root user:** Add before `CMD`/`ENTRYPOINT`:
```dockerfile
RUN useradd -r -u 1001 appuser
USER appuser
```

**Missing HEALTHCHECK:** Add an appropriate `HEALTHCHECK` instruction before `CMD`.

**Hardcoded secrets:** Replace inline value with `os.Getenv("SECRET_NAME")`.

**Go module CVEs:** Update the vulnerable package version in `go.mod`, then note that `go mod tidy` should be run.

### Step 5: Summarize

Output:
1. What was changed (file, line range, before/after)
2. Why this fixes the vulnerability
3. Any manual follow-up needed (e.g. `go mod tidy`, rotate secret, set env var)
4. Link to the alert

Do NOT mark the alert as resolved in Orca — leave that for the user after they verify and merge.
