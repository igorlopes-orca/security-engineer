---
name: orca-fix-alert
description: Fetch an Orca alert by ID and apply a code fix to resolve the vulnerability
argument-hint: "<alert-id>"
disable-model-invocation: true
context: fork
allowed-tools: Read, Edit, Write, Bash
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

Run:
```bash
python3 ${CLAUDE_SKILL_DIR}/orca_get_alert.py $ARGUMENTS
```

The script reads `ORCA_API_TOKEN` or `ORCA_AUTH_TOKEN` from the environment and prints the alert details.

From the output, extract:
- **Feature Type** — `sast`, `iac`, `scm_posture`, or `secret`
- **Source** — file path + line (e.g. `k8s-cloudcamp/main.go:88`)
- **Description** — what the vulnerability is
- **Recommendation** — how to fix it
- **AI Triage** — source/sink analysis (for SAST alerts)
- **Vulnerable Lines** — start_line / end_line
- **Code Snippet** — surrounding code context

### Step 2: Determine fixability

Based on Feature Type:

- **`sast`** — source code vulnerability → fix the source file
- **`iac`** — infrastructure as code (Dockerfile, K8s YAML, Terraform) → fix the config file
- **`scm_posture`** — repository/branch settings → **cannot be fixed in code**. Explain the setting to the user and where to configure it in GitHub, then stop.
- **`secret`** — hardcoded secret → remove and replace with `os.Getenv("SECRET_NAME")`
- **CVE** (Labels contain `shiftleft:sast:lang:*` and a CVE ID) → update the dependency version in `go.mod`, `package.json`, etc.

### Step 3: Read the file

Strip the line number from the Source path (e.g. `k8s-cloudcamp/main.go:88` → `k8s-cloudcamp/main.go`) and read the full file using the Read tool.

### Step 4: Apply the fix

Use the Edit tool. Base your fix on the Recommendation, AI Triage analysis, and Code Snippet from Step 1.

**Fix guidelines by type:**

**SQL Injection (CWE-89):** Replace string concatenation with parameterized queries.
```go
// Before
query := "SELECT ... WHERE username = '" + username + "'"
rows, err := db.Query(query)

// After
rows, err := db.Query("SELECT ... WHERE username = ?", username)
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

Do NOT mark the alert as resolved in Orca — leave that for the user after they verify and merge.
