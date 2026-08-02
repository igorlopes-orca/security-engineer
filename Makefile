VERSION     := $(shell python3 -c "import json; print(json.load(open('.claude-plugin/plugin.json'))['version'])")
PLUGIN_CACHE := $(HOME)/.claude/plugins/cache/orca-security/security-engineer/$(VERSION)

.PHONY: test e2e all install validate reset run observe loop fast

# Unit tests — no API token needed, no network, pure Python
test:
	python3 skills/security-engineer/tests/test_orchestrator.py
	python3 skills/security-engineer/tests/test_version_data.py
	python3 skills/security-engineer/tests/test_package_identity.py
	python3 skills/security-engineer/tests/test_pipelines.py
	python3 devloop/tests/test_observe.py

# Integration tests — requires ORCA_API_TOKEN
e2e:
	python3 skills/security-engineer/tests/test_e2e_orca.py

# Run both
all: test e2e

# Copy local files to plugin cache for testing without pushing
install:
	@test -d "$(PLUGIN_CACHE)" || (echo "Plugin not installed. Run install.sh first." && exit 1)
	rsync -a --exclude='__pycache__' --exclude='*.pyc' --exclude='security-engineer-run.json' skills/ "$(PLUGIN_CACHE)/skills/"
	rsync -a commands/ "$(PLUGIN_CACHE)/commands/"
	rsync -a bin/ "$(PLUGIN_CACHE)/bin/"
	rm -f "$(PLUGIN_CACHE)/.claude-plugin/marketplace.json"
	find "$(PLUGIN_CACHE)" -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@echo "Installed v$(VERSION) to plugin cache. Restart Claude Code or run /reload-plugins."

# Verify cached plugin is valid
validate:
	claude plugin validate "$(PLUGIN_CACHE)"

# ---------------------------------------------------------------------------
# Dev loop — see devloop/README.md
#
# The pipeline only really exists in a live --remote run: worktree lifecycle,
# what the gates actually see, whether the Orca check gate fires. These targets
# make that run one command and one readable report.
# ---------------------------------------------------------------------------

# Sandbox back to clean — close fix/orca-* PRs, drop those branches, prune /tmp
reset:
	devloop/reset.sh

# Live run against the sandbox. Pass orchestrator flags via ARGS.
#   make run ARGS="cve --max 1"
#   make run ARGS="--dry-run cve"
#   make run ARGS="--scan"          -> list live alert IDs
run:
	devloop/run.sh $(ARGS)

# Report on the newest run — per-alert state, PRs, Orca checks, annotations
observe:
	python3 devloop/observe.py

# Full loop. Held together with && so a failing step stops the chain instead of
# letting `observe` report on a run that never happened.
loop:
	$(MAKE) test && $(MAKE) reset && $(MAKE) run ARGS="$(ARGS)" && $(MAKE) observe

# Single-alert loop — the fast iteration path.
#
# Defaults to "one CVE" rather than a fixed alert ID: Orca mints new IDs every
# time it rescans the sandbox, so any hardcoded ID goes stale and the run dies
# with "Alert <id> not found". A CVE is also the most deterministic fix to
# judge — usually a one-line version bump.
#   make fast                      -> highest-severity CVE
#   make fast ALERT=orca-4060654   -> that specific alert
fast:
	$(MAKE) loop ARGS="$(if $(ALERT),--alert $(ALERT),cve --max 1)"
