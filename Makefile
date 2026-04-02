VERSION     := $(shell python3 -c "import json; print(json.load(open('.claude-plugin/plugin.json'))['version'])")
PLUGIN_CACHE := $(HOME)/.claude/plugins/cache/orca-security/security-engineer/$(VERSION)

.PHONY: test e2e all install validate

# Unit tests — no API token needed, pure Python
test:
	python3 skills/security-engineer/tests/test_orchestrator.py

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
	rm -f "$(PLUGIN_CACHE)/.claude-plugin/marketplace.json"
	find "$(PLUGIN_CACHE)" -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@echo "Installed v$(VERSION) to plugin cache. Restart Claude Code or run /reload-plugins."

# Verify cached plugin is valid
validate:
	claude plugin validate "$(PLUGIN_CACHE)"
