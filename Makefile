.PHONY: test e2e all

# Unit tests — no API token needed, pure Python
test:
	python3 .claude/skills/security-engineer/tests/test_orchestrator.py

# Integration tests — requires ORCA_API_TOKEN
e2e:
	python3 .claude/skills/security-engineer/tests/test_e2e_orca.py

# Run both
all: test e2e
