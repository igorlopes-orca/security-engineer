VERSION     := $(shell python3 -c "import json; print(json.load(open('.claude-plugin/plugin.json'))['version'])")
MARKETPLACE := orca-security
PLUGIN      := security-engineer@$(MARKETPLACE)
ORIGIN      := igorlopes-orca/security-engineer
PLUGIN_CACHE := $(HOME)/.claude/plugins/cache/orca-security/security-engineer/$(VERSION)

.PHONY: test e2e all install uninstall plugin-status validate reset run observe loop fast

# Unit tests — no API token needed, no network, pure Python
test:
	python3 skills/run/tests/test_orchestrator.py
	python3 skills/run/tests/test_version_data.py
	python3 skills/run/tests/test_package_identity.py
	python3 skills/run/tests/test_pipelines.py
	python3 devloop/tests/test_observe.py
	python3 devloop/tests/test_plugin_sync.py

# Integration tests — requires ORCA_API_TOKEN
e2e:
	python3 skills/run/tests/test_e2e_orca.py

# Run both
all: test e2e

# Install this working tree as the plugin, so /security-engineer:run executes
# the code you are editing.
#
# Without this the two entry points diverge. devloop/run.sh runs orchestrator.py
# straight out of the repo, while the skill runs the copy Claude Code made when
# the plugin was installed — and nothing refreshes that copy on its own:
# `claude plugin update` short-circuits while plugin.json's version is
# unchanged, and installing over an existing install is a no-op. So the skill
# keeps running the commit it was installed at until you say otherwise.
#
# Three steps, none of them optional:
#   marketplace add  points the orca-security marketplace at THIS directory
#                    instead of GitHub, so "install" means "install what I have
#                    here" rather than "download origin/main"
#   uninstall        the no-op-on-reinstall rule means the old copy has to go
#                    first, or nothing is refreshed. Ignored if not installed.
#   install          copies the working tree into the plugin cache
#
# `make uninstall` puts the marketplace back on GitHub.
install:
	@claude plugin marketplace add "$(CURDIR)" --scope user >/dev/null
	@claude plugin uninstall $(PLUGIN) --scope user >/dev/null 2>&1 || true
	@claude plugin install $(PLUGIN) --scope user
	@python3 devloop/plugin_sync.py check
	@echo "Installed v$(VERSION) from $(CURDIR)."
	@echo "SKILL.md or frontmatter changes need a Claude Code restart to re-register."

# Remove the plugin and put the marketplace back on GitHub.
#
# Uninstalls every scope the registry actually lists, each from its own
# projectPath. A project-scoped entry is only visible to `claude plugin
# uninstall` when the command runs from the directory it was installed from —
# this plugin's is $HOME, not this repo — and getting that wrong leaves a
# registry entry pointing at a cache directory this target then deletes.
#
# Uninstall also leaves the copied files behind, hence the rm.
uninstall:
	@python3 devloop/plugin_sync.py scopes | while IFS="$$(printf '\t')" read -r scope dir; do \
	  cd "$${dir:-$(CURDIR)}" && claude plugin uninstall $(PLUGIN) --scope "$$scope" || true; \
	done
	@rm -rf "$(HOME)/.claude/plugins/cache/orca-security/security-engineer"
	-@claude plugin marketplace add $(ORIGIN) --scope user >/dev/null
	@python3 devloop/plugin_sync.py check || true
	@echo "Removed $(PLUGIN); marketplace restored to $(ORIGIN)."
	@echo "Reinstall the published version with ./install.sh, or this tree with 'make install'."

# Is the installed plugin the code in this tree? Names the files if not.
# Reports rather than fails — `make: *** Error 1` on a status query is noise.
# The script itself still exits non-zero, which is what run.sh keys off.
plugin-status:
	@python3 devloop/plugin_sync.py check || true

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
#
# `install` is in the chain so the skill and the dev loop never test different
# code: the run exercises the working tree, and the install makes
# /security-engineer:run agree with it. It costs a couple of seconds and it is
# the only thing keeping the two entry points honest.
loop:
	$(MAKE) test && $(MAKE) install && $(MAKE) reset && $(MAKE) run ARGS="$(ARGS)" && $(MAKE) observe

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
