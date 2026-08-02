#!/usr/bin/env python3
"""
Say whether the installed plugin is the code in this working tree.

Two entry points reach the orchestrator, and they do not share a copy of it:

  * devloop/run.sh runs skills/run/orchestrator.py from this
    repo — uncommitted edits included.
  * /security-engineer:run runs it from the plugin install directory, a copy
    Claude Code made when the plugin was installed.

Nothing refreshes that copy on its own. `claude plugin update` short-circuits
while plugin.json's version is unchanged, and reinstalling over an existing
install is a no-op — so the installed skill keeps running whatever was current
the day it went in. On 2026-08-02 that was twelve commits back, and a green dev
loop said nothing about it.

`make install` closes the gap by reinstalling from this directory. This module
is how you find out that you need to: it compares the two trees file by file
and names what differs.

Usage:
    python3 devloop/plugin_sync.py check     # exit 0 in sync, 1 drifted
    python3 devloop/plugin_sync.py check --quiet   # print only when wrong
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

PLUGIN_KEY = "security-engineer@orca-security"

# What `claude plugin install` actually copies out of this repo. devloop/,
# docs/ and the tests at the root are not part of the plugin, so a difference
# there is not drift.
COMPONENTS = ("skills", "commands", "bin")

_SKIP_DIRS = {"__pycache__", ".in_use", ".git"}
# Runtime output, not source: the orchestrator writes its event log beside
# itself, so whichever tree last ran has one and the other does not.
_SKIP_NAMES = {"security-engineer-run.json", ".DS_Store"}
_SKIP_SUFFIXES = {".pyc", ".pyo"}

_REPO_ROOT = Path(__file__).resolve().parent.parent
_REGISTRY = Path.home() / ".claude" / "plugins" / "installed_plugins.json"

IN_SYNC = "in_sync"
DRIFTED = "drifted"
NOT_INSTALLED = "not_installed"


def install_paths(registry, plugin_key=PLUGIN_KEY):
    """Every distinct installPath registered for a plugin, in registry order.

    A plugin installed at both user and project scope appears twice, normally
    sharing one installPath — dedupe so callers compare it once.
    """
    entries = (registry or {}).get("plugins", {}).get(plugin_key) or []
    seen, paths = set(), []
    for entry in entries:
        path = (entry or {}).get("installPath")
        if path and path not in seen:
            seen.add(path)
            paths.append(path)
    return paths


def scopes(registry, plugin_key=PLUGIN_KEY):
    """Every (scope, project_path) the plugin is registered under.

    `claude plugin uninstall --scope project` only finds an entry when it runs
    from that entry's projectPath, and the path recorded there is wherever the
    plugin happened to be installed from — for this repo's own install that is
    $HOME, not the repo. Uninstalling from the wrong directory fails with
    "not installed in project scope" and silently leaves the entry behind,
    pointing at a cache directory that has been deleted.
    """
    entries = (registry or {}).get("plugins", {}).get(plugin_key) or []
    out, seen = [], set()
    for entry in entries:
        scope = (entry or {}).get("scope")
        if not scope:
            continue
        pair = (scope, (entry.get("projectPath") or ""))
        if pair not in seen:
            seen.add(pair)
            out.append(pair)
    return out


def read_registry(path=_REGISTRY):
    """The plugin registry, or an empty dict if it is absent or unreadable."""
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {}


def is_source(rel_path):
    """Whether a plugin-relative path is shipped source worth comparing."""
    parts = Path(rel_path).parts
    if any(part in _SKIP_DIRS for part in parts):
        return False
    name = parts[-1] if parts else ""
    return name not in _SKIP_NAMES and Path(name).suffix not in _SKIP_SUFFIXES


def hash_tree(root, components=COMPONENTS):
    """Map every shipped file under root to a digest of its contents.

    Keys are relative to root so two trees in different places compare
    directly. A component the tree does not have contributes nothing, which is
    what makes a missing directory show up as missing files rather than a crash.
    """
    root = Path(root)
    out = {}
    for component in components:
        base = root / component
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file():
                continue
            rel = str(path.relative_to(root))
            if not is_source(rel):
                continue
            out[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


def drift(installed, working):
    """Compare two hashed trees from the installed copy's point of view.

    Returns (changed, missing, stale):
      changed — in both, different contents
      missing — in the working tree but never copied across
      stale   — still installed after being deleted here
    """
    changed = sorted(k for k in installed.keys() & working.keys()
                     if installed[k] != working[k])
    missing = sorted(working.keys() - installed.keys())
    stale = sorted(installed.keys() - working.keys())
    return changed, missing, stale


def summarize(registered, present, changed, missing, stale, limit=6):
    """Turn a comparison into a state and a message a human can act on.

    `registered` is what the registry claims, `present` is what is actually on
    disk. They differ after an uninstall that could not reach every scope: the
    entry survives, the files do not. Reporting that as "every file is behind"
    would be true but useless — the install is broken, not stale.
    """
    if not registered:
        return NOT_INSTALLED, (
            f"{PLUGIN_KEY} is not installed — /security-engineer:run will not "
            f"resolve.\n  Install this working tree with: make install")

    if not present:
        return NOT_INSTALLED, (
            f"{PLUGIN_KEY} is registered but its files are gone:\n"
            f"    {registered[0]}\n"
            f"  A partly-completed uninstall leaves this behind.\n"
            f"  Fix with: make install  (or 'make uninstall' to clear the entry)")

    total = len(changed) + len(missing) + len(stale)
    if not total:
        return IN_SYNC, "installed plugin matches this working tree"

    lines = [f"installed plugin is {total} file(s) behind this working tree:"]
    for label, group in (("modified", changed), ("not installed", missing),
                         ("deleted here", stale)):
        for name in group[:limit]:
            lines.append(f"    {label:>14}  {name}")
        if len(group) > limit:
            lines.append(f"    {'':>14}  … and {len(group) - limit} more")
    lines.append("  /security-engineer:run would test different code than the "
                 "dev loop.")
    lines.append("  Fix with: make install")
    return DRIFTED, "\n  ".join(lines)


def evaluate(repo_root=_REPO_ROOT, registry_path=_REGISTRY):
    """Full check against the real filesystem. Returns (state, message)."""
    registered = install_paths(read_registry(registry_path))
    present = [p for p in registered if Path(p).is_dir()]
    if not present:
        return summarize(registered, present, [], [], [])

    working = hash_tree(repo_root)
    # More than one install path is unusual; the worst drift is the one worth
    # reporting, so accumulate across all of them.
    changed, missing, stale = [], [], []
    for path in present:
        c, m, s = drift(hash_tree(path), working)
        changed += c
        missing += m
        stale += s
    return summarize(registered, present, sorted(set(changed)),
                     sorted(set(missing)), sorted(set(stale)))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["check", "scopes"])
    parser.add_argument("--quiet", action="store_true",
                        help="print only when the trees differ")
    args = parser.parse_args(argv)

    if args.action == "scopes":
        # Tab-separated so `make uninstall` can read it with a shell loop.
        # An empty second field means "no projectPath — run from anywhere".
        for scope, project_path in scopes(read_registry()):
            print(f"{scope}\t{project_path}")
        return 0

    state, detail = evaluate()
    if state == IN_SYNC:
        if not args.quiet:
            print(f"plugin-sync: {detail}")
        return 0
    print(f"plugin-sync: {detail}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
