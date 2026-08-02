#!/usr/bin/env python3
"""
Tests for devloop/plugin_sync.py.

The comparison layer takes hashed trees as arguments, so it needs no
filesystem; hash_tree itself is exercised against a temp directory.

Run with: python3 devloop/tests/test_plugin_sync.py
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from plugin_sync import (
    DRIFTED,
    IN_SYNC,
    NOT_INSTALLED,
    PLUGIN_KEY,
    drift,
    hash_tree,
    install_paths,
    is_source,
    read_registry,
    scopes,
    summarize,
)

CACHE = "/cache/orca-security/security-engineer/1.0.0"


def _reg(entries):
    return {"version": 2, "plugins": {PLUGIN_KEY: entries}}


class TestInstallPaths(unittest.TestCase):

    CASES = [
        ("empty registry", {}, []),
        ("no plugins key", {"version": 2}, []),
        ("plugin absent", _reg(None), []),
        ("single scope", _reg([{"scope": "user", "installPath": CACHE}]), [CACHE]),
        # The real registry lists this plugin at both user and project scope,
        # both pointing at one directory — compare it once, not twice.
        ("two scopes, same path",
         _reg([{"scope": "user", "installPath": CACHE},
               {"scope": "project", "installPath": CACHE}]), [CACHE]),
        ("two scopes, different paths",
         _reg([{"scope": "user", "installPath": CACHE},
               {"scope": "project", "installPath": "/cache/other"}]),
         [CACHE, "/cache/other"]),
        ("entry without installPath skipped",
         _reg([{"scope": "user"}, {"scope": "project", "installPath": CACHE}]),
         [CACHE]),
        ("null entry skipped",
         _reg([None, {"scope": "user", "installPath": CACHE}]), [CACHE]),
    ]

    def test_install_paths(self):
        for desc, registry, expected in self.CASES:
            with self.subTest(desc):
                self.assertEqual(install_paths(registry), expected)

    def test_other_plugin_ignored(self):
        registry = {"plugins": {"unrelated@mp": [{"installPath": "/elsewhere"}]}}
        self.assertEqual(install_paths(registry), [])


class TestIsSource(unittest.TestCase):

    CASES = [
        ("plain module", "skills/run/orchestrator.py", True),
        ("skill body", "skills/run/SKILL.md", True),
        ("nested agent prompt", "skills/run/fix-agents/cve/npm.md", True),
        ("shipped launcher", "bin/security-engineer", True),
        ("slash command", "commands/run.md", True),
        ("bytecode cache", "skills/run/__pycache__/x.cpython-314.pyc", False),
        ("loose pyc", "skills/x.pyc", False),
        # Written by whichever tree last ran the orchestrator — its presence in
        # one tree and not the other is not a code difference.
        ("runtime event log", "skills/run/security-engineer-run.json", False),
        # The harness drops pid markers into the install directory.
        ("in_use marker", ".in_use/29740", False),
        ("finder junk", "skills/.DS_Store", False),
    ]

    def test_is_source(self):
        for desc, rel, expected in self.CASES:
            with self.subTest(desc):
                self.assertEqual(is_source(rel), expected)


class TestDrift(unittest.TestCase):

    A = {"skills/a.py": "h1", "bin/b": "h2"}

    CASES = [
        ("identical trees", A, A, ([], [], [])),
        ("both empty", {}, {}, ([], [], [])),
        ("one file edited", A, {"skills/a.py": "CHANGED", "bin/b": "h2"},
         (["skills/a.py"], [], [])),
        ("new file not yet installed", A,
         {**A, "skills/new.py": "h3"}, ([], ["skills/new.py"], [])),
        # rsync without --delete used to leave these behind: a file deleted in
        # the repo kept running from the install.
        ("file deleted here still installed",
         {**A, "skills/gone.py": "h9"}, A, ([], [], ["skills/gone.py"])),
        ("nothing installed at all", {}, A, ([], sorted(A), [])),
        ("all three kinds at once",
         {"skills/a.py": "h1", "skills/gone.py": "h9"},
         {"skills/a.py": "CHANGED", "skills/new.py": "h3"},
         (["skills/a.py"], ["skills/new.py"], ["skills/gone.py"])),
    ]

    def test_drift(self):
        for desc, installed, working, expected in self.CASES:
            with self.subTest(desc):
                self.assertEqual(drift(installed, working), expected)


class TestScopes(unittest.TestCase):
    """`claude plugin uninstall --scope project` only works from projectPath."""

    CASES = [
        ("empty registry", {}, []),
        ("plugin absent", _reg(None), []),
        ("user scope has no projectPath",
         _reg([{"scope": "user", "installPath": CACHE}]), [("user", "")]),
        # The real registry: installed from $HOME, so a project-scope uninstall
        # run from the repo fails and silently leaves the entry behind.
        ("project scope carries its directory",
         _reg([{"scope": "project", "projectPath": "/Users/igorlopes",
                "installPath": CACHE}]), [("project", "/Users/igorlopes")]),
        ("both scopes",
         _reg([{"scope": "user", "installPath": CACHE},
               {"scope": "project", "projectPath": "/home/x", "installPath": CACHE}]),
         [("user", ""), ("project", "/home/x")]),
        ("duplicate entries collapse",
         _reg([{"scope": "user", "installPath": CACHE},
               {"scope": "user", "installPath": CACHE}]), [("user", "")]),
        # Two projects can install the same plugin; each needs its own uninstall.
        ("same scope, two project paths",
         _reg([{"scope": "project", "projectPath": "/a"},
               {"scope": "project", "projectPath": "/b"}]),
         [("project", "/a"), ("project", "/b")]),
        ("entry without a scope skipped",
         _reg([{"installPath": CACHE}, {"scope": "user"}]), [("user", "")]),
        ("null entry skipped", _reg([None, {"scope": "user"}]), [("user", "")]),
    ]

    def test_scopes(self):
        for desc, registry, expected in self.CASES:
            with self.subTest(desc):
                self.assertEqual(scopes(registry), expected)


class TestSummarize(unittest.TestCase):

    # (description, registered, present, changed, missing, stale, expected)
    CASES = [
        ("nothing registered", [], [], [], [], [], NOT_INSTALLED),
        # Left by an uninstall that could not reach every scope: the registry
        # still claims an install, the directory is gone.
        ("registered but files deleted", [CACHE], [], [], [], [], NOT_INSTALLED),
        ("clean", [CACHE], [CACHE], [], [], [], IN_SYNC),
        ("one modified", [CACHE], [CACHE], ["skills/a.py"], [], [], DRIFTED),
        ("only a missing file", [CACHE], [CACHE], [], ["skills/new.py"], [], DRIFTED),
        ("only a stale file", [CACHE], [CACHE], [], [], ["skills/gone.py"], DRIFTED),
    ]

    def test_state(self):
        for desc, registered, present, changed, missing, stale, expected in self.CASES:
            with self.subTest(desc):
                state, detail = summarize(registered, present, changed, missing, stale)
                self.assertEqual(state, expected)
                self.assertTrue(detail, "every state must explain itself")

    def test_drift_message_names_files_and_the_fix(self):
        _, detail = summarize([CACHE], [CACHE], ["skills/a.py"], [], [])
        self.assertIn("skills/a.py", detail)
        self.assertIn("make install", detail)

    def test_long_lists_are_truncated(self):
        changed = [f"skills/f{i}.py" for i in range(20)]
        _, detail = summarize([CACHE], [CACHE], changed, [], [], limit=3)
        self.assertIn("and 17 more", detail)
        self.assertNotIn("skills/f9.py", detail)

    def test_counts_every_kind(self):
        _, detail = summarize([CACHE], [CACHE], ["a"], ["b"], ["c"])
        self.assertIn("3 file(s) behind", detail)

    def test_not_installed_says_so(self):
        _, detail = summarize([], [], [], [], [])
        self.assertIn("not installed", detail)

    def test_broken_install_is_not_reported_as_drift(self):
        """The bug this distinction exists for: a dangling registry entry used
        to read as "34 file(s) behind", which points at the wrong fix."""
        _, detail = summarize([CACHE], [], [], [], [])
        self.assertIn("files are gone", detail)
        self.assertNotIn("file(s) behind", detail)
        self.assertIn(CACHE, detail)


class TestHashTree(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def test_hashes_shipped_components_only(self):
        self._write("skills/run/orchestrator.py", "code")
        self._write("bin/security-engineer", "#!/bin/sh")
        self._write("commands/run.md", "cmd")
        self._write("devloop/run.sh", "not shipped")
        self._write("README.md", "not shipped")
        keys = set(hash_tree(self.root))
        self.assertEqual(keys, {"skills/run/orchestrator.py",
                                "bin/security-engineer", "commands/run.md"})

    def test_skips_noise(self):
        self._write("skills/a.py", "code")
        self._write("skills/__pycache__/a.cpython-314.pyc", "bytes")
        self._write("skills/run/security-engineer-run.json", "{}")
        self.assertEqual(set(hash_tree(self.root)), {"skills/a.py"})

    def test_content_change_changes_the_digest(self):
        self._write("skills/a.py", "one")
        before = hash_tree(self.root)
        self._write("skills/a.py", "two")
        self.assertNotEqual(before["skills/a.py"], hash_tree(self.root)["skills/a.py"])

    def test_missing_component_is_not_an_error(self):
        self._write("skills/a.py", "code")
        self.assertEqual(set(hash_tree(self.root)), {"skills/a.py"})

    def test_two_trees_with_equal_content_compare_equal(self):
        other = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(other))
        for root in (self.root, other):
            (root / "skills").mkdir(parents=True, exist_ok=True)
            (root / "skills" / "a.py").write_text("code")
        self.assertEqual(drift(hash_tree(other), hash_tree(self.root)), ([], [], []))


class TestReadRegistry(unittest.TestCase):

    def test_missing_file_is_empty(self):
        self.assertEqual(read_registry("/nonexistent/installed_plugins.json"), {})

    def test_malformed_json_is_empty(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write("{not json")
            path = fh.name
        self.assertEqual(read_registry(path), {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
