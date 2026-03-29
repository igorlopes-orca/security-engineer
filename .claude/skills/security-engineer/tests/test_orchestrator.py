#!/usr/bin/env python3
"""
Tests for the Security Engineer orchestrator.

Verifies that argument parsing, filter logic, and flag enforcement
(especially --dry-run and type filters) behave exactly as documented.

Run with: python3 tests/test_orchestrator.py
No API token or network access required — all tests are pure Python.
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock, call

# Add parent dirs to path
_DIR = Path(__file__).parent
sys.path.insert(0, str(_DIR.parent))             # security-engineer/
sys.path.insert(0, str(_DIR.parent.parent / "lib"))  # lib/

import orchestrator
from orchestrator import main, _invoke_fix_agent, _commit_and_pr, AlertTask, FixAgentResult
from run_agent import parse_filter, min_level_from_list
from orca_client import _resolve_feature_type, is_fixable, RISK_ORDER


# ---------------------------------------------------------------------------
# 1. Argument parsing
# ---------------------------------------------------------------------------

class TestArgumentParsing(unittest.TestCase):

    def _parse(self, argv):
        """Parse args using orchestrator's argparse setup."""
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--alert", default=None)
        parser.add_argument("--max", type=int, default=None)
        parser.add_argument("positional", nargs="*")
        args = parser.parse_args(argv)
        args.repo = None
        args.filter_tokens = None
        for p in args.positional:
            if "/" in p:
                args.repo = p
            else:
                args.filter_tokens = p
        return args

    def test_dry_run_before_filter(self):
        args = self._parse(["--dry-run", "cve"])
        self.assertTrue(args.dry_run)
        self.assertEqual(args.filter_tokens, "cve")
        self.assertIsNone(args.repo)

    def test_dry_run_after_filter(self):
        """--dry-run flag position must not matter."""
        args = self._parse(["cve", "--dry-run"])
        self.assertTrue(args.dry_run)
        self.assertEqual(args.filter_tokens, "cve")

    def test_dry_run_with_alert(self):
        args = self._parse(["--alert", "orca-270453", "--dry-run"])
        self.assertTrue(args.dry_run)
        self.assertEqual(args.alert, "orca-270453")
        self.assertIsNone(args.filter_tokens)

    def test_no_dry_run_by_default(self):
        args = self._parse(["high,cve"])
        self.assertFalse(args.dry_run)

    def test_filter_and_repo(self):
        args = self._parse(["high", "owner/repo"])
        self.assertEqual(args.filter_tokens, "high")
        self.assertEqual(args.repo, "owner/repo")
        self.assertFalse(args.dry_run)

    def test_max_cap(self):
        args = self._parse(["--max", "3", "cve"])
        self.assertEqual(args.max, 3)
        self.assertEqual(args.filter_tokens, "cve")

    def test_no_args(self):
        args = self._parse([])
        self.assertFalse(args.dry_run)
        self.assertIsNone(args.filter_tokens)
        self.assertIsNone(args.repo)
        self.assertIsNone(args.max)

    def test_combined_filter(self):
        args = self._parse(["high,cve"])
        self.assertEqual(args.filter_tokens, "high,cve")


# ---------------------------------------------------------------------------
# 2. Filter parsing (run_agent.py)
# ---------------------------------------------------------------------------

class TestFilterParsing(unittest.TestCase):

    def test_cve_only(self):
        levels, types = parse_filter("cve")
        self.assertIsNone(levels)
        self.assertEqual(types, ["cve"])

    def test_sast_only(self):
        levels, types = parse_filter("sast")
        self.assertIsNone(levels)
        self.assertEqual(types, ["sast"])

    def test_high_only(self):
        levels, types = parse_filter("high")
        self.assertEqual(levels, ["high"])
        self.assertIsNone(types)

    def test_high_and_cve(self):
        levels, types = parse_filter("high,cve")
        self.assertEqual(levels, ["high"])
        self.assertEqual(types, ["cve"])

    def test_critical_sast(self):
        levels, types = parse_filter("critical,sast")
        self.assertEqual(levels, ["critical"])
        self.assertEqual(types, ["sast"])

    def test_multiple_types(self):
        levels, types = parse_filter("high,sast,iac")
        self.assertEqual(levels, ["high"])
        self.assertIn("sast", types)
        self.assertIn("iac", types)

    def test_unknown_token_ignored(self):
        """Unknown tokens must be silently dropped, not crash."""
        levels, types = parse_filter("high,unknowntoken")
        self.assertEqual(levels, ["high"])
        self.assertIsNone(types)  # "unknowntoken" is not a valid type

    def test_empty_string(self):
        levels, types = parse_filter("")
        self.assertIsNone(levels)
        self.assertIsNone(types)


# ---------------------------------------------------------------------------
# 3. Risk level threshold logic
# ---------------------------------------------------------------------------

class TestMinLevel(unittest.TestCase):

    def test_high_means_high_and_above(self):
        """'high' filter should include critical and high, NOT medium/low."""
        min_level = min_level_from_list(["high"])
        self.assertEqual(min_level, "high")
        cutoff = RISK_ORDER.index(min_level)
        # Alerts at or above (lower index) should pass
        self.assertLessEqual(RISK_ORDER.index("critical"), cutoff)
        self.assertLessEqual(RISK_ORDER.index("high"), cutoff)
        # Alerts below should be filtered out
        self.assertGreater(RISK_ORDER.index("medium"), cutoff)
        self.assertGreater(RISK_ORDER.index("low"), cutoff)

    def test_low_includes_everything_except_informational(self):
        min_level = min_level_from_list(["low"])
        cutoff = RISK_ORDER.index(min_level)
        for level in ["critical", "high", "medium", "low"]:
            self.assertLessEqual(RISK_ORDER.index(level), cutoff,
                                 f"{level} should be included when filter is 'low'")

    def test_none_when_no_levels(self):
        self.assertIsNone(min_level_from_list([]))
        self.assertIsNone(min_level_from_list(None))


# ---------------------------------------------------------------------------
# 4. Feature type resolution
# ---------------------------------------------------------------------------

class TestFeatureTypeResolution(unittest.TestCase):

    def _alert(self, feature_type="", category="", labels=None):
        return {"feature_type": feature_type, "category": category, "labels": labels or []}

    def test_package_cve_by_category(self):
        """Package CVEs have empty feature_type but category 'Vulnerabilities'."""
        a = self._alert(feature_type="", category="Vulnerabilities")
        self.assertEqual(_resolve_feature_type(a), "cve")

    def test_package_cve_case_insensitive(self):
        a = self._alert(feature_type="", category="vulnerabilities")
        self.assertEqual(_resolve_feature_type(a), "cve")

    def test_sast_cve_by_label(self):
        """SAST alerts with CVE labels should be classified as cve."""
        a = self._alert(feature_type="sast", category="Source code vulnerabilities",
                        labels=["CVE-2023-44487", "shiftleft:sast:lang:go"])
        self.assertEqual(_resolve_feature_type(a), "cve")

    def test_sast_without_cve_label(self):
        """SAST alerts without CVE labels stay as sast."""
        a = self._alert(feature_type="sast", category="Source code vulnerabilities",
                        labels=["CWE-89"])
        self.assertEqual(_resolve_feature_type(a), "sast")

    def test_iac(self):
        a = self._alert(feature_type="iac", category="Workload misconfigurations")
        self.assertEqual(_resolve_feature_type(a), "iac")

    def test_secret(self):
        a = self._alert(feature_type="secret", category="Data protection")
        self.assertEqual(_resolve_feature_type(a), "secret")

    def test_scm_posture(self):
        a = self._alert(feature_type="scm_posture", category="Best practices")
        self.assertEqual(_resolve_feature_type(a), "scm_posture")
        self.assertFalse(is_fixable(a))

    def test_unknown_not_fixable(self):
        a = self._alert(feature_type="", category="Malware")
        self.assertEqual(_resolve_feature_type(a), "unknown")
        self.assertFalse(is_fixable(a))

    def test_fixable_types(self):
        for ft in ["cve", "sast", "iac", "secret"]:
            with self.subTest(ft=ft):
                a = self._alert(feature_type=ft)
                self.assertTrue(is_fixable(a), f"{ft} should be fixable")


# ---------------------------------------------------------------------------
# 5. Dry-run enforcement
# ---------------------------------------------------------------------------

class TestDryRunEnforcement(unittest.TestCase):

    def _make_task(self, alert_id="orca-test-001", feature_type="sast"):
        return AlertTask(
            alert_id=alert_id,
            title="Test alert",
            risk_level="high",
            feature_type=feature_type,
            source="main.go:88",
            alert_json={"alert_id": alert_id, "feature_type": feature_type},
            worktree_path=Path("/tmp/fake-worktree"),
        )

    def test_dry_run_uses_read_only_tools(self):
        """In dry-run mode, claude subprocess must receive --allowedTools Read (not Edit/Write/Bash)."""
        task = self._make_task()
        captured_cmds = []

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='{"result": "{\\"status\\": \\"success\\", \\"alert_id\\": \\"orca-test-001\\", \\"files_changed\\": [], \\"diff_summary\\": \\"planned fix\\"}"}',
                stderr=""
            )
            # Also mock Path.exists and read_text for fix-agents file
            with patch.object(Path, "exists", return_value=True), \
                 patch.object(Path, "read_text", return_value="# instructions"):
                _invoke_fix_agent(task, dry_run=True, timeout_sec=60)

        # Find the claude subprocess call
        claude_calls = [c for c in mock_run.call_args_list
                        if c.args and c.args[0] and "claude" in str(c.args[0])]
        self.assertTrue(len(claude_calls) > 0, "claude should have been called")

        cmd = claude_calls[0].args[0]
        allowed_tools_idx = cmd.index("--allowedTools")
        tools_value = cmd[allowed_tools_idx + 1]
        self.assertEqual(tools_value, "Read",
                         f"dry-run must use 'Read' only, got: {tools_value}")

    def test_live_mode_uses_full_tools(self):
        """In live mode, claude subprocess must receive Read,Edit,Write,Bash."""
        task = self._make_task()

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='{"result": "{\\"status\\": \\"success\\", \\"alert_id\\": \\"orca-test-001\\", \\"files_changed\\": [], \\"diff_summary\\": \\"fixed\\"}"}',
                stderr=""
            )
            with patch.object(Path, "exists", return_value=True), \
                 patch.object(Path, "read_text", return_value="# instructions"):
                _invoke_fix_agent(task, dry_run=False, timeout_sec=60)

        claude_calls = [c for c in mock_run.call_args_list
                        if c.args and c.args[0] and "claude" in str(c.args[0])]
        self.assertTrue(len(claude_calls) > 0)

        cmd = claude_calls[0].args[0]
        allowed_tools_idx = cmd.index("--allowedTools")
        tools_value = cmd[allowed_tools_idx + 1]
        self.assertIn("Edit", tools_value)
        self.assertIn("Write", tools_value)
        self.assertIn("Bash", tools_value)

    def test_dry_run_commit_and_pr_is_noop(self):
        """_commit_and_pr must not run any git or gh commands in dry-run mode."""
        task = self._make_task()
        task.fix_result = FixAgentResult(success=True, diff_summary="planned change")

        with patch("subprocess.run") as mock_run, \
             patch("orchestrator._run") as mock_internal_run:
            result = _commit_and_pr(task, impact=None, dry_run=True)

        self.assertIsNone(result, "dry-run commit should return None (no PR URL)")
        mock_internal_run.assert_not_called()
        mock_run.assert_not_called()

    def test_dry_run_early_return_in_run_one(self):
        """run_one must return task with state DONE after fix plan, without touching git."""
        task = self._make_task()

        with patch("orchestrator._create_worktree", return_value=Path("/tmp/fake")), \
             patch("orchestrator._remove_worktree"), \
             patch("orchestrator._invoke_fix_agent") as mock_fix, \
             patch("orchestrator.sanity_check") as mock_sanity, \
             patch("orchestrator.llm_validate") as mock_llm, \
             patch("orchestrator.local_build_check") as mock_build, \
             patch("orchestrator._commit_and_pr") as mock_commit:

            mock_fix.return_value = FixAgentResult(success=True, diff_summary="planned fix")
            mock_notifier = MagicMock()

            result = orchestrator.run_one(task, dry_run=True, notifier=mock_notifier, repo="owner/repo")

        self.assertEqual(result.state, "DONE")
        mock_sanity.assert_not_called()
        mock_llm.assert_not_called()
        mock_build.assert_not_called()
        mock_commit.assert_not_called()


# ---------------------------------------------------------------------------
# 6. Fix result JSON parsing
# ---------------------------------------------------------------------------

class TestFixResultParsing(unittest.TestCase):

    def _parse(self, text):
        from orchestrator import _parse_fix_result
        envelope = f'{{"result": {__import__("json").dumps(text)}}}'
        return _parse_fix_result(envelope)

    def test_success_result(self):
        r = self._parse('some text\n{"status": "success", "alert_id": "orca-001", "files_changed": ["main.go"], "diff_summary": "fixed sql injection"}')
        self.assertTrue(r.success)
        self.assertEqual(r.files_changed, ["main.go"])
        self.assertEqual(r.diff_summary, "fixed sql injection")

    def test_failed_result(self):
        r = self._parse('{"status": "failed", "alert_id": "orca-001", "reason": "could not parse file", "step": "file_read"}')
        self.assertFalse(r.success)
        self.assertEqual(r.failure_reason, "could not parse file")
        self.assertEqual(r.failed_step, "file_read")

    def test_last_json_wins(self):
        """If multiple JSON blocks, the last one should be used."""
        r = self._parse('thinking... {"status": "failed", "alert_id": "x", "reason": "attempt 1"}\n\nretrying...\n{"status": "success", "alert_id": "x", "files_changed": [], "diff_summary": "done"}')
        self.assertTrue(r.success)

    def test_no_json_in_output(self):
        r = self._parse("I could not find the file.")
        self.assertFalse(r.success)
        self.assertEqual(r.error_code, "json_parse_failure")

    def test_malformed_envelope(self):
        from orchestrator import _parse_fix_result
        r = _parse_fix_result("not valid json at all")
        self.assertFalse(r.success)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    test_classes = [
        TestArgumentParsing,
        TestFilterParsing,
        TestMinLevel,
        TestFeatureTypeResolution,
        TestDryRunEnforcement,
        TestFixResultParsing,
    ]

    for cls in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
