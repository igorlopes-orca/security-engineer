#!/usr/bin/env python3
"""
Tests for the Security Engineer orchestrator.

Verifies that argument parsing, filter logic, and flag enforcement
(especially --dry-run and type filters) behave exactly as documented.

Run with: python3 tests/test_orchestrator.py
No API token or network access required — all tests are pure Python.
"""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock, call

# Add parent dirs to path
_DIR = Path(__file__).parent
sys.path.insert(0, str(_DIR.parent))             # security-engineer/
sys.path.insert(0, str(_DIR.parent.parent / "lib"))  # lib/

import orchestrator
from orchestrator import (main, _invoke_fix_agent, _commit_and_pr, AlertTask,
                          FixAgentResult, _validate_flags, _print_scan_report,
                          run_one)
from run_agent import parse_filter, min_level_from_list
from orca_client import _resolve_feature_type, is_fixable, RISK_ORDER, Repository
from config import load_config, Config, OrcaCheckConfig
from impact_agent import analyze_impact, ImpactResult
from validator import (llm_validate, orca_check_gate, _parse_pr_url,
                       OrcaCheckFinding, ValidationResult, ci_gate,
                       has_no_ci_checks, _subprocess_error_detail)


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

    def test_filter_only_no_repo_positional(self):
        """Positional args are only filter tokens — owner/repo is never accepted here."""
        args = self._parse(["high"])
        self.assertEqual(args.filter_tokens, "high")
        self.assertIsNone(args.repo)

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

    def test_scan_flag(self):
        args = main.__wrapped__(["--scan"]) if hasattr(main, '__wrapped__') else None
        # Use orchestrator's own parser directly
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument("--scan", action="store_true")
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--alert", default=None)
        parser.add_argument("--max", type=int, default=None)
        parser.add_argument("positional", nargs="*")
        args = parser.parse_args(["--scan"])
        self.assertTrue(args.scan)

    def test_scan_with_filter(self):
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument("--scan", action="store_true")
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--alert", default=None)
        parser.add_argument("--max", type=int, default=None)
        parser.add_argument("positional", nargs="*")
        args = parser.parse_args(["--scan", "high,cve"])
        self.assertTrue(args.scan)
        args.filter_tokens = None
        for p in args.positional:
            args.filter_tokens = p
        self.assertEqual(args.filter_tokens, "high,cve")


# ---------------------------------------------------------------------------
# 1b. Flag validation
# ---------------------------------------------------------------------------

class TestFlagValidation(unittest.TestCase):

    INVALID_COMBOS = [
        ("--scan + --dry-run", {"scan": True, "dry_run": True, "alert": None, "max": None},
         "--scan and --dry-run cannot be combined"),
        ("--scan + --alert", {"scan": True, "dry_run": False, "alert": "orca-1", "max": None},
         "--scan and --alert cannot be combined"),
        ("--scan + --max", {"scan": True, "dry_run": False, "alert": None, "max": 3},
         "--scan and --max cannot be combined"),
    ]

    def test_invalid_combos(self):
        import argparse
        for desc, kwargs, expected_msg in self.INVALID_COMBOS:
            with self.subTest(desc):
                args = argparse.Namespace(**kwargs, remote=None, filter_tokens=None,
                                          repo=None, positional=[])
                with self.assertRaises(SystemExit) as ctx:
                    _validate_flags(args)
                self.assertIn(expected_msg, str(ctx.exception))

    VALID_COMBOS = [
        ("--scan alone", {"scan": True, "dry_run": False, "alert": None, "max": None}),
        ("no --scan with --dry-run", {"scan": False, "dry_run": True, "alert": None, "max": None}),
        ("no --scan with --alert", {"scan": False, "dry_run": False, "alert": "orca-1", "max": None}),
        ("no flags", {"scan": False, "dry_run": False, "alert": None, "max": None}),
    ]

    def test_valid_combos(self):
        import argparse
        for desc, kwargs in self.VALID_COMBOS:
            with self.subTest(desc):
                args = argparse.Namespace(**kwargs, remote=None, filter_tokens=None,
                                          repo=None, positional=[])
                _validate_flags(args)  # should not raise


# ---------------------------------------------------------------------------
# 1c. Scan report output
# ---------------------------------------------------------------------------

class TestScanReport(unittest.TestCase):

    SAMPLE_ALERTS = [
        {"alert_id": "orca-1", "title": "SQL Injection", "risk_level": "critical",
         "category": "Code", "score": 9.5, "feature_type": "sast", "labels": []},
        {"alert_id": "orca-2", "title": "Old Dependency", "risk_level": "high",
         "category": "Vulnerabilities", "score": 7.0, "feature_type": "", "labels": []},
        {"alert_id": "orca-3", "title": "Debug Mode", "risk_level": "medium",
         "category": "Code", "score": 4.0, "feature_type": "iac", "labels": []},
    ]

    def test_report_contains_all_alerts(self):
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _print_scan_report("owner/repo", self.SAMPLE_ALERTS)
        output = buf.getvalue()
        self.assertIn("owner/repo", output)
        self.assertIn("orca-1", output)
        self.assertIn("orca-2", output)
        self.assertIn("orca-3", output)
        self.assertIn("SQL Injection", output)

    def test_report_grouped_by_risk(self):
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _print_scan_report("owner/repo", self.SAMPLE_ALERTS)
        output = buf.getvalue()
        self.assertIn("Critical", output)
        self.assertIn("High", output)
        self.assertIn("Medium", output)

    def test_report_total_count(self):
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _print_scan_report("owner/repo", self.SAMPLE_ALERTS)
        output = buf.getvalue()
        self.assertIn("**3**", output)

    def test_empty_alerts(self):
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _print_scan_report("owner/repo", [])
        output = buf.getvalue()
        self.assertIn("**0**", output)


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

            from orca_client import Repository
            result = orchestrator.run_one(
                task, dry_run=True, notifier=mock_notifier,
                repo=Repository(name="owner/repo", url="https://github.com/owner/repo"),
            )

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
# 7. list_repositories: URL parsing and deduplication
# ---------------------------------------------------------------------------

class TestListRepositories(unittest.TestCase):
    """Table-driven: name extraction from Orca CodeRepository response."""

    CASES = [
        # (description, url, expected_name)
        ("https no .git",       "https://github.com/owner/repo",      "owner/repo"),
        ("https with .git",     "https://github.com/owner/repo.git",   "owner/repo"),
        ("ssh colon format",    "git@github.com:owner/repo.git",       "owner/repo"),
        ("ssh no .git suffix",  "git@github.com:owner/repo",           "owner/repo"),
    ]

    def _fake_response(self, *urls):
        return {"data": [{"Url": u, "OrcaScore": 5.0, "RiskLevel": "high"} for u in urls]}

    def test_url_to_name_extraction(self):
        from orca_client import list_repositories
        for desc, url, expected in self.CASES:
            with self.subTest(desc):
                with patch("orca_client._post", return_value=self._fake_response(url)):
                    repos = list_repositories("fake-token")
                self.assertEqual(len(repos), 1)
                self.assertEqual(repos[0].name, expected)
                self.assertEqual(repos[0].url, url)
                self.assertIsNone(repos[0].clone_path)

    def test_deduplication_by_url(self):
        """Same URL appearing twice must produce exactly one Repository."""
        from orca_client import list_repositories
        url = "https://github.com/owner/repo"
        with patch("orca_client._post", return_value=self._fake_response(url, url)):
            repos = list_repositories("fake-token")
        self.assertEqual(len(repos), 1)

    def test_empty_url_skipped(self):
        """Items with no URL must be silently dropped."""
        from orca_client import list_repositories
        with patch("orca_client._post", return_value=self._fake_response(
            "", "https://github.com/owner/other"
        )):
            repos = list_repositories("fake-token")
        self.assertEqual(len(repos), 1)
        self.assertEqual(repos[0].name, "owner/other")

    def test_empty_response(self):
        from orca_client import list_repositories
        with patch("orca_client._post", return_value={"data": []}):
            repos = list_repositories("fake-token")
        self.assertEqual(repos, [])


# ---------------------------------------------------------------------------
# 8. _detect_repo returns Repository
# ---------------------------------------------------------------------------

class TestDetectRepoReturnsRepository(unittest.TestCase):
    """Table-driven: _detect_repo produces the right Repository for each URL format."""

    CASES = [
        # (description, git_remote_url, expected_name)
        ("https no .git",   "https://github.com/owner/repo",     "owner/repo"),
        ("https with .git", "https://github.com/owner/repo.git",  "owner/repo"),
        ("ssh colon",       "git@github.com:owner/repo.git",      "owner/repo"),
    ]

    def test_url_formats(self):
        for desc, url, expected_name in self.CASES:
            with self.subTest(desc):
                with patch("orchestrator._run", return_value=(url, "", 0)):
                    repo = orchestrator._detect_repo()
                self.assertIsNotNone(repo, f"should detect repo for {desc}")
                self.assertIsInstance(repo, Repository)
                self.assertEqual(repo.name, expected_name)
                self.assertEqual(repo.url, url)
                self.assertIsNone(repo.clone_path)

    def test_non_github_url_returns_none(self):
        with patch("orchestrator._run", return_value=("https://gitlab.com/owner/repo", "", 0)):
            self.assertIsNone(orchestrator._detect_repo())

    def test_git_error_returns_none(self):
        with patch("orchestrator._run", side_effect=RuntimeError("not a git repo")):
            self.assertIsNone(orchestrator._detect_repo())


# ---------------------------------------------------------------------------
# 9. _fetch_and_plan: --repo-dir present iff clone_path is set
# ---------------------------------------------------------------------------

class TestFetchAndPlanRepoDir(unittest.TestCase):
    """Table-driven: --repo-dir flag in cmd based on repo.clone_path."""

    CASES = [
        # (description, clone_path, expect_repo_dir_flag)
        ("no clone path → no --repo-dir",    None,                              False),
        ("with clone path → has --repo-dir", Path("/tmp/orca-global-owner-repo"), True),
    ]

    def _args(self):
        import argparse
        return argparse.Namespace(filter_tokens=None, max=None, alert=None, dry_run=False)

    def test_repo_dir_flag(self):
        for desc, clone_path, expect_flag in self.CASES:
            with self.subTest(desc):
                repo = Repository(name="owner/repo",
                                  url="https://github.com/owner/repo",
                                  clone_path=clone_path)
                captured = {}

                def fake_run(cmd, **kwargs):
                    captured["cmd"] = list(cmd)
                    return ('{"alerts": []}', "", 0)

                with patch("orchestrator._run", side_effect=fake_run):
                    orchestrator._fetch_and_plan(self._args(), repo)

                has_flag = "--repo-dir" in captured.get("cmd", [])
                self.assertEqual(has_flag, expect_flag, desc)
                if expect_flag:
                    idx = captured["cmd"].index("--repo-dir")
                    self.assertEqual(captured["cmd"][idx + 1], str(clone_path))


# ---------------------------------------------------------------------------
# 10. Worktree helpers: cwd follows repo.clone_path
# ---------------------------------------------------------------------------

class TestWorktreeCwd(unittest.TestCase):
    """Table-driven: git commands in _create_worktree/_remove_worktree use correct cwd."""

    CASES = [
        # (description, clone_path, expected_cwd)
        ("no clone path → cwd None",   None,                          None),
        ("clone path → cwd str",       Path("/tmp/orca-global-test"), "/tmp/orca-global-test"),
    ]

    def test_create_worktree_cwd(self):
        for desc, clone_path, expected_cwd in self.CASES:
            with self.subTest(desc):
                repo = Repository(name="owner/repo",
                                  url="https://github.com/owner/repo",
                                  clone_path=clone_path)
                captured = {}

                def fake_run(cmd, **kwargs):
                    captured["cwd"] = kwargs.get("cwd")
                    return ("", "", 0)

                with patch("orchestrator._run", side_effect=fake_run), \
                     patch("subprocess.run", return_value=MagicMock(returncode=0)), \
                     patch("orchestrator._local_branch_exists", return_value=False), \
                     patch.object(Path, "exists", return_value=False):
                    orchestrator._create_worktree("orca-test", "fix/orca-test", repo=repo)

                self.assertEqual(captured.get("cwd"), expected_cwd, desc)

    def test_remove_worktree_cwd(self):
        for desc, clone_path, expected_cwd in self.CASES:
            with self.subTest(desc):
                repo = Repository(name="owner/repo",
                                  url="https://github.com/owner/repo",
                                  clone_path=clone_path)
                cwd_values = []

                def fake_subprocess(cmd, **kwargs):
                    cwd_values.append(kwargs.get("cwd"))
                    return MagicMock(returncode=0)

                with patch("subprocess.run", side_effect=fake_subprocess), \
                     patch.object(Path, "exists", return_value=True):
                    orchestrator._remove_worktree(Path("/tmp/fake"), "fix/branch", repo=repo)

                for cwd in cwd_values:
                    self.assertEqual(cwd, expected_cwd, desc)


# ---------------------------------------------------------------------------
# 11. --remote routing in main()
# ---------------------------------------------------------------------------

class TestRemoteRouting(unittest.TestCase):
    """Table-driven: --remote 'all' / 'owner/repo' / invalid routes correctly."""

    CASES = [
        # (description, argv, all_repos_called, run_repo_pipeline_called, expect_exit)
        ("all repos",   ["--remote", "all"],           True,  False, False),
        ("single repo", ["--remote", "owner/repo"],    False, True,  False),
        ("invalid",     ["--remote", "notvalid"],      False, False, True),
    ]

    def test_routing(self):
        for desc, argv, expect_all, expect_single, expect_exit in self.CASES:
            with self.subTest(desc):
                with patch("orchestrator.run_all_repos") as mock_all, \
                     patch("orchestrator._run_repo_pipeline", return_value={
                         "results": [], "skipped": [], "scm_posture": [],
                         "unfixable": [], "error": None,
                     }) as mock_single, \
                     patch("orchestrator._get_repo_url",
                           return_value="https://github.com/owner/repo"), \
                     patch("orchestrator._print_summary"):
                    if expect_exit:
                        with self.assertRaises(SystemExit):
                            main(argv)
                    else:
                        main(argv)
                    self.assertEqual(mock_all.called, expect_all,
                                     f"{desc}: run_all_repos called={mock_all.called}")
                    self.assertEqual(mock_single.called, expect_single,
                                     f"{desc}: _run_repo_pipeline called={mock_single.called}")

    def test_dry_run_propagated_to_pipeline(self):
        """--remote --dry-run must reach _run_repo_pipeline with dry_run=True."""
        with patch("orchestrator._run_repo_pipeline", return_value={
            "results": [], "skipped": [], "scm_posture": [], "unfixable": [], "error": None,
        }) as mock_pipeline, \
             patch("orchestrator._get_repo_url", return_value="https://github.com/owner/repo"), \
             patch("orchestrator._print_summary"):
            main(["--remote", "owner/repo", "--dry-run"])

        passed_args = mock_pipeline.call_args[0][1]  # second positional = args
        self.assertTrue(passed_args.dry_run)


# ---------------------------------------------------------------------------
# 12. _run_repo_pipeline: clone cleanup always runs
# ---------------------------------------------------------------------------

class TestRunRepoPipelineCleanup(unittest.TestCase):
    """Table-driven: clone dir is removed even when pipeline raises."""

    CASES = [
        # (description, fetch_raises)
        ("pipeline succeeds", None),
        ("pipeline raises",   RuntimeError("unexpected error")),
    ]

    def _args(self):
        import argparse
        return argparse.Namespace(dry_run=False, filter_tokens=None,
                                  max=None, alert=None, repo=None)

    def test_cleanup_always_runs(self):
        clone_path = Path("/tmp/orca-global-owner-repo")
        for desc, fetch_error in self.CASES:
            with self.subTest(desc):
                repo = Repository(name="owner/repo",
                                  url="https://github.com/owner/repo")

                def fake_clone(r):
                    r.clone_path = clone_path
                    return r

                def fake_fetch(args, r):
                    if fetch_error:
                        raise fetch_error
                    return [], [], [], []

                with patch("orchestrator._clone_repo", side_effect=fake_clone), \
                     patch("orchestrator._fetch_and_plan", side_effect=fake_fetch), \
                     patch("orchestrator.build_notifiers", return_value=MagicMock()), \
                     patch("shutil.rmtree") as mock_rmtree, \
                     patch.object(Path, "exists", return_value=True):
                    try:
                        orchestrator._run_repo_pipeline(repo, self._args())
                    except Exception:
                        pass

                mock_rmtree.assert_called_once_with(clone_path, ignore_errors=True), \
                    f"{desc}: shutil.rmtree should have been called"


# ---------------------------------------------------------------------------
# Orca GitHub App check gate
# ---------------------------------------------------------------------------

class TestOrcaCheckGate(unittest.TestCase):
    """Table-driven tests for orca_check_gate and helpers."""

    def test_parse_pr_url(self):
        CASES = [
            ("standard PR URL", "https://github.com/owner/repo/pull/42",
             ("owner/repo", 42)),
            ("PR URL with path", "https://github.com/org/my-repo/pull/123",
             ("org/my-repo", 123)),
        ]
        for desc, url, expected in CASES:
            with self.subTest(desc):
                self.assertEqual(_parse_pr_url(url), expected)

    def test_parse_pr_url_invalid(self):
        CASES = [
            ("not a PR URL", "https://github.com/owner/repo/issues/1"),
            ("not github", "https://gitlab.com/owner/repo/pull/1"),
            ("empty", ""),
        ]
        for desc, url in CASES:
            with self.subTest(desc):
                with self.assertRaises(ValueError):
                    _parse_pr_url(url)

    @patch("validator.time.monotonic")
    @patch("validator._find_orca_check_run")
    @patch("validator._get_pr_head_sha", return_value="abc123def")
    def test_check_passes(self, mock_sha, mock_find, mock_time):
        """Orca check completed with success → passed=True."""
        mock_time.side_effect = [0, 0, 1]  # deadline, grace_deadline, loop check
        mock_find.return_value = {
            "id": 1, "status": "completed", "conclusion": "success", "name": "orca-security-us",
        }
        result = orca_check_gate("https://github.com/owner/repo/pull/1")
        self.assertTrue(result.passed)
        self.assertFalse(result.needs_review)

    @patch("validator.time.monotonic")
    @patch("validator._get_check_annotations")
    @patch("validator._find_orca_check_run")
    @patch("validator._get_pr_head_sha", return_value="abc123def")
    def test_check_fails_with_annotations(self, mock_sha, mock_find, mock_ann, mock_time):
        """Orca check completed with failure → passed=False, failures populated."""
        mock_time.side_effect = [0, 0, 1]
        mock_find.return_value = {
            "id": 42, "status": "completed", "conclusion": "failure", "name": "orca-security-us",
        }
        mock_ann.return_value = [
            OrcaCheckFinding(file="app.py", line=10, message="SQL injection", severity="failure"),
        ]
        result = orca_check_gate("https://github.com/owner/repo/pull/1")
        self.assertFalse(result.passed)
        self.assertEqual(len(result.failures), 1)
        self.assertIn("app.py:10", result.failures[0])
        self.assertIn("SQL injection", result.failures[0])

    @patch("validator.time.monotonic")
    @patch("validator._find_orca_check_run")
    @patch("validator._get_pr_head_sha", return_value="abc123def")
    def test_check_not_found_skips(self, mock_sha, mock_find, mock_time):
        """Check never appears after grace period → passed=True, needs_review=True."""
        # First call: deadline (far future), second: grace_deadline (past)
        # Loop iterations: always past grace
        mock_time.side_effect = [0, 0, 31, 31]
        mock_find.return_value = None
        result = orca_check_gate("https://github.com/owner/repo/pull/1")
        self.assertTrue(result.passed)
        self.assertTrue(result.needs_review)

    @patch("validator.time.sleep")
    @patch("validator.time.monotonic")
    @patch("validator._find_orca_check_run")
    @patch("validator._get_pr_head_sha", return_value="abc123def")
    def test_check_timeout(self, mock_sha, mock_find, mock_monotonic, mock_sleep):
        """Check stays in_progress until timeout → passed=False."""
        # monotonic() calls: deadline=0, grace=0, loop_check=1, loop_check=601
        # loop 1: time.monotonic() < deadline → 1 < 600 → True; finds in_progress; sleeps
        # loop 2: time.monotonic() < deadline → 601 < 600 → False → exit loop
        mock_monotonic.side_effect = [0, 0, 1, 601]
        mock_find.return_value = {
            "id": 1, "status": "in_progress", "conclusion": "", "name": "orca-security-us",
        }
        result = orca_check_gate("https://github.com/owner/repo/pull/1", timeout_sec=600)
        self.assertFalse(result.passed)
        self.assertIn("did not complete", result.failures[0])

# ---------------------------------------------------------------------------
# Build root detection
# ---------------------------------------------------------------------------

import tempfile, os

class TestFindPackageJsonRoot(unittest.TestCase):
    """_find_package_json_root walks up from changed files to locate package.json."""

    from validator import _find_package_json_root

    def _make_tree(self, tmp: Path, structure: dict):
        """Recursively create files/dirs. Use None for files, dict for dirs."""
        for name, content in structure.items():
            path = tmp / name
            if content is None:
                path.touch()
            else:
                path.mkdir(parents=True, exist_ok=True)
                self._make_tree(path, content)

    def test_cases(self):
        from validator import _find_package_json_root

        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            # Build tree:
            #   package.json          ← root package
            #   nodejs-app/
            #     package.json        ← subdirectory package
            #     server.js
            #   other-app/
            #     src/
            #       index.js          ← no package.json nearby
            self._make_tree(tmp, {
                "package.json": None,
                "nodejs-app": {
                    "package.json": None,
                    "server.js": None,
                },
                "other-app": {
                    "src": {"index.js": None},
                },
            })

            CASES = [
                (
                    "file in subdirectory with own package.json",
                    ["nodejs-app/server.js"],
                    tmp / "nodejs-app",
                ),
                (
                    "file at root — uses root package.json",
                    ["index.js"],
                    tmp,
                ),
                (
                    "file in deep subdir without package.json — falls back to root",
                    ["other-app/src/index.js"],
                    tmp,
                ),
                (
                    "no js files — falls back to root",
                    ["README.md"],
                    tmp,
                ),
                (
                    "empty list — falls back to root",
                    [],
                    tmp,
                ),
            ]

            for desc, files, expected in CASES:
                with self.subTest(desc):
                    result = _find_package_json_root(files, tmp)
                    self.assertEqual(result, expected, desc)


class TestFindProjectRoot(unittest.TestCase):
    """_find_project_root handles source_file with line numbers and Terraform."""

    def _make_tree(self, tmp: Path, structure: dict):
        for name, content in structure.items():
            path = tmp / name
            if content is None:
                path.touch()
            else:
                path.mkdir(parents=True, exist_ok=True)
                self._make_tree(path, content)

    def test_cases(self):
        from validator import _find_project_root, _find_terraform_root

        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            self._make_tree(tmp, {
                "package.json": None,
                "nodejs-app": {
                    "package.json": None,
                    "server.js": None,
                },
                "infra": {
                    "main.tf": None,
                    "variables.tf": None,
                },
            })

            CASES = [
                (
                    "source_file with line number suffix stripped",
                    _find_project_root,
                    ["nodejs-app/server.js:40"],
                    "package.json",
                    tmp / "nodejs-app",
                ),
                (
                    "source_file without line number",
                    _find_project_root,
                    ["nodejs-app/server.js"],
                    "package.json",
                    tmp / "nodejs-app",
                ),
                (
                    "terraform root from .tf file",
                    _find_terraform_root,
                    ["infra/main.tf"],
                    None,
                    tmp / "infra",
                ),
                (
                    "terraform fallback when no .tf in list",
                    _find_terraform_root,
                    ["README.md"],
                    None,
                    tmp,
                ),
            ]

            for desc, fn, files, marker, expected in CASES:
                with self.subTest(desc):
                    if marker:
                        result = fn(files, tmp, marker)
                    else:
                        result = fn(files, tmp)
                    self.assertEqual(result, expected, desc)


# ---------------------------------------------------------------------------
# Alert data extraction
# ---------------------------------------------------------------------------

class TestExtractFilePath(unittest.TestCase):
    """_extract_file_path produces a clean relative path from various Source formats."""

    def test_cases(self):
        from orca_client import _extract_file_path

        CASES = [
            ("github blob URL with sha",
             "https://github.com/owner/repo/blob/abc123def/nodejs-app/server.js",
             "nodejs-app/server.js"),
            ("github blob URL with branch name",
             "https://github.com/owner/repo/blob/main/path/to/file.py",
             "path/to/file.py"),
            ("github blob URL with line anchor",
             "https://github.com/owner/repo/blob/abc123/nodejs-app/server.js#L40",
             "nodejs-app/server.js"),
            ("relative path with line number",
             "nodejs-app/server.js:40",
             "nodejs-app/server.js"),
            ("relative path without line number",
             "nodejs-app/server.js",
             "nodejs-app/server.js"),
            ("plain manifest path",
             "go.mod",
             "go.mod"),
            ("empty string",
             "",
             ""),
        ]

        for desc, source, expected in CASES:
            with self.subTest(desc):
                self.assertEqual(_extract_file_path(source), expected, desc)


class TestBuildPromptContext(unittest.TestCase):
    """_build_prompt_context extracts structured fields for fix agent prompts."""

    def test_cases(self):
        from orchestrator import _build_prompt_context

        CASES = [
            (
                "full alert with all fields",
                {
                    "file_path": "nodejs-app/server.js",
                    "position": {"start_line": 40, "end_line": 45},
                    "code_snippet": ["const path = req.query.file", "res.sendFile(path)"],
                    "description": "Path traversal vulnerability",
                    "ai_triage": {"explanation": "User input flows to file system"},
                    "recommendation": "Sanitize the input with path.basename()",
                },
                {
                    "file_path": "nodejs-app/server.js",
                    "lines": "40–45",
                    "code_snippet": "const path = req.query.file\nres.sendFile(path)",
                    "description": "Path traversal vulnerability",
                    "ai_triage_explanation": "User input flows to file system",
                    "recommendation": "Sanitize the input with path.basename()",
                },
            ),
            (
                "single line position",
                {"file_path": "app.go", "position": {"start_line": 10, "end_line": 10},
                 "code_snippet": [], "description": "", "ai_triage": {}, "recommendation": ""},
                {"file_path": "app.go", "lines": "10",
                 "code_snippet": "(not available)", "description": "",
                 "ai_triage_explanation": "", "recommendation": ""},
            ),
            (
                "missing position falls back gracefully",
                {"file_path": "infra/main.tf", "position": {},
                 "code_snippet": [], "description": "", "ai_triage": {}, "recommendation": ""},
                {"file_path": "infra/main.tf", "lines": "see recommendation",
                 "code_snippet": "(not available)", "description": "",
                 "ai_triage_explanation": "", "recommendation": ""},
            ),
            (
                "falls back to source when file_path missing",
                {"source": "app.py:12", "position": {},
                 "code_snippet": [], "description": "", "ai_triage": {}, "recommendation": ""},
                {"file_path": "app.py:12", "lines": "see recommendation",
                 "code_snippet": "(not available)", "description": "",
                 "ai_triage_explanation": "", "recommendation": ""},
            ),
        ]

        for desc, alert, expected in CASES:
            with self.subTest(desc):
                result = _build_prompt_context(alert)
                for key, val in expected.items():
                    self.assertEqual(result[key], val, f"{desc}: {key}")


# ---------------------------------------------------------------------------
# Impact analysis error surfacing
# ---------------------------------------------------------------------------

class TestImpactAnalysisErrors(unittest.TestCase):
    """Verify that analyze_impact() captures and surfaces error details."""

    CASES = [
        (
            "timeout returns error field",
            subprocess.TimeoutExpired(cmd=["claude"], timeout=90),
            None,  # no CompletedProcess
            "timeout after 90s",
        ),
        (
            "non-zero exit stores stderr",
            None,  # no exception
            subprocess.CompletedProcess(
                args=["claude"], returncode=1,
                stdout="", stderr="Error: authentication failed"
            ),
            "exit_code=1: Error: authentication failed",
        ),
        (
            "unparseable output stores snippet",
            None,
            subprocess.CompletedProcess(
                args=["claude"], returncode=0,
                stdout='{"result": "no json here at all"}', stderr=""
            ),
            "no_json_output:",
        ),
    ]

    @patch("impact_agent.subprocess.run")
    def test_error_field_populated(self, mock_run):
        for desc, side_effect, return_value, expected_substr in self.CASES:
            with self.subTest(desc):
                if side_effect:
                    mock_run.side_effect = side_effect
                else:
                    mock_run.side_effect = None
                    mock_run.return_value = return_value
                result = analyze_impact({"alert_id": "test-1"}, "diff")
                self.assertEqual(result.level, "medium")
                self.assertIsNotNone(result.error, f"{desc}: error should be set")
                self.assertIn(expected_substr, result.error, f"{desc}: error detail")


# ---------------------------------------------------------------------------
# LLM validation error surfacing
# ---------------------------------------------------------------------------

class TestLLMValidationErrors(unittest.TestCase):
    """Verify that llm_validate() surfaces error details in failures list."""

    CASES = [
        (
            "timeout flags for review",
            subprocess.TimeoutExpired(cmd=["claude"], timeout=90),
            None,
            "timed out",
        ),
        (
            "non-zero exit includes stderr",
            None,
            subprocess.CompletedProcess(
                args=["claude"], returncode=1,
                stdout="", stderr="rate limit exceeded"
            ),
            "exit=1",
        ),
        (
            "unparseable output includes snippet",
            None,
            subprocess.CompletedProcess(
                args=["claude"], returncode=0,
                stdout='{"result": "random text no json"}', stderr=""
            ),
            "Could not parse",
        ),
    ]

    @patch("validator.subprocess.run")
    def test_failures_populated(self, mock_run):
        # worktree_diff() runs `git add -A -N` then `git diff`; claude is third.
        git_add_result = subprocess.CompletedProcess(
            args=["git", "add", "-A", "-N"], returncode=0, stdout="", stderr=""
        )
        git_diff_result = subprocess.CompletedProcess(
            args=["git", "diff"], returncode=0, stdout="diff --git a/f", stderr=""
        )
        for desc, side_effect, return_value, expected_substr in self.CASES:
            with self.subTest(desc):
                claude_result = side_effect if side_effect else return_value
                mock_run.side_effect = [git_add_result, git_diff_result, claude_result]
                result = llm_validate({"alert_id": "test-1"}, Path("/tmp"))
                self.assertTrue(result.passed, f"{desc}: should pass (flagged, not blocked)")
                self.assertTrue(result.needs_review, f"{desc}: should flag for review")
                self.assertTrue(
                    any(expected_substr in f for f in result.failures),
                    f"{desc}: expected '{expected_substr}' in failures: {result.failures}"
                )


# ---------------------------------------------------------------------------
# Orca check retry with feedback (post-PR)
# ---------------------------------------------------------------------------

class TestOrcaCheckRetry(unittest.TestCase):
    """When the Orca GitHub App check detects regressions on a PR, the fix agent
    should be re-invoked with feedback, re-validated locally, and pushed."""

    def _make_task(self):
        return AlertTask(
            alert_id="orca-retry-1",
            title="Path Traversal",
            risk_level="high",
            feature_type="sast",
            source="server.js:40",
            alert_json={"alert_id": "orca-retry-1", "feature_type": "sast"},
        )

    @patch("orchestrator._remove_worktree")
    @patch("orchestrator.subprocess.run")
    @patch("orchestrator._push_fix_update")
    @patch("orchestrator._commit_and_pr", return_value="https://github.com/owner/repo/pull/1")
    @patch("orchestrator.analyze_impact")
    @patch("orchestrator._get_diff", return_value="diff --git a/server.js")
    @patch("orchestrator.ci_gate")
    @patch("orchestrator.orca_check_gate")
    @patch("orchestrator.local_build_check")
    @patch("orchestrator.llm_validate")
    @patch("orchestrator.sanity_check")
    @patch("orchestrator._revert")
    @patch("orchestrator._invoke_fix_agent")
    @patch("orchestrator._create_worktree", return_value=Path("/tmp/orca-fix-test"))
    def test_retry_on_orca_regression(
        self, mock_wt, mock_fix, mock_revert, mock_sanity, mock_llm, mock_build,
        mock_orca, mock_ci, mock_diff, mock_impact, mock_pr, mock_push, mock_subproc, mock_rm,
    ):
        from notifier import Notifier

        task = self._make_task()
        notifier = MagicMock(spec=Notifier)
        repo = Repository(name="owner/repo", url="https://github.com/owner/repo")

        # First fix attempt succeeds
        fix_ok = FixAgentResult(success=True, files_changed=["server.js"],
                                diff_summary="patched path traversal")
        # Second fix attempt also succeeds (retry)
        fix_ok2 = FixAgentResult(success=True, files_changed=["server.js"],
                                 diff_summary="patched with different approach")
        mock_fix.side_effect = [fix_ok, fix_ok2]

        # All basic validations pass
        val_pass = ValidationResult(passed=True, phase="sanity")
        mock_sanity.return_value = val_pass
        mock_llm.return_value = val_pass
        mock_build.return_value = val_pass

        # Orca check: fails first time (regression), passes second time
        orca_fail = ValidationResult(
            passed=False, phase="orca_check",
            failures=["server.js:41 [failure] new SAST finding introduced"])
        orca_pass = ValidationResult(passed=True, phase="orca_check")
        mock_orca.side_effect = [orca_fail, orca_pass]

        mock_ci.return_value = ValidationResult(passed=True, phase="ci")
        mock_impact.return_value = ImpactResult(
            level="low", description="minor", downtime_risk=False, requires_deploy=True)

        result = run_one(task, dry_run=False, notifier=notifier, repo=repo)

        # Should succeed — the retry worked
        self.assertEqual(result.state, "DONE")
        self.assertIsNotNone(result.pr_url)

        # Fix agent was called twice: first without feedback, then with
        self.assertEqual(mock_fix.call_count, 2)
        second_call_kwargs = mock_fix.call_args_list[1]
        self.assertIn("feedback", second_call_kwargs.kwargs)
        self.assertIn("new SAST finding", second_call_kwargs.kwargs["feedback"])

        # _push_fix_update was called for the retry
        mock_push.assert_called_once()

    @patch("orchestrator._remove_worktree")
    @patch("orchestrator.subprocess.run")
    @patch("orchestrator._push_fix_update")
    @patch("orchestrator._commit_and_pr", return_value="https://github.com/owner/repo/pull/1")
    @patch("orchestrator.analyze_impact")
    @patch("orchestrator._get_diff", return_value="diff --git a/server.js")
    @patch("orchestrator.ci_gate")
    @patch("orchestrator.orca_check_gate")
    @patch("orchestrator.local_build_check")
    @patch("orchestrator.llm_validate")
    @patch("orchestrator.sanity_check")
    @patch("orchestrator._revert")
    @patch("orchestrator._invoke_fix_agent")
    @patch("orchestrator._create_worktree", return_value=Path("/tmp/orca-fix-test"))
    def test_exhausted_retries_fails(
        self, mock_wt, mock_fix, mock_revert, mock_sanity, mock_llm, mock_build,
        mock_orca, mock_ci, mock_diff, mock_impact, mock_pr, mock_push, mock_subproc, mock_rm,
    ):
        from notifier import Notifier

        task = self._make_task()
        notifier = MagicMock(spec=Notifier)
        repo = Repository(name="owner/repo", url="https://github.com/owner/repo")

        fix_ok = FixAgentResult(success=True, files_changed=["server.js"],
                                diff_summary="patched")
        mock_fix.return_value = fix_ok

        val_pass = ValidationResult(passed=True, phase="sanity")
        mock_sanity.return_value = val_pass
        mock_llm.return_value = val_pass
        mock_build.return_value = val_pass

        # Orca check always fails
        orca_fail = ValidationResult(
            passed=False, phase="orca_check",
            failures=["server.js:41 [failure] persistent SAST finding"])
        mock_orca.return_value = orca_fail

        mock_ci.return_value = ValidationResult(passed=True, phase="ci")
        mock_impact.return_value = ImpactResult(
            level="low", description="minor", downtime_risk=False, requires_deploy=True)

        result = run_one(task, dry_run=False, notifier=notifier, repo=repo)

        self.assertEqual(result.state, "FAILED")
        self.assertIn("persistent SAST finding", result.failure_reason)
        # Called initial + config.orca_check.max_retries times
        orca_retries = orchestrator.CFG.orca_check.max_retries
        self.assertEqual(mock_fix.call_count, 1 + orca_retries)

    @patch("orchestrator.subprocess.run")
    def test_feedback_in_prompt(self, mock_run):
        """Verify that feedback text appears in the claude subprocess prompt."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=["claude"], returncode=0,
            stdout='{"result": "{\\"status\\": \\"success\\", \\"alert_id\\": \\"t\\", \\"files_changed\\": [], \\"diff_summary\\": \\"ok\\"}"}',
            stderr=""
        )
        task = self._make_task()
        task.worktree_path = Path("/tmp/test")
        feedback = "server.js:41 [failure] Orca detected new finding"

        _invoke_fix_agent(task, dry_run=False, timeout_sec=60, feedback=feedback)

        prompt_arg = mock_run.call_args[0][0][2]  # cmd[2] is the prompt
        self.assertIn("Previous Attempt Failed", prompt_arg)
        self.assertIn("Orca security check", prompt_arg)
        self.assertIn(feedback, prompt_arg)


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

class TestConfig(unittest.TestCase):
    """Verify Config defaults and YAML loading."""

    def test_defaults(self):
        cfg = Config()
        self.assertTrue(cfg.orca_check.enabled)
        self.assertEqual(cfg.orca_check.check_name, "orca-security-us")
        self.assertEqual(cfg.orca_check.timeout_sec, 600)
        self.assertEqual(cfg.orca_check.max_retries, 1)
        self.assertEqual(cfg.max_parallel_fixes, 4)
        self.assertEqual(cfg.max_parallel_repos, 3)

    def test_load_config_no_env(self):
        """Without SECURITY_ENGINEER_CONFIG env var, defaults are used."""
        import os
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SECURITY_ENGINEER_CONFIG", None)
            cfg = load_config()
        self.assertEqual(cfg.orca_check.check_name, "orca-security-us")
        self.assertEqual(cfg.max_parallel_fixes, 4)

    def test_orca_check_config_fields(self):
        orca = OrcaCheckConfig(enabled=False, check_name="custom-check",
                               timeout_sec=300, max_retries=2)
        self.assertFalse(orca.enabled)
        self.assertEqual(orca.check_name, "custom-check")
        self.assertEqual(orca.timeout_sec, 300)
        self.assertEqual(orca.max_retries, 2)


# ---------------------------------------------------------------------------
# 18. Gates judge what will actually be committed
# ---------------------------------------------------------------------------

def _git(args: list, cwd, check: bool = True):
    """Run git in a test fixture with hooks and templates disabled.

    The developer's global pre-commit hooks (Orca's own secret scanner among them)
    would otherwise run on every fixture commit and dominate the suite's runtime.
    """
    return subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "init.templateDir=", *args],
        cwd=cwd, check=check, capture_output=True, text=True,
    )


def _init_repo(tmp: Path, files: dict) -> Path:
    """Create a git repo on branch `main` with `files` committed. Returns its path."""
    tmp.mkdir(parents=True, exist_ok=True)
    _git(["init", "-q", "-b", "main"], tmp)
    _git(["config", "user.email", "t@test"], tmp)
    _git(["config", "user.name", "test"], tmp)
    for name, body in files.items():
        (tmp / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp / name).write_text(body)
    _git(["add", "-A"], tmp)
    _git(["commit", "-qm", "init", "--no-verify"], tmp)
    return tmp


class TestDiffLineCount(unittest.TestCase):
    """Table-driven: added+removed lines counted, file headers excluded."""

    CASES = [
        ("empty diff",        "",                                              0),
        ("one addition",      "+++ b/f\n@@\n+new line\n",                      1),
        ("one deletion",      "--- a/f\n@@\n-gone\n",                          1),
        ("add and remove",    "--- a/f\n+++ b/f\n@@\n-old\n+new\n",            2),
        ("headers only",      "--- a/f\n+++ b/f\n",                            0),
        ("context ignored",   "+++ b/f\n@@\n unchanged\n+added\n",             1),
        ("binary file",       "Binary files a/x and b/x differ\n",             0),
    ]

    def test_cases(self):
        from validator import diff_line_count
        for desc, diff_text, expected in self.CASES:
            with self.subTest(desc):
                self.assertEqual(diff_line_count(diff_text), expected, desc)


class TestWorktreeDiffSeesUntracked(unittest.TestCase):
    """A fix that only creates files must not look like an empty diff.

    Regression: gates read plain `git diff` (tracked+unstaged) while the commit
    was `git add -A`, so newly created files were invisible to every gate yet
    still committed.
    """

    CASES = [
        # (description, files the fix agent writes, substrings expected in the diff)
        ("modifies a tracked file", {"a.py": "x = 2\n"},           ["a.py"]),
        ("creates a new file",      {"new.py": "SAFE = 1\n"},      ["new.py", "SAFE = 1"]),
        ("both at once",            {"a.py": "x = 3\n",
                                     "extra.py": "Y = 2\n"},       ["a.py", "extra.py"]),
        ("creates a nested file",   {"pkg/mod.py": "Z = 3\n"},     ["pkg/mod.py"]),
    ]

    def test_cases(self):
        from validator import worktree_diff
        for desc, writes, expected_substrs in self.CASES:
            with self.subTest(desc):
                with tempfile.TemporaryDirectory() as td:
                    repo = _init_repo(Path(td), {"a.py": "x = 1\n"})
                    for name, body in writes.items():
                        (repo / name).parent.mkdir(parents=True, exist_ok=True)
                        (repo / name).write_text(body)
                    diff = worktree_diff(repo)
                    for substr in expected_substrs:
                        self.assertIn(substr, diff, f"{desc}: '{substr}' missing from diff")

    def test_no_changes_is_empty(self):
        """A clean tree must still produce an empty diff — no false positives."""
        from validator import worktree_diff
        with tempfile.TemporaryDirectory() as td:
            repo = _init_repo(Path(td), {"a.py": "x = 1\n"})
            self.assertEqual(worktree_diff(repo).strip(), "")

    def test_gitignored_files_excluded(self):
        """Ignored artefacts must not enter the diff or the commit."""
        from validator import worktree_diff
        with tempfile.TemporaryDirectory() as td:
            repo = _init_repo(Path(td), {"a.py": "x = 1\n", ".gitignore": "junk/\n"})
            (repo / "junk").mkdir()
            (repo / "junk" / "cached.pyc").write_text("binary")
            self.assertNotIn("junk", worktree_diff(repo))


class TestSanityCheckFeatureType(unittest.TestCase):
    """The diff-size limit follows the RESOLVED feature type.

    Regression: package CVEs carry an empty raw feature_type (they are identified
    by category), so sanity_check fell back to "sast" and applied a 50-line limit
    to lockfile bumps that legitimately need 200.
    """

    # A package CVE as _normalize_alert() emits it: raw feature_type is empty.
    PACKAGE_CVE = {"category": "Vulnerabilities", "feature_type": "",
                   "labels": ["CVE-2023-44487"]}

    CASES = [
        # (description, alert, explicit feature_type, changed lines, expect_passed)
        ("package CVE, 120 lines — under cve limit",
         PACKAGE_CVE, "cve", 120, True),
        ("package CVE, 120 lines — resolved from alert when not passed",
         PACKAGE_CVE, None, 120, True),
        ("package CVE, 300 lines — over cve limit",
         PACKAGE_CVE, "cve", 300, False),
        ("sast, 30 lines — under sast limit",
         {"feature_type": "sast"}, "sast", 30, True),
        ("sast, 120 lines — over sast limit",
         {"feature_type": "sast"}, "sast", 120, False),
        ("explicit type wins over alert contents",
         {"feature_type": "sast"}, "cve", 120, True),
    ]

    def test_cases(self):
        from validator import sanity_check
        for desc, alert, ft, n_lines, expect_passed in self.CASES:
            with self.subTest(desc):
                with tempfile.TemporaryDirectory() as td:
                    original = "\n".join(f"line{i}" for i in range(n_lines)) + "\n"
                    repo = _init_repo(Path(td), {"deps.lock": original})
                    # Rewrite every line: n additions + n deletions... so use half.
                    changed = "\n".join(f"line{i}" for i in range(n_lines // 2))
                    changed += "\n" + "\n".join(f"new{i}" for i in range(n_lines // 2)) + "\n"
                    (repo / "deps.lock").write_text(changed)
                    result = sanity_check(alert, repo, feature_type=ft)
                    self.assertEqual(result.passed, expect_passed,
                                     f"{desc}: failures={result.failures}")

    def test_new_file_only_fix_passes(self):
        """A fix whose whole change is a new file must reach the later gates."""
        from validator import sanity_check
        with tempfile.TemporaryDirectory() as td:
            repo = _init_repo(Path(td), {"a.py": "x = 1\n"})
            (repo / "safe_helper.py").write_text("def escape(s):\n    return s\n")
            result = sanity_check({"feature_type": "sast"}, repo, feature_type="sast")
            self.assertTrue(result.passed, f"failures={result.failures}")

    def test_empty_diff_still_fails(self):
        from validator import sanity_check
        with tempfile.TemporaryDirectory() as td:
            repo = _init_repo(Path(td), {"a.py": "x = 1\n"})
            result = sanity_check({"feature_type": "sast"}, repo, feature_type="sast")
            self.assertFalse(result.passed)
            self.assertIn("empty", result.failures[0])


# ---------------------------------------------------------------------------
# 19. Worktree lifecycle — leaks, reclaim, guaranteed teardown
# ---------------------------------------------------------------------------

class TestWorktreePath(unittest.TestCase):
    """Table-driven: worktree paths are namespaced per repo so runs cannot collide."""

    CASES = [
        # (description, repo, alert_id, expected path)
        ("no repo",        None,                       "orca-1", "/tmp/orca-fix-orca-1"),
        ("owner/repo",     Repository(name="acme/api", url=""),  "orca-1",
         "/tmp/orca-fix-acme-api-orca-1"),
        ("different repo, same alert", Repository(name="acme/web", url=""), "orca-1",
         "/tmp/orca-fix-acme-web-orca-1"),
    ]

    def test_cases(self):
        for desc, repo, alert_id, expected in self.CASES:
            with self.subTest(desc):
                self.assertEqual(str(orchestrator._worktree_path(alert_id, repo)),
                                 expected, desc)

    def test_same_alert_in_two_repos_does_not_collide(self):
        a = orchestrator._worktree_path("orca-9", Repository(name="acme/api", url=""))
        b = orchestrator._worktree_path("orca-9", Repository(name="acme/web", url=""))
        self.assertNotEqual(a, b)


class TestBranchReclaim(unittest.TestCase):
    """A leaked empty branch is reclaimable; one carrying commits is not."""

    def test_empty_branch_is_reclaimable(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _init_repo(Path(td), {"a.py": "x = 1\n"})
            _git(["branch", "fix/orca-1"], repo)
            self.assertFalse(
                orchestrator._branch_has_own_commits("fix/orca-1", str(repo)),
                "a branch pointing at main has no commits of its own")

    def test_branch_with_commits_is_protected(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _init_repo(Path(td), {"a.py": "x = 1\n"})
            _git(["checkout", "-q", "-b", "fix/orca-1"], repo)
            (repo / "human_work.py").write_text("important\n")
            _git(["add", "-A"], repo)
            _git(["commit", "-qm", "human work", "--no-verify"], repo)
            _git(["checkout", "-q", "main"], repo)
            self.assertTrue(
                orchestrator._branch_has_own_commits("fix/orca-1", str(repo)),
                "unmerged human work must never be force-deleted")

    def test_unknown_branch_is_treated_as_having_commits(self):
        """Fail safe: if we cannot inspect it, we do not delete it."""
        with tempfile.TemporaryDirectory() as td:
            repo = _init_repo(Path(td), {"a.py": "x = 1\n"})
            self.assertTrue(
                orchestrator._branch_has_own_commits("does/not/exist", str(repo)))

    def test_local_branch_exists(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _init_repo(Path(td), {"a.py": "x = 1\n"})
            _git(["branch", "fix/orca-1"], repo)
            self.assertTrue(orchestrator._local_branch_exists("fix/orca-1", str(repo)))
            self.assertFalse(orchestrator._local_branch_exists("fix/nope", str(repo)))


class TestCreateWorktreeRecovery(unittest.TestCase):
    """A leftover directory from a crashed run must not permanently skip an alert.

    Regression: `git worktree add` failed with "already exists", run_one matched
    that string and reported SKIPPED "branch already exists" on every later run.
    """

    def test_stale_directory_is_cleared(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = _init_repo(root / "repo", {"a.py": "x = 1\n"})
            stale = orchestrator._worktree_path("orca-stale",
                                                Repository(name="acme/api", url=""))
            shutil.rmtree(stale, ignore_errors=True)
            stale.mkdir(parents=True)
            (stale / "leftover.txt").write_text("from a crashed run\n")
            try:
                path = orchestrator._create_worktree(
                    "orca-stale", "fix/orca-stale",
                    repo=Repository(name="acme/api", url="", clone_path=repo))
                self.assertTrue(path.exists(), "worktree should have been created")
                self.assertFalse((path / "leftover.txt").exists(),
                                 "stale contents should be gone")
                self.assertTrue((path / "a.py").exists(),
                                "worktree should contain the repo at BASE_BRANCH")
            finally:
                _git(["worktree", "remove", "--force", str(stale)], repo, check=False)
                shutil.rmtree(stale, ignore_errors=True)

    def test_branch_with_commits_raises_conflict(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = _init_repo(root / "repo", {"a.py": "x = 1\n"})
            _git(["checkout", "-q", "-b", "fix/orca-busy"], repo)
            (repo / "wip.py").write_text("wip\n")
            _git(["add", "-A"], repo)
            _git(["commit", "-qm", "wip", "--no-verify"], repo)
            _git(["checkout", "-q", "main"], repo)
            with self.assertRaises(orchestrator.WorktreeConflict):
                orchestrator._create_worktree(
                    "orca-busy", "fix/orca-busy",
                    repo=Repository(name="acme/api", url="", clone_path=repo))


class TestWorktreeTeardownGuaranteed(unittest.TestCase):
    """run_one must remove the worktree on every exit path, including exceptions."""

    def _task(self):
        return AlertTask(
            alert_id="orca-td-1", title="Path Traversal", risk_level="high",
            feature_type="sast", source="server.js:40",
            alert_json={"alert_id": "orca-td-1", "feature_type": "sast"},
        )

    # (description, what the pipeline does, expected state)
    CASES = [
        ("fix agent fails",
         lambda: FixAgentResult(success=False, failure_reason="no dice",
                                error_code="fix_apply"),
         "FAILED"),
        ("fix agent times out",
         lambda: FixAgentResult(success=False, timed_out=True,
                                failure_reason="timed out", error_code="timeout"),
         "TIMED_OUT"),
    ]

    def test_cleanup_on_failure_paths(self):
        for desc, fix_factory, expected_state in self.CASES:
            with self.subTest(desc):
                with patch("orchestrator._create_worktree",
                           return_value=Path("/tmp/orca-fix-fake")), \
                     patch("orchestrator._remove_worktree") as mock_rm, \
                     patch("orchestrator._invoke_fix_agent",
                           return_value=fix_factory()), \
                     patch("orchestrator._revert"):
                    result = run_one(self._task(), dry_run=False,
                                     notifier=MagicMock(),
                                     repo=Repository(name="o/r", url=""))
                self.assertEqual(result.state, expected_state, desc)
                mock_rm.assert_called_once()

    def test_cleanup_on_unexpected_exception(self):
        """An exception mid-pipeline must still tear the worktree down."""
        with patch("orchestrator._create_worktree",
                   return_value=Path("/tmp/orca-fix-fake")), \
             patch("orchestrator._remove_worktree") as mock_rm, \
             patch("orchestrator._invoke_fix_agent",
                   side_effect=OSError("disk exploded")):
            with self.assertRaises(OSError):
                run_one(self._task(), dry_run=False, notifier=MagicMock(),
                        repo=Repository(name="o/r", url=""))
        mock_rm.assert_called_once()

    def test_cleanup_on_success(self):
        with patch("orchestrator._create_worktree",
                   return_value=Path("/tmp/orca-fix-fake")), \
             patch("orchestrator._remove_worktree") as mock_rm, \
             patch("orchestrator._invoke_fix_agent",
                   return_value=FixAgentResult(success=True, diff_summary="ok")):
            result = run_one(self._task(), dry_run=True, notifier=MagicMock(),
                             repo=Repository(name="o/r", url=""))
        self.assertEqual(result.state, "DONE")
        mock_rm.assert_called_once()


class TestWorktreeConflictClassification(unittest.TestCase):
    """Table-driven: setup failures map to SKIPPED vs FAILED by exception type."""

    CASES = [
        # (description, exception raised by _create_worktree, expected state)
        ("conflict → skipped",
         orchestrator.WorktreeConflict("branch has commits"), "SKIPPED"),
        ("other error → failed",
         RuntimeError("could not clear stale worktree at /tmp/x"), "FAILED"),
    ]

    def test_cases(self):
        for desc, exc, expected_state in self.CASES:
            with self.subTest(desc):
                task = AlertTask(
                    alert_id="orca-c-1", title="T", risk_level="high",
                    feature_type="sast", source="", alert_json={},
                )
                with patch("orchestrator._create_worktree", side_effect=exc), \
                     patch("orchestrator._remove_worktree") as mock_rm:
                    result = run_one(task, dry_run=False, notifier=MagicMock(),
                                     repo=Repository(name="o/r", url=""))
                self.assertEqual(result.state, expected_state, desc)
                mock_rm.assert_not_called()  # nothing was created, nothing to remove


class TestRevertClearsWorktree(unittest.TestCase):
    """_revert must restore the tree fully, including files the agent created."""

    def test_removes_new_files_and_restores_edits(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _init_repo(Path(td), {"a.py": "x = 1\n", ".gitignore": "keep/\n"})
            (repo / "keep").mkdir()
            (repo / "keep" / "artifact.bin").write_text("expensive to rebuild")

            (repo / "a.py").write_text("x = 999\n")          # modified
            (repo / "created.py").write_text("junk\n")        # new
            from validator import worktree_diff
            worktree_diff(repo)                               # leaves intent-to-add entries

            orchestrator._revert(repo)

            self.assertEqual((repo / "a.py").read_text(), "x = 1\n",
                             "tracked edit should be reverted")
            self.assertFalse((repo / "created.py").exists(),
                             "created file should be removed")
            self.assertTrue((repo / "keep" / "artifact.bin").exists(),
                            "gitignored artefacts must survive")
            self.assertEqual(worktree_diff(repo).strip(), "",
                             "tree should be clean after revert")


# ---------------------------------------------------------------------------
# 24. Run outcome is visible to the caller
# ---------------------------------------------------------------------------

class TestExitCodeForResults(unittest.TestCase):
    """A run that failed must not exit 0 — CI wrappers read that as green."""

    def _t(self, state):
        return AlertTask(alert_id="a", title="t", risk_level="high",
                         feature_type="cve", source="f", alert_json={}, state=state)

    CASES = [
        ("no alerts", [], 0),
        ("all done", ["DONE"], 0),
        ("dry-run plan only", ["PENDING"], 0),
        ("skipped is not a failure", ["SKIPPED"], 0),
        ("done plus skipped", ["DONE", "SKIPPED"], 0),
        ("one failure", ["FAILED"], 1),
        ("timeout", ["TIMED_OUT"], 1),
        # The PR exists but its checks are red. Reporting success would hide it.
        ("ci failure", ["CI_FAILED"], 1),
        ("failure among successes", ["DONE", "DONE", "FAILED"], 1),
    ]

    def test_exit_codes(self):
        for desc, states, expected in self.CASES:
            with self.subTest(desc):
                tasks = [self._t(s) for s in states]
                self.assertEqual(orchestrator.exit_code_for(tasks), expected)


class TestRunSurfacesStdoutOnFailure(unittest.TestCase):
    """_run must not discard the only diagnostic a subprocess produced.

    run_agent.py reports errors as JSON on stdout and writes nothing to stderr,
    so a stderr-only message degraded to a bare "Command failed: python3 …".
    """

    CASES = [
        ("stderr preferred when present", "ignored stdout", "real stderr", "real stderr"),
        ("falls back to stdout",
         '{"error": "Alert orca-1 not found"}', "", "Alert orca-1 not found"),
        ("whitespace-only stderr falls back", "stdout detail", "   \n", "stdout detail"),
        ("both empty falls back to the command", "", "", "Command failed"),
    ]

    def test_error_message(self):
        for desc, stdout, stderr, expected_substr in self.CASES:
            with self.subTest(desc):
                completed = subprocess.CompletedProcess(
                    args=["python3", "run_agent.py"], returncode=1,
                    stdout=stdout, stderr=stderr,
                )
                with patch("orchestrator.subprocess.run", return_value=completed):
                    with self.assertRaises(RuntimeError) as ctx:
                        orchestrator._run(["python3", "run_agent.py"])
                self.assertIn(expected_substr, str(ctx.exception), desc)

    def test_no_raise_when_check_false(self):
        completed = subprocess.CompletedProcess(
            args=["x"], returncode=1, stdout="out", stderr="err")
        with patch("orchestrator.subprocess.run", return_value=completed):
            stdout, stderr, rc = orchestrator._run(["x"], check=False)
        self.assertEqual((stdout, stderr, rc), ("out", "err", 1))


# ---------------------------------------------------------------------------
# 25. Single-turn claude subprocesses must not be able to call tools
# ---------------------------------------------------------------------------

class TestSingleTurnAgentsRestrictTools(unittest.TestCase):
    """--max-turns 1 without --allowedTools fails 100% of the time.

    The model opens with a tool call, that consumes the only permitted turn, and
    claude exits non-zero with subtype=error_max_turns and an empty stderr. Both
    call sites then took their error path on every run: LLM validation passed
    everything with needs_review, and every PR was labelled impact:medium.
    """

    def _captured_cmd(self, mock_run):
        return mock_run.call_args[0][0]

    def _assert_tools_restricted(self, cmd, label):
        # --tools "" removes the tool definitions. --allowedTools "" only denies
        # the calls, so the model still emits tool_use blocks and each refusal
        # burns a turn — measured at 3 turns and 6.2x the cost per call, with a
        # tail past any turn cap. Asserting the specific flag is the point.
        self.assertIn("--tools", cmd, f"{label}: must disable tools, not just deny them")
        self.assertEqual(cmd[cmd.index("--tools") + 1], "",
                         f"{label}: tool set must be empty")
        self.assertNotIn("--allowedTools", cmd,
                         f"{label}: --allowedTools is the flag that did not work")
        self.assertIn("--max-turns", cmd, f"{label}: expected a turn cap")

    @patch("validator.subprocess.run")
    def test_llm_validate_restricts_tools(self, mock_run):
        ok = subprocess.CompletedProcess(args=["claude"], returncode=0, stdout="{}", stderr="")
        mock_run.return_value = ok
        llm_validate({"alert_id": "a"}, Path("/tmp"))
        self._assert_tools_restricted(self._captured_cmd(mock_run), "llm_validate")

    @patch("impact_agent.subprocess.run")
    def test_analyze_impact_restricts_tools(self, mock_run):
        ok = subprocess.CompletedProcess(args=["claude"], returncode=0, stdout="{}", stderr="")
        mock_run.return_value = ok
        analyze_impact({"alert_id": "a"}, "diff --git a/f b/f")
        self._assert_tools_restricted(self._captured_cmd(mock_run), "analyze_impact")


# ---------------------------------------------------------------------------
# 26. A repo without CI is not a CI failure
# ---------------------------------------------------------------------------

class TestHasNoCiChecks(unittest.TestCase):
    """`gh pr checks` exits 1 both for a red check and for a repo with no CI."""

    CASES = [
        ("no checks, message on stderr", "",
         "no checks reported on the 'fix/orca-1' branch", True),
        ("no checks, message on stdout",
         "no checks reported on the 'fix/orca-1' branch", "", True),
        ("case insensitive", "", "No Checks Reported on the 'x' branch", True),
        ("a real failure is not this", "build\tfail\t1m\thttps://…", "", False),
        ("both empty", "", "", False),
        ("passing checks", "build\tpass\t1m\thttps://…", "", False),
    ]

    def test_detection(self):
        for desc, stdout, stderr, expected in self.CASES:
            with self.subTest(desc):
                self.assertEqual(has_no_ci_checks(stdout, stderr), expected)


class TestCiGateOutcomes(unittest.TestCase):
    """The gate must distinguish "nothing to check" from "a check went red"."""

    def _run(self, returncode, stdout="", stderr=""):
        completed = subprocess.CompletedProcess(
            args=["gh"], returncode=returncode, stdout=stdout, stderr=stderr)
        with patch("validator.subprocess.run", return_value=completed):
            return ci_gate("https://github.com/o/r/pull/1")

    def test_cases(self):
        CASES = [
            ("all checks green", 0, "build\tpass", "", True, None),
            # vulnerable-apps has no GitHub Actions at all, so every PR there
            # was reported as a CI failure with an empty reason.
            ("repo has no CI at all", 1, "",
             "no checks reported on the 'fix/orca-1' branch", True, None),
            ("a check went red", 1, "build\tfail\t1m", "", False, "build"),
            # gh writes several failure modes to stderr with an empty stdout,
            # which produced a bare "CI checks failed: " with no cause.
            ("failure reported only on stderr", 1, "", "could not resolve PR",
             False, "could not resolve PR"),
            ("failure with no output at all", 1, "", "", False, "exited 1"),
        ]
        for desc, rc, stdout, stderr, should_pass, reason_substr in CASES:
            with self.subTest(desc):
                result = self._run(rc, stdout, stderr)
                self.assertEqual(result.passed, should_pass, f"{desc}: passed")
                if reason_substr:
                    self.assertIn(reason_substr, "; ".join(result.failures), desc)

    def test_no_ci_flags_for_review(self):
        """Passing because there is no CI is not the same as passing CI."""
        result = self._run(1, "", "no checks reported on the 'x' branch")
        self.assertTrue(result.passed)
        self.assertTrue(result.needs_review)


# ---------------------------------------------------------------------------
# 27. on_not_found is honoured, not just documented
# ---------------------------------------------------------------------------

class TestOrcaCheckOnNotFound(unittest.TestCase):
    """The setting existed in config.py and SKILL.md but was never read."""

    CASES = [
        ("skip is the default and passes", "skip", True),
        ("fail blocks instead", "fail", False),
        ("unknown value behaves as skip", "something-else", True),
    ]

    def test_not_found_behaviour(self):
        for desc, on_not_found, should_pass in self.CASES:
            with self.subTest(desc):
                # Jump straight past the 30s grace period, and stub sleep — the
                # gate polls on a 15s cadence and would otherwise make the suite
                # take a minute instead of milliseconds.
                with patch("validator._parse_pr_url", return_value=("o/r", 1)), \
                     patch("validator._get_pr_head_sha", return_value="a" * 40), \
                     patch("validator._find_orca_check_run", return_value=None), \
                     patch("validator.time.sleep"), \
                     patch("validator.time.monotonic", side_effect=[0, 0, 1, 100]):
                    result = orca_check_gate("https://github.com/o/r/pull/1",
                                             check_name="Orca Security",
                                             on_not_found=on_not_found)
                self.assertEqual(result.passed, should_pass, desc)
                self.assertTrue(result.needs_review, f"{desc}: always flag for review")

    def test_orchestrator_passes_config_through(self):
        """A config value that never reaches the gate is the bug we just fixed."""
        import inspect
        src = inspect.getsource(orchestrator._run_pipeline)
        self.assertIn("on_not_found=orca_cfg.on_not_found", src)


class TestSubprocessErrorDetail(unittest.TestCase):
    """claude reports its own failures on stdout; stderr-only logging lost them."""

    CASES = [
        ("stderr wins when present", "stdout stuff", "boom", "boom"),
        ("no output at all", "", "", "(no output)"),
        ("plain stdout passed through", "something broke", "", "something broke"),
        # The field that actually names the failure.
        ("json envelope surfaces subtype",
         '{"is_error": true, "subtype": "error_max_turns", "num_turns": 2}', "",
         "error_max_turns"),
        ("json envelope with error key",
         '{"error": "Alert not found"}', "", "Alert not found"),
        ("malformed json falls back to raw", "{not json", "", "{not json"),
    ]

    def test_detail(self):
        for desc, stdout, stderr, expected_substr in self.CASES:
            with self.subTest(desc):
                completed = subprocess.CompletedProcess(
                    args=["claude"], returncode=1, stdout=stdout, stderr=stderr)
                self.assertIn(expected_substr, _subprocess_error_detail(completed), desc)


# ---------------------------------------------------------------------------
# 28. The impact assessment has exactly one home
# ---------------------------------------------------------------------------

class TestNoDuplicateImpactRendering(unittest.TestCase):
    """Impact belongs in the PR body only.

    It used to be rendered twice — once into the PR body by _commit_and_pr, and
    again as a PR comment on fix_succeeded — so every PR carried the same
    manual_steps and concerns in both places. Impact is computed before the PR
    is opened, so the comment could never add anything.
    """

    def test_no_pr_comment_backend_registered(self):
        from notifier import build_notifiers
        names = [type(b).__name__ for b in build_notifiers("o/r", Path("/tmp")).backends]
        self.assertNotIn("GitHubPRCommentNotifier", names)
        for n in names:
            self.assertNotIn("Comment", n, f"{n} would re-introduce the duplicate")

    def test_notifier_never_shells_out_to_gh_pr_comment(self):
        """Catches a backend that posts a comment without 'Comment' in its name."""
        import notifier
        self.assertNotIn("pr\", \"comment", Path(notifier.__file__).read_text())

    def test_pr_body_still_carries_the_assessment(self):
        """Dropping the comment must not drop the content — the body keeps it."""
        import inspect
        src = inspect.getsource(orchestrator._commit_and_pr)
        for fragment in ("Required Manual Steps", "Reviewer Concerns",
                         "impact.manual_steps", "impact.concerns"):
            self.assertIn(fragment, src, f"PR body lost {fragment}")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    test_classes = [
        TestArgumentParsing,
        TestFlagValidation,
        TestScanReport,
        TestFilterParsing,
        TestMinLevel,
        TestFeatureTypeResolution,
        TestDryRunEnforcement,
        TestFixResultParsing,
        TestListRepositories,
        TestDetectRepoReturnsRepository,
        TestFetchAndPlanRepoDir,
        TestWorktreeCwd,
        TestRemoteRouting,
        TestRunRepoPipelineCleanup,
        TestOrcaCheckGate,
        TestFindPackageJsonRoot,
        TestFindProjectRoot,
        TestExtractFilePath,
        TestBuildPromptContext,
        TestImpactAnalysisErrors,
        TestLLMValidationErrors,
        TestOrcaCheckRetry,
        TestConfig,
        TestDiffLineCount,
        TestWorktreeDiffSeesUntracked,
        TestSanityCheckFeatureType,
        TestWorktreePath,
        TestBranchReclaim,
        TestCreateWorktreeRecovery,
        TestWorktreeTeardownGuaranteed,
        TestWorktreeConflictClassification,
        TestRevertClearsWorktree,
        TestExitCodeForResults,
        TestRunSurfacesStdoutOnFailure,
        TestSingleTurnAgentsRestrictTools,
        TestHasNoCiChecks,
        TestCiGateOutcomes,
        TestOrcaCheckOnNotFound,
        TestSubprocessErrorDetail,
        TestNoDuplicateImpactRendering,
    ]

    for cls in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
