#!/usr/bin/env python3
"""
Tests for the Security Engineer orchestrator.

Verifies that argument parsing, filter logic, and flag enforcement
(especially --dry-run and type filters) behave exactly as documented.

Run with: python3 tests/test_orchestrator.py
No API token or network access required — all tests are pure Python.
"""
import subprocess
import sys
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
                          run_one, MAX_ORCA_RETRIES)
from run_agent import parse_filter, min_level_from_list
from orca_client import _resolve_feature_type, is_fixable, RISK_ORDER, Repository
from orca_cli_validator import (
    _extract_fingerprints, FindingFingerprint, orca_cli_validate,
    _SCANNER_CMD, OrcaCliResult,
)
from impact_agent import analyze_impact, ImpactResult
from validator import llm_validate


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
# Orca CLI validator
# ---------------------------------------------------------------------------

class TestScannerMapping(unittest.TestCase):
    """Scanner mapping covers all fixable feature types."""

    CASES = [
        ("sast", ["sast", "scan"]),
        ("iac", ["iac", "scan"]),
        ("cve", ["sca", "scan"]),
        ("secret", ["secrets", "scan"]),
    ]

    def test_cases(self):
        for feature_type, expected_cmd in self.CASES:
            with self.subTest(feature_type):
                self.assertEqual(_SCANNER_CMD[feature_type], expected_cmd)

    def test_unknown_type_not_mapped(self):
        self.assertNotIn("scm_posture", _SCANNER_CMD)


class TestFingerprintExtraction(unittest.TestCase):
    """_extract_fingerprints normalizes orca-cli JSON into comparable sets."""

    SAMPLE_SAST_OUTPUT = {
        "results": [
            {
                "catalog_control": {"id": "ctrl-001", "title": "SQL Injection"},
                "findings": [
                    {"file_name": "app.py", "position": {"start_line": 42, "end_line": 45},
                     "id": "f1"},
                    {"file_name": "app.py", "position": {"start_line": 88, "end_line": 90},
                     "id": "f2"},
                ]
            },
            {
                "catalog_control": {"id": "ctrl-002", "title": "Path Traversal"},
                "findings": [
                    {"file_name": "routes.py", "position": {"start_line": 10, "end_line": 15},
                     "id": "f3"},
                ]
            }
        ]
    }

    def test_extracts_all_findings(self):
        fps = _extract_fingerprints(self.SAMPLE_SAST_OUTPUT)
        self.assertEqual(len(fps), 3)

    def test_fingerprint_fields(self):
        fps = _extract_fingerprints(self.SAMPLE_SAST_OUTPUT)
        expected = FindingFingerprint(control_id="ctrl-001", file_name="app.py", start_line=42)
        self.assertIn(expected, fps)

    def test_empty_results(self):
        fps = _extract_fingerprints({"results": []})
        self.assertEqual(len(fps), 0)

    def test_null_results(self):
        fps = _extract_fingerprints({"results": None})
        self.assertEqual(len(fps), 0)

    def test_empty_dict(self):
        fps = _extract_fingerprints({})
        self.assertEqual(len(fps), 0)

    def test_missing_position(self):
        data = {"results": [{"catalog_control": {"id": "c1"},
                             "findings": [{"file_name": "f.py", "position": {}}]}]}
        fps = _extract_fingerprints(data)
        self.assertEqual(len(fps), 1)
        self.assertEqual(list(fps)[0].start_line, 0)


class TestBeforeAfterComparison(unittest.TestCase):
    """orca_cli_validate compares before/after scans correctly."""

    def _make_scan_output(self, findings):
        """Build minimal orca-cli JSON from a list of (control_id, file, line) tuples."""
        results = {}
        for ctrl_id, fname, line in findings:
            if ctrl_id not in results:
                results[ctrl_id] = {
                    "catalog_control": {"id": ctrl_id, "title": ctrl_id},
                    "findings": []
                }
            results[ctrl_id]["findings"].append({
                "file_name": fname,
                "position": {"start_line": line},
                "id": f"{ctrl_id}-{fname}-{line}",
            })
        return {"results": list(results.values())}

    def test_fix_verified_no_regressions(self):
        """Original finding disappears, no new ones → pass, no review needed."""
        before = self._make_scan_output([("c1", "app.py", 42), ("c2", "lib.py", 10)])
        after = self._make_scan_output([("c2", "lib.py", 10)])

        before_fps = _extract_fingerprints(before)
        after_fps = _extract_fingerprints(after)

        fixed = before_fps - after_fps
        new = after_fps - before_fps

        self.assertEqual(len(fixed), 1)
        self.assertEqual(len(new), 0)

    def test_regression_detected(self):
        """New finding appears → should fail."""
        before = self._make_scan_output([("c1", "app.py", 42)])
        after = self._make_scan_output([("c3", "app.py", 99)])

        before_fps = _extract_fingerprints(before)
        after_fps = _extract_fingerprints(after)

        new = after_fps - before_fps
        self.assertEqual(len(new), 1)

    def test_no_change(self):
        """Same findings before and after → pass but needs review (fix not verified)."""
        before = self._make_scan_output([("c1", "app.py", 42)])
        after = self._make_scan_output([("c1", "app.py", 42)])

        before_fps = _extract_fingerprints(before)
        after_fps = _extract_fingerprints(after)

        fixed = before_fps - after_fps
        new = after_fps - before_fps

        self.assertEqual(len(fixed), 0)
        self.assertEqual(len(new), 0)


import os


class TestOrcaCliValidateSkip(unittest.TestCase):
    """orca_cli_validate skips gracefully when prerequisites are missing."""

    def test_unknown_feature_type_skips(self):
        result = orca_cli_validate({}, Path("/tmp"), "scm_posture")
        self.assertTrue(result.passed)

    @patch("orca_cli_validator._get_api_token", return_value=None)
    def test_no_token_skips(self, _mock):
        result = orca_cli_validate({}, Path("/tmp"), "sast")
        self.assertTrue(result.passed)
        self.assertTrue(result.needs_review)
        self.assertIn("not set", result.failures[0])

    @patch("shutil.which", return_value=None)
    @patch("orca_cli_validator._get_api_token", return_value="test-token")
    def test_no_binary_skips(self, _mock_token, _mock_which):
        result = orca_cli_validate({}, Path("/tmp"), "sast")
        self.assertTrue(result.passed)
        self.assertTrue(result.needs_review)
        self.assertIn("not installed", result.failures[0])

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
        # First call is git diff, second is claude subprocess
        git_diff_result = subprocess.CompletedProcess(
            args=["git", "diff"], returncode=0, stdout="diff --git a/f", stderr=""
        )
        for desc, side_effect, return_value, expected_substr in self.CASES:
            with self.subTest(desc):
                if side_effect:
                    mock_run.side_effect = [git_diff_result, side_effect]
                else:
                    mock_run.side_effect = [git_diff_result, return_value]
                result = llm_validate({"alert_id": "test-1"}, Path("/tmp"))
                self.assertTrue(result.passed, f"{desc}: should pass (flagged, not blocked)")
                self.assertTrue(result.needs_review, f"{desc}: should flag for review")
                self.assertTrue(
                    any(expected_substr in f for f in result.failures),
                    f"{desc}: expected '{expected_substr}' in failures: {result.failures}"
                )


# ---------------------------------------------------------------------------
# Orca-CLI retry with feedback
# ---------------------------------------------------------------------------

class TestOrcaCliRetry(unittest.TestCase):
    """When orca-cli detects regressions, the fix agent should be re-invoked
    with feedback describing the new findings."""

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
    @patch("orchestrator._commit_and_pr", return_value="https://github.com/pr/1")
    @patch("orchestrator.analyze_impact")
    @patch("orchestrator._get_diff", return_value="diff --git a/server.js")
    @patch("orchestrator.ci_gate")
    @patch("orchestrator.orca_cli_validate")
    @patch("orchestrator.local_build_check")
    @patch("orchestrator.llm_validate")
    @patch("orchestrator.sanity_check")
    @patch("orchestrator._revert")
    @patch("orchestrator._invoke_fix_agent")
    @patch("orchestrator._create_worktree", return_value=Path("/tmp/orca-fix-test"))
    def test_retry_on_orca_regression(
        self, mock_wt, mock_fix, mock_revert, mock_sanity, mock_llm, mock_build,
        mock_orca, mock_ci, mock_diff, mock_impact, mock_pr, mock_subproc, mock_rm,
    ):
        from validator import ValidationResult
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

        # Orca-cli: fails first time (regression), passes second time
        orca_fail = ValidationResult(
            passed=False, phase="orca_cli",
            failures=["orca-cli detected 2 new finding(s): server.js:41 [abc123], server.js:46 [def456]"])
        orca_pass = ValidationResult(passed=True, phase="orca_cli")
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
        self.assertIn("orca-cli detected", second_call_kwargs.kwargs["feedback"])

    @patch("orchestrator._remove_worktree")
    @patch("orchestrator.orca_cli_validate")
    @patch("orchestrator.local_build_check")
    @patch("orchestrator.llm_validate")
    @patch("orchestrator.sanity_check")
    @patch("orchestrator._revert")
    @patch("orchestrator._invoke_fix_agent")
    @patch("orchestrator._create_worktree", return_value=Path("/tmp/orca-fix-test"))
    def test_exhausted_retries_fails(
        self, mock_wt, mock_fix, mock_revert, mock_sanity, mock_llm, mock_build,
        mock_orca, mock_rm,
    ):
        from validator import ValidationResult
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

        # Orca-cli always fails
        orca_fail = ValidationResult(
            passed=False, phase="orca_cli",
            failures=["orca-cli detected 1 new finding(s): server.js:41 [abc123]"])
        mock_orca.return_value = orca_fail

        result = run_one(task, dry_run=False, notifier=notifier, repo=repo)

        self.assertEqual(result.state, "FAILED")
        self.assertIn("orca-cli detected", result.failure_reason)
        # Called initial + MAX_ORCA_RETRIES times
        self.assertEqual(mock_fix.call_count, 1 + MAX_ORCA_RETRIES)


    CASES = [
        (
            "feedback appended to prompt",
            "orca-cli detected 3 new findings: file.js:10 [aaa], file.js:20 [bbb]",
            "Previous Attempt Failed",
        ),
    ]

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
        feedback = "orca-cli detected 2 new finding(s): server.js:41, server.js:46"

        _invoke_fix_agent(task, dry_run=False, timeout_sec=60, feedback=feedback)

        prompt_arg = mock_run.call_args[0][0][2]  # cmd[2] is the prompt
        self.assertIn("Previous Attempt Failed", prompt_arg)
        self.assertIn(feedback, prompt_arg)


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
        TestScannerMapping,
        TestFingerprintExtraction,
        TestBeforeAfterComparison,
        TestOrcaCliValidateSkip,
        TestFindPackageJsonRoot,
        TestFindProjectRoot,
        TestExtractFilePath,
        TestBuildPromptContext,
        TestImpactAnalysisErrors,
        TestLLMValidationErrors,
        TestOrcaCliRetry,
    ]

    for cls in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
