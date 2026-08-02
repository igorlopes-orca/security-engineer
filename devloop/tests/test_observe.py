#!/usr/bin/env python3
"""
Tests for devloop/observe.py — the pure parsing layer only.

No network, no gh, no filesystem. Everything that talks to GitHub is a thin
wrapper around subprocess and is covered by actually running the loop.

Run with: python3 devloop/tests/test_observe.py
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from observe import (parse_events, alert_events, derive_state, last_value,
                     parse_pr_url, last_phase, classify_checks, _duration,
                     verdict, planned_alerts, TERMINAL_STATES, NOT_STARTED)


class TestParseEvents(unittest.TestCase):

    CASES = [
        ("empty input", "", 0),
        ("single event", '{"event":"fix_started","alert_id":"a"}', 1),
        ("two events", '{"event":"a"}\n{"event":"b"}', 2),
        ("blank lines ignored", '{"event":"a"}\n\n\n{"event":"b"}\n', 2),
        ("malformed line skipped", '{"event":"a"}\n{not json\n{"event":"b"}', 2),
        # A run still in flight can leave the final line half-written.
        ("truncated tail skipped", '{"event":"a"}\n{"event":"fix_su', 1),
        ("non-dict json skipped", '{"event":"a"}\n["list"]\n42', 1),
        ("whitespace padded", '   {"event":"a"}   ', 1),
    ]

    def test_parse_events(self):
        for desc, text, expected in self.CASES:
            with self.subTest(desc):
                self.assertEqual(len(parse_events(text)), expected)


class TestAlertEvents(unittest.TestCase):

    CASES = [
        ("no events", [], {}),
        ("one alert",
         [{"event": "fix_started", "alert_id": "orca-1"}],
         {"orca-1": 1}),
        ("two alerts interleaved",
         [{"event": "fix_started", "alert_id": "orca-1"},
          {"event": "fix_started", "alert_id": "orca-2"},
          {"event": "fix_succeeded", "alert_id": "orca-1"}],
         {"orca-1": 2, "orca-2": 1}),
        # LogFileNotifier drops empty fields, so repo-level events arrive
        # without an alert_id at all.
        ("repo-level event dropped",
         [{"event": "clone_started", "repo": "o/r"},
          {"event": "fix_started", "alert_id": "orca-1"}],
         {"orca-1": 1}),
        ("run_complete placeholder dropped",
         [{"event": "run_complete", "alert_id": "-"},
          {"event": "fix_started", "alert_id": "orca-1"}],
         {"orca-1": 1}),
    ]

    def test_grouping(self):
        for desc, events, expected in self.CASES:
            with self.subTest(desc):
                grouped = alert_events(events)
                self.assertEqual({k: len(v) for k, v in grouped.items()}, expected)


class TestDeriveState(unittest.TestCase):

    CASES = [
        ("no events", [], "UNKNOWN"),
        ("only started", ["fix_started"], "RUNNING"),
        ("committed but no PR yet", ["fix_started", "committed"], "RUNNING"),
        ("PR opened, gates pending", ["fix_started", "committed", "pr_opened"], "RUNNING"),
        ("clean success", ["fix_started", "committed", "pr_opened", "fix_succeeded"], "DONE"),
        ("dry run", ["fix_started", "fix_planned"], "PLANNED"),
        ("fix agent failed", ["fix_started", "fix_failed"], "FAILED"),
        ("validation gate failed", ["fix_started", "validation_failed"], "FAILED"),
        ("timeout", ["fix_started", "timeout"], "TIMED_OUT"),
        # The orchestrator notifies ci_failed and then fix_succeeded on the
        # same alert — last-event-wins would report this as a success.
        ("ci_failed outranks trailing fix_succeeded",
         ["fix_started", "pr_opened", "ci_failed", "fix_succeeded"], "CI_FAILED"),
        ("failure outranks success",
         ["fix_started", "pr_opened", "fix_succeeded", "fix_failed"], "FAILED"),
        ("timeout outranks everything",
         ["fix_started", "fix_failed", "timeout"], "TIMED_OUT"),
        ("unknown event only", ["some_new_event"], "UNKNOWN"),
    ]

    def test_states(self):
        for desc, names, expected in self.CASES:
            with self.subTest(desc):
                events = [{"event": n} for n in names]
                self.assertEqual(derive_state(events), expected)

    def test_every_state_classified_terminal_or_not(self):
        for desc, names, expected in self.CASES:
            with self.subTest(desc):
                self.assertIn(expected, TERMINAL_STATES | {"RUNNING", "UNKNOWN"})


class TestLastValue(unittest.TestCase):

    CASES = [
        ("missing key", [{"event": "a"}], "pr_url", None),
        ("single value", [{"pr_url": "u1"}], "pr_url", "u1"),
        ("latest wins", [{"pr_url": "u1"}, {"pr_url": "u2"}], "pr_url", "u2"),
        # LogFileNotifier omits empty values, but be defensive: an empty
        # trailing value must not erase a real earlier one.
        ("empty later value ignored", [{"pr_url": "u1"}, {"pr_url": ""}], "pr_url", "u1"),
        ("skips events without the key",
         [{"reason": "boom"}, {"event": "x"}], "reason", "boom"),
    ]

    def test_last_value(self):
        for desc, events, key, expected in self.CASES:
            with self.subTest(desc):
                self.assertEqual(last_value(events, key), expected)


class TestParsePrUrl(unittest.TestCase):

    CASES = [
        ("standard url", "https://github.com/acme/app/pull/42", ("acme", "app", 42)),
        ("with trailing path", "https://github.com/acme/app/pull/42/files", ("acme", "app", 42)),
        ("hyphenated owner", "https://github.com/igorlopes-orca/vulnerable-apps/pull/7",
         ("igorlopes-orca", "vulnerable-apps", 7)),
        ("empty string", "", None),
        ("not a PR url", "https://github.com/acme/app", None),
        ("issue url", "https://github.com/acme/app/issues/42", None),
    ]

    def test_parse(self):
        for desc, url, expected in self.CASES:
            with self.subTest(desc):
                self.assertEqual(parse_pr_url(url), expected)


class TestLastPhase(unittest.TestCase):

    CASES = [
        ("no phase lines", "starting up\ndone\n", {}),
        ("single phase", "[PHASE] orca-1 sanity check", {"orca-1": "sanity check"}),
        ("latest phase per alert",
         "[PHASE] orca-1 sanity check\n[PHASE] orca-1 waiting for CI checks",
         {"orca-1": "waiting for CI checks"}),
        ("two alerts tracked separately",
         "[PHASE] orca-1 sanity check\n[PHASE] orca-2 LLM validation",
         {"orca-1": "sanity check", "orca-2": "LLM validation"}),
        ("interleaved with other output",
         "[OK]    done\n[PHASE] orca-1 sanity check\n[START] x",
         {"orca-1": "sanity check"}),
    ]

    def test_last_phase(self):
        for desc, text, expected in self.CASES:
            with self.subTest(desc):
                self.assertEqual(last_phase(text), expected)


class TestPlannedAlerts(unittest.TestCase):
    """The event log cannot distinguish "not reached yet" from "never ran"."""

    PLAN = """Found 5 alerts:
  ✓  5 to fix

Planned fixes:
  1. orca-4060654 — Potential SQL Injection (high, sast) — webhook-service/db.js:22
  2. orca-4060655 — Potential SQL Injection (high, sast) — webhook-service/db.js:27
[START] Fix started for orca-4060654 (sast, high)
"""

    CASES = [
        ("no plan block", "[START] Fix started for orca-1\n", []),
        ("empty input", "", []),
        ("single entry",
         "Planned fixes:\n  1. orca-1 — Title (high, sast) — f.js:1\n", ["orca-1"]),
        ("stops at first non-matching line", PLAN, ["orca-4060654", "orca-4060655"]),
        ("blank lines inside the block are skipped",
         "Planned fixes:\n  1. orca-1 — T — f\n\n  2. orca-2 — T — f\n",
         ["orca-1", "orca-2"]),
        # The orchestrator uses an em dash; tolerate a plain hyphen too.
        ("hyphen separator", "Planned fixes:\n  1. orca-1 - Title\n", ["orca-1"]),
    ]

    def test_planned(self):
        for desc, text, expected in self.CASES:
            with self.subTest(desc):
                self.assertEqual(planned_alerts(text), expected)


class TestNotStartedIsNotGood(unittest.TestCase):
    """A planned alert that never ran must not be reported as success."""

    def _a(self, alert_id, state):
        return {"alert_id": alert_id, "state": state, "reason": "",
                "terminal": True, "phase": ""}

    def test_not_started_fails_the_verdict(self):
        text, code = verdict([self._a("orca-1", "DONE"),
                              self._a("orca-2", NOT_STARTED)], finished=True)
        self.assertEqual(code, 1)
        self.assertIn("orca-2", text)

    def test_not_started_is_not_a_terminal_state_constant(self):
        # Mid-run it means "queued"; only a finished run makes it terminal, and
        # build_report applies that, not the constant.
        self.assertNotIn(NOT_STARTED, TERMINAL_STATES)


class TestClassifyChecks(unittest.TestCase):

    # Real check names as posted by the Orca GitHub App on the sandbox repo.
    ORCA_SAST = {"name": "Orca Security - SAST", "status": "completed",
                 "conclusion": "success", "id": 1,
                 "started_at": "2026-08-01T10:00:00Z",
                 "completed_at": "2026-08-01T10:00:34Z"}
    ORCA_VULN = {"name": "Orca Security - Vulnerabilities", "status": "completed",
                 "conclusion": "failure", "id": 2}
    CI_BUILD = {"name": "build", "status": "in_progress", "conclusion": None, "id": 3}

    CASES = [
        ("none", [], 0, 0),
        ("one orca check", [ORCA_SAST], 1, 0),
        ("two orca checks", [ORCA_SAST, ORCA_VULN], 2, 0),
        ("orca plus ci", [ORCA_SAST, CI_BUILD], 1, 1),
        ("ci only", [CI_BUILD], 0, 1),
    ]

    def test_split(self):
        for desc, runs, n_orca, n_other in self.CASES:
            with self.subTest(desc):
                out = classify_checks(runs)
                self.assertEqual(len(out["orca"]), n_orca)
                self.assertEqual(len(out["other"]), n_other)

    def test_none_conclusion_becomes_empty_string(self):
        # A running check has conclusion=None; the renderer falls back to
        # status, so None must not leak into the formatted output.
        out = classify_checks([self.CI_BUILD])
        self.assertEqual(out["other"][0]["conclusion"], "")
        self.assertEqual(out["other"][0]["status"], "in_progress")

    def test_matching_is_case_insensitive(self):
        out = classify_checks([{"name": "ORCA security - IaC"}])
        self.assertEqual(len(out["orca"]), 1)


class TestDuration(unittest.TestCase):

    CASES = [
        ("missing both", None, None, ""),
        ("missing end", "2026-08-01T10:00:00Z", None, ""),
        ("sub-minute", "2026-08-01T10:00:00Z", "2026-08-01T10:00:34Z", "34s"),
        ("exactly a minute", "2026-08-01T10:00:00Z", "2026-08-01T10:01:00Z", "1m00s"),
        ("minutes and seconds", "2026-08-01T10:00:00Z", "2026-08-01T10:02:05Z", "2m05s"),
        ("unparseable", "not-a-date", "also-not", ""),
        ("negative clamped", "2026-08-01T10:01:00Z", "2026-08-01T10:00:00Z", ""),
    ]

    def test_duration(self):
        for desc, start, end, expected in self.CASES:
            with self.subTest(desc):
                self.assertEqual(_duration(start, end), expected)


class TestVerdict(unittest.TestCase):

    def _a(self, alert_id, state, reason=""):
        return {"alert_id": alert_id, "state": state, "reason": reason,
                "terminal": state in TERMINAL_STATES, "phase": ""}

    def test_cases(self):
        CASES = [
            # An empty run means the loop tested nothing — almost always a
            # stale sandbox. Exit 2 distinguishes it from a real failure.
            ("no alerts", [], 2, "no alerts exercised"),
            ("single success", [self._a("orca-1", "DONE")], 0, "all good"),
            ("dry run", [self._a("orca-1", "PLANNED")], 0, "all good"),
            ("mixed good states",
             [self._a("orca-1", "DONE"), self._a("orca-2", "PLANNED")], 0, "all good"),
            ("one failure", [self._a("orca-1", "FAILED", "diff too large")], 1, "orca-1"),
            ("failure reason surfaced",
             [self._a("orca-1", "FAILED", "diff too large")], 1, "diff too large"),
            ("ci failure is not good", [self._a("orca-1", "CI_FAILED")], 1, "orca-1"),
            ("still running is not good", [self._a("orca-1", "RUNNING")], 1, "orca-1"),
            ("mixed", [self._a("orca-1", "DONE"), self._a("orca-2", "TIMED_OUT")], 1, "orca-2"),
        ]
        for desc, alerts, expected_code, expected_substr in CASES:
            with self.subTest(desc):
                text, code = verdict(alerts)
                self.assertEqual(code, expected_code, f"{desc}: exit code")
                self.assertIn(expected_substr, text, f"{desc}: message")

    def test_in_progress_cases(self):
        """A mid-run report must never read as a final answer.

        An agent polling every minute sees these; reporting exit 2 ("no alerts
        exercised") thirty seconds into a run would look like a broken loop.
        """
        running = dict(self._a("orca-1", "RUNNING"))
        running["phase"] = "waiting for CI checks"

        CASES = [
            ("nothing started yet", [], 1, "no alerts started yet"),
            ("one alert still moving", [running], 1, "waiting on orca-1"),
            ("phase surfaced for pending alert", [running], 1, "waiting for CI checks"),
            ("progress counted",
             [self._a("orca-1", "DONE"), running], 1, "1/2 settled"),
            # Every alert settled but the process has not exited — more alerts
            # may still be starting, so this is not a final verdict either.
            ("all settled, process still running",
             [self._a("orca-1", "DONE")], 1, "still wrapping up"),
        ]
        for desc, alerts, expected_code, expected_substr in CASES:
            with self.subTest(desc):
                text, code = verdict(alerts, finished=False)
                self.assertEqual(code, expected_code, f"{desc}: exit code")
                self.assertIn(expected_substr, text, f"{desc}: message")

    def test_finished_default_preserves_final_semantics(self):
        text, code = verdict([self._a("orca-1", "DONE")])
        self.assertEqual(code, 0)
        self.assertIn("all good", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
