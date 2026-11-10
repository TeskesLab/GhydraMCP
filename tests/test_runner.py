#!/usr/bin/env python3
"""Tests for the test runner itself (I6: honest CI).

Needs neither Ghidra nor any external binary. The point is that `run_tests.py`
must be able to run several suites in one invocation and that `--no-ghidra`
covers exactly the suites that always give a real signal.

Run with:  python tests/test_runner.py
"""

import glob
import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import run_tests  # noqa: E402


class RunnerContractTests(unittest.TestCase):

    def test_no_ghidra_suites_are_all_registered(self):
        self.assertTrue(run_tests.NO_GHIDRA_SUITES)
        for flag in run_tests.NO_GHIDRA_SUITES:
            with self.subTest(flag=flag):
                self.assertIn(flag, run_tests.SUITES)
                self.assertTrue(callable(run_tests.SUITES[flag]))

    def test_every_suite_flag_maps_to_a_callable(self):
        for flag, runner in run_tests.SUITES.items():
            with self.subTest(flag=flag):
                self.assertTrue(flag.startswith("--"))
                self.assertTrue(callable(runner))

    def test_several_flags_run_every_selected_suite(self):
        """The old runner only looked at sys.argv[1]; combining flags is new.

        The suites are the cheap ones on purpose: this asserts that two flags both
        run, and it runs inside the runner, so anything heavy here is a nested
        process tree whose timeout measures the machine rather than the contract.
        """
        result = subprocess.run(
            [sys.executable, "run_tests.py", "--docs", "--examples"],
            cwd=ROOT, capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("--docs: PASSED", result.stdout)
        self.assertIn("--examples: PASSED", result.stdout)

    def test_every_suite_lives_in_the_tests_directory(self):
        """A test file at the repository root is the clutter this layout removed."""
        root_suites = sorted(
            os.path.basename(item)
            for item in glob.glob(os.path.join(ROOT, "test_*.py")))
        self.assertEqual([], root_suites,
                         "test suites belong in tests/, not at the root")

    def test_the_runner_points_at_a_file_that_exists(self):
        """`suite_script` builds a path; a renamed suite must not go silent."""
        with open(os.path.join(ROOT, "run_tests.py"), encoding="utf-8") as handle:
            runner = handle.read()
        names = sorted(set(re.findall(r'suite_script\("(test_[a-z_]+\.py)"\)',
                                     runner)))
        self.assertGreater(len(names), 20, "the scan found no suites")
        missing = [name for name in names
                   if not os.path.exists(os.path.join(run_tests.TESTS_DIR, name))]
        self.assertEqual([], missing, f"the runner names missing suites: {missing}")

    def test_the_suites_directory_holds_the_suites(self):
        found = glob.glob(os.path.join(run_tests.TESTS_DIR, "test_*.py"))
        self.assertGreaterEqual(len(found), 30,
                                "tests/ does not look like the suite directory")

    def test_unknown_flag_is_rejected_with_usage(self):
        result = subprocess.run(
            [sys.executable, "run_tests.py", "--not-a-suite"],
            cwd=ROOT, capture_output=True, text=True, timeout=60,
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("Unknown argument", result.stdout + result.stderr)
        self.assertIn("Usage:", result.stdout + result.stderr)


class UsageTests(unittest.TestCase):
    """The line that says what the runner accepts, built from what it accepts."""

    def test_every_suite_is_in_the_usage(self):
        """A suite that works but is not in the line cannot be discovered."""
        import run_tests

        for flag in run_tests.SUITES:
            self.assertIn(flag, run_tests.USAGE,
                          f"{flag} works but the usage does not mention it")

    def test_the_usage_names_no_suite_that_does_not_exist(self):
        import re

        import run_tests

        # A flag may carry digits (--x64dbg), so the pattern takes them.
        named = set(re.findall(r"--[a-z][a-z0-9-]*", run_tests.USAGE))
        for flag in named:
            if flag in ("--no-ghidra", "--require-live"):
                continue
            self.assertIn(flag, run_tests.SUITES,
                          f"the usage names {flag}, which is not a suite")

    def test_the_usage_is_built_from_the_suites(self):
        """A hand-written line is how it drifted in the first place."""
        import run_tests

        self.assertEqual(run_tests.build_usage(), run_tests.USAGE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
