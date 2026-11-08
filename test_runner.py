#!/usr/bin/env python3
"""Tests for the test runner itself (I6: honest CI).

Needs neither Ghidra nor any external binary. The point is that `run_tests.py`
must be able to run several suites in one invocation and that `--no-ghidra`
covers exactly the suites that always give a real signal.

Run with:  python test_runner.py
"""

import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.abspath(__file__))
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
        """The old runner only looked at sys.argv[1]; combining flags is new."""
        result = subprocess.run(
            [sys.executable, "run_tests.py", "--surface", "--scripts"],
            cwd=ROOT, capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("--surface: PASSED", result.stdout)
        self.assertIn("--scripts: PASSED", result.stdout)

    def test_unknown_flag_is_rejected_with_usage(self):
        result = subprocess.run(
            [sys.executable, "run_tests.py", "--not-a-suite"],
            cwd=ROOT, capture_output=True, text=True, timeout=60,
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("Unknown argument", result.stdout + result.stderr)
        self.assertIn("Usage:", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
