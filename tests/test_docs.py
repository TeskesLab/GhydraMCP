#!/usr/bin/env python3
"""Tests for the documentation drift guard (I13).

Needs neither Ghidra nor a network. Run with:  python tests/test_docs.py
"""

import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import check_docs  # noqa: E402


class DocGuardTests(unittest.TestCase):

    def test_the_guard_passes_on_the_current_tree(self):
        result = subprocess.run(
            [sys.executable, "scripts/check_docs.py", "--report"],
            cwd=ROOT, capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("OK:", result.stdout)

    def test_bridge_surface_is_internally_consistent(self):
        surface = check_docs.bridge_surface()
        self.assertGreater(surface["tools"], 100)
        self.assertEqual(surface["tools"], surface["formatters"])
        # The namespace count is whatever the code has; the docs must follow
        # it, so only sanity-bound it here (check_docs compares the docs).
        self.assertGreaterEqual(surface["namespaces"], 28)
        self.assertEqual(3, surface["prompts"])
        self.assertEqual(12, surface["resources"])

    def test_a_wrong_tool_count_is_reported(self):
        surface = {"tools": 111, "formatters": 111, "namespaces": 28}
        problems = check_docs.compare_counts(
            surface, {"README.md": (99, 24), "AGENTS.md": (111, 28)})
        self.assertTrue(any("99" in problem for problem in problems))
        self.assertTrue(any("24" in problem for problem in problems))

    def test_a_formatter_gap_is_reported(self):
        surface = {"tools": 111, "formatters": 82, "namespaces": 28}
        problems = check_docs.compare_counts(surface, {"README.md": (111, 28)})
        self.assertTrue(any("FORMATTERS" in problem for problem in problems))

    def test_a_missing_doc_line_is_reported(self):
        surface = {"tools": 111, "formatters": 111, "namespaces": 28}
        problems = check_docs.compare_counts(surface, {"AGENTS.md": None})
        self.assertTrue(problems)

    def test_the_sixth_version_copy_is_not_hardcoded(self):
        self.assertTrue(check_docs.version_copy_ok())


if __name__ == "__main__":
    unittest.main(verbosity=2)
