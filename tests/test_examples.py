"""The examples suite: prove the examples work, or they are decoration.

Four checks, and each one answers a way an example rots:

* the offline twin example is **run** and its output compared — a query that
  stops working fails the build;
* `asserts.json` is validated against the assertion kinds the code really has
  (the file is documentation of the format, and a made-up kind would teach it
  wrong);
* every path `examples/README.md` names exists;
* the snapshot loads through `ghydra/twin.py`, from the version check to the md5,
  so the file is a valid snapshot and not just JSON that looks like one.

No Ghidra, no network, no binary.
"""

import io
import json
import os
import sys
import unittest

# The tests live in tests/; the code and the repository are one level up.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from click.testing import CliRunner  # noqa: E402

from ghydra import twin  # noqa: E402
from ghydra.cli.main import cli  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(ROOT, "examples")
SNAPSHOT = os.path.join(EXAMPLES, "twin", "example-snapshot.json")


def run(*arguments):
    """Run the CLI in-process and return (exit code, output)."""
    result = CliRunner().invoke(cli, list(arguments), catch_exceptions=False)
    return result.exit_code, result.output


class TwinExampleTests(unittest.TestCase):
    """The example that runs with nothing installed."""

    def test_the_overview_reads_the_snapshot(self):
        code, output = run("twin", "query", SNAPSHOT)
        self.assertEqual(0, code, output)
        self.assertIn("example.dll", output)
        self.assertIn("functions: 6", output)

    def test_a_name_search_finds_one_function(self):
        code, output = run("twin", "query", SNAPSHOT, "--kind", "functions",
                           "--match", "Parse")
        self.assertEqual(0, code, output)
        self.assertIn("1 of 1 matching", output)
        self.assertIn("ParseConfig", output)

    def test_a_function_is_found_by_name_and_reports_its_return_type(self):
        code, output = run("twin", "query", SNAPSHOT, "--kind", "function",
                           "--match", "ParseConfig")
        self.assertEqual(0, code, output)
        self.assertIn("ParseConfig @ 0x1800010a0 -> int", output)

    def test_an_import_is_found_case_insensitively(self):
        code, output = run("twin", "query", SNAPSHOT, "--kind", "imports",
                           "--match", "FILE")
        self.assertEqual(0, code, output)
        self.assertIn("CreateFileW", output)

    def test_the_snapshot_is_a_valid_snapshot(self):
        document = twin.load(SNAPSHOT)
        self.assertEqual(twin.TWIN_VERSION, document["twin_version"])
        self.assertEqual("0123456789abcdef0123456789abcdef",
                         document["program"]["md5"])
        self.assertEqual(6, document["counts"]["functions"])
        self.assertTrue(twin.as_diff_snapshot(document)["functions_complete"])

    def test_the_snapshot_says_it_is_synthetic(self):
        """An example that looks like a real analysis teaches the wrong thing."""
        text = io.open(os.path.join(EXAMPLES, "twin", "README.md"),
                       encoding="utf-8").read().lower()
        self.assertIn("synthetic", text)
        self.assertIn("not the analysis of anything", text)


class AssertionExampleTests(unittest.TestCase):
    """`asserts.json` documents the format; the format has to be the real one."""

    def setUp(self):
        with io.open(os.path.join(EXAMPLES, "asserts.json"), encoding="utf-8") as handle:
            self.assertions = json.load(handle)

    def test_every_assertion_has_an_id_a_kind_and_a_message(self):
        for assertion in self.assertions:
            self.assertIn("id", assertion)
            self.assertIn("kind", assertion)
            self.assertIn("message", assertion)

    def test_every_kind_is_one_the_code_understands(self):
        from ghydra.assertions import ASSERTION_KINDS
        for assertion in self.assertions:
            self.assertIn(assertion["kind"], ASSERTION_KINDS,
                          f"{assertion['id']} names a kind that does not exist")

    def test_the_ids_are_unique(self):
        ids = [assertion["id"] for assertion in self.assertions]
        self.assertEqual(len(ids), len(set(ids)))

    def test_the_file_is_a_list(self):
        self.assertIsInstance(self.assertions, list)
        self.assertGreater(len(self.assertions), 0)


class ExampleIndexTests(unittest.TestCase):
    """The index must not point at a file that is not there."""

    def test_every_path_the_index_names_exists(self):
        import re
        index = os.path.join(EXAMPLES, "README.md")
        text = io.open(index, encoding="utf-8").read()
        problems = []
        for target in sorted(set(re.findall(r"\]\(([^)]+)\)", text))):
            if target.startswith(("http://", "https://", "#")):
                continue
            path = os.path.join(EXAMPLES, target)
            if not os.path.exists(path):
                problems.append(target)
        self.assertEqual([], problems, f"examples/README.md names missing paths: {problems}")

    def test_every_shell_example_starts_with_a_shebang(self):
        for relative in ("mission/mission.sh", "fleet/fleet.sh"):
            path = os.path.join(EXAMPLES, relative)
            with io.open(path, encoding="utf-8") as handle:
                first = handle.readline()
            self.assertTrue(first.startswith("#!/usr/bin/env bash"),
                            f"{relative} has no shebang")


if __name__ == "__main__":
    unittest.main(verbosity=2)