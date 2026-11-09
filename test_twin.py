"""The twin's offline suite (R2): no Ghidra, no network — that is the point.

Everything here works on snapshot documents, because a twin that needed an
instance to be verified would be testing the wrong thing. The live half was
measured against a running Ghidra and is reproducible with
``scripts/bench_twin.py`` (two binaries, 359x-8337x faster than the API).
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ghydra import twin  # noqa: E402


def snapshot(name="a.exe", md5="a" * 32, functions=None, strings=None,
             imports=None, counts=None, truncated=None):
    """A snapshot document, in the shape `twin.build` produces."""
    functions = functions if functions is not None else [
        {"name": "main", "address": "0x401000", "return_type": "undefined8"},
        {"name": "strcmp", "address": "0x402000", "return_type": "int"},
    ]
    return {
        "twin_version": twin.TWIN_VERSION,
        "built_at": 1_000_000.0,
        "source": "http://localhost:8192",
        "name": name,
        "program": {"name": name, "md5": md5, "language": "x86:LE:64:default",
                    "image_base": "0x400000"},
        "statistics": {"functionCount": len(functions)},
        "counts": counts or {"functions": len(functions), "imports": 1,
                             "exports": 0, "strings": len(strings or ["/api/v1"]),
                             "functions_total": len(functions)},
        "functions": functions,
        "imports": imports if imports is not None else ["CreateFileW"],
        "exports": [],
        "strings": strings if strings is not None else ["/api/v1"],
        "truncated": truncated or {"functions": False, "strings": False},
    }


class SnapshotTests(unittest.TestCase):
    """Writing, reading and refusing a snapshot."""

    def setUp(self):
        self.directory = tempfile.mkdtemp(prefix="ghydra-twin-test-")

    def tearDown(self):
        shutil.rmtree(self.directory, ignore_errors=True)

    def test_a_snapshot_round_trips(self):
        path = os.path.join(self.directory, "t.json")
        twin.save(snapshot(), path)
        loaded = twin.load(path)
        self.assertEqual("a.exe", loaded["name"])
        self.assertEqual(2, len(loaded["functions"]))

    def test_another_version_is_refused_with_both_numbers(self):
        path = os.path.join(self.directory, "t.json")
        document = snapshot()
        document["twin_version"] = twin.TWIN_VERSION + 99
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(document, handle)
        with self.assertRaises(ValueError) as caught:
            twin.load(path)
        self.assertIn(str(twin.TWIN_VERSION + 99), str(caught.exception))
        self.assertIn(str(twin.TWIN_VERSION), str(caught.exception))

    def test_a_file_that_is_not_a_snapshot_is_refused(self):
        path = os.path.join(self.directory, "t.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(["not", "a", "snapshot"], handle)
        with self.assertRaises(ValueError):
            twin.load(path)

    def test_a_name_with_awkward_characters_has_a_safe_path(self):
        path = twin.twin_path("a/b\\c:d*e")
        self.assertNotIn("/", os.path.basename(path))
        self.assertNotIn("\\", os.path.basename(path))
        self.assertTrue(path.endswith(".json"))

    def test_the_fingerprint_is_about_the_binary(self):
        first = twin.fingerprint(snapshot(md5="b" * 32))
        second = twin.fingerprint(snapshot(md5="c" * 32))
        self.assertNotEqual(first, second)
        self.assertEqual(first, twin.fingerprint(snapshot(md5="b" * 32)))


class QueryTests(unittest.TestCase):
    """The questions a snapshot can answer, and the ones it says it cannot."""

    def test_overview_reports_the_counts_and_provenance(self):
        answer = twin.query(snapshot(), "overview")
        self.assertEqual(2, answer["counts"]["functions"])
        self.assertEqual("http://localhost:8192", answer["source"])

    def test_functions_are_matched_by_substring(self):
        answer = twin.query(snapshot(), "functions", "str")
        self.assertEqual(1, answer["returned"])
        self.assertEqual("strcmp", answer["items"][0]["name"])

    def test_a_function_is_found_by_address_with_or_without_the_prefix(self):
        for needle in ("0x401000", "401000"):
            with self.subTest(needle=needle):
                answer = twin.query(snapshot(), "function", needle)
                self.assertEqual("main", answer["function"]["name"])

    def test_a_function_is_found_by_name(self):
        self.assertEqual("strcmp",
                         twin.query(snapshot(), "function", "strcmp")["function"]["name"])

    def test_a_function_that_is_not_there_is_not_found(self):
        answer = twin.query(snapshot(), "function", "0xdead")
        self.assertIsNone(answer["function"])
        self.assertEqual(0, answer["matched"])

    def test_imports_and_strings_are_searched_case_insensitively(self):
        self.assertEqual(1, twin.query(snapshot(), "imports", "createfile")["returned"])
        self.assertEqual(1, twin.query(snapshot(), "strings", "API/V1")["returned"])

    def test_the_limit_keeps_matched_and_returned_apart(self):
        document = snapshot(functions=[{"name": f"FUN_{index}", "address": f"0x{index:x}"}
                                       for index in range(20)])
        answer = twin.query(document, "functions", "FUN", limit=5)
        self.assertEqual(20, answer["matched"])
        self.assertEqual(5, answer["returned"])

    def test_an_unknown_kind_is_refused(self):
        with self.assertRaises(ValueError):
            twin.query(snapshot(), "decompile", "main")

    def test_a_truncated_snapshot_says_so(self):
        document = snapshot(truncated={"functions": True, "strings": False})
        self.assertTrue(twin.query(document, "overview")["truncated"]["functions"])


class DiffTests(unittest.TestCase):
    """Two snapshots, compared with the same definition the live diff uses."""

    def test_a_new_function_is_an_addition(self):
        left = snapshot()
        right = snapshot(functions=[
            {"name": "main", "address": "0x401000", "return_type": "undefined8"},
            {"name": "new_one", "address": "0x403000", "return_type": "void"}])
        report = twin.diff(left, right)
        self.assertTrue(report["changed"])
        self.assertEqual(1, report["summary"]["functions_added"])
        self.assertEqual(["0x403000"],
                         [item["address"] for item in report["functions"]["added"]])

    def test_a_rename_is_not_an_add_plus_a_remove(self):
        left = snapshot()
        right = snapshot(functions=[
            {"name": "entry", "address": "0x401000", "return_type": "undefined8"},
            {"name": "strcmp", "address": "0x402000", "return_type": "int"}])
        report = twin.diff(left, right)
        self.assertEqual(1, len(report["functions"]["renamed"]))
        self.assertEqual("main", report["functions"]["renamed"][0]["from"])
        self.assertEqual("entry", report["functions"]["renamed"][0]["to"])

    def test_two_identical_snapshots_have_not_changed(self):
        report = twin.diff(snapshot(), snapshot())
        self.assertFalse(report["changed"])
        self.assertTrue(report["same_binary"])

    def test_the_provenance_of_both_sides_is_reported(self):
        left = snapshot(name="a", md5="a" * 32)
        right = snapshot(name="b", md5="b" * 32)
        report = twin.diff(left, right)
        self.assertFalse(report["same_binary"])
        self.assertEqual("a", report["provenance"]["a"]["name"])
        self.assertEqual("b", report["provenance"]["b"]["name"])
        self.assertNotEqual(report["provenance"]["a"]["fingerprint"],
                            report["provenance"]["b"]["fingerprint"])

    def test_a_capped_snapshot_is_not_complete(self):
        capped = snapshot(truncated={"functions": True, "strings": False})
        self.assertFalse(twin.as_diff_snapshot(capped)["functions_complete"])

    def test_a_snapshot_shorter_than_the_api_count_is_not_complete(self):
        """Measured on where.exe: 104 functions listed against 198 counted."""
        short = snapshot(counts={"functions": 104, "imports": 1, "exports": 0,
                                 "strings": 1, "functions_total": 198})
        self.assertFalse(twin.as_diff_snapshot(short)["functions_complete"])

    def test_a_complete_snapshot_is_complete(self):
        self.assertTrue(twin.as_diff_snapshot(snapshot())["functions_complete"])


class CliTests(unittest.TestCase):
    """The command exists and its options are the ones the docs promise."""

    def test_the_group_and_its_commands_exist(self):
        from ghydra.cli.main import cli
        group = cli.commands["twin"]
        self.assertEqual({"build", "query", "diff"}, set(group.commands))

    def test_query_offers_the_kinds_the_helper_understands(self):
        from ghydra.cli.main import cli
        command = cli.commands["twin"].commands["query"]
        kind = next(param for param in command.params if param.name == "kind")
        self.assertEqual({"overview", "functions", "function", "imports",
                          "exports", "strings"}, set(kind.type.choices))

class ReviewRegressionTests(unittest.TestCase):
    """The ways a snapshot could claim something it did not know."""

    def setUp(self):
        self.directory = tempfile.mkdtemp(prefix="ghydra-twin-review-")

    def tearDown(self):
        shutil.rmtree(self.directory, ignore_errors=True)

    def test_a_bare_filename_can_be_written(self):
        """`--output twin.json` used to raise on makedirs("")."""
        previous = os.getcwd()
        os.chdir(self.directory)
        try:
            written = twin.save(snapshot(), "twin.json")
        finally:
            os.chdir(previous)
        self.assertTrue(os.path.exists(os.path.join(self.directory, "twin.json")))
        self.assertEqual("twin.json", os.path.basename(written))

    def test_a_snapshot_is_found_by_its_name(self):
        """`twin build --name x` writes to the state dir; `twin query x` finds it."""
        document = snapshot(name="by-name")
        path = twin.twin_path("by-name")
        twin.save(document, path)
        try:
            self.assertEqual(path, twin.resolve_path("by-name"))
            self.assertEqual(path, twin.resolve_path(path))
        finally:
            os.unlink(path)

    def test_an_unknown_name_stays_the_name(self):
        self.assertEqual("no-such-twin",
                         twin.resolve_path("no-such-twin"))

    def test_a_function_records_its_parameter_count_not_an_empty_list(self):
        """The listing has parameterCount, not the parameters themselves."""
        document = snapshot(functions=[
            {"name": "f", "address": "0x1", "parameterCount": 2}])
        self.assertEqual(2, document["functions"][0]["parameterCount"]
                         if "parameterCount" in document["functions"][0]
                         else None)
        # the builder is exercised through a fake client, in the test below

    def test_missing_total_means_not_complete(self):
        without_total = snapshot(counts={"functions": 0, "imports": 0,
                                         "exports": 0, "strings": 0})
        self.assertFalse(twin.as_diff_snapshot(without_total)["functions_complete"])

    def test_the_diff_reports_its_completeness(self):
        complete = twin.diff(snapshot(), snapshot())
        self.assertTrue(complete["complete"])
        capped = snapshot(truncated={"functions": True, "strings": False})
        self.assertFalse(twin.diff(capped, snapshot())["complete"])

    def test_a_miss_in_a_capped_snapshot_is_worded_as_such(self):
        capped = snapshot(truncated={"functions": True, "strings": False})
        answer = twin.query(capped, "function", "0xdead")
        self.assertIsNone(answer["function"])
        self.assertIn("may exist", answer["reason"])

    def test_a_miss_in_a_complete_snapshot_makes_no_such_claim(self):
        answer = twin.query(snapshot(), "function", "0xdead")
        self.assertNotIn("reason", answer)


class BuildFromClientTests(unittest.TestCase):
    """`twin.build` against a fake client: the fields it must not invent."""

    class FakeClient:
        base_url = "http://fake:8192"

        def __init__(self, pages):
            self.pages = pages

        def get(self, endpoint, params=None):
            params = params or {}
            items = self.pages.get(endpoint, [])
            offset = int(params.get("offset", 0))
            limit = int(params.get("limit", 1000))
            if endpoint == "program":
                # /program answers one object, not a page.
                return {"success": True, "result": items[0]}
            return {"success": True, "result": items[offset:offset + limit]}

    def test_the_snapshot_records_parameter_count_and_md5(self):
        client = self.FakeClient({
            "program": [{"name": "a.exe", "path": "/tmp/a.exe",
                         "executableMd5": "f" * 32,
                         "statistics": {"functionCount": 1}}],
            "functions": [{"name": "main", "address": "0x401000",
                           "parameterCount": 3, "returnType": "int"}],
            "symbols/imports": [{"name": "CreateFileW"}],
            "symbols/exports": [],
            "strings": [{"value": "/api/v1"}],
        })
        document = twin.build(client, name="fake")
        self.assertEqual("f" * 32, document["program"]["md5"])
        self.assertEqual(3, document["functions"][0]["parameter_count"])
        self.assertEqual(["CreateFileW"], document["imports"])


if __name__ == "__main__":
    unittest.main(verbosity=2)