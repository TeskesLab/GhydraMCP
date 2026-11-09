#!/usr/bin/env python3
"""Tests for the single-core mechanism (I1).

The bridge ships as one file and cannot import ``ghydra``, so the shared pure
helpers are *generated* into it by ``scripts/gen_core.py``. What these tests pin
down is the property that makes that safe:

* the generated region is **current** — a core change that was not regenerated
  fails here, which is the drift the mechanism exists to prevent;
* the generated code is **identical** to the core's behaviour;
* the bridge's named helpers are **delegations**, not second copies.

Run with:  python test_core.py
"""

import os
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bridge_mcp_hydra as bridge  # noqa: E402
from ghydra.core import digest as core  # noqa: E402
from ghydra.core import cache as cache_core  # noqa: E402
from ghydra.core import diff as diff_core  # noqa: E402
from ghydra.core import hints as hints_core  # noqa: E402
from ghydra.core import runbook as runbook_core  # noqa: E402
from scripts import gen_core  # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))


def _bridge_text():
    with open(os.path.join(ROOT, "bridge_mcp_hydra.py"), encoding="utf-8") as handle:
        return handle.read()


class GenerationTests(unittest.TestCase):
    def test_the_generated_region_is_current(self):
        """A core change that was not regenerated must fail, not drift."""
        result = subprocess.run(
            [sys.executable, os.path.join("scripts", "gen_core.py"), "--check"],
            cwd=ROOT, capture_output=True, text=True, timeout=120)
        self.assertEqual(0, result.returncode,
                         (result.stdout or "") + (result.stderr or ""))
        self.assertIn("current", result.stdout)

    def test_every_core_module_is_generated_exactly_once(self):
        text = _bridge_text()
        for module in gen_core.CORE_MODULES:
            with self.subTest(module=module):
                begin = gen_core.BEGIN.format(source=module, digest="").split(" (")[0]
                self.assertEqual(1, text.count(begin))
                self.assertEqual(1, text.count(gen_core.END.format(source=module)))

    def test_the_region_is_byte_identical_to_a_fresh_generation(self):
        """The property the --check runs on, asserted directly."""
        text = _bridge_text()
        for module in gen_core.CORE_MODULES:
            with self.subTest(module=module):
                region = gen_core._region(module)
                self.assertIn(region, text)

    def test_the_generated_names_are_the_private_core_ones(self):
        text = _bridge_text()
        for name in ("_core_canonical", "_core_digest", "_core_stable_result"):
            with self.subTest(name=name):
                self.assertIn(f"def {name}(", text)

    def test_a_stale_region_is_detected(self):
        """The check must actually fail when the bridge disagrees with the core."""
        text = _bridge_text()
        tampered = text.replace("def _core_digest(value):",
                                "def _core_digest(value):  # tampered\n    ''", 1)
        original = gen_core._bridge_text
        gen_core._bridge_text = lambda: tampered
        try:
            with open(os.path.join(ROOT, "bridge_mcp_hydra.py"), encoding="utf-8") as handle:
                del handle  # the patched reader is what --check uses
            code = gen_core.main(["--check"])
        finally:
            gen_core._bridge_text = original
        self.assertEqual(1, code)


class ParityTests(unittest.TestCase):
    """The generated copy must behave exactly like the core."""

    VALUES = (
        {"a": 1, "b": [2, 3]},
        [1, 2, 3],
        "text",
        {"nested": {"b": [2, 1], "a": None}},
        {"unicode": "café 雪"},
        {},
        None,
    )

    def test_the_digest_agrees(self):
        for value in self.VALUES:
            with self.subTest(value=value):
                self.assertEqual(core.digest(value), bridge._core_digest(value))

    def test_the_canonical_text_agrees(self):
        for value in self.VALUES:
            with self.subTest(value=value):
                self.assertEqual(core.canonical(value),
                                 bridge._core_canonical(value))

    def test_the_stable_view_agrees(self):
        envelope = {"success": True, "id": "1", "timestamp": 2,
                    "instance": "http://x", "_links": {"self": {}},
                    "result": {"name": "f", "address": "0x1"}}
        self.assertEqual(core.stable_result(envelope),
                         bridge._core_stable_result(envelope))


class CanonicalTests(unittest.TestCase):
    def test_the_key_order_does_not_matter(self):
        self.assertEqual(core.digest({"a": 1, "b": 2}),
                         core.digest({"b": 2, "a": 1}))

    def test_a_different_value_is_a_different_digest(self):
        self.assertNotEqual(core.digest({"a": 1}), core.digest({"a": 2}))

    def test_unicode_is_kept_verbatim(self):
        self.assertIn("café 雪", core.canonical({"k": "café 雪"}))

    def test_the_volatile_keys_are_dropped(self):
        payload = {"result": {"name": "f", "id": "x", "timestamp": 3,
                              "instance": 1, "_links": {}, "api_links": {}}}
        self.assertEqual({"name": "f"}, core.stable_result(payload))

    def test_a_widened_volatile_set_is_honoured(self):
        payload = {"result": {"name": "f", "address": "0x1"}}
        self.assertEqual({"name": "f"},
                         core.stable_result(payload, ["address"]))

    def test_an_envelope_without_a_result_is_the_payload(self):
        self.assertEqual({"name": "f"}, core.stable_result({"name": "f",
                                                            "id": "drop"}))

    def test_a_non_dict_passes_through(self):
        for value in ("text", [1, 2], None, 7):
            with self.subTest(value=value):
                self.assertEqual(value, core.stable_result(value))


class DelegationTests(unittest.TestCase):
    """The bridge's named helpers are thin delegations, not second copies."""

    def test_the_bridge_keeps_one_definition_of_the_digest(self):
        text = _bridge_text()
        # One in the generated core; the named helpers only call it.
        self.assertEqual(1, text.count("hashlib.sha256(_core_canonical"))
        self.assertIn("return _core_digest(value)", text)
        self.assertIn("return _core_canonical(value)", text)

    def test_the_runbook_digest_is_the_core_digest(self):
        for value in ParityTests.VALUES:
            with self.subTest(value=value):
                self.assertEqual(bridge._core_digest(value),
                                 bridge._runbook_digest(value))

    def test_the_cache_digest_is_the_core_digest(self):
        for value in ParityTests.VALUES:
            with self.subTest(value=value):
                self.assertEqual(bridge._core_digest(value),
                                 bridge._cache_digest(value))

    def test_the_runbook_stable_view_uses_the_runbook_key_set(self):
        envelope = {"success": True, "result": {"name": "f", "id": "x"}}
        self.assertEqual({"name": "f"},
                         bridge._runbook_stable_result(envelope))
        self.assertIn("_RUNBOOK_VOLATILE_KEYS", bridge._runbook_stable_result.__code__.co_names)

class RunbookCoreTests(unittest.TestCase):
    """The step rules live once, in the core, and both surfaces obey them."""

    def test_the_validation_agrees(self):
        documents = (
            [{"endpoint": "program"}],
            [{"endpoint": " functions/0x1 ", "method": "patch",
              "params": {"a": 1}, "payload": {"b": 2}}],
            {"steps": [{"endpoint": "program", "method": "GET"}]},
        )
        for document in documents:
            with self.subTest(document=document):
                self.assertEqual(runbook_core.validate_steps(document),
                                 bridge._core_validate_steps(document))

    def test_the_same_documents_are_refused(self):
        for document in ([], {}, "not a list", [{"method": "GET"}],
                         [{"endpoint": "x", "method": "BREW"}], ["nope"]):
            with self.subTest(document=document):
                with self.assertRaises(ValueError):
                    runbook_core.validate_steps(document)
                with self.assertRaises(ValueError):
                    bridge._core_validate_steps(document)

    def test_the_failure_names_the_step(self):
        with self.assertRaises(runbook_core.BadEntry) as caught:
            runbook_core.validate_steps([{"endpoint": "a"},
                                         {"endpoint": "b", "method": "BREW"}])
        self.assertIn("step #2", str(caught.exception))
        self.assertIn("BREW", str(caught.exception))

    def test_the_exceptions_subclass_value_error(self):
        """The bridge's callers catch ValueError; the core's types must satisfy it."""
        self.assertTrue(issubclass(runbook_core.BadSteps, ValueError))
        self.assertTrue(issubclass(runbook_core.BadEntry, ValueError))
        self.assertTrue(issubclass(bridge._CoreBadSteps, ValueError))
        self.assertTrue(issubclass(bridge._CoreBadEntry, ValueError))

    def test_the_bridge_reads_text_and_paths_through_the_same_rule(self):
        text = bridge._runbook_load_steps('[{"endpoint": "program"}]')
        self.assertEqual([{"endpoint": "program", "method": "GET",
                           "params": None, "payload": None}], text)
        import json as _json
        import tempfile
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                             encoding="utf-8")
        try:
            _json.dump({"steps": [{"endpoint": "functions"}]}, handle)
            handle.close()
            from_path = bridge._runbook_load_steps(handle.name)
        finally:
            import os as _os
            _os.unlink(handle.name)
        self.assertEqual("functions", from_path[0]["endpoint"])

    def test_the_bridge_keeps_no_second_copy_of_the_rules(self):
        text = _bridge_text()
        self.assertIn("return _core_validate_steps(data)", text)
        self.assertEqual(1, text.count("expected a non-empty list of steps"))
        self.assertEqual(1, text.count("unknown method"))


class HintsCoreTests(unittest.TestCase):
    """The goal hints live once, in the core."""

    GOALS = (
        "does data from recv reach system?",
        "does data from ReadFile reach WinExec",
        "o que faz esta funcao main",
        "what is at 0x401000",
        "what does this binary do",
        "",
        None,
    )

    def test_the_hints_agree(self):
        for goal in self.GOALS:
            with self.subTest(goal=goal):
                self.assertEqual(hints_core.parse_goal(goal),
                                 bridge._core_parse_goal(goal))

    def test_the_bridge_delegates_to_the_core(self):
        for goal in self.GOALS:
            with self.subTest(goal=goal):
                self.assertEqual(bridge._core_parse_goal(goal),
                                 bridge._mission_parse_goal(goal))

    def test_the_patterns_are_the_core_ones(self):
        self.assertEqual(set(hints_core.HINT_PATTERNS),
                         set(bridge._CORE_HINT_PATTERNS))
        self.assertEqual(hints_core.HINT_PATTERNS,
                         bridge._CORE_HINT_PATTERNS)
        self.assertIs(bridge._MISSION_HINT_PATTERNS, bridge._CORE_HINT_PATTERNS)

    def test_a_goal_without_hints_yields_nothing(self):
        self.assertEqual({}, hints_core.parse_goal("what does this binary do"))

    def test_source_and_sink_are_read_in_both_languages(self):
        self.assertEqual({"source": "recv", "sink": "system"},
                         hints_core.parse_goal("does data from recv reach system?"))
        self.assertEqual({"source": "ReadFile", "sink": "WinExec"},
                         hints_core.parse_goal("de ReadFile até WinExec"))

class CacheCoreTests(unittest.TestCase):
    """The cache key and the program identity live once, in the core."""

    PROGRAM = {
        "programId": "proj:/a.exe", "path": "/tmp/a.exe",
        "language": "x86:LE:64:default", "imageBase": "0x400000",
        "creationDate": "Mon Jan 01 2024",
        "statistics": {"functionCount": 10, "symbolCount": 20,
                       "memoryBlockCount": 4, "notAKey": 1},
        "ignored": "not part of the identity",
    }

    def test_the_identity_agrees(self):
        self.assertEqual(cache_core.identity_from_program(self.PROGRAM),
                         bridge._core_cache_identity(self.PROGRAM))

    def test_the_identity_keeps_the_statistics_and_drops_the_rest(self):
        identity = cache_core.identity_from_program(self.PROGRAM)
        self.assertEqual(10, identity["statistics"]["functionCount"])
        self.assertNotIn("notAKey", identity["statistics"])
        self.assertNotIn("ignored", identity)

    def test_a_program_that_is_not_a_dict_has_no_identity(self):
        for value in (None, [], "x", 7):
            with self.subTest(value=value):
                self.assertEqual({}, cache_core.identity_from_program(value))
                self.assertEqual({}, bridge._core_cache_identity(value))

    def test_the_key_agrees(self):
        identity = cache_core.identity_from_program(self.PROGRAM)
        request = {"endpoint": "functions/0x1/decompile",
                   "params": {"style": "normalize"}}
        self.assertEqual(cache_core.cache_key(identity, "decompile", request),
                         bridge._core_cache_key(identity, "decompile", request))

    def test_a_different_program_is_a_different_key(self):
        base = cache_core.identity_from_program(self.PROGRAM)
        other = dict(base, programId="proj:/b.exe")
        self.assertNotEqual(cache_core.cache_key(base, "decompile", {}),
                            cache_core.cache_key(other, "decompile", {}))

    def test_an_edited_program_is_a_different_key(self):
        base = cache_core.identity_from_program(self.PROGRAM)
        edited = cache_core.identity_from_program(dict(
            self.PROGRAM, statistics={"symbolCount": 21}))
        self.assertNotEqual(cache_core.cache_key(base, "decompile", {}),
                            cache_core.cache_key(edited, "decompile", {}))

    def test_a_different_question_is_a_different_key(self):
        identity = cache_core.identity_from_program(self.PROGRAM)
        self.assertNotEqual(cache_core.cache_key(identity, "decompile", {"page": 1}),
                            cache_core.cache_key(identity, "decompile", {"page": 2}))


class CacheDelegationTests(unittest.TestCase):
    """The bridge delegates; the constants have one source."""

    def test_the_bridge_key_is_the_core_key(self):
        identity = {"programId": "p"}
        request = {"endpoint": "x"}
        self.assertEqual(bridge._core_cache_key(identity, "decompile", request),
                         bridge._cache_key(identity, "decompile", request))

    def test_the_version_constant_comes_from_the_core(self):
        self.assertEqual(bridge._CORE_CACHE_VERSION, bridge._CACHE_VERSION)
        self.assertEqual(cache_core.CACHE_VERSION, bridge._CORE_CACHE_VERSION)

    def test_the_field_tuples_come_from_the_core(self):
        self.assertEqual(cache_core.IDENTITY_FIELDS, bridge._CORE_CACHE_IDENTITY_FIELDS)
        self.assertEqual(cache_core.STATISTIC_FIELDS, bridge._CORE_CACHE_STATISTIC_FIELDS)
        self.assertIs(bridge._CACHE_IDENTITY_FIELDS, bridge._CORE_CACHE_IDENTITY_FIELDS)
        self.assertIs(bridge._CACHE_STATISTIC_FIELDS, bridge._CORE_CACHE_STATISTIC_FIELDS)

    def test_the_bridge_keeps_no_second_copy_of_the_identity_fields(self):
        text = _bridge_text()
        self.assertEqual(1, text.count('"programId", "path", "executablePath"'))


class GeneratorGuardTests(unittest.TestCase):
    """The generator refuses a region that would be a NameError at import."""

    def test_the_bridge_imports_are_known(self):
        available = gen_core._bridge_imports()
        for name in ("json", "hashlib", "re", "os", "time"):
            with self.subTest(name=name):
                self.assertIn(name, available)

    def test_an_import_the_bridge_lacks_is_reported(self):
        with mock.patch.object(gen_core, "_imported_names",
                               return_value={"mystery"}), \
                mock.patch.object(gen_core, "_bridge_imports",
                                  return_value={"json"}), \
                mock.patch.dict(gen_core.CORE_RENAMES,
                                {"ghydra/core/digest.py": {}}):
            unresolved = gen_core._unresolved_imports(
                "ghydra/core/digest.py",
                "def f():\n    return mystery(1)\n")
        self.assertEqual({"mystery"}, unresolved)

    def test_an_import_the_bridge_has_is_allowed(self):
        with mock.patch.object(gen_core, "_imported_names",
                               return_value={"json"}), \
                mock.patch.object(gen_core, "_bridge_imports",
                                  return_value={"json"}), \
                mock.patch.dict(gen_core.CORE_RENAMES,
                                {"ghydra/core/digest.py": {}}):
            self.assertEqual(set(), gen_core._unresolved_imports(
                "ghydra/core/digest.py",
                "def f(v):\n    return json.dumps(v)\n"))

    def test_a_renamed_import_is_allowed(self):
        with mock.patch.object(gen_core, "_imported_names",
                               return_value={"digest"}), \
                mock.patch.object(gen_core, "_bridge_imports",
                                  return_value=set()), \
                mock.patch.dict(gen_core.CORE_RENAMES,
                                {"ghydra/core/digest.py": {"digest": "_core_digest"}}):
            self.assertEqual(set(), gen_core._unresolved_imports(
                "ghydra/core/digest.py", "def f(v):\n    return _core_digest(v)\n"))

    def test_every_region_generates_without_a_guard_failure(self):
        for module in gen_core.CORE_MODULES:
            with self.subTest(module=module):
                self.assertTrue(gen_core._region(module).startswith("# >>> generated"))

class DiffCoreTests(unittest.TestCase):
    """The comparison lives once, in the core, and both surfaces use it."""

    def _pair(self):
        a = {"program": {"name": "a.exe"},
             "functions": [{"address": "0x1", "name": "main"},
                           {"address": "0x2", "name": "gone"}],
             "imports": ["A", "B"], "strings": ["s1"],
             "functions_complete": True}
        b = {"program": {"name": "b.exe"},
             "functions": [{"address": "0x1", "name": "entry"},
                           {"address": "0x3", "name": "new"}],
             "imports": ["A", "C"], "strings": ["s1", "s2"],
             "functions_complete": True}
        return a, b

    def test_the_comparison_agrees(self):
        a, b = self._pair()
        self.assertEqual(diff_core.diff_snapshots(a, b),
                         bridge._core_diff_snapshots(a, b))

    def test_a_rename_is_not_an_add_plus_a_remove(self):
        a, b = self._pair()
        report = diff_core.diff_snapshots(a, b)
        self.assertEqual(1, len(report["functions"]["renamed"]))
        self.assertEqual("main", report["functions"]["renamed"][0]["from"])
        self.assertEqual("entry", report["functions"]["renamed"][0]["to"])
        self.assertEqual(["0x3"], [fn["address"] for fn in report["functions"]["added"]])
        self.assertEqual(["0x2"], [fn["address"] for fn in report["functions"]["removed"]])

    def test_names_are_compared_as_sets(self):
        report = diff_core.diff_snapshots({"imports": ["A", "A", ""]},
                                          {"imports": ["A"]})
        self.assertFalse(report["changed"])
        self.assertEqual(1, report["imports"]["count_a"])

    def test_the_program_fingerprint_is_compared(self):
        a, b = self._pair()
        self.assertTrue(diff_core.diff_snapshots(a, b)["program_changed"])

    def test_the_complete_flag_needs_both_sides(self):
        report = diff_core.diff_snapshots({"functions_complete": False},
                                          {"functions_complete": True})
        self.assertFalse(report["functions"]["complete"])

    def test_the_summary_counts_every_section(self):
        a, b = self._pair()
        summary = diff_core.diff_snapshots(a, b)["summary"]
        self.assertEqual(1, summary["functions_added"])
        self.assertEqual(1, summary["functions_removed"])
        self.assertEqual(1, summary["functions_renamed"])
        self.assertEqual(1, summary["imports_added"])
        self.assertEqual(1, summary["imports_removed"])
        self.assertEqual(1, summary["strings_added"])

    def test_the_bridge_delegates_both_helpers(self):
        a, b = self._pair()
        self.assertEqual(diff_core.diff_names({"A"}, {"B"}),
                         bridge._diff_names({"A"}, {"B"}))
        self.assertEqual(diff_core.diff_snapshots(a, b),
                         bridge._diff_snapshots(a, b))

    def test_the_program_fields_come_from_the_core(self):
        self.assertEqual(diff_core.PROGRAM_FIELDS, bridge._CORE_DIFF_PROGRAM_FIELDS)
        self.assertIs(bridge._DIFF_PROGRAM_FIELDS, bridge._CORE_DIFF_PROGRAM_FIELDS)


if __name__ == "__main__":
    unittest.main(verbosity=2)