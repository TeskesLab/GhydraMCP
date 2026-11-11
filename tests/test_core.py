#!/usr/bin/env python3
"""Tests for the single-core mechanism (I1).

The bridge ships as one file and cannot import ``ghydra``, so the shared pure
helpers are *generated* into it by ``scripts/gen_core.py``. What these tests pin
down is the property that makes that safe:

* the generated region is **current** — a core change that was not regenerated
  fails here, which is the drift the mechanism exists to prevent;
* the generated code is **identical** to the core's behaviour;
* the bridge's named helpers are **delegations**, not second copies.

Run with:  python tests/test_core.py
"""

import os
import subprocess
import sys
import unittest
from unittest import mock

# The tests live in tests/; the code and the repository are one level up.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bridge_mcp_hydra as bridge  # noqa: E402
from ghydra.core import digest as core  # noqa: E402
from ghydra import capabilities  # noqa: E402
from ghydra import contextpack  # noqa: E402
from ghydra import mission  # noqa: E402
from ghydra import taint as taint_helper  # noqa: E402
from ghydra import telemetry  # noqa: E402
from ghydra.core import cache as cache_core  # noqa: E402
from ghydra.core import capabilities as cap_core  # noqa: E402
from ghydra.core import contextpack as ctx_core  # noqa: E402
from ghydra.core import diff as diff_core  # noqa: E402
from ghydra.core import fleet as fleet_core  # noqa: E402
from ghydra.core import mission as mission_core  # noqa: E402
from ghydra.core import taint as taint_core  # noqa: E402
from ghydra.core import telemetry as tel_core  # noqa: E402
from ghydra.core import hints as hints_core  # noqa: E402
from ghydra.core import runbook as runbook_core  # noqa: E402
from scripts import gen_core  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _bridge_text():
    with open(os.path.join(ROOT, "bridge_mcp_hydra.py"), encoding="utf-8") as handle:
        return handle.read()


def _definitions_outside_regions(text):
    """The top-level defs/assigns of the bridge that sit outside every region."""
    import ast as _ast
    spans = []
    for module in gen_core.CORE_MODULES:
        begin = text.index(f"# >>> generated from {module}")
        marker = f"# <<< end generated from {module}"
        finish = text.index(marker) + len(marker)
        spans.append((begin, finish))
    kept = []
    offset = 0
    outside = text
    for begin, finish in reversed(spans):
        outside = outside[:begin] + "\n" * 0 + outside[finish:]
    tree = _ast.parse(outside)
    for node in tree.body:
        if isinstance(node, (_ast.FunctionDef, _ast.ClassDef)):
            kept.append((node.name, node))
        elif isinstance(node, _ast.Assign):
            for target in node.targets:
                if isinstance(target, _ast.Name):
                    kept.append((target.id, node))
    return kept


def _delegates(node):
    """Does this definition's body hand off to the generated copy?"""
    import ast as _ast
    if isinstance(node, _ast.Assign):
        value = node.value
        return (isinstance(value, _ast.Name)
                and (value.id.startswith("_CORE_") or value.id.startswith("_core_")))
    return any(isinstance(item, _ast.Name)
               and (item.id.startswith("_core_") or item.id.startswith("_CORE_"))
               for item in _ast.walk(node))


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

    def test_every_core_name_in_the_bridge_is_generated_or_delegated(self):
        """The point of the mechanism: one definition, not a second copy.

        A public name of a core module may appear in the bridge only as the
        generated ``_core_*`` copy. A *wrapper* with the public name is allowed
        only when its whole body delegates — a constant assigned from the core,
        or a function that calls the ``_core_*`` name. A real implementation
        would be the duplication coming back.
        """
        import ast as _ast
        tree = _ast.parse(_bridge_text())
        top = {}
        for node in tree.body:
            if isinstance(node, (_ast.FunctionDef, _ast.ClassDef)):
                top.setdefault(node.name, []).append(node)
            elif isinstance(node, _ast.Assign):
                for target in node.targets:
                    if isinstance(target, _ast.Name):
                        top.setdefault(target.id, []).append(node)

        def delegates(node) -> bool:
            if isinstance(node, _ast.Assign):
                value = node.value
                return (isinstance(value, _ast.Name)
                        and (value.id.startswith("_CORE_") or value.id.startswith("_core_")))
            return any(isinstance(item, _ast.Name)
                       and (item.id.startswith("_core_") or item.id.startswith("_CORE_"))
                       for item in _ast.walk(node))

        for module in gen_core.CORE_MODULES:
            for public in gen_core.CORE_RENAMES.get(module, {}):
                for node in top.get(public, []):
                    with self.subTest(module=module, name=public):
                        self.assertTrue(delegates(node),
                                        f"{public} has a body of its own in the bridge")


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

class FleetCoreTests(unittest.TestCase):
    """The fleet identity and the merge live once, in the core."""

    def test_the_identity_agrees_and_prefers_the_program_id(self):
        program = {"programId": "proj:/a.exe", "path": "/tmp/a.exe",
                   "executablePath": "/tmp/a.exe", "imageBase": "0x400000"}
        self.assertEqual("proj:/a.exe", fleet_core.program_identity_of(program))
        self.assertEqual(fleet_core.program_identity_of(program),
                         bridge._core_fleet_identity_of(program))

    def test_the_identity_falls_back_to_the_paths(self):
        self.assertEqual("/tmp/a.exe",
                         fleet_core.program_identity_of({"path": "/tmp/a.exe"}))
        self.assertEqual("/x", fleet_core.program_identity_of(
            {"executablePath": "/x"}))

    def test_a_program_with_no_identity_is_empty(self):
        for value in ({}, None, [], "x"):
            with self.subTest(value=value):
                self.assertEqual("", fleet_core.program_identity_of(value))

    def _seen(self):
        return [
            {"port": 8192, "identity": "p:/a.exe", "name": "a.exe",
             "answer": {"ok": True, "present": True, "detail": {"address": "0x1"}}},
            {"port": 8193, "identity": "p:/a.exe", "name": "a.exe",
             "answer": {"ok": True, "present": True, "detail": {"address": "0x1"}}},
            {"port": 8194, "identity": "p:/b.exe", "name": "b.exe",
             "answer": {"ok": True, "present": False, "detail": {}}},
        ]

    def test_the_merge_agrees(self):
        report = fleet_core.merge_answers(self._seen(), "has_function", "main", [])
        self.assertEqual(report, bridge._core_fleet_merge(
            self._seen(), "has_function", "main", []))

    def test_two_ports_of_one_program_are_one_row(self):
        report = fleet_core.merge_answers(self._seen(), "has_function", "main", [])
        result = report["result"]
        self.assertEqual(2, result["count"])
        self.assertEqual([8192, 8193], result["binaries"][0]["ports"])
        self.assertEqual(1, result["with_it"])
        self.assertEqual(1, result["without_it"])

    def test_a_disagreement_is_reported(self):
        seen = self._seen()
        seen[1]["answer"] = {"ok": True, "present": False, "detail": {}}
        result = fleet_core.merge_answers(seen, "has_function", "main", [])["result"]
        self.assertTrue(result["binaries"][0]["disagreements"])

    def test_an_unreachable_member_is_carried_and_fails_the_answer(self):
        result = fleet_core.merge_answers(
            self._seen(), "has_function", "main",
            [{"port": 8195, "reason": "NO_PROGRAM"}])["result"]
        self.assertEqual([8195], [item["port"] for item in result["unreachable"]])
        self.assertFalse(result["ok"])

    def test_a_truncated_answer_marks_the_row(self):
        seen = [{"port": 8192, "identity": "p", "name": "a",
                 "answer": {"ok": True, "present": False, "complete": False,
                            "detail": {}}}]
        result = fleet_core.merge_answers(seen, "has_import", "X", [])["result"]
        self.assertFalse(result["binaries"][0]["complete"])
        self.assertEqual(["p"], result["truncated"])

    def test_the_kinds_come_from_the_core(self):
        self.assertEqual(fleet_core.KINDS, bridge._CORE_FLEET_KINDS)
        self.assertIs(bridge._FLEET_KINDS, bridge._CORE_FLEET_KINDS)
        self.assertIs(bridge._FLEET_IDENTITY_FIELDS,
                      bridge._CORE_FLEET_IDENTITY_FIELDS)

class CapabilitiesCoreTests(unittest.TestCase):
    """The ATT&CK rules and the composer live once, in the core."""

    IMPORTS = {"success": True, "result": [
        {"name": "VirtualAllocEx", "address": "0x140001000"},
        {"name": "WriteProcessMemory", "address": "0x140001010"},
        {"name": "CreateRemoteThread", "address": "0x140001020"},
    ]}
    STRINGS = {"success": True, "result": [
        {"value": "SeDebugPrivilege", "address": "0x140002000"},
    ]}

    def _report(self):
        program = {"success": True, "result": {"name": "sample.exe"}}
        return {"program": program, "imports": self.IMPORTS,
                "strings": self.STRINGS}

    def test_the_rules_agree_and_are_the_shim_s(self):
        self.assertEqual(cap_core.CAPABILITY_RULES, bridge._CORE_CAPABILITY_RULES)
        self.assertIs(bridge.CAPABILITY_RULES, bridge._CORE_CAPABILITY_RULES)
        self.assertIs(capabilities.build_capability_report,
                      cap_core.build_capability_report)
        self.assertEqual(capabilities.CAPABILITY_RULES, cap_core.CAPABILITY_RULES)

    def test_the_report_agrees(self):
        payload = self._report()
        expected = cap_core.build_capability_report(
            payload["program"], payload["imports"], payload["strings"])
        self.assertEqual(expected, bridge._core_build_capability_report(
            payload["program"], payload["imports"], payload["strings"]))
        self.assertEqual(expected, bridge.build_capability_report(
            payload["program"], payload["imports"], payload["strings"]))

    def test_the_report_carries_evidence_addresses(self):
        payload = self._report()
        report = cap_core.build_capability_report(
            payload["program"], payload["imports"], payload["strings"])
        self.assertTrue(report["result"]["findings"], report)
        addresses = [item["address"]
                     for finding in report["result"]["findings"]
                     for item in finding["evidence"]]
        self.assertIn("0x140001000", addresses)

    def test_a_rule_with_no_evidence_produces_no_finding(self):
        report = cap_core.build_capability_report(
            {"success": True, "result": {"name": "x"}},
            {"success": True, "result": []},
            {"success": True, "result": []})
        self.assertEqual([], report["result"]["findings"])
        self.assertEqual(0, report["result"]["summary"]["techniques_matched"])

    def test_a_failed_listing_is_reported_not_hidden(self):
        report = cap_core.build_capability_report(
            {"success": True, "result": {"name": "x"}},
            {"success": False, "error": {"code": "TIMEOUT"}},
            {"success": True, "result": []})
        self.assertIn("imports", report["result"]["failures"])

    def test_strings_can_be_skipped(self):
        payload = self._report()
        report = cap_core.build_capability_report(
            payload["program"], payload["imports"], payload["strings"],
            include_strings=False)
        self.assertEqual(0, report["result"]["summary"]["strings_scanned"])

    def test_every_rule_declares_its_parts(self):
        for rule in cap_core.CAPABILITY_RULES:
            with self.subTest(rule=rule.get("id")):
                for key in ("id", "name", "tactic", "imports", "strings"):
                    self.assertIn(key, rule)

class ContextPackCoreTests(unittest.TestCase):
    """The question classifier and the budget composer live once, in the core."""

    def test_the_classifier_agrees(self):
        questions = ("what does this function do?", "o que faz essa função?",
                     "de onde vem esse dado?", "where is this written?",
                     "o que mudou desde a última versão?", "what changed",
                     "qual o tamanho do binário?", "", None)
        for question in questions:
            with self.subTest(question=question):
                self.assertEqual(ctx_core.classify_question(question),
                                 bridge._core_context_classify(question))
                self.assertEqual(ctx_core.classify_question(question),
                                 bridge._ctx_classify_question(question))

    def test_the_classifier_falls_back_to_the_overview(self):
        self.assertEqual("overview",
                         ctx_core.classify_question("qual o tamanho do binário?"))

    def test_the_three_templates_are_the_shim_s(self):
        self.assertEqual(set(ctx_core.TEMPLATES), set(contextpack.TEMPLATES))
        self.assertIs(bridge._CONTEXT_TEMPLATES, bridge._CORE_CONTEXT_TEMPLATES)
        self.assertEqual(ctx_core._CHAR_PER_TOKEN,
                         bridge._CORE_CONTEXT_CHAR_PER_TOKEN)

    def test_the_token_estimate_agrees(self):
        for text in ("", "a", "abcd", "x" * 400, "linha\n" * 30):
            with self.subTest(text=text[:12]):
                self.assertEqual(ctx_core.estimate_tokens(text),
                                 bridge._ctx_tokens(text))

    def _sections(self):
        return [{"title": "function", "body": "x" * 2000,
                 "citations": ["0x401000", "0x401010"]},
                {"title": "program", "body": "y" * 200, "citations": ["0x401010"]}]

    def test_the_pack_agrees(self):
        sections = self._sections()
        expected = ctx_core.build_context_pack("q", "what_it_does", "a.exe",
                                               sections, 300)
        self.assertEqual(expected, bridge._core_build_context_pack(
            "q", "what_it_does", "a.exe", sections, 300))
        self.assertEqual(expected, bridge.build_context_pack(
            "q", "what_it_does", "a.exe", sections, 300))

    def test_the_first_section_is_never_dropped_only_truncated(self):
        report = ctx_core.build_context_pack("q", "what_it_does", "a.exe",
                                             self._sections(), 300)
        titles = [item["title"] for item in report["result"]["sections"]]
        self.assertEqual("function", titles[0])
        reasons = [item["reason"] for item in report["result"]["omitted"]]
        self.assertTrue(any(reason.startswith("truncated") for reason in reasons),
                        report["result"]["omitted"])

    def test_an_over_budget_section_is_dropped_whole_with_a_reason(self):
        sections = [{"title": "function", "body": "x" * 100, "citations": []},
                    {"title": "huge", "body": "y" * 8000, "citations": []}]
        report = ctx_core.build_context_pack("q", "what_it_does", "a.exe",
                                             sections, 400)
        self.assertEqual(["function"],
                         [item["title"] for item in report["result"]["sections"]])
        self.assertEqual(["huge"],
                         [item["section"] for item in report["result"]["omitted"]])

    def test_the_budget_never_goes_below_the_floor(self):
        report = ctx_core.build_context_pack("q", "overview", "a.exe", [], 1)
        self.assertGreaterEqual(report["result"]["budget_tokens"], 200)

    def test_citations_are_deduplicated_in_order(self):
        sections = [{"title": "a", "body": "", "citations": ["0x1", "0x2"]},
                    {"title": "b", "body": "", "citations": ["0x2", "0x3"]}]
        report = ctx_core.build_context_pack("q", "overview", "a.exe",
                                             sections, 4000)
        self.assertEqual(["0x1", "0x2", "0x3"], report["result"]["citations"])

class TelemetryCoreTests(unittest.TestCase):
    """The window, the aggregate and the advice live once, in the core."""

    NOW = 1_000_000.0

    def _entries(self):
        return [
            {"ts": self.NOW, "tool": "functions_get", "ok": True, "ms": 10,
             "tokens": 100},
            {"ts": self.NOW, "tool": "functions_decompile", "ok": True, "ms": 900,
             "tokens": 400},
            {"ts": self.NOW, "tool": "analysis_callers", "ok": True, "ms": 20,
             "tokens": 50},
            {"ts": self.NOW, "tool": "xrefs_list", "ok": False, "code": "XREF_IO",
             "ms": 5, "tokens": 10},
            {"ts": self.NOW - 30 * 86400, "tool": "functions_get", "ok": True,
             "ms": 10, "tokens": 5},
        ]

    def test_the_window_is_the_callers(self):
        recent = tel_core.filter_recent(self._entries(), 7, now=self.NOW)
        self.assertEqual(4, len(recent))
        self.assertEqual([], tel_core.filter_recent(self._entries(), 7,
                                                    now=self.NOW + 40 * 86400))

    def test_the_window_never_goes_below_one_day(self):
        self.assertEqual(4, len(tel_core.filter_recent(self._entries(), 0,
                                                       now=self.NOW)))

    def test_the_advice_agrees(self):
        entries = tel_core.filter_recent(self._entries(), 7, now=self.NOW)
        self.assertEqual(tel_core.recommendations(entries),
                         bridge._core_telemetry_recommendations(entries))
        self.assertEqual(tel_core.recommendations(entries),
                         bridge._telemetry_recommendations(entries))

    def test_the_inspection_pattern_names_the_context_pack(self):
        entries = tel_core.filter_recent(self._entries(), 7, now=self.NOW)
        advice = " ".join(tel_core.recommendations(entries))
        self.assertIn("analysis_context_pack", advice)

    def test_a_slow_tool_is_named(self):
        entries = tel_core.filter_recent(self._entries(), 7, now=self.NOW)
        advice = " ".join(tel_core.recommendations(entries))
        self.assertIn("functions_decompile", advice)

    def test_the_advice_is_capped(self):
        many = [{"ts": self.NOW, "tool": name, "ok": True, "ms": 10}
                for name in ("functions_get", "functions_decompile",
                             "analysis_callers", "analysis_callees", "xrefs_list",
                             "inspect_address", "functions_list", "data_list",
                             "symbols_list", "variables_list") * 2]
        self.assertLessEqual(len(tel_core.recommendations(many)), 5)

    def test_the_report_agrees(self):
        entries = tel_core.filter_recent(self._entries(), 7, now=self.NOW)
        expected = tel_core.summarize(entries, 7, "/log")
        self.assertEqual(expected, bridge._core_telemetry_summarize(
            entries, 7, "/log"))

    def test_the_totals_count_and_sort(self):
        entries = tel_core.filter_recent(self._entries(), 7, now=self.NOW)
        report = tel_core.summarize(entries, 7, "/log")
        self.assertEqual(4, report["calls"])
        rows = {row["tool"]: row for row in report["tools"]}
        self.assertEqual(1, rows["xrefs_list"]["failed"])
        self.assertEqual("XREF_IO", list(report["error_codes"])[0])
        self.assertEqual(4, len(report["tools"]))
        calls = [row["calls"] for row in report["tools"]]
        self.assertEqual(sorted(calls, reverse=True), calls)

    def test_an_empty_window_says_so(self):
        report = tel_core.summarize([], 7, "/log")
        self.assertEqual(0, report["calls"])
        self.assertIn("no telemetry", report["message"])

    def test_only_the_busiest_25_tools_are_listed(self):
        entries = [{"ts": self.NOW, "tool": f"tool_{index}", "ok": True, "ms": 1}
                   for index in range(40)]
        self.assertEqual(25, len(tel_core.summarize(entries, 7, "/l")["tools"]))

    def test_the_constants_come_from_the_core(self):
        self.assertEqual(tel_core.MAX_BYTES, telemetry.MAX_BYTES)
        self.assertEqual(tel_core.KEEP_LINES, telemetry.KEEP_LINES)
        self.assertEqual(tel_core.MAX_BYTES, bridge._TELEMETRY_MAX_BYTES)
        self.assertEqual(tel_core.KEEP_LINES, bridge._TELEMETRY_KEEP_LINES)


class TelemetryToolTests(unittest.TestCase):
    """The bridge's tool reads the file, then hands the rows to the core."""

    def test_the_tool_summarizes_a_real_log(self):
        import os
        import tempfile
        directory = tempfile.mkdtemp(prefix="ghydra-telemetry-")
        previous = os.environ.get("GHYDRA_STATE_DIR")
        os.environ["GHYDRA_STATE_DIR"] = directory
        try:
            bridge._telemetry_record("functions_get", True, None, 12.0, 100)
            bridge._telemetry_record("xrefs_list", False, "XREF_IO", 5.0, 10)
            result = bridge.telemetry_summary.__wrapped__(days=7)
        finally:
            if previous is None:
                os.environ.pop("GHYDRA_STATE_DIR", None)
            else:
                os.environ["GHYDRA_STATE_DIR"] = previous
            import shutil
            shutil.rmtree(directory, ignore_errors=True)
        self.assertTrue(result["success"], result)
        payload = result["result"]
        self.assertEqual(2, payload["calls"])
        self.assertEqual(1, len(payload["error_codes"]))
        self.assertIn("telemetry.jsonl", payload["path"])
        for row in payload["tools"]:
            self.assertEqual({"tool", "calls", "failed", "ms_total", "ms_max",
                              "tokens", "ms_avg"}, set(row))

class TaintCoreTests(unittest.TestCase):
    """The pure half of source-to-sink reasoning lives once, in the core."""

    CALLS = [
        {"target": "0x401000", "at": "0x402000"},
        {"target": "system@plt", "at": "0x403000"},
        {"target": "", "at": "0x404000"},
    ]

    def test_the_constants_come_from_the_core(self):
        self.assertEqual(taint_core.PAGE_LIMIT, taint_helper.PAGE_LIMIT)
        self.assertEqual(taint_core.MAX_PAGES, taint_helper.MAX_PAGES)
        self.assertEqual(taint_core.CALL_OPCODES, taint_helper.CALL_OPCODES)
        self.assertIsInstance(taint_core.CALL_OPCODES, set)
        # `PcodeOp.CALL` is 7 and `CALLIND` is 8 (read with `javap -p -constants`
        # against the committed SoftwareModeling.jar). 57 and 58 are
        # `FLOAT_CEIL` and `FLOAT_FLOOR`: the first version of this constant
        # named them, so every real call was discarded.
        self.assertEqual(taint_core.CALL_OPCODES, {7, 8})
        # The floating-point opcodes are not calls, and must stay out.
        self.assertNotIn(57, taint_core.CALL_OPCODES)
        self.assertNotIn(58, taint_core.CALL_OPCODES)
        self.assertEqual(taint_core.DISCLAIMER, bridge._TAINT_DISCLAIMER)
        self.assertIs(bridge._TAINT_CALL_OPCODES, bridge._CORE_TAINT_CALL_OPCODES)
        self.assertIn("not proof", taint_core.DISCLAIMER)

    def test_the_site_is_found_by_address(self):
        self.assertEqual("0x402000",
                         taint_core.site_for(self.CALLS, "0x401000", "func"))
        self.assertEqual("0x402000",
                         bridge._core_taint_site_for(self.CALLS, "0X401000", "func"))

    def test_the_site_is_found_by_name_inside_the_target(self):
        self.assertEqual("0x403000",
                         taint_core.site_for(self.CALLS, "0x999", "System"))
        self.assertEqual("0x403000",
                         bridge._taint_site_for(self.CALLS, "0x999", "System"))

    def test_no_match_and_empty_targets_are_none(self):
        self.assertIsNone(taint_core.site_for(self.CALLS, "0xdead", "nope"))
        self.assertIsNone(taint_core.site_for([{"target": "", "at": "0x1"}],
                                              "0x1", "x"))
        self.assertIsNone(taint_core.site_for([], "0x1", "x"))

    def test_an_address_sorts_numerically(self):
        addresses = ["0x10", "0x9", "0x100"]
        self.assertEqual(["0x9", "0x10", "0x100"],
                         sorted(addresses, key=taint_core.address_key))

    def test_an_unparseable_address_goes_last_instead_of_raising(self):
        values = ["0x10", "not-an-address", "0x8"]
        ordered = sorted(values, key=taint_core.address_key)
        self.assertEqual("not-an-address", ordered[-1])
        self.assertEqual((1, 0), taint_core.address_key("nope"))
        self.assertEqual((0, 16), bridge._core_taint_address_key("0x10"))

    def test_the_summary_counts_by_confidence(self):
        report = {"hypotheses": [
            {"confidence": "direct"}, {"confidence": "reachable"},
            {"confidence": "weak"}, {"confidence": "weak"}, {}]}
        summary = taint_core.summarize(report)
        self.assertEqual(5, summary["total"])
        self.assertEqual(1, summary["direct"])
        self.assertEqual(1, summary["reachable"])
        self.assertEqual(2, summary["weak"])
        self.assertTrue(summary["found"])
        self.assertEqual(summary, bridge._core_taint_summarize(report))
        self.assertEqual(summary, bridge._taint_summarize(report))

    def test_weak_alone_is_not_a_finding(self):
        summary = taint_core.summarize(
            {"hypotheses": [{"confidence": "weak"}, {"confidence": "weak"}]})
        self.assertFalse(summary["found"])
        self.assertEqual(0, summary["direct"] + summary["reachable"])

    def test_an_empty_report_is_not_found(self):
        self.assertFalse(taint_core.summarize({})["found"])
        self.assertEqual(0, taint_core.summarize({})["total"])

    def test_the_report_result_helper_distinguishes_failure_from_absence(self):
        self.assertEqual({"x": 1},
                         taint_core.result_of({"success": True, "result": {"x": 1}}))
        self.assertIsNone(taint_core.result_of({"success": False,
                                                "error": {"code": "X"}}))
        self.assertIsNone(taint_core.result_of("nope"))
        self.assertEqual(taint_core.result_of({"success": True, "result": []}),
                         bridge._core_taint_result_of({"success": True, "result": []}))

class MissionCoreTests(unittest.TestCase):
    """The budget rules and the dossier live once, in the core."""

    def test_the_budget_trips_calls_then_tokens_then_time(self):
        exhausted = mission_core.budget_exhausted
        self.assertEqual("the call budget (2) is spent",
                         exhausted(2, 2, 0, 100, 0.0, 900))
        self.assertEqual("the token budget (10) is spent",
                         exhausted(0, 2, 10, 10, 0.0, 900))
        self.assertEqual("the time budget (5s) is spent",
                         exhausted(0, 2, 0, 10, 5.0, 5))
        self.assertIsNone(exhausted(0, 2, 0, 10, 0.0, 5))

    def test_a_surface_without_a_clock_never_trips_time(self):
        self.assertIsNone(mission_core.budget_exhausted(0, 60, 0, 1000, 10 ** 9))

    def test_a_call_always_costs_at_least_one_token(self):
        self.assertEqual(1, mission_core.tokens_of(None))
        self.assertEqual(1, mission_core.tokens_of({}))
        self.assertGreater(mission_core.tokens_of({"a": "x" * 400}), 1)

    def test_the_budget_row_is_the_same_on_both_surfaces(self):
        cli = mission_core.budget_row(3, 60, 100, 200000, 1.24, 900)
        self.assertEqual(1.2, cli["seconds"])
        self.assertEqual(900, cli["max_seconds"])
        builtin = mission_core.budget_row(3, 60, 100, 200000, 1.24)
        self.assertNotIn("max_seconds", builtin)

    def _findings(self):
        return [
            {"id": "F1", "title": "a lead", "kind": "capability",
             "confidence": "high", "status": "verified", "detail": "detail",
             "evidence": [{"endpoint": "capabilities", "digest": "a" * 32}]},
            {"id": "F2", "title": "a doubt", "kind": "taint",
             "confidence": "low", "status": "unknown", "detail": ""},
        ]

    def _dossier(self, **overrides):
        payload = dict(
            goal="does data from recv reach system?", mission_id="m1",
            program={"name": "a.exe", "executable_path": "/tmp/a.exe"},
            hints={"source": "recv", "sink": "system"},
            budget=mission_core.budget_row(3, 60, 100, 200000, 1.2, 900),
            failed=None, skipped=[],
            findings=self._findings(),
            verification={"checked": 2, "verified": 1, "unverified": ["F1"]})
        payload.update(overrides)
        return mission_core.dossier(**payload)

    def test_the_dossier_has_the_sections_a_reader_expects(self):
        text = self._dossier()
        for expected in ("# Mission: does data from recv reach system?",
                         "- id: `m1`", "- program: `a.exe`",
                         "## Findings", "### F1 — a lead",
                         "## Verification", "## Not determined"):
            with self.subTest(expected=expected):
                self.assertIn(expected, text)

    def test_a_finding_whose_evidence_moved_is_marked_unverified(self):
        self.assertIn("**unverified: F1**", self._dossier())

    def test_every_verification_passing_says_so(self):
        text = self._dossier(verification={"checked": 1, "verified": 1,
                                           "unverified": []})
        self.assertIn("every conclusion still holds", text)

    def test_an_unknown_finding_is_in_not_determined(self):
        text = self._dossier()
        not_determined = text.split("## Not determined")[1]
        self.assertIn("F2", not_determined)

    def test_an_empty_mission_says_so_instead_of_showing_nothing(self):
        text = self._dossier(findings=[], verification=None)
        self.assertIn("_No finding was recorded._", text)
        # Nothing was answered, so "nothing is undetermined" would be a claim
        # about a question nobody asked.
        self.assertIn("No question was answered", text)
        self.assertNotIn("## Verification", text)

    def test_a_stopped_mission_does_not_claim_completeness(self):
        text = self._dossier(findings=[],
                             failed="the call budget (3) is spent",
                             verification=None)
        self.assertIn("The mission stopped before it could answer", text)
        self.assertNotIn("_Nothing was left undetermined._", text)

    def test_verification_without_a_reread_claims_nothing(self):
        text = self._dossier(verification={"checked": 0, "verified": 0,
                                           "unverified": []})
        self.assertIn("no evidence item was re-read", text)
        self.assertNotIn("every conclusion still holds", text)

    def test_a_truncated_detail_says_it_was_cut(self):
        text = self._dossier(findings=[{
            "id": "F1", "title": "long", "kind": "k", "confidence": "low",
            "status": "verified", "detail": "x" * 2500, "evidence": []}],
            verification=None)
        self.assertIn("detail truncated to 2000 of 2500 characters", text)

    def test_a_stopped_mission_says_why_and_what_was_skipped(self):
        text = self._dossier(failed="the call budget (3) is spent",
                             skipped=["taint: no sink in the goal"])
        self.assertIn("**The mission stopped: the call budget (3) is spent**", text)
        self.assertIn("Skipped steps: taint: no sink in the goal", text)

    def test_the_constants_come_from_the_core(self):
        self.assertEqual(mission_core.MISSION_VERSION, mission.MISSION_VERSION)
        self.assertEqual(mission_core.DEFAULT_CALLS, mission.DEFAULT_CALLS)
        self.assertEqual(mission_core.DEFAULT_SECONDS, mission.DEFAULT_SECONDS)
        self.assertEqual(mission_core.STATUS_UNKNOWN, mission.STATUS_UNKNOWN)
        self.assertEqual(mission_core.ERROR_BUDGET, mission.ERROR_BUDGET)

    def test_the_two_surfaces_render_the_same_document(self):
        """The artifact is the evidence: it cannot differ by surface."""
        findings = self._findings()
        cli = mission.Mission.__new__(mission.Mission)
        cli.goal = "goal"
        cli.id = "m1"
        # The fingerprint's own names, which are not the payload's names:
        # `/program` sends `path` and `imageBase`, the fingerprint carries
        # `executable_path` and `image_base`.
        cli.program = {"name": "a.exe", "executable_path": "/a"}
        cli.hints = {"source": "recv"}
        cli.failed = None
        cli.skipped = []
        cli.findings = findings
        cli.budget = mission.Budget(60, 200000, 900)
        cli.budget.calls = 2
        cli.budget.tokens = 50
        cli.budget.started = cli.budget.started  # fixed: same start

        bridge_mission = bridge._Mission.__new__(bridge._Mission)
        bridge_mission.goal = cli.goal
        bridge_mission.id = cli.id
        bridge_mission.program = cli.program
        bridge_mission.hints = cli.hints
        bridge_mission.failed = None
        bridge_mission.skipped = []
        bridge_mission.findings = findings
        bridge_mission.budget = bridge._MissionBudget(60, 200000)
        bridge_mission.budget.calls = 2
        bridge_mission.budget.tokens = 50
        bridge_mission.budget.started = cli.budget.started

        verification = {"checked": 2, "verified": 1, "unverified": ["F1"]}
        self.assertEqual(mission.to_markdown(cli, verification),
                         bridge._mission_markdown(bridge_mission, verification))


class I1InventoryTests(unittest.TestCase):
    """The close-out: what the mechanism now owns, and what it must never lose."""

    EXPECTED = {
        "ghydra/core/digest.py", "ghydra/core/runbook.py",
        "ghydra/core/hints.py", "ghydra/core/cache.py",
        "ghydra/core/diff.py", "ghydra/core/fleet.py",
        "ghydra/core/capabilities.py", "ghydra/core/contextpack.py",
        "ghydra/core/telemetry.py", "ghydra/core/taint.py",
        "ghydra/core/mission.py",
    }

    def test_every_module_is_registered_and_generated(self):
        self.assertEqual(self.EXPECTED, set(gen_core.CORE_MODULES))
        text = _bridge_text()
        for module in self.EXPECTED:
            with self.subTest(module=module):
                self.assertIn(f"# >>> generated from {module}", text)
                self.assertIn(f"# <<< end generated from {module}", text)
                self.assertEqual(1, text.count(f"# >>> generated from {module}"))

    def test_every_module_has_its_own_rename_map(self):
        for module in self.EXPECTED:
            with self.subTest(module=module):
                self.assertTrue(gen_core.CORE_RENAMES.get(module),
                                f"{module} has no rename map")

    def test_a_core_name_appears_only_inside_its_own_region(self):
        """The claim is "one definition", not "fewer lines".

        The bridge keeps a generated copy — it ships as one file — so the file
        does not shrink. What must hold is that no core name has a definition
        *outside* its region: that would be the duplication coming back.
        """
        definitions = _definitions_outside_regions(_bridge_text())
        for module in gen_core.CORE_MODULES:
            for public in gen_core.CORE_RENAMES[module]:
                for name, node in definitions:
                    if name != public:
                        continue
                    with self.subTest(module=module, name=public):
                        self.assertTrue(
                            _delegates(node),
                            f"{public} is defined outside its region with a body of its own")

    def test_the_regions_are_contiguous_and_ordered(self):
        text = _bridge_text()
        positions = [text.index(f"# >>> generated from {module}")
                     for module in gen_core.CORE_MODULES]
        self.assertEqual(sorted(positions), positions)


class FingerprintTests(unittest.TestCase):
    """One program fingerprint, read from the keys the API actually sends."""

    #: The payload `ProgramResource.getCurrentProgram()` sends.
    PAYLOAD = {"name": "sample.exe", "path": "C:/bin/sample.exe",
               "imageBase": "140000000", "language": "x86:LE:64:default",
               "compiler": "windows"}

    def test_the_path_and_the_image_base_survive(self):
        from ghydra.core.cache import fingerprint_from_program
        fingerprint = fingerprint_from_program(self.PAYLOAD)
        self.assertEqual("C:/bin/sample.exe", fingerprint["executable_path"])
        self.assertEqual("140000000", fingerprint["image_base"])

    def test_the_names_the_fingerprint_carries_are_the_names_the_callers_read(self):
        from ghydra.core.cache import fingerprint_from_program
        fingerprint = fingerprint_from_program(self.PAYLOAD)
        self.assertEqual(sorted(diff_core.PROGRAM_FIELDS),
                         sorted(fingerprint))

    def test_a_payload_that_is_not_a_dict_is_no_fingerprint(self):
        from ghydra.core.cache import fingerprint_from_program
        self.assertEqual({}, fingerprint_from_program(None))
        self.assertEqual({}, fingerprint_from_program("not a payload"))

    def test_a_fact_the_payload_does_not_carry_is_absent(self):
        from ghydra.core.cache import fingerprint_from_program
        fingerprint = fingerprint_from_program({"name": "sample.exe"})
        self.assertEqual({"name": "sample.exe"}, fingerprint)

    def test_the_bridge_and_the_cli_build_the_same_fingerprint(self):
        from ghydra.core.cache import fingerprint_from_program
        self.assertEqual(fingerprint_from_program(self.PAYLOAD),
                         bridge._core_cache_fingerprint(self.PAYLOAD))

    def test_two_different_binaries_of_the_same_name_are_not_the_same_program(self):
        """The defect: the fingerprint held only the name, so this was equal."""
        from ghydra.core.cache import fingerprint_from_program
        left = fingerprint_from_program(
            dict(self.PAYLOAD, path="C:/bin/cmd.exe"))
        right = fingerprint_from_program(
            dict(self.PAYLOAD, path="C:/other/cmd.exe"))
        self.assertNotEqual(left, right)

    def test_a_different_image_base_is_not_the_same_program(self):
        from ghydra.core.cache import fingerprint_from_program
        left = fingerprint_from_program(self.PAYLOAD)
        right = fingerprint_from_program(
            dict(self.PAYLOAD, imageBase="180000000"))
        self.assertNotEqual(left, right)


class CoreCoverageTests(unittest.TestCase):
    """The core's last two public functions.

    A sweep of the core's public names found two that no test called by name.
    One of them (`name_set`) runs inside `diff_names` on every comparison; the
    other (`looks_like_address`) decides whether a reference's `function` field
    is an address or a name — and only its "no" branch was ever taken.
    """

    def test_the_name_set_drops_the_empty_and_the_repeats(self):
        from ghydra.core.diff import name_set

        self.assertEqual({"a", "b"}, name_set(["a", "b", "a", ""]))

    def test_an_address_is_recognised_by_its_digits(self):
        from ghydra.core.taint import looks_like_address

        self.assertTrue(looks_like_address("0x401000"))
        self.assertTrue(looks_like_address("401000"))
        self.assertTrue(looks_like_address("00401000"))

    def test_a_name_is_not_an_address(self):
        from ghydra.core.taint import looks_like_address

        self.assertFalse(looks_like_address("caller"))
        self.assertFalse(looks_like_address(""))
        self.assertFalse(looks_like_address(None))
        self.assertFalse(looks_like_address("recv"))

    def test_the_bridge_has_the_same_answer(self):
        """The core is generated into the bridge: the two must agree."""
        from ghydra.core.taint import looks_like_address

        self.assertEqual(looks_like_address("401000"),
                         bridge._core_taint_looks_like_address("401000"))
        self.assertEqual(looks_like_address("caller"),
                         bridge._core_taint_looks_like_address("caller"))


if __name__ == "__main__":
    unittest.main(verbosity=2)