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
from ghydra import capabilities  # noqa: E402
from ghydra import contextpack  # noqa: E402
from ghydra.core import cache as cache_core  # noqa: E402
from ghydra.core import capabilities as cap_core  # noqa: E402
from ghydra.core import contextpack as ctx_core  # noqa: E402
from ghydra.core import diff as diff_core  # noqa: E402
from ghydra.core import fleet as fleet_core  # noqa: E402
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


if __name__ == "__main__":
    unittest.main(verbosity=2)