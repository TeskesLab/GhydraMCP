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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bridge_mcp_hydra as bridge  # noqa: E402
from ghydra.core import digest as core  # noqa: E402
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


if __name__ == "__main__":
    unittest.main(verbosity=2)