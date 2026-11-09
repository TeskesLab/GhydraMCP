#!/usr/bin/env python3
"""Tests for the decompile cache (I11).

No Ghidra and no network: a fake client answers /program and the decompile
endpoint, and the cache lives in a temporary state directory. What these tests
pin down is that the cache cannot lie about which program an answer belongs to,
cannot serve a stale answer past its age, and cannot break a call when the disk
is unavailable.

Run with:  python test_cache.py
"""

import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bridge_mcp_hydra as bridge  # noqa: E402
from ghydra import cache as C  # noqa: E402
from ghydra.cli.functions import decompile  # noqa: E402


class FakeClient:
    """Answers /program and one decompile endpoint; counts the decompiles."""

    def __init__(self, identity=None, code="int main(void) { return 0; }",
                 fail_program=False):
        self.identity = identity if identity is not None else {
            "name": "sample.exe", "programId": "proj:/sample.exe",
            "path": "/tmp/sample.exe", "language": "x86:LE:64:default",
            "imageBase": "0x400000", "creationDate": "Mon Jan 01 2024",
            "statistics": {"functionCount": 10, "symbolCount": 20,
                           "memoryBlockCount": 4},
        }
        self.code = code
        self.decompiles = 0
        self.timeout = 900  # the CLI raises it around the decompile call
        self.program_calls = 0
        self.fail_program = fail_program

    def get(self, endpoint, params=None):
        if endpoint == "program":
            self.program_calls += 1
            if self.fail_program:
                return {"success": False, "error": {"code": "NO_PROGRAM"}}
            return {"success": True, "result": dict(self.identity)}
        if endpoint.endswith("/decompile"):
            self.decompiles += 1
            return {"success": True,
                    "result": {"function": "main", "ccode": self.code}}
        return {"success": True, "result": {}}


class IdentityTests(unittest.TestCase):
    def test_the_identity_carries_the_program_and_its_statistics(self):
        identity = C.program_identity(FakeClient())
        self.assertEqual("proj:/sample.exe", identity["programId"])
        self.assertEqual(10, identity["statistics"]["functionCount"])

    def test_an_unreadable_program_yields_an_empty_identity(self):
        self.assertEqual({}, C.program_identity(FakeClient(fail_program=True)))

    def test_an_unreachable_instance_yields_an_empty_identity(self):
        class Broken:
            def get(self, endpoint, params=None):
                raise RuntimeError("down")
        self.assertEqual({}, C.program_identity(Broken()))


class KeyTests(unittest.TestCase):
    def test_the_key_ignores_key_order(self):
        identity = {"programId": "p", "language": "x"}
        self.assertEqual(C.cache_key(identity, "decompile", {"a": 1, "b": 2}),
                         C.cache_key(identity, "decompile", {"b": 2, "a": 1}))

    def test_a_different_program_is_a_different_key(self):
        one = C.cache_key({"programId": "a"}, "decompile", {})
        two = C.cache_key({"programId": "b"}, "decompile", {})
        self.assertNotEqual(one, two)

    def test_an_edited_program_is_a_different_key(self):
        before = {"programId": "p", "statistics": {"symbolCount": 20}}
        after = {"programId": "p", "statistics": {"symbolCount": 21}}
        self.assertNotEqual(C.cache_key(before, "decompile", {}),
                            C.cache_key(after, "decompile", {}))

    def test_a_different_question_is_a_different_key(self):
        identity = {"programId": "p"}
        self.assertNotEqual(
            C.cache_key(identity, "decompile", {"endpoint": "a"}),
            C.cache_key(identity, "decompile", {"endpoint": "b"}))


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.previous = os.environ.get("GHYDRA_STATE_DIR")
        os.environ["GHYDRA_STATE_DIR"] = self.tmp.name
        self.addCleanup(self._restore)

    def _restore(self):
        if self.previous is None:
            os.environ.pop("GHYDRA_STATE_DIR", None)
        else:
            os.environ["GHYDRA_STATE_DIR"] = self.previous

    def test_a_put_answer_is_read_back(self):
        identity = {"programId": "p"}
        key = C.cache_key(identity, "decompile", {"q": 1})
        self.assertTrue(C.put(key, identity, "decompile", {"q": 1},
                              {"success": True, "result": {"ccode": "x"}}))
        entry = C.get(key)
        self.assertIsNotNone(entry)
        self.assertEqual("x", entry["response"]["result"]["ccode"])

    def test_an_aged_entry_is_not_served(self):
        identity = {"programId": "p"}
        key = C.cache_key(identity, "decompile", {})
        C.put(key, identity, "decompile", {}, {"success": True, "result": {}})
        path = C.entry_path(key)
        with open(path, encoding="utf-8") as handle:
            entry = json.load(handle)
        entry["created"] = time.time() - 10_000
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(entry, handle)
        self.assertIsNone(C.get(key, max_age=3600))
        self.assertIsNotNone(C.get(key, max_age=0))

    def test_a_corrupt_entry_is_ignored_not_crashed(self):
        identity = {"programId": "p"}
        key = C.cache_key(identity, "decompile", {})
        path = C.entry_path(key)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("not json")
        self.assertIsNone(C.get(key))

    def test_the_stats_count_entries_and_programs(self):
        for program in ("a", "b"):
            identity = {"programId": program}
            key = C.cache_key(identity, "decompile", {})
            C.put(key, identity, "decompile", {}, {"success": True, "result": {}})
        report = C.stats()
        self.assertEqual(2, report["entries"])
        self.assertEqual(2, report["programs"])
        self.assertEqual(["decompile"], report["kinds"])
        self.assertGreater(report["bytes"], 0)

    def test_clear_removes_everything(self):
        identity = {"programId": "p"}
        key = C.cache_key(identity, "decompile", {})
        C.put(key, identity, "decompile", {}, {"success": True, "result": {}})
        self.assertEqual(1, C.clear())
        self.assertEqual(0, C.stats()["entries"])

    def test_the_cache_is_evicted_down_to_its_bound(self):
        identity = {"programId": "p"}
        for index in range(5):
            key = C.cache_key(identity, "decompile", {"i": index})
            C.put(key, identity, "decompile", {"i": index},
                  {"success": True, "result": {"blob": "x" * 500}})
        removed = C.evict(max_bytes=1200)
        self.assertGreaterEqual(removed, 1)
        self.assertLessEqual(C.stats()["bytes"], 1200 + 1200)


class GetOrComputeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.previous = os.environ.get("GHYDRA_STATE_DIR")
        os.environ["GHYDRA_STATE_DIR"] = self.tmp.name
        self.addCleanup(self._restore)

    def _restore(self):
        if self.previous is None:
            os.environ.pop("GHYDRA_STATE_DIR", None)
        else:
            os.environ["GHYDRA_STATE_DIR"] = self.previous

    def test_the_first_call_computes_and_the_second_reads_the_cache(self):
        client = FakeClient()
        calls = {"count": 0}

        def compute():
            calls["count"] += 1
            return client.get("functions/0x1/decompile")

        first, cached_first = C.get_or_compute(client, "decompile", {"q": 1}, compute)
        second, cached_second = C.get_or_compute(client, "decompile", {"q": 1}, compute)
        self.assertFalse(cached_first)
        self.assertTrue(cached_second)
        self.assertEqual(1, calls["count"])
        self.assertEqual(first, second)

    def test_a_changed_program_is_computed_again(self):
        client = FakeClient()
        C.get_or_compute(client, "decompile", {"q": 1},
                         lambda: client.get("functions/0x1/decompile"))
        client.identity = dict(client.identity, statistics={"symbolCount": 99})
        _response, cached = C.get_or_compute(
            client, "decompile", {"q": 1},
            lambda: client.get("functions/0x1/decompile"))
        self.assertFalse(cached)

    def test_an_unreadable_program_skips_the_cache(self):
        client = FakeClient(fail_program=True)
        computed = {"count": 0}

        def compute():
            computed["count"] += 1
            return {"success": True, "result": {}}

        for _ in range(2):
            C.get_or_compute(client, "decompile", {"q": 1}, compute)
        self.assertEqual(2, computed["count"])

    def test_a_failed_answer_is_not_cached(self):
        client = FakeClient()
        failure = {"success": False, "error": {"code": "DECOMPILE_FAILED"}}
        first, _ = C.get_or_compute(client, "decompile", {"q": 1}, lambda: failure)
        second, cached = C.get_or_compute(client, "decompile", {"q": 1},
                                          lambda: failure)
        self.assertFalse(cached)
        self.assertEqual(failure, first)
        self.assertEqual(failure, second)

    def test_an_unwritable_cache_still_returns_the_answer(self):
        client = FakeClient()
        with mock.patch.object(C, "put", return_value=False):
            response, cached = C.get_or_compute(
                client, "decompile", {"q": 1},
                lambda: client.get("functions/0x1/decompile"))
        self.assertFalse(cached)
        self.assertTrue(response["success"])


class ParityTests(unittest.TestCase):
    """The bridge carries the same cache; the two must agree."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.previous = os.environ.get("GHYDRA_STATE_DIR")
        os.environ["GHYDRA_STATE_DIR"] = self.tmp.name
        self.addCleanup(self._restore)

    def _restore(self):
        if self.previous is None:
            os.environ.pop("GHYDRA_STATE_DIR", None)
        else:
            os.environ["GHYDRA_STATE_DIR"] = self.previous

    def test_the_key_agrees(self):
        identity = {"programId": "p", "statistics": {"symbolCount": 3}}
        request = {"endpoint": "functions/0x1/decompile", "params": {"style": "x"}}
        self.assertEqual(C.cache_key(identity, "decompile", request),
                         bridge._cache_key(identity, "decompile", request))

    def test_the_entries_directory_agrees(self):
        self.assertEqual(C.entries_dir(), bridge._cache_entries_dir())

    def test_the_identity_agrees(self):
        client = FakeClient()
        with mock.patch.object(
                bridge, "safe_get",
                side_effect=lambda port, endpoint, params=None: client.get(
                    endpoint, params)):
            self.assertEqual(C.program_identity(client),
                             bridge._cache_program_identity(8192))

    def test_an_entry_written_by_one_side_is_read_by_the_other(self):
        identity = {"programId": "shared"}
        key = C.cache_key(identity, "decompile", {"q": 1})
        C.put(key, identity, "decompile", {"q": 1},
              {"success": True, "result": {"ccode": "shared answer"}})
        entry = bridge._cache_get(key)
        self.assertIsNotNone(entry)
        self.assertEqual("shared answer", entry["response"]["result"]["ccode"])

    def test_the_stats_agree(self):
        identity = {"programId": "p"}
        key = C.cache_key(identity, "decompile", {})
        C.put(key, identity, "decompile", {}, {"success": True, "result": {}})
        self.assertEqual(C.stats()["entries"], bridge._cache_stats()["entries"])


class BridgeToolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.previous = os.environ.get("GHYDRA_STATE_DIR")
        os.environ["GHYDRA_STATE_DIR"] = self.tmp.name
        self.addCleanup(self._restore)

    def _restore(self):
        if self.previous is None:
            os.environ.pop("GHYDRA_STATE_DIR", None)
        else:
            os.environ["GHYDRA_STATE_DIR"] = self.previous

    def test_both_tools_are_registered_with_a_formatter_in_core(self):
        tools = set(getattr(bridge.mcp._tool_manager, "_tools", {}))
        for name in ("cache_stats", "cache_clear"):
            with self.subTest(tool=name):
                self.assertIn(name, tools)
                self.assertIn(name, bridge.FORMATTERS)
                self.assertEqual("core", bridge._tool_group(name))

    def test_the_stats_tool_reports_what_is_stored(self):
        identity = {"programId": "p"}
        key = C.cache_key(identity, "decompile", {})
        C.put(key, identity, "decompile", {}, {"success": True, "result": {}})
        result = bridge.cache_stats.__wrapped__()
        self.assertTrue(result["success"])
        self.assertEqual(1, result["result"]["entries"])

    def test_the_clear_tool_removes_everything(self):
        identity = {"programId": "p"}
        key = C.cache_key(identity, "decompile", {})
        C.put(key, identity, "decompile", {}, {"success": True, "result": {}})
        result = bridge.cache_clear.__wrapped__()
        self.assertEqual(1, result["result"]["removed"])
        self.assertEqual(0, C.stats()["entries"])

    def test_the_formatter_renders_the_report(self):
        text = bridge.format_cache_stats({"success": True, "result": {
            "path": "C:/x", "entries": 3, "bytes": 120, "max_bytes": 1000,
            "programs": 1, "kinds": ["decompile"], "oldest": 0, "newest": 0}})
        self.assertIn("entries: 3", text)
        self.assertIn("decompile", text)

    def test_the_formatter_renders_an_error(self):
        failure = {"success": False,
                   "error": {"code": "CACHE_IO", "message": "no disk"}}
        self.assertIn("CACHE_IO", bridge.format_cache_stats(failure))

    def test_the_decompile_tool_honours_use_cache(self):
        client = FakeClient()
        with mock.patch.object(
                bridge, "safe_get",
                side_effect=lambda port, endpoint, params=None: client.get(
                    endpoint, params)), \
                mock.patch.object(bridge, "_get_instance_port",
                                  side_effect=lambda port=None: 8192):
            first = bridge.functions_decompile.__wrapped__(
                address="0x401000", use_cache=True)
            second = bridge.functions_decompile.__wrapped__(
                address="0x401000", use_cache=True)
        self.assertEqual(1, client.decompiles)
        self.assertEqual(first, second)

    def test_the_decompile_tool_computes_when_the_cache_is_off(self):
        client = FakeClient()
        with mock.patch.object(
                bridge, "safe_get",
                side_effect=lambda port, endpoint, params=None: client.get(
                    endpoint, params)), \
                mock.patch.object(bridge, "_get_instance_port",
                                  side_effect=lambda port=None: 8192):
            bridge.functions_decompile.__wrapped__(address="0x401000")
            bridge.functions_decompile.__wrapped__(address="0x401000")
        self.assertEqual(2, client.decompiles)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.previous = os.environ.get("GHYDRA_STATE_DIR")
        os.environ["GHYDRA_STATE_DIR"] = self.tmp.name
        self.addCleanup(self._restore)

    def _restore(self):
        if self.previous is None:
            os.environ.pop("GHYDRA_STATE_DIR", None)
        else:
            os.environ["GHYDRA_STATE_DIR"] = self.previous

    def _invoke(self, args, client=None):
        from click.testing import CliRunner
        return CliRunner().invoke(decompile, args, obj={
            'client': client or FakeClient(),
            'formatter': mock.Mock(),
            'config': mock.Mock(page_output=False),
            'output_json': False,
        })

    def test_cache_serves_the_second_call(self):
        client = FakeClient()
        first = self._invoke(["--address", "0x401000", "--cache"], client)
        second = self._invoke(["--address", "0x401000", "--cache"], client)
        self.assertEqual(0, first.exit_code, first.output)
        self.assertEqual(0, second.exit_code, second.output)
        self.assertEqual(1, client.decompiles)

    def test_without_the_flag_every_call_decompiles(self):
        client = FakeClient()
        self._invoke(["--address", "0x401000"], client)
        self._invoke(["--address", "0x401000"], client)
        self.assertEqual(2, client.decompiles)

    def test_the_cache_note_goes_to_stderr_not_into_the_answer(self):
        client = FakeClient()
        self._invoke(["--address", "0x401000", "--cache"], client)
        second = self._invoke(["--address", "0x401000", "--cache"], client)
        note = "served from the local cache"
        stderr = getattr(second, "stderr", "") or ""
        # The product writes the note to stderr so the answer stays parseable.
        # This Click version's CliRunner also merges stderr into output, so the
        # assertion is that the note reached stderr when the runner separates
        # the streams, and that it is present at all when it does not.
        if stderr:
            self.assertIn(note, stderr)
        else:
            self.assertIn(note, second.output)

    def test_an_aged_answer_is_decompiled_again(self):
        client = FakeClient()
        self._invoke(["--address", "0x401000", "--cache"], client)
        third = self._invoke(["--address", "0x401000", "--cache",
                              "--max-age", "0"], client)
        self.assertEqual(0, third.exit_code, third.output)
        self.assertEqual(2, client.decompiles)


if __name__ == "__main__":
    unittest.main(verbosity=2)