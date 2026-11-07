#!/usr/bin/env python3
"""Tests for the background task registry (I7).

No Ghidra, no network: the registry is exercised with synthetic bodies and
mocked HTTP, covering the lifecycle, the cancel semantics, the synchronous
fallback and the tool contract.

Run with:  python test_tasks.py
"""

import inspect
import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bridge_mcp_hydra as bridge  # noqa: E402


def _drain(record, timeout=5.0):
    """Wait until the task record leaves the working state."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        with bridge._bg_tasks_lock:
            if record["status"] != "working":
                return record["status"]
        time.sleep(0.01)
    return "still-working"


class RegistryTests(unittest.TestCase):
    def setUp(self):
        bridge._bg_tasks.clear()
        bridge._bg_task_counter = 0

    def test_lifecycle_completed_captures_the_result(self):
        record = bridge._task_new("batch_decompile", "test")
        self.assertEqual("working", record["status"])
        bridge._task_run(record,
                         body=lambda: {"success": True, "result": [1, 2]},
                         result_of=lambda o: o)
        self.assertEqual("completed", record["status"])
        self.assertEqual([1, 2], record["result"]["result"])
        self.assertIsNotNone(record["finished"])

    def test_a_failing_envelope_is_a_failed_task(self):
        record = bridge._task_new("batch_decompile", "test")
        bridge._task_run(record,
                         body=lambda: {"success": False,
                                       "error": {"code": "X", "message": "m"}},
                         result_of=lambda o: o)
        self.assertEqual("failed", record["status"])
        self.assertEqual("X", record["error"])

    def test_an_exception_in_the_body_never_raises(self):
        record = bridge._task_new("batch_decompile", "test")

        def boom():
            raise RuntimeError("transport died")
        bridge._task_run(record, body=boom, result_of=lambda o: o)
        self.assertEqual("failed", record["status"])
        self.assertIn("RuntimeError", record["error"])

    def test_cancel_discards_the_outcome(self):
        import threading as _threading
        release = _threading.Event()
        record = bridge._task_new("batch_decompile", "test")

        def slow_body():
            release.wait(timeout=5)
            return {"success": True, "result": "late"}

        worker = _threading.Thread(
            target=bridge._task_run, args=(record, slow_body, lambda o: o))
        worker.start()
        record["cancel_requested"] = True
        release.set()
        worker.join(timeout=5)
        self.assertEqual("cancelled", record["status"])
        self.assertIsNone(record["result"])

    def test_ids_are_sequential_and_addressable(self):
        first = bridge._task_new("a", "one")
        second = bridge._task_new("b", "two")
        self.assertEqual("T-0001", first["id"])
        self.assertEqual("T-0002", second["id"])


class ToolTests(unittest.TestCase):
    def setUp(self):
        bridge._bg_tasks.clear()
        bridge._bg_task_counter = 0

    def test_all_three_tools_are_registered_and_formatted(self):
        registered = getattr(bridge.mcp._tool_manager, "_tools", {})
        for name in ("tasks_list", "tasks_get", "tasks_cancel"):
            with self.subTest(tool=name):
                self.assertIn(name, registered)
                self.assertTrue(hasattr(getattr(bridge, name), "__wrapped__"))
                self.assertIn(name, bridge.FORMATTERS)

    def test_tasks_get_unknown_id_is_task_not_found(self):
        raw = bridge.tasks_get.__wrapped__(task_id="T-9999")
        self.assertFalse(raw["success"])
        self.assertEqual("TASK_NOT_FOUND", raw["error"]["code"])

    def test_tasks_cancel_unknown_id_is_task_not_found(self):
        raw = bridge.tasks_cancel.__wrapped__(task_id="T-9999")
        self.assertFalse(raw["success"])
        self.assertEqual("TASK_NOT_FOUND", raw["error"]["code"])

    @mock.patch.object(bridge, "_get_instance_port", return_value=8192)
    @mock.patch.object(bridge, "safe_post")
    def test_batch_sync_mode_is_unchanged(self, fake_post, fake_port):
        fake_post.return_value = {"success": True, "result": [{"name": "main"}]}
        raw = bridge.functions_batch_decompile.__wrapped__(targets='["main"]')
        self.assertEqual([{"name": "main"}], raw["result"])
        self.assertEqual({}, bridge._bg_tasks)  # nothing was spawned

    @mock.patch.object(bridge, "_get_instance_port", return_value=8192)
    @mock.patch.object(bridge, "safe_post")
    def test_batch_async_mode_returns_a_handle_then_completes(self, fake_post, fake_port):
        fake_post.return_value = {"success": True,
                                  "result": [{"name": "main"}, {"name": "sub"}]}
        handle = bridge.functions_batch_decompile.__wrapped__(
            targets='["main","sub"]', async_mode=True)
        self.assertTrue(handle["success"])
        task_id = handle["result"]["task"]["id"]
        # A fast body may already be completed by the time the handle is
        # inspected — what the handle guarantees is the id, not the state.
        self.assertTrue(task_id.startswith("T-"))

        status = _drain(bridge._bg_tasks[task_id])
        self.assertEqual("completed", status)
        view = bridge.tasks_get.__wrapped__(task_id=task_id)
        self.assertEqual("completed", view["result"]["status"])
        self.assertEqual(2, len(view["result"]["result"]["result"]))
        listing = bridge.tasks_list.__wrapped__()
        self.assertEqual(1, listing["result"]["count"])

    @mock.patch.object(bridge, "_get_instance_port", return_value=8192)
    @mock.patch.object(bridge, "safe_post")
    def test_batch_cancel_marks_and_discards(self, fake_post, fake_port):
        import threading as _threading
        gate = _threading.Event()

        def slow(*a, **k):
            gate.wait(timeout=5)
            return {"success": True, "result": ["late"]}

        fake_post.side_effect = slow
        handle = bridge.functions_batch_decompile.__wrapped__(
            targets='["main"]', async_mode=True)
        task_id = handle["result"]["task"]["id"]

        cancelled = bridge.tasks_cancel.__wrapped__(task_id=task_id)
        self.assertTrue(cancelled["success"])
        gate.set()
        self.assertEqual("cancelled", _drain(bridge._bg_tasks[task_id]))
        view = bridge.tasks_get.__wrapped__(task_id=task_id)
        self.assertEqual("cancelled", view["result"]["status"])
        self.assertNotIn("result", view["result"])

    def test_headless_async_mode_spawns_without_ghidra(self):
        with mock.patch.object(
                bridge, "_headless_start_raw",
                return_value={"success": False,
                              "error": {"code": "HEADLESS_NO_FILE",
                                        "message": "no such binary"}}) as raw:
            handle = bridge.headless_start.__wrapped__(
                binary="C:/definitely/missing.exe", async_mode=True)
        self.assertTrue(handle["success"])  # the handle itself succeeded
        task_id = handle["result"]["task"]["id"]
        self.assertEqual("failed", _drain(bridge._bg_tasks[task_id]))
        view = bridge.tasks_get.__wrapped__(task_id=task_id)
        self.assertEqual("HEADLESS_NO_FILE", view["result"]["error"])


class FormatterTests(unittest.TestCase):
    def test_the_list_renders_one_line_per_task(self):
        text = bridge.format_tasks_list({"success": True, "result": {"count": 2, "tasks": [
            {"id": "T-0001", "status": "completed", "kind": "batch_decompile",
             "elapsed_seconds": 1.2, "label": "3 target(s) on port 8192"},
            {"id": "T-0002", "status": "working", "kind": "headless_start",
             "elapsed_seconds": 4.0, "label": "cmd.exe on port 8193"},
        ]}})
        self.assertIn("T-0001  [completed]", text)
        self.assertIn("T-0002  [working", text)
        self.assertIn("batch_decompile", text)
        self.assertIn("headless_start", text)

    def test_the_view_shows_status_and_outcome(self):
        text = bridge.format_task_view({"success": True, "result": {
            "id": "T-0001", "status": "completed", "kind": "batch_decompile",
            "label": "2 target(s)", "elapsed_seconds": 3.0,
            "result": {"result": [{"name": "main"}]}}})
        self.assertIn("[completed]", text)
        self.assertIn("1 item(s)", text)

    def test_an_empty_list_says_so(self):
        self.assertIn("No background tasks",
                      bridge.format_tasks_list({"success": True,
                                                "result": {"count": 0, "tasks": []}}))


class ContractTests(unittest.TestCase):
    def test_the_long_tools_declare_async_mode(self):
        for name in ("functions_batch_decompile", "headless_start"):
            fn = getattr(bridge, name).__wrapped__
            with self.subTest(tool=name):
                self.assertIn("async_mode",
                              inspect.signature(fn).parameters)

    def test_no_reserved_parameter_names(self):
        for name in ("tasks_list", "tasks_get", "tasks_cancel"):
            with self.subTest(tool=name):
                fn = getattr(bridge, name).__wrapped__
                self.assertNotIn("arguments",
                                 inspect.signature(fn).parameters)


if __name__ == "__main__":
    unittest.main(verbosity=2)
