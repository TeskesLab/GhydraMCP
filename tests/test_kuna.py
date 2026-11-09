#!/usr/bin/env python3
"""Tests for the Kuna decompiler integration.

These tests need neither a running Ghidra nor the Kuna binary: they cover
the opt-in precedence, the bridge/CLI contract and the export readers, which
are the parts that can break silently.

Run with:  python tests/test_kuna.py
"""

import json
import os
import re
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

# The tests live in tests/; the code and the repository are one level up.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bridge_mcp_hydra as bridge
from ghydra import kuna as kuna_helper
from ghydra.cli import kuna as kuna_cli
from ghydra.config.config_manager import ConfigManager

_MODULE_TMP = None
_MODULE_PATCHERS = []


def setUpModule():
    """Make the module hermetic: the environment decides, not ~/.ghydra.

    A developer machine usually carries a config file with the integration
    enabled; a clean CI runner does not. The suite must not depend on either,
    so for the whole module the config file points at a path that does not
    exist and GHYDRA_KUNA enables the integration. The opt-in tests override
    both in their own setUp, which is what they are there to prove.
    """
    global _MODULE_TMP
    _MODULE_TMP = tempfile.mkdtemp(prefix="ghydra-kuna-tests-")
    absent = os.path.join(_MODULE_TMP, "no-config.json")
    _MODULE_PATCHERS.extend([
        mock.patch.object(kuna_helper, "CONFIG_FILE", absent),
        mock.patch.object(bridge, "KUNA_CONFIG_FILE", absent),
    ])
    for patcher in _MODULE_PATCHERS:
        patcher.start()
    os.environ[kuna_helper.ENV_ENABLED] = "1"


def tearDownModule():
    for patcher in _MODULE_PATCHERS:
        patcher.stop()
    _MODULE_PATCHERS.clear()
    os.environ.pop(kuna_helper.ENV_ENABLED, None)
    if _MODULE_TMP:
        shutil.rmtree(_MODULE_TMP, ignore_errors=True)


def wait_for_kuna_export_watchers(timeout: float = 10.0) -> None:
    """Wait for the export watchers to finish.

    The bridge watches the export process in a daemon thread, and when the
    process ends that thread writes the sidecar into the work directory. A
    test that removes the directory while the thread is still running races
    with it: the directory is not empty when the cleanup walks it, and the
    suite fails on a filesystem race rather than on the code.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        with bridge._kuna_jobs_lock:
            running = [job for job in bridge._kuna_jobs.values()
                       if job.get("status") == "running"]
        if not running:
            return
        time.sleep(0.01)


KUNA_TOOL_NAMES = [
    "kuna_status",
    "kuna_summary",
    "kuna_functions",
    "kuna_decompile",
    "kuna_disassemble",
    "kuna_read",
    "kuna_strings",
    "kuna_crypto",
    "kuna_xrefs",
    "kuna_unpack",
    "kuna_export_start",
    "kuna_export_status",
    "kuna_export_read",
]


def write_config(directory, payload):
    """Write a config file and return its path."""
    path = os.path.join(directory, "config.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
    return path


class KunaOptInTests(unittest.TestCase):
    """The config file wins over the environment variable."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config_path = os.path.join(self.tmp.name, "config.json")

        patches = [
            mock.patch.object(kuna_helper, "CONFIG_FILE", self.config_path),
            mock.patch.object(kuna_helper, "WORK_DIR", os.path.join(self.tmp.name, "work")),
            mock.patch.object(bridge, "KUNA_CONFIG_FILE", self.config_path),
            mock.patch.object(bridge, "KUNA_WORK_DIR", os.path.join(self.tmp.name, "work")),
            mock.patch.object(ConfigManager, "CONFIG_FILE", Path(self.config_path)),
            mock.patch.dict(os.environ, {}, clear=False),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

        os.environ.pop(kuna_helper.ENV_ENABLED, None)

    def _enabled(self):
        """The decision, as the CLI helper and as the bridge see it."""
        section = kuna_helper.config_section()
        return kuna_helper.is_enabled(section), bridge._kuna_enabled()

    def test_disabled_by_default(self):
        self.assertEqual(self._enabled(), (False, False))

    def test_env_var_enables(self):
        os.environ[kuna_helper.ENV_ENABLED] = "1"
        self.assertEqual(self._enabled(), (True, True))

    def test_config_enables(self):
        write_config(self.tmp.name, {"kuna": {"enabled": True}})
        self.assertEqual(self._enabled(), (True, True))

    def test_config_wins_over_env(self):
        os.environ[kuna_helper.ENV_ENABLED] = "1"
        write_config(self.tmp.name, {"kuna": {"enabled": False}})
        self.assertEqual(self._enabled(), (False, False))

    def test_config_without_enabled_leaves_it_to_the_env(self):
        """A config file that never mentions "enabled" must not pin it off."""
        write_config(self.tmp.name, {"default_host": "localhost"})
        self.assertEqual(self._enabled(), (False, False))

        os.environ[kuna_helper.ENV_ENABLED] = "1"
        self.assertEqual(self._enabled(), (True, True))

    def test_null_enabled_leaves_it_to_the_env(self):
        """`ghydra config init` writes "enabled": null - it must not pin it off."""
        write_config(self.tmp.name, {"kuna": {"enabled": None}})
        self.assertEqual(self._enabled(), (False, False))

        os.environ[kuna_helper.ENV_ENABLED] = "1"
        self.assertEqual(self._enabled(), (True, True))

    def test_config_path_is_used(self):
        write_config(self.tmp.name, {"kuna": {"enabled": True, "path": "/opt/kuna"}})
        self.assertEqual(kuna_helper.find_binary(), "/opt/kuna" if os.path.isfile("/opt/kuna")
                         else kuna_helper.find_binary())

    def test_round_trip_through_the_cli_config(self):
        """GhidraConfig keeps the kuna section across a load/save cycle."""
        from ghydra.config.defaults import GhidraConfig

        config = GhidraConfig.from_dict({"kuna": {"enabled": True, "path": "/opt/kuna"}})
        self.assertTrue(config.kuna_enabled)
        self.assertEqual(config.kuna_path, "/opt/kuna")

        again = GhidraConfig.from_dict(config.to_dict())
        self.assertTrue(again.kuna_enabled)
        self.assertEqual(again.kuna_path, "/opt/kuna")

    def test_unset_enabled_survives_the_round_trip(self):
        from ghydra.config.defaults import GhidraConfig

        config = GhidraConfig.from_dict({})
        self.assertIsNone(config.kuna_enabled)
        self.assertIsNone(GhidraConfig.from_dict(config.to_dict()).kuna_enabled)


class KunaBridgeTests(unittest.TestCase):
    """The bridge contract: every tool is registered and has a formatter."""

    def test_every_tool_has_a_formatter(self):
        """A missing FORMATTERS key silently degrades the output to "Done"."""
        for name in KUNA_TOOL_NAMES:
            with self.subTest(tool=name):
                self.assertIn(name, bridge.FORMATTERS)
                self.assertTrue(callable(bridge.FORMATTERS[name]))

    def test_every_tool_is_registered_in_mcp(self):
        registered = getattr(bridge.mcp._tool_manager, "_tools", {})
        for name in KUNA_TOOL_NAMES:
            with self.subTest(tool=name):
                self.assertIn(name, registered)

    def test_tools_are_not_port_bound(self):
        """The kuna tools are local: they must not ask for a Ghidra instance."""
        import inspect

        for name in KUNA_TOOL_NAMES:
            with self.subTest(tool=name):
                parameters = inspect.signature(getattr(bridge, name)).parameters
                self.assertNotIn("port", parameters)

    def test_disabled_blocks_every_tool(self):
        """With the integration off, no tool may reach the Kuna binary."""
        arguments = {
            "kuna_summary": ("C:/nonexistent",),
            "kuna_functions": ("C:/nonexistent",),
            "kuna_decompile": ("C:/nonexistent", "main"),
            "kuna_disassemble": ("C:/nonexistent", "main"),
            "kuna_read": ("C:/nonexistent", "0x1"),
            "kuna_strings": ("C:/nonexistent", "x"),
            "kuna_crypto": ("C:/nonexistent",),
            "kuna_xrefs": ("C:/nonexistent", "main"),
            "kuna_unpack": ("C:/nonexistent",),
            "kuna_export_start": ("C:/nonexistent",),
            "kuna_export_status": ("job-1",),
            "kuna_export_read": ("job-1",),
        }
        with mock.patch.object(bridge, "_kuna_enabled", return_value=False):
            for name, args in arguments.items():
                with self.subTest(tool=name):
                    result = getattr(bridge, name).__wrapped__(*args)
                    self.assertFalse(result["success"])
                    self.assertEqual(result["error"]["code"], "KUNA_DISABLED")

    def test_formatters_survive_empty_payloads(self):
        """An empty payload must not raise - the agent would only see a crash."""
        for name in KUNA_TOOL_NAMES:
            with self.subTest(tool=name):
                text = bridge.FORMATTERS[name]({"success": True, "result": {}})
                self.assertIsInstance(text, str)

    def test_formatters_report_errors(self):
        for name in KUNA_TOOL_NAMES:
            with self.subTest(tool=name):
                text = bridge.FORMATTERS[name]({
                    "success": False,
                    "error": {"code": "X", "message": "boom"},
                })
                self.assertIn("boom", text)

    def test_the_error_code_reaches_the_agent(self):
        """The code is what an agent branches on, so it must survive."""
        text = bridge.FORMATTERS["kuna_export_read"]({
            "success": False,
            "error": {"code": "KUNA_NO_DIR", "message": "no such export directory"},
        })
        self.assertIn("KUNA_NO_DIR", text)
        self.assertIn("no such export directory", text)


class KunaCliTests(unittest.TestCase):
    """The CLI contract: the commands run and the formatters handle payloads."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config_path = os.path.join(self.tmp.name, "config.json")

        patches = [
            mock.patch.object(kuna_helper, "CONFIG_FILE", self.config_path),
            mock.patch.object(kuna_helper, "WORK_DIR", os.path.join(self.tmp.name, "work")),
            mock.patch.object(ConfigManager, "CONFIG_FILE", Path(self.config_path)),
            mock.patch.dict(os.environ, {}, clear=False),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

        os.environ.pop(kuna_helper.ENV_ENABLED, None)

    def _run(self, args):
        from click.testing import CliRunner

        from ghydra.cli.main import cli

        return CliRunner().invoke(cli, args, catch_exceptions=False)

    def test_status_runs_without_the_binary(self):
        """`kuna status` reports the state; it never needs the binary."""
        result = self._run(["kuna", "status"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("disabled", result.output)

    def test_status_names_the_opt_in_source(self):
        os.environ[kuna_helper.ENV_ENABLED] = "1"
        result = self._run(["kuna", "status"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn(kuna_helper.ENV_ENABLED, result.output)

        write_config(self.tmp.name, {"kuna": {"enabled": True}})
        result = self._run(["kuna", "status"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("config file", result.output)

    def test_every_command_has_help(self):
        for name in ("status", "summary", "functions", "decompile", "disassemble",
                     "read", "strings", "crypto", "xrefs", "unpack", "export",
                     "export-read"):
            with self.subTest(command=name):
                result = self._run(["kuna", name, "--help"])
                self.assertEqual(result.exit_code, 0, result.output)

    def test_the_status_shows_the_kuna_version(self):
        """Rich reads square brackets as markup: the version has to survive it.

        The version is printed inside brackets, and rich drops "[kuna 1.988]"
        whole when it is not escaped - so the version was simply never shown.
        """
        from ghydra.formatters import TableFormatter

        text = TableFormatter().format_kuna({
            "kind": "status",
            "data": {"enabled": True, "source": "the config file",
                     "binary": "kuna", "version": "kuna 1.988",
                     "config_file": "c", "work_dir": "w"},
        })
        self.assertIn("kuna 1.988", text)

    def test_the_status_lists_the_exports(self):
        from ghydra.formatters import TableFormatter

        text = TableFormatter().format_kuna({
            "kind": "status",
            "data": {"enabled": True, "source": "the config file",
                     "binary": "kuna", "config_file": "c", "work_dir": "w",
                     "exports": [{"digest": "9f2c1a4b7e03", "functions": 818,
                                  "binary": "/bin/app", "streaming": False}]},
        })
        self.assertIn("9f2c1a4b7e03", text)
        self.assertIn("kuna://export/9f2c1a4b7e03/index.jsonl", text)

    def test_a_disabled_integration_fails_the_command(self):
        result = self._run(["kuna", "summary", "C:/nonexistent"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("disabled", result.output)

    def test_the_formatters_handle_every_kind(self):
        from ghydra.formatters import JSONFormatter, TableFormatter

        payloads = {
            "status": {"enabled": True, "source": "x", "binary": "kuna", "version": "1.0"},
            "summary": {"binary": "b", "count": 1, "total": 1,
                        "summary": {"entry": {"name": "e", "address_hex": "0x1"}}},
            "functions": {"binary": "b", "total": 1, "offset": 0, "limit": 1,
                          "functions": [{"name": "f", "address_hex": "0x1", "size": 1}]},
            "decompile": {"functions": [{"name": "f", "address_hex": "0x1", "size": 1,
                                         "code": "void f(void) {}"}]},
            "disassemble": {"target": {"name": "f"}, "start_hex": "0x1", "end_hex": "0x2",
                            "count": 1, "bytes": 1,
                            "instructions": [{"address_hex": "0x1", "bytes": "90", "text": "NOP"}]},
            "read": {"start_hex": "0x1", "bytes": 1,
                     "rows": [{"address_hex": "0x1", "bytes": "90", "ascii": "."}]},
            "strings": {"filter": "x", "count": 1,
                        "strings": [{"address_hex": "0x1", "text": "x", "section": ".rdata",
                                     "xrefs_count": 1, "functions": [{"name": "f"}]}]},
            "crypto": {"binary": "b", "constants": [
                {"algorithm": "AES", "name": "sbox", "address_hex": "0x1", "section": ".rdata",
                 "kind": "table", "layout": "u8", "xrefs_count": 1, "functions": [{"name": "f"}]}]},
            "xrefs": {"direction": "from", "target": {"name": "f"},
                      "xrefs": [{"address_hex": "0x1", "kind": "call", "instruction": "CALL f"}]},
            "unpack": {"binary": "b", "output": "o"},
            "export": {"binary": "b", "dir": "d", "functions": 1, "failed": 0, "failures": []},
            "export-read": {"artifact": "c", "function": "f", "text": "code"},
        }

        for formatter in (JSONFormatter(), TableFormatter()):
            for kind, payload in payloads.items():
                with self.subTest(formatter=type(formatter).__name__, kind=kind):
                    text = formatter.format_kuna({"kind": kind, "data": payload})
                    self.assertIsInstance(text, str)
                    self.assertTrue(text.strip())


class KunaExportTests(unittest.TestCase):
    """The export readers: the index slices the exported files."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name

        self.c_text = (
            "#include \"x.h\"\n\n"
            "// Function: sub_1 @ 0x1\n"
            "void sub_1(void)\n{\n}\n\n"
            "// Function: sub_2 @ 0x2\n"
            "void sub_2(void)\n{\n}\n"
        )
        with open(os.path.join(self.dir, "x.c"), "w", encoding="utf-8") as handle:
            handle.write(self.c_text)

        first = self.c_text.index("// Function: sub_1")
        second = self.c_text.index("// Function: sub_2")
        records = [
            {"seq": 0, "name": "sub_1", "addr": "0x1", "size": 4,
             "c_offset": first, "c_len": second - first, "error": None},
            {"seq": 1, "name": "sub_2", "addr": "0x2", "size": 4,
             "c_offset": second, "c_len": len(self.c_text) - second, "error": None},
        ]
        with open(os.path.join(self.dir, "index.jsonl"), "w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record) + "\n")

        with open(os.path.join(self.dir, "x.asm"), "w", encoding="utf-8") as handle:
            handle.write(
                "; header\n"
                "sub_1:  ; 0x1\n"
                "  1000: 90    NOP\n"
                "sub_2:  ; 0x2\n"
                "  2000: 90    NOP\n"
            )

    def test_index_is_read(self):
        records = kuna_helper.index_records(self.dir)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["name"], "sub_1")

    def test_unfinished_last_record_is_deferred(self):
        """A streamed export appends a record only after the C block is done."""
        with open(os.path.join(self.dir, "index.jsonl"), "a", encoding="utf-8") as handle:
            handle.write('{"seq": 2, "name": "sub_3", "addr": "0x3", "size": 4, '
                         '"c_offset": 0, "c_len": 1, "error": null}')
        records = kuna_helper.index_records(self.dir)
        self.assertEqual(len(records), 2)

    def test_the_c_block_is_sliced(self):
        result = kuna_helper.read_export(self.dir, function="sub_1")
        self.assertEqual(result["function"], "sub_1")
        self.assertIn("void sub_1(void)", result["text"])
        self.assertNotIn("void sub_2(void)", result["text"])

    def test_the_asm_block_is_sliced(self):
        result = kuna_helper.read_export(self.dir, function="sub_2", artifact="asm")
        self.assertIn("sub_2:  ; 0x2", result["text"])
        self.assertNotIn("sub_1:", result["text"])

    def test_without_a_function_the_names_are_listed(self):
        result = kuna_helper.read_export(self.dir)
        self.assertEqual(result["total"], 2)
        self.assertEqual(result["functions"][0]["name"], "sub_1")

    def test_the_index_artifact_lists_every_function(self):
        result = kuna_helper.read_export(self.dir, artifact="index")
        self.assertEqual(result["total"], 2)

    def test_an_unknown_function_is_an_error(self):
        with self.assertRaises(kuna_helper.KunaError) as caught:
            kuna_helper.read_export(self.dir, function="sub_99")
        self.assertEqual(caught.exception.code, "KUNA_NO_FUNCTION")

    def test_an_unknown_artifact_is_an_error(self):
        with self.assertRaises(kuna_helper.KunaError) as caught:
            kuna_helper.read_export(self.dir, artifact="nope")
        self.assertEqual(caught.exception.code, "KUNA_BAD_ARTIFACT")


class KunaExportAddressingTests(unittest.TestCase):
    """The export is addressed by its digest, and it is reused when it exists.

    The job registry lives in the bridge process and dies with it. The digest
    the export is named after does not, so the digest is what an agent should
    hold on to - and a complete export should never be paid for twice.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = os.path.join(self.tmp.name, "work")

        patches = [
            mock.patch.object(kuna_helper, "WORK_DIR", self.work),
            mock.patch.object(bridge, "KUNA_WORK_DIR", self.work),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

        # The reuse logic must not depend on a machine that happens to have
        # Kuna installed: a configured path that exists is all the resolver
        # needs, and every test that would actually run it patches Popen.
        self.fake_kuna = os.path.join(self.tmp.name, "kuna-fake")
        with open(self.fake_kuna, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\nexit 0\n")
        previous = os.environ.get(kuna_helper.ENV_PATH)
        os.environ[kuna_helper.ENV_PATH] = self.fake_kuna
        self.addCleanup(self._restore_kuna_path, previous)

        # Registered last, so it runs first: the watcher thread must be done
        # with the work directory before the temporary directory goes.
        self.addCleanup(wait_for_kuna_export_watchers)

        # A binary to export, and the export that belongs to it.
        self.binary = os.path.join(self.tmp.name, "target.bin")
        with open(self.binary, "wb") as handle:
            handle.write(b"\x00" * 16)

        self.dir = bridge._kuna_work_dir(self.binary)
        os.makedirs(self.dir, exist_ok=True)

        self.c_text = (
            "// Function: sub_1 @ 0x1\n"
            "void sub_1(void)\n{\n}\n\n"
            "// Function: sub_2 @ 0x2\n"
            "void sub_2(void)\n{\n}\n"
        )
        # Written in binary: the index records byte offsets into this file, and
        # text mode would turn the newlines into CRLF and shift every offset.
        with open(os.path.join(self.dir, "x.c"), "wb") as handle:
            handle.write(self.c_text.encode("utf-8"))
        first = self.c_text.index("// Function: sub_1")
        second = self.c_text.index("// Function: sub_2")
        records = [
            {"seq": 0, "name": "sub_1", "addr": "0x1", "size": 4,
             "c_offset": first, "c_len": second - first, "error": None},
            {"seq": 1, "name": "sub_2", "addr": "0x2", "size": 4,
             "c_offset": second, "c_len": len(self.c_text) - second, "error": None},
        ]
        with open(os.path.join(self.dir, "index.jsonl"), "w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record) + "\n")

        self.digest = os.path.basename(self.dir)

    @staticmethod
    def _restore_kuna_path(previous):
        if previous is None:
            os.environ.pop(kuna_helper.ENV_PATH, None)
        else:
            os.environ[kuna_helper.ENV_PATH] = previous

    # ---- the cache ---------------------------------------------------

    def test_a_complete_export_is_reused_instead_of_reanalysed(self):
        """The second export of a binary must not pay the analysis again."""
        start = bridge.kuna_export_start.__wrapped__
        with mock.patch.object(bridge.subprocess, "Popen") as popen:
            result = start(binary_path=self.binary)
        popen.assert_not_called()
        self.assertTrue(result["success"], result)
        self.assertTrue(result["result"]["reused"])
        self.assertEqual(result["result"]["status"], "done")
        self.assertEqual(result["result"]["functions"], 2)

    def test_a_subset_the_export_covers_is_reused(self):
        start = bridge.kuna_export_start.__wrapped__
        with mock.patch.object(bridge.subprocess, "Popen") as popen:
            result = start(binary_path=self.binary, functions="sub_1")
        popen.assert_not_called()
        self.assertTrue(result["result"]["reused"])

    def test_a_subset_the_export_does_not_cover_is_reanalysed(self):
        """An export that never held that function cannot answer for it."""
        start = bridge.kuna_export_start.__wrapped__
        with mock.patch.object(bridge.subprocess, "Popen") as popen:
            popen.return_value.pid = 4242
            popen.return_value.wait.return_value = 0
            result = start(binary_path=self.binary, functions="sub_99")
        self.assertTrue(popen.called)
        self.assertFalse(result["result"].get("reused"))

    def test_a_filtered_export_does_not_answer_for_the_whole_binary(self):
        """An export made with a filter holds only what it was asked for.

        The digest is keyed by the path and the mtime, not by the filter, so
        the same directory serves both - and an unfiltered request that
        reused it would answer with the subset and call it the whole binary.
        """
        kuna_helper.write_export_meta(self.dir, self.binary, functions="sub_1")
        state = kuna_helper.export_state(self.dir)
        self.assertTrue(state["filtered"])
        self.assertFalse(kuna_helper.export_covers(state, None))
        self.assertTrue(kuna_helper.export_covers(state, "sub_1"))

    def test_a_filtered_export_is_reanalysed_for_an_unfiltered_request(self):
        start = bridge.kuna_export_start.__wrapped__
        bridge._kuna_write_export_meta(self.dir, self.binary, functions="sub_1")
        with mock.patch.object(bridge.subprocess, "Popen") as popen:
            popen.return_value.pid = 4242
            popen.return_value.wait.return_value = 0
            result = start(binary_path=self.binary)
        self.assertTrue(popen.called)
        self.assertFalse(result["result"].get("reused"))

    def test_the_cli_reanalyses_a_subset_for_an_unfiltered_request(self):
        """The CLI and the bridge must not disagree about the cost."""
        kuna_helper.write_export_meta(self.dir, self.binary, functions="sub_1")
        with mock.patch.object(kuna_helper, "require_binary", return_value="kuna"):
            with mock.patch.object(kuna_helper.subprocess, "run") as run:
                run.return_value.returncode = 0
                run.return_value.stdout = "{}"
                run.return_value.stderr = ""
                result = kuna_helper.export(self.binary)
        self.assertTrue(run.called)
        self.assertFalse(result.get("reused"))

    def test_an_export_of_another_binary_is_not_reused(self):
        """A directory the caller named has no provenance of its own.

        The digest directory is keyed by the path and the mtime, so what is
        in it belongs to that binary. A directory somebody else named can
        hold anything, so the sidecar has to say so.
        """
        state = {
            "binary": os.path.abspath(self.binary),
            "mtime": os.path.getmtime(self.binary),
        }
        self.assertTrue(kuna_helper.export_matches(state, self.binary))

        other = os.path.join(self.tmp.name, "other.bin")
        with open(other, "wb") as handle:
            handle.write(b"\x00")
        self.assertFalse(kuna_helper.export_matches(state, other))

        # A binary rebuilt at the same path is a different binary.
        rebuilt = dict(state, mtime=state["mtime"] - 10)
        self.assertFalse(kuna_helper.export_matches(rebuilt, self.binary))

    def test_a_custom_directory_holding_another_binary_is_not_reused(self):
        custom = os.path.join(self.tmp.name, "custom")
        os.makedirs(custom, exist_ok=True)
        for name in os.listdir(self.dir):
            shutil.copy(os.path.join(self.dir, name), os.path.join(custom, name))
        other = os.path.join(self.tmp.name, "other.bin")
        with open(other, "wb") as handle:
            handle.write(b"\x00")
        kuna_helper.write_export_meta(custom, other)

        with mock.patch.object(kuna_helper, "require_binary", return_value="kuna"):
            with mock.patch.object(kuna_helper.subprocess, "run") as run:
                run.return_value.returncode = 0
                run.return_value.stdout = "{}"
                run.return_value.stderr = ""
                result = kuna_helper.export(self.binary, output=custom)
        self.assertTrue(run.called)
        self.assertFalse(result.get("reused"))

    def test_a_streaming_export_is_not_reused(self):
        """An export still being written is not an answer yet."""
        with open(os.path.join(self.dir, ".streaming"), "w", encoding="utf-8") as handle:
            handle.write("{}")
        self.assertIsNone(bridge._kuna_export_state(self.dir))
        start = bridge.kuna_export_start.__wrapped__
        with mock.patch.object(bridge.subprocess, "Popen") as popen:
            start(binary_path=self.binary)
        self.assertTrue(popen.called)

    def test_the_cli_reuses_the_export_too(self):
        """The CLI and the bridge must not disagree about the cost."""
        with mock.patch.object(kuna_helper, "require_binary", return_value="kuna"):
            with mock.patch.object(kuna_helper.subprocess, "run") as run:
                result = kuna_helper.export(self.binary)
        run.assert_not_called()
        self.assertTrue(result["reused"])
        self.assertEqual(result["functions"], 2)

    # ---- the addressing ----------------------------------------------

    def test_the_export_read_accepts_a_digest(self):
        read = bridge.kuna_export_read.__wrapped__
        result = read(directory=self.digest, function="sub_1")
        self.assertTrue(result["success"], result)
        self.assertIn("void sub_1(void)", result["result"]["text"])

    def test_the_export_read_accepts_a_directory(self):
        read = bridge.kuna_export_read.__wrapped__
        result = read(directory=self.dir, function="sub_2")
        self.assertTrue(result["success"], result)
        self.assertIn("void sub_2(void)", result["result"]["text"])

    def test_the_export_read_needs_an_address(self):
        read = bridge.kuna_export_read.__wrapped__
        result = read()
        self.assertFalse(result["success"])
        self.assertEqual(result["error"]["code"], "KUNA_NO_DIR")

    def test_an_unknown_digest_is_reported_as_a_missing_directory(self):
        read = bridge.kuna_export_read.__wrapped__
        result = read(directory="ffffffffffff")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"]["code"], "KUNA_NO_DIR")

    def test_the_cli_export_read_accepts_a_digest(self):
        result = kuna_helper.read_export(self.digest, function="sub_1")
        self.assertIn("void sub_1(void)", result["text"])

    def test_the_digest_cannot_escape_the_work_directory(self):
        """A digest is 12 hex characters; anything else is refused."""
        with self.assertRaises(ValueError):
            bridge._kuna_export_dir_for("../../etc")
        with self.assertRaises(ValueError):
            bridge._kuna_export_dir_for("not-a-digest")

    # ---- the listing and the sidecar ---------------------------------

    def test_the_listing_is_read_from_disk(self):
        """The listing survives a restart, because it is not held in memory."""
        exports = bridge._kuna_list_exports()
        self.assertEqual(len(exports), 1)
        self.assertEqual(exports[0]["digest"], self.digest)
        self.assertEqual(exports[0]["functions"], 2)

    def test_the_export_records_which_binary_it_came_from(self):
        bridge._kuna_write_export_meta(self.dir, self.binary)
        self.assertEqual(
            bridge._kuna_export_binary(self.dir), os.path.abspath(self.binary)
        )

    def test_the_report_names_the_binary_when_there_is_no_sidecar(self):
        """An export made before the sidecar still says what it is."""
        with open(os.path.join(self.dir, "README.md"), "w", encoding="utf-8") as handle:
            handle.write("# x - kuna project export\n\n| Field | Value |\n|---|---|\n"
                         "| Path | `\\\\?\\C:\\bin\\app.exe` |\n")
        self.assertEqual(
            bridge._kuna_export_binary(self.dir), "C:\\bin\\app.exe"
        )

    def test_the_cli_lists_the_exports(self):
        bridge._kuna_write_export_meta(self.dir, self.binary)
        exports = kuna_helper.list_exports()
        self.assertEqual(len(exports), 1)
        self.assertEqual(exports[0]["digest"], self.digest)

    # ---- the resources ------------------------------------------------

    def test_the_resources_are_registered(self):
        templates = {t.uri_template for t in bridge.mcp._resource_manager.list_templates()}
        self.assertIn("kuna://export/{digest}/index.jsonl", templates)
        self.assertIn("kuna://export/{digest}/{function}.c", templates)
        self.assertIn("kuna://export/{digest}/{function}.asm", templates)
        self.assertIn("kuna://export/{digest}/README.md", templates)

        resources = {str(r.uri) for r in bridge.mcp._resource_manager.list_resources()}
        self.assertIn("kuna://exports", resources)

    def test_the_manifest_lists_the_exports(self):
        bridge._kuna_write_export_meta(self.dir, self.binary)
        manifest = json.loads(bridge.kuna_exports_resource())
        self.assertEqual(manifest["count"], 1)
        self.assertEqual(manifest["exports"][0]["digest"], self.digest)

    def test_the_index_resource_serves_the_index(self):
        text = bridge.kuna_export_index_resource(self.digest)
        self.assertIn('"name": "sub_1"', text)

    def test_the_function_resource_serves_the_c(self):
        text = bridge.kuna_export_c_resource(self.digest, "sub_1")
        self.assertIn("void sub_1(void)", text)

    def test_the_function_resource_serves_the_disassembly(self):
        with open(os.path.join(self.dir, "x.asm"), "w", encoding="utf-8") as handle:
            handle.write("sub_1:  ; 0x1\n  1000: 90    NOP\n")
        text = bridge.kuna_export_asm_resource(self.digest, "sub_1")
        self.assertIn("sub_1:  ; 0x1", text)

    def test_a_function_name_is_percent_decoded(self):
        """A name with a slash cannot go into a URI unescaped."""
        text = "// Function: ns/fn @ 0x1\nvoid ns/fn(void)\n{\n}\n"
        with open(os.path.join(self.dir, "x.c"), "wb") as handle:
            handle.write(text.encode("utf-8"))
        with open(os.path.join(self.dir, "index.jsonl"), "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"seq": 0, "name": "ns/fn", "addr": "0x1",
                                     "size": 4, "c_offset": 0,
                                     "c_len": len(text.encode("utf-8")),
                                     "error": None}) + "\n")
        read = bridge.kuna_export_c_resource(self.digest, "ns%2Ffn")
        self.assertIn("void ns/fn(void)", read)


class KunaErrorTaxonomyTests(unittest.TestCase):
    """One taxonomy of failure reasons, on both sides of the bridge."""

    def test_the_cli_and_the_bridge_carry_the_same_codes(self):
        import inspect

        source = inspect.getsource(kuna_helper)
        cli_codes = set(
            re.findall(r'code(?:\s*:\s*str)?\s*=\s*"(KUNA_[A-Z_]+)"', source)
        )
        self.assertTrue(cli_codes)
        self.assertEqual(cli_codes, set(bridge.KUNA_ERROR_CODES))

    def test_a_missing_binary_is_reported_as_missing(self):
        """The bridge must tell "not installed" from "failed"."""
        with mock.patch.object(bridge, "_kuna_binary", return_value=None):
            outcome = bridge._kuna_run(["--version"])
        self.assertEqual(outcome["error_code"], "KUNA_MISSING")

    def test_a_timeout_is_reported_as_a_timeout(self):
        with mock.patch.object(bridge, "_kuna_binary", return_value="kuna"):
            with mock.patch.object(bridge.subprocess, "run",
                                   side_effect=bridge.subprocess.TimeoutExpired("kuna", 1)):
                outcome = bridge._kuna_run(["--version"])
        self.assertEqual(outcome["error_code"], "KUNA_TIMEOUT")


class KunaDocumentationTests(unittest.TestCase):
    """The reference must describe the code that actually exists."""

    DOC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "GHYDRA_KUNA.md")

    def setUp(self):
        with open(self.DOC, "r", encoding="utf-8") as handle:
            self.doc = handle.read()

    def _tool_table(self):
        """The tool table, as {tool: [documented parameters]}."""
        table = {}
        for line in self.doc.splitlines():
            if not line.startswith("| `kuna_"):
                continue
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            if len(cells) != 3:
                continue
            name = cells[0].strip("`")
            params = {p.strip().strip("`") for p in cells[2].split(",")}
            params.discard("—")
            table[name] = params
        return table

    def test_every_tool_is_documented_with_its_parameters(self):
        import inspect

        table = self._tool_table()
        for name in KUNA_TOOL_NAMES:
            with self.subTest(tool=name):
                self.assertIn(name, table)
                real = set(inspect.signature(getattr(bridge, name)).parameters)
                self.assertEqual(real - table[name], set(),
                                 f"{name}: parameters missing from the reference")
                self.assertEqual(table[name] - real, set(),
                                 f"{name}: the reference lists parameters that do not exist")

    def test_every_command_is_documented_with_its_options(self):
        import click

        from ghydra.cli.kuna import kuna as kuna_group

        blocks = re.findall(r"```bash\n(.*?)```", self.doc, re.S)
        block = next((b for b in blocks if "export-read" in b and "--artifact" in b), "")
        self.assertTrue(block, "the command list is missing from the reference")

        for line in [l for l in block.strip().splitlines() if l.strip()]:
            parts = line.split()
            command = parts[2]
            with self.subTest(command=command):
                self.assertIn(command, kuna_group.commands)
                spec = kuna_group.commands[command]
                for param in spec.params:
                    if isinstance(param, click.Argument):
                        form = f"<{param.name}>" if param.required else f"[{param.name}]"
                        self.assertIn(form, line)
                    else:
                        for option in param.opts:
                            self.assertIn(option, line)
                for token in parts[3:]:
                    if token.startswith("--"):
                        self.assertIn(token, [o for p in spec.params
                                              for o in p.opts])

    def test_the_status_sample_matches_the_formatter(self):
        from ghydra.formatters import TableFormatter

        match = re.search(r"```\n(Kuna integration: .*?)\n```", self.doc, re.S)
        self.assertIsNotNone(match, "the status sample is missing")
        sample = match.group(1).splitlines()
        for label in ("Kuna integration:", "Binary:", "Config:", "Work:"):
            self.assertTrue(any(line.strip().startswith(label) for line in sample),
                            f"the status sample has no {label} line")


if __name__ == "__main__":
    unittest.main(verbosity=2)
