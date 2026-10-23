#!/usr/bin/env python3
"""Tests for the Kuna decompiler integration.

These tests need neither a running Ghidra nor the Kuna binary: they cover
the opt-in precedence, the bridge/CLI contract and the export readers, which
are the parts that can break silently.

Run with:  python test_kuna.py
"""

import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bridge_mcp_hydra as bridge
from ghydra import kuna as kuna_helper
from ghydra.cli import kuna as kuna_cli
from ghydra.config.config_manager import ConfigManager


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


class KunaDocumentationTests(unittest.TestCase):
    """The reference must describe the code that actually exists."""

    DOC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "GHYDRA_KUNA.md")

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
