"""The `--mcp-config` suite: Phase 2's combined client configuration.

What is proven here:

* the configuration registers the two servers **separately**, with the transports
  each one actually speaks (stdio for the bridge, HTTP + bearer for the debugger);
* the debugger entry is left out — with the reason — when the token is unknown,
  instead of naming a server nobody can authenticate against;
* the token is a secret: it is masked in everything the summary prints, and a
  written file holds it while the printed document does not;
* **every environment variable the configuration sets is one the bridge reads** —
  the guard for a mistake made while writing this: `GHIDRA_HYDRA_PORT` was invented,
  and a configuration that sets it would send the user looking for a mechanism that
  does not exist;
* the tool groups are the bridge's groups, checked against the generated contract.

No Ghidra, no debugger, no network.
"""

import io
import json
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from click.testing import CliRunner  # noqa: E402

from ghydra import mcpconfig  # noqa: E402
from ghydra.cli.main import cli  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOKEN = "0123456789abcdef0123456789abcdef"


def real_bridge_environment() -> set:
    """Every GHYDRA_/GHIDRA_ name that appears in the bridge's source."""
    with io.open(os.path.join(ROOT, "bridge_mcp_hydra.py"), encoding="utf-8") as handle:
        text = handle.read()
    return set(re.findall(r"GHYDRA_[A-Z_]+|GHIDRA_[A-Z_]+", text))


class EntryTests(unittest.TestCase):

    def test_the_bridge_entry_points_at_a_file_that_exists(self):
        entry = mcpconfig.bridge_entry()
        script = entry["args"][-1]
        self.assertEqual("bridge_mcp_hydra.py", os.path.basename(script))
        self.assertTrue(os.path.exists(script), script)
        self.assertIn(entry["command"], ("uv", sys.executable, "python3", "python"))

    def test_the_groups_and_the_host_travel_in_the_environment(self):
        entry = mcpconfig.bridge_entry(groups=["core", "functions"],
                                       host="192.168.0.10")
        self.assertEqual("core,functions", entry["env"]["GHYDRA_TOOL_GROUPS"])
        self.assertEqual("192.168.0.10", entry["env"]["GHIDRA_HYDRA_HOST"])

    def test_every_variable_set_is_one_the_bridge_reads(self):
        """The guard for the invented variable: the bridge decides what exists."""
        known = real_bridge_environment()
        entry = mcpconfig.bridge_entry(groups=["core"], host="127.0.0.1",
                                       state_dir="/tmp/state")
        for name in entry.get("env") or {}:
            with self.subTest(name=name):
                self.assertIn(name, known,
                              f"{name} is not read by bridge_mcp_hydra.py")

    def test_an_unknown_group_is_refused_with_the_list(self):
        with self.assertRaises(ValueError) as caught:
            mcpconfig.parse_groups("core,nope")
        self.assertIn("nope", str(caught.exception))
        self.assertIn("functions", str(caught.exception))

    def test_the_groups_are_the_ones_the_contract_describes(self):
        with io.open(os.path.join(ROOT, "contract", "tools.json"),
                     encoding="utf-8") as handle:
            tools = json.load(handle)["tools"]
        from_contract = {tool["group"] for tool in tools}
        self.assertTrue(from_contract.issubset(set(mcpconfig.TOOL_GROUPS)),
                        f"contract has groups the module does not: "
                        f"{from_contract - set(mcpconfig.TOOL_GROUPS)}")


class DebuggerEntryTests(unittest.TestCase):

    def test_a_known_token_gives_an_http_entry(self):
        entry, reason = mcpconfig.debugger_entry({"token": TOKEN, "port": 9094})
        self.assertIsNone(reason)
        self.assertEqual("http", entry["type"])
        self.assertEqual(f"Bearer {TOKEN}", entry["headers"]["Authorization"])
        self.assertTrue(entry["url"].startswith("http://127.0.0.1:9094"))

    def test_an_unknown_token_omits_the_entry_and_says_why(self):
        entry, reason = mcpconfig.debugger_entry({"token": ""})
        self.assertIsNone(entry)
        self.assertIn("token", reason)
        self.assertIn("GHYDRA_X64DBG_TOKEN", reason)


class DocumentTests(unittest.TestCase):

    def test_the_two_servers_are_separate_entries(self):
        document = mcpconfig.build(settings={"token": TOKEN})
        servers = document["mcpServers"]
        self.assertIn("ghydra", servers)
        self.assertIn("x64dbg", servers)

    def test_without_the_debugger_only_the_bridge_is_registered(self):
        document = mcpconfig.build(settings={"token": TOKEN}, include_debugger=False)
        self.assertEqual(["ghydra"], list(document["mcpServers"]))

    def test_the_missing_token_is_a_note_not_a_silent_omission(self):
        document = mcpconfig.build(settings={"token": ""})
        self.assertEqual(["ghydra"], list(document["mcpServers"]))
        self.assertTrue(document.get("_notes"))
        self.assertIn("token", " ".join(document["_notes"]))

    def test_the_summary_masks_the_token(self):
        document = mcpconfig.build(settings={"token": TOKEN})
        lines = mcpconfig.summary(document)
        joined = "\n".join(lines)
        self.assertNotIn(TOKEN, joined)
        self.assertIn(mcpconfig.MASK, joined)

    def test_the_summary_can_show_it_when_asked(self):
        document = mcpconfig.build(settings={"token": TOKEN})
        joined = "\n".join(mcpconfig.summary(document, include_secrets=True))
        self.assertIn(TOKEN, joined)

    def test_the_gateway_form_is_one_entry(self):
        """Phase 3's form: one server, five tools, the workflow in one call."""
        document = mcpconfig.build(gateway=True)
        self.assertEqual(["ghydra-gateway"], list(document["mcpServers"]))
        entry = document["mcpServers"]["ghydra-gateway"]
        self.assertEqual(mcpconfig.GATEWAY_SCRIPT, entry["command"])
        self.assertNotIn("headers", entry, "the gateway resolves the token itself")

    def test_the_gateway_entry_does_not_carry_the_token(self):
        document = mcpconfig.build(gateway=True, settings={"token": TOKEN})
        self.assertNotIn(TOKEN, json.dumps(document))

    def test_masking_does_not_touch_the_original(self):
        document = mcpconfig.build(settings={"token": TOKEN})
        masked = mcpconfig.mask(document)
        self.assertEqual(TOKEN,
                         document["mcpServers"]["x64dbg"]["headers"]["Authorization"]
                         .split(" ", 1)[1])
        self.assertEqual(mcpconfig.MASK,
                         masked["mcpServers"]["x64dbg"]["headers"]["Authorization"]
                         .split(" ", 1)[1])


class WriteTests(unittest.TestCase):

    def test_the_file_holds_the_token_and_not_the_notes(self):
        document = mcpconfig.build(settings={"token": ""})
        directory = tempfile.mkdtemp(prefix="ghydra-mcp-config-")
        path = os.path.join(directory, "mcp.json")
        mcpconfig.write(document, path)
        try:
            written = json.load(io.open(path, encoding="utf-8"))
            self.assertNotIn("_notes", written)
            self.assertIn("ghydra", written["mcpServers"])
        finally:
            os.unlink(path)
            os.rmdir(directory)

    def test_the_file_is_the_only_place_the_token_is_printed(self):
        """Printing and writing differ on purpose; both are needed."""
        document = mcpconfig.build(settings={"token": TOKEN})
        directory = tempfile.mkdtemp(prefix="ghydra-mcp-config-")
        path = os.path.join(directory, "mcp.json")
        mcpconfig.write(document, path)
        try:
            raw = io.open(path, encoding="utf-8").read()
            self.assertIn(TOKEN, raw)
            self.assertNotIn(TOKEN, "\n".join(mcpconfig.summary(document)))
        finally:
            os.unlink(path)
            os.rmdir(directory)


class CommandTests(unittest.TestCase):

    def run_command(self, *arguments, env=None):
        runner = CliRunner(env=env)
        return runner.invoke(cli, ["mcp-config", *arguments],
                             catch_exceptions=False)

    def test_the_command_prints_a_configuration_the_client_can_read(self):
        result = self.run_command("--groups", "core,functions")
        self.assertEqual(0, result.exit_code, result.output)
        # The runner mixes stdout and stderr; the summary that follows the JSON is
        # not part of it, so decode exactly one object.
        start = result.output.index("{")
        document, _end = json.JSONDecoder().raw_decode(result.output[start:])
        self.assertIn("ghydra", document["mcpServers"])
        self.assertEqual("core,functions",
                         document["mcpServers"]["ghydra"]["env"]["GHYDRA_TOOL_GROUPS"])

    def test_an_unknown_group_is_a_usage_error(self):
        result = self.run_command("--groups", "nope")
        self.assertEqual(1, result.exit_code)
        self.assertIn("unknown tool group", result.output)

    def test_the_printed_configuration_masks_a_known_token(self):
        result = self.run_command(env={"GHYDRA_X64DBG_TOKEN": TOKEN})
        self.assertEqual(0, result.exit_code, result.output)
        self.assertNotIn(TOKEN, result.output)
        self.assertIn(mcpconfig.MASK, result.output)

    def test_writing_puts_the_secret_in_the_file_and_warns(self):
        directory = tempfile.mkdtemp(prefix="ghydra-mcp-config-")
        path = os.path.join(directory, "mcp.json")
        result = self.run_command("-o", path, env={"GHYDRA_X64DBG_TOKEN": TOKEN})
        try:
            self.assertEqual(0, result.exit_code, result.output)
            self.assertIn("keep it out of version control", result.output)
            written = json.load(io.open(path, encoding="utf-8"))
            self.assertIn(TOKEN,
                          json.dumps(written))
        finally:
            if os.path.exists(path):
                os.unlink(path)
            os.rmdir(directory)


if __name__ == "__main__":
    unittest.main(verbosity=2)