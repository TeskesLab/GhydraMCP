#!/usr/bin/env python3
"""The four gaps that were closed against the REA.

`REA_PARITY.md` named them: `batch_decompile`, `find_xrefs_to_name`,
`inspect_address_context` and `trace_call_path`. This suite is what proves
they are closed - the API answers, the bridge tools answer, and the CLI
answers, and all three agree on the same names.

Two halves, on purpose:

- the contract half needs neither Ghidra nor the network, and always runs;
- the live half needs a Ghidra with a loaded program, and skips itself
  honestly when there is none.
"""

import json
import os
import sys
import unittest

import requests

# The tests live in tests/; the code and the repository are one level up.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bridge_mcp_hydra as bridge
from ghydra.cli.main import cli
from ghydra.utils import parse_targets

DEFAULT_PORT = int(os.getenv("GHYDRAMCP_TEST_PORT") or "8192")

GHYDRAMCP_TEST_HOST = os.getenv('GHYDRAMCP_TEST_HOST')
if GHYDRAMCP_TEST_HOST and GHYDRAMCP_TEST_HOST.strip():
    BASE_URL = f"http://{GHYDRAMCP_TEST_HOST}:{DEFAULT_PORT}"
else:
    BASE_URL = f"http://localhost:{DEFAULT_PORT}"

# The four gaps, by the name each surface gives them.
TOOLS = {
    "batch_decompile": "functions_batch_decompile",
    "find_xrefs_to_name": "xrefs_find_by_name",
    "inspect_address_context": "inspect_address",
    "trace_call_path": "analysis_trace_call_path",
}

# The composed calls the REA has and this project did not: the callers and
# the callees of one function, everything about one function, and an overview
# of the loaded binary.
COMPOSED_TOOLS = {
    "procedure_callers": "analysis_callers",
    "procedure_callees": "analysis_callees",
    "analyze_function": "functions_analyze",
    "binary_overview": "programs_overview",
}

# The parameter names the MCP protocol reserves for itself.
RESERVED_PARAMETERS = {"arguments"}


class ReaParityContractTests(unittest.TestCase):
    """The contract between the three surfaces. Needs no Ghidra."""

    def test_every_gap_has_a_bridge_tool(self):
        names = {tool.name for tool in bridge.mcp._tool_manager.list_tools()}
        for gap, tool in TOOLS.items():
            with self.subTest(gap=gap):
                self.assertIn(tool, names)

    def test_every_composed_call_has_a_bridge_tool(self):
        names = {tool.name for tool in bridge.mcp._tool_manager.list_tools()}
        for gap, tool in COMPOSED_TOOLS.items():
            with self.subTest(gap=gap):
                self.assertIn(tool, names)

    def test_every_composed_call_has_a_formatter(self):
        for gap, tool in COMPOSED_TOOLS.items():
            with self.subTest(gap=gap):
                self.assertIn(tool, bridge.FORMATTERS)

    def test_every_gap_has_a_formatter(self):
        """A missing formatter degrades the answer to "Done" - and nobody notices."""
        for gap, tool in TOOLS.items():
            with self.subTest(gap=gap):
                self.assertIn(tool, bridge.FORMATTERS)

    def test_the_formatter_answers_with_something_readable(self):
        """The formatter must not fall back to the generic one."""
        for gap, tool in TOOLS.items():
            with self.subTest(gap=gap):
                formatter = bridge.FORMATTERS[tool]
                self.assertIsNot(formatter, bridge.format_generic_dict)
                self.assertIsNot(formatter, bridge.format_generic_list)

    def test_no_tool_declares_a_parameter_the_protocol_reserves(self):
        """A parameter called "arguments" loses its value on the way in."""
        for tool in bridge.mcp._tool_manager.list_tools():
            schema = getattr(tool, "parameters", None) or {}
            properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
            reserved = RESERVED_PARAMETERS.intersection(properties)
            with self.subTest(tool=tool.name):
                self.assertFalse(reserved, f"{tool.name} declares {reserved}")

    def test_the_batch_targets_take_a_list_in_every_shape(self):
        """A client hands over a list as text; the tool has to read all of it."""
        shapes = {
            '["main", "0x401000"]': ["main", "0x401000"],
            'main': ["main"],
            'main,strcmp': ["main", "strcmp"],
            '["main"]': ["main"],
        }
        for text, expected in shapes.items():
            with self.subTest(text=text):
                self.assertEqual(bridge._parse_targets(text), expected)
                self.assertEqual(parse_targets(text), expected)

    def test_a_list_given_as_a_list_is_read(self):
        """Some clients deliver the list itself; it has to work too."""
        self.assertEqual(bridge._parse_targets(["main", "0x401000"]), ["main", "0x401000"])
        self.assertEqual(parse_targets(["main", "0x401000"]), ["main", "0x401000"])

    def test_the_validator_turns_a_list_into_the_text_the_tool_reads(self):
        """The schema asks for text; a list that arrives anyway is taken back."""
        as_text = bridge._targets_text(["main", "0x401000"])
        self.assertIsInstance(as_text, str)
        self.assertEqual(bridge._parse_targets(as_text), ["main", "0x401000"])

    def test_an_empty_batch_is_refused(self):
        self.assertEqual(bridge._parse_targets(""), [])
        self.assertEqual(parse_targets("   "), [])

    def test_the_cli_has_a_command_for_every_gap(self):
        """The CLI is the third surface; a gap without a command is half a gap."""
        top = dict(cli.commands)

        self.assertIn("inspect-address", top)

        for group_name, command_name in (("functions", "decompile-batch"),
                                         ("functions", "analyze"),
                                         ("xrefs", "find-by-name"),
                                         ("analysis", "trace-call-path"),
                                         ("analysis", "callers"),
                                         ("analysis", "callees"),
                                         ("analysis", "overview")):
            with self.subTest(group=group_name):
                group = top[group_name]
                self.assertIn(command_name, set(group.commands))

    def test_the_cli_command_help_works(self):
        """The docstring is the help; a broken one is a broken command."""
        from click.testing import CliRunner
        runner = CliRunner()

        for args in (["inspect-address", "--help"],
                     ["functions", "decompile-batch", "--help"],
                     ["functions", "analyze", "--help"],
                     ["xrefs", "find-by-name", "--help"],
                     ["analysis", "trace-call-path", "--help"],
                     ["analysis", "callers", "--help"],
                     ["analysis", "callees", "--help"],
                     ["analysis", "overview", "--help"]):
            with self.subTest(args=args):
                result = runner.invoke(cli, args)
                self.assertEqual(result.exit_code, 0, result.output)

    def test_the_formatters_render_a_sample(self):
        """Each formatter is given a plausible answer and must produce text."""
        samples = {
            "functions_batch_decompile": {
                "success": True,
                "result": [
                    {"functionName": "main", "functionAddress": "140001000",
                     "decompilation": "int main(void) {\n  return 0;\n}", "success": True,
                     "errorMessage": None},
                    {"functionName": "nope", "functionAddress": None, "decompilation": None,
                     "success": False, "errorMessage": "No function at that address"},
                ],
            },
            "xrefs_find_by_name": {
                "success": True,
                "result": {"name": "main", "total": 1,
                           "symbols": [{"name": "main", "address": "140001000", "type": "Function"}],
                           "references": [{"fromAddress": "140002000", "toAddress": "140001000",
                                           "refType": "UNCONDITIONAL_CALL", "fromFunction": "caller"}]},
            },
            "inspect_address": {
                "success": True,
                "result": {"address": "140001000", "addressSpace": "ram",
                           "symbol": {"name": "main", "type": "Function"},
                           "function": {"name": "main", "address": "140001000"},
                           "data": None, "instruction": None,
                           "comment": "the entry point", "eolComment": None,
                           "xrefsTo": [], "xrefsFrom": []},
            },
            "analysis_trace_call_path": {
                "success": True,
                "result": {"found": True, "depth": 1, "maxDepth": 8, "visited": 1,
                           "from": {"name": "caller", "address": "140002000"},
                           "to": {"name": "main", "address": "140001000"},
                           "path": [{"name": "caller", "address": "140002000"},
                                    {"name": "main", "address": "140001000"}],
                           "reason": None},
            },
        }

        for tool, response in samples.items():
            with self.subTest(tool=tool):
                text = bridge.FORMATTERS[tool](response)
                self.assertIsInstance(text, str)
                self.assertTrue(text.strip())
                self.assertNotEqual(text.strip(), "Done")

    def test_a_page_that_is_not_the_whole_list_says_so(self):
        """A list of a hundred that reads as "there are a hundred".

        A function with a hundred and thirty-six callers came back as a list
        of the first hundred, and nothing said that the other thirty-six were
        not there.
        """
        response = {
            "success": True,
            "result": [{"name": "caller", "address": "140002000", "signature": "void f()"}],
            "meta": {"total": 136, "offset": 0, "limit": 1},
        }
        text = bridge.FORMATTERS["analysis_callers"](response)
        self.assertIn("136", text)
        self.assertIn("offset", text)

        # The whole list says nothing about a page it does not have.
        whole = {"success": True, "result": response["result"], "meta": {"total": 1}}
        self.assertNotIn("136", bridge.FORMATTERS["analysis_callers"](whole))

    def test_the_callers_and_the_callees_take_a_page(self):
        """The tools expose the page the endpoint already had."""
        import inspect

        for tool in ("analysis_callers", "analysis_callees"):
            with self.subTest(tool=tool):
                parameters = inspect.signature(getattr(bridge, tool)).parameters
                self.assertIn("offset", parameters)
                self.assertIn("limit", parameters)

    def test_the_deadline_of_a_batch_covers_the_batch(self):
        """The server runs the targets one after the other.

        The timeout of a batch travels in the body and not in the query, so a
        deadline derived from the query alone is one function long - and the
        bridge gives up while the server is still decompiling the rest.
        """
        deadline = bridge._extract_batch_transport_timeout(
            {"targets": ["a", "b", "c"], "timeout": 120})
        self.assertGreaterEqual(deadline, 3 * 120)

        # Not a batch, no batch deadline.
        self.assertEqual(bridge._extract_batch_transport_timeout(None), 0)
        self.assertEqual(bridge._extract_batch_transport_timeout({"targets": []}), 0)

    def test_a_composed_answer_keeps_what_it_already_has(self):
        """A part that failed does not throw away the rest.

        The function was found and the decompilation came with it; a caller
        that could not be fetched is an empty part, not a lost answer.
        """
        from click.testing import CliRunner

        from ghydra.cli.functions import functions
        from ghydra.client.exceptions import GhidraError

        class HalfBrokenClient:
            """Answers everything but the callers."""

            timeout = 30

            def get(self, endpoint, params=None):
                if endpoint.startswith("analysis/callers"):
                    raise GhidraError("the callers could not be fetched")
                if endpoint.endswith("/decompile"):
                    return {"result": {"decompilation": "int main(void) { return 0; }"}}
                if endpoint.startswith("functions/"):
                    return {"result": {"name": "main", "address": "140001000"}}
                return {"result": []}

        class PlainFormatter:
            def format_function_analysis(self, payload):
                return json.dumps(payload)

            def format_error(self, exc):
                return str(exc)

        result = CliRunner().invoke(functions, ["analyze", "--address", "140001000"], obj={
            "client": HalfBrokenClient(),
            "formatter": PlainFormatter(),
            "config": None,
            "output_json": True,
        })

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload["result"]["function"]["name"], "main")
        self.assertIn("return 0", payload["result"]["decompilation"])
        self.assertEqual(payload["result"]["callers"], [])

    def test_the_relations_are_rendered_after_the_decompilation(self):
        """The relations are part of the answer either way.

        The formatter returned as soon as the decompilation was there, so the
        default table carried the function and the C code and nothing else.
        """
        from ghydra.formatters.table_formatter import TableFormatter

        payload = {
            "success": True,
            "result": {
                "function": {"name": "main", "address": "140001000"},
                "decompilation": "int main(void) { return 0; }",
                "callers": [{"name": "caller", "address": "140002000"}],
                "callees": [{"name": "callee", "address": "140003000"}],
                "xrefs": [{"fromAddress": "140004000", "toAddress": "140001000",
                           "refType": "UNCONDITIONAL_CALL"}],
            },
        }
        text = TableFormatter(use_colors=False).format_function_analysis(payload)
        self.assertIn("Callers", text)
        self.assertIn("Callees", text)
        self.assertIn("References", text)
        self.assertIn("caller", text)


class ReaParityApiTests(unittest.TestCase):
    """The API against a live Ghidra."""

    def setUp(self):
        try:
            response = requests.get(f"{BASE_URL}/info", timeout=3)
            if response.status_code != 200:
                raise RuntimeError("no info")
        except Exception:
            self.skipTest("Ghidra not running")
        # The bridge answers for 8192 by default; the instance under test is
        # not always the first one.
        bridge.instances_use.__wrapped__(port=DEFAULT_PORT)

    # -- helpers ----------------------------------------------------------

    def _get(self, endpoint, **params):
        response = requests.get(f"{BASE_URL}/{endpoint}", params=params, timeout=60)
        return response

    def _functions(self, limit=40):
        response = self._get("functions", limit=limit)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json().get("result", [])

    def _caller_and_callee(self):
        """A pair of functions where one calls the other, found in the program."""
        for function in self._functions():
            address = function.get("address")
            if not address:
                continue
            response = self._get("xrefs", to_addr=address, type="CALL", limit=10)
            if response.status_code != 200:
                continue
            for ref in response.json().get("result", []):
                # Ghidra names the call types UNCONDITIONAL_CALL, CALL_OVERRIDE,
                # CALL_INDIRECT - the type filter matches them all.
                if "CALL" not in str(ref.get("refType", "")):
                    continue
                caller = ref.get("fromFunction")
                if isinstance(caller, dict):
                    caller = caller.get("name")
                if caller and caller != function.get("name"):
                    return caller, function.get("name")
        return None

    # -- the four gaps ----------------------------------------------------

    def test_batch_decompile_answers_one_entry_per_target(self):
        functions = self._functions(limit=3)
        if not functions:
            self.skipTest("the program has no functions")

        targets = [functions[0]["name"], "a_name_that_is_not_there"]
        response = requests.post(f"{BASE_URL}/functions/decompile-batch",
                                 json={"targets": targets, "timeout": 60},
                                 timeout=300)
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()

        self.assertTrue(body.get("success"), body)
        self.assertIn("result", body)
        self.assertIn("_links", body)

        entries = body["result"]
        self.assertEqual(len(entries), len(targets))
        self.assertTrue(entries[0]["success"], entries[0])
        self.assertTrue(entries[0]["decompilation"])
        # A target that resolves to nothing must not take the batch down with it.
        self.assertFalse(entries[1]["success"])
        self.assertTrue(entries[1]["errorMessage"])

    def test_find_xrefs_to_name_answers_the_symbols_and_the_references(self):
        functions = self._functions(limit=20)
        if not functions:
            self.skipTest("the program has no functions")

        name = functions[0]["name"]
        response = self._get("xrefs/to-name/" + name)
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()

        self.assertTrue(body.get("success"), body)
        result = body["result"]
        self.assertEqual(result["name"], name)
        self.assertTrue(result["symbols"], "the symbol must be resolved")
        self.assertIn("references", result)
        self.assertEqual(result["total"], len(result["references"]))

    def test_find_xrefs_to_name_says_so_when_there_is_no_such_symbol(self):
        response = self._get("xrefs/to-name/no_symbol_with_this_name_xyz")
        self.assertEqual(response.status_code, 404, response.text)
        body = response.json()
        self.assertFalse(body.get("success"))
        self.assertEqual(body["error"]["code"], "SYMBOL_NOT_FOUND")

    def test_inspect_address_context_answers_everything_at_once(self):
        functions = self._functions(limit=1)
        if not functions:
            self.skipTest("the program has no functions")

        address = functions[0]["address"]
        response = self._get("inspect/address/" + address)
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()

        self.assertTrue(body.get("success"), body)
        result = body["result"]
        self.assertEqual(result["address"], address)
        self.assertIn("addressSpace", result)
        self.assertIn("symbol", result)
        self.assertIn("function", result)
        self.assertIn("xrefsTo", result)
        self.assertIn("xrefsFrom", result)
        # The function that holds the address is the one that was asked about.
        self.assertEqual(result["function"]["name"], functions[0]["name"])

    def test_inspect_address_context_refuses_an_address_that_is_not_one(self):
        response = self._get("inspect/address/not_an_address")
        self.assertIn(response.status_code, (400, 404), response.text)
        self.assertFalse(response.json().get("success"))

    def test_trace_call_path_finds_the_chain(self):
        pair = self._caller_and_callee()
        if not pair:
            self.skipTest("no caller/callee pair in this program")

        caller, callee = pair
        response = self._get("analysis/call-path", **{"from": caller, "to": callee})
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()

        self.assertTrue(body.get("success"), body)
        result = body["result"]
        self.assertTrue(result["found"], result)
        self.assertEqual(result["from"]["name"], caller)
        self.assertEqual(result["to"]["name"], callee)
        self.assertGreaterEqual(len(result["path"]), 2)
        self.assertEqual(result["path"][0]["name"], caller)
        self.assertEqual(result["path"][-1]["name"], callee)

    def test_trace_call_path_keeps_the_function_in_the_middle(self):
        """Every link of the path is a node of it.

        The path was rebuilt from the last hop back to the source, and the
        rebuild put the source in twice and dropped the function in between:
        a path of A -> B -> C came back as A, A, C.
        """
        pair = self._caller_and_callee()
        if not pair:
            self.skipTest("no caller/callee pair in this program")

        caller, callee = pair
        response = self._get("analysis/call-path", **{"from": caller, "to": callee})
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()["result"]

        if not result.get("found"):
            self.skipTest("this program has no path between the two")

        path = result["path"]
        names = [node.get("name") for node in path]
        self.assertEqual(len(names), len(set(names)),
                         f"the path repeats a function: {names}")
        self.assertEqual(result["depth"], len(path) - 1,
                         f"the depth does not match the path: {names}")

    def test_trace_call_path_says_so_when_there_is_no_chain(self):
        pair = self._caller_and_callee()
        if not pair:
            self.skipTest("no caller/callee pair in this program")

        caller, callee = pair
        # The other way round is not a path: a call goes one way.
        response = self._get("analysis/call-path", **{"from": callee, "to": caller, "max_depth": 1})
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()["result"]

        self.assertFalse(result["found"])
        self.assertTrue(result["reason"])
        self.assertEqual(result["path"], [])

    def test_trace_call_path_refuses_a_function_that_is_not_there(self):
        response = self._get("analysis/call-path",
                             **{"from": "main", "to": "no_function_with_this_name_xyz"})
        self.assertEqual(response.status_code, 404, response.text)
        self.assertEqual(response.json()["error"]["code"], "FUNCTION_NOT_FOUND")

    # -- the bridge over the same ground ----------------------------------

    def test_the_bridge_tools_answer_over_the_wire(self):
        functions = self._functions(limit=2)
        if not functions:
            self.skipTest("the program has no functions")

        name = functions[0]["name"]
        address = functions[0]["address"]

        batch = bridge.functions_batch_decompile.__wrapped__(
            targets=json.dumps([name, "a_name_that_is_not_there"]))
        self.assertTrue(batch.get("success"), batch)
        self.assertEqual(len(batch["result"]), 2)
        self.assertTrue(batch["result"][0]["success"])
        self.assertFalse(batch["result"][1]["success"])

        by_name = bridge.xrefs_find_by_name.__wrapped__(name=name)
        self.assertTrue(by_name.get("success"), by_name)
        self.assertTrue(by_name["result"]["symbols"])

        context = bridge.inspect_address.__wrapped__(address=address)
        self.assertTrue(context.get("success"), context)
        self.assertEqual(context["result"]["address"], address)

        pair = self._caller_and_callee()
        if pair:
            caller, callee = pair
            path = bridge.analysis_trace_call_path.__wrapped__(
                from_function=caller, to_function=callee)
            self.assertTrue(path.get("success"), path)
            self.assertTrue(path["result"]["found"])

    # -- the composed calls -----------------------------------------------

    def test_the_callers_and_the_callees_answer(self):
        pair = self._caller_and_callee()
        if not pair:
            self.skipTest("no caller/callee pair in this program")

        caller, callee = pair
        functions = {f["name"]: f for f in self._functions(limit=200)}
        if callee not in functions:
            self.skipTest("the callee is not in the first page of functions")

        callee_address = functions[callee]["address"]

        callers = bridge.analysis_callers.__wrapped__(address=callee_address)
        self.assertTrue(callers.get("success"), callers)
        self.assertTrue(callers["result"], "the callee has at least one caller")

        # The caller of that caller is the callee again: the two answers
        # have to agree about the edge between them.
        caller_address = self._caller_address(callee_address)
        callees = bridge.analysis_callees.__wrapped__(address=caller_address)
        self.assertTrue(callees.get("success"), callees)
        self.assertIn(callee, [c.get("name") for c in callees["result"]])

    def _caller_address(self, callee_address):
        """The address of the function that calls the given one."""
        response = self._get("xrefs", to_addr=callee_address, type="CALL", limit=10)
        for ref in response.json().get("result", []):
            if "CALL" not in str(ref.get("refType", "")):
                continue
            address = ref.get("fromFunctionAddress")
            if address:
                return address
        self.fail("no caller found for " + callee_address)

    def test_analyzing_a_function_answers_everything_at_once(self):
        functions = self._functions(limit=1)
        if not functions:
            self.skipTest("the program has no functions")

        function = functions[0]
        analysis = bridge.functions_analyze.__wrapped__(address=function["address"])
        self.assertTrue(analysis.get("success"), analysis)

        result = analysis["result"]
        self.assertEqual(result["function"]["name"], function["name"])
        self.assertIn("callers", result)
        self.assertIn("callees", result)
        self.assertIn("xrefs", result)
        self.assertTrue(result["decompilation"], "the decompilation must be there")

    def test_the_overview_of_the_loaded_binary_answers(self):
        overview = bridge.programs_overview.__wrapped__()
        self.assertTrue(overview.get("success"), overview)

        result = overview["result"]
        self.assertIn("program", result)
        self.assertTrue(result["segments"])
        self.assertIn("statistics", result)
        self.assertIsNotNone(result["statistics"]["functions"])

    def test_the_batch_survives_the_protocol(self):
        """The list of targets has to survive the way a client sends it.

        A client that hands over a nested list flattens it, and every value
        arrives as a string. This drives the tool over the protocol, the way
        a client does, and looks at what arrived - not at the text of the
        answer.
        """
        functions = self._functions(limit=1)
        if not functions:
            self.skipTest("the program has no functions")

        name = functions[0]["name"]
        text = self._call_over_the_protocol(
            "functions_batch_decompile",
            {"targets": json.dumps([name, "no_such_function_xyz"])})

        self.assertIn(name, text)
        self.assertIn("no_such_function_xyz", text)
        self.assertIn("1 of 2 succeeded", text)

    def _call_over_the_protocol(self, tool: str, arguments: dict) -> str:
        """Call a bridge tool the way a client does, over the protocol."""
        import asyncio

        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "bridge_mcp_hydra.py")

        async def call():
            params = StdioServerParameters(command=sys.executable, args=[script])
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    # The bridge answers for 8192 by default; the instance
                    # under test is not always the first one.
                    await session.call_tool("instances_use",
                                            arguments={"port": DEFAULT_PORT})
                    result = await session.call_tool(tool, arguments=arguments)
                    return result.content[0].text

        return asyncio.run(call())


if __name__ == "__main__":
    unittest.main(verbosity=2)
