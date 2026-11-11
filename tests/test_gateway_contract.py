"""The contract's gateway section, and the gateway that implements it.

`contract/vocabulary.json` names the five tools of the gateway server and maps
the plan's step names to them. Nothing tied that document to the code: the
gateway could rename a tool, drop one or add one, and the contract would still
say what it always said — the document is the contract, and a contract that no
longer describes the thing is worse than no contract.

The gateway's tools are closures inside `build_server()`, so the test builds the
server — with the fake clients — and asks the server for its tools.
"""

import io
import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ghydra import gateway  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class GatewayContractTests(unittest.TestCase):
    """The vocabulary describes the gateway that exists."""

    def _vocabulary(self):
        with io.open(os.path.join(ROOT, "contract", "vocabulary.json"),
                     encoding="utf-8") as handle:
            return json.load(handle)

    def _tools(self):
        """The tools the gateway registers, built with the fake clients."""
        server = gateway.build_server(factory=lambda: (object(), lambda: object()))
        manager = getattr(server, "_tool_manager", None)
        tools = getattr(manager, "_tools", {})
        return set(tools)

    def test_the_gateway_tools_are_the_ones_the_contract_names(self):
        section = self._vocabulary()["gateway"]
        named = set(section["tools"])
        self.assertEqual(named, self._tools(),
                         "the contract and the gateway name different tools")

    def test_the_steps_are_mapped_the_way_the_code_maps_them(self):
        section = self._vocabulary()["gateway"]
        documented = section["steps"]
        implemented = {step: tool for step, tool in gateway.GATEWAY_STEPS}
        self.assertEqual(documented, implemented,
                         "the contract and the gateway map the steps differently")

    def test_the_names_follow_the_naming_rule(self):
        """`namespace_verb`, snake_case: the contract's own rule."""
        pattern = re.compile(r"^[a-z][a-z0-9]*(_[a-z0-9]+)+$")
        for name in self._vocabulary()["gateway"]["tools"]:
            self.assertTrue(pattern.match(name),
                            f"{name} does not follow the naming rule")

    def test_a_tool_that_cannot_reach_its_clients_answers_with_a_code(self):
        """The contract's rule 3: a tool answers with a code, it does not raise.

        The refusal that protects the address translation is the whole point of
        the workflow, and it has to reach the agent as a code.
        """
        def refuse():
            raise OSError("no Ghidra instance is serving the API")

        server = gateway.build_server(factory=refuse)
        tools = server._tool_manager._tools
        answer = tools["target_open"].fn()
        self.assertIsInstance(answer, dict)
        self.assertFalse(answer.get("success", True))
        self.assertTrue(answer.get("code"), "the failure carries no code")


if __name__ == "__main__":
    unittest.main()
