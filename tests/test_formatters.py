"""Every formatter, with the answer of the tool it belongs to.

The surface-parity suite checked that each formatter was **callable** and took
`**kwargs` — it never called one with a payload. A formatter that raises takes
the whole answer down: the tool succeeded and the text did not come out.

The pairing is the real one: the tool is called (with the network cut), the
answer it produces is handed to its formatter, and the formatter must answer.
Guessing the shape would test a shape no tool produces; this tests the pair as
it runs.

The error envelope is checked for every formatter too: any tool can fail, and
the formatter has to say so rather than raise.
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bridge_mcp_hydra as bridge  # noqa: E402

from test_bridge_tools import (  # noqa: E402
    BridgeToolTests, _no_network, _value_for)


class FormatterTests(unittest.TestCase):
    """Every formatter answers for the answer of its own tool."""

    def setUp(self):
        self.helper = BridgeToolTests()

    def _tool_arguments(self, tool):
        import inspect

        arguments = {}
        for parameter in inspect.signature(tool.fn).parameters.values():
            if parameter.default is not inspect._empty:
                continue
            arguments[parameter.name] = _value_for(parameter.name)
        return arguments

    def test_every_formatter_answers_for_the_answer_of_its_tool(self):
        """The pair as it runs: the tool's answer goes into its formatter."""
        workspace = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            ".formatter-walk")
        os.makedirs(workspace, exist_ok=True)
        failures = []
        checked = 0
        patches = _no_network()
        for patcher in patches:
            patcher.start()
        try:
            with mock.patch.dict(os.environ,
                                 {"GHYDRA_STATE_DIR": workspace}):
                for name, tool in sorted(self.helper._tools().items()):
                    formatter = bridge.FORMATTERS.get(name)
                    if formatter is None:
                        failures.append(f"{name}: no formatter")
                        continue
                    unwrapped = getattr(tool.fn, "__wrapped__", tool.fn)
                    try:
                        response = unwrapped(**self._tool_arguments(tool))
                    except Exception:  # noqa: BLE001 - the tool refused
                        # A tool that refuses has no answer to format; the
                        # refusal is checked by the tool suite.
                        continue
                    try:
                        answer = formatter(response, **self._tool_arguments(tool))
                    except Exception as exc:  # noqa: BLE001 - that is measured
                        failures.append(f"{name}: {type(exc).__name__}: {exc}")
                        continue
                    if answer is None or (isinstance(answer, str)
                                          and not answer.strip()):
                        failures.append(f"{name}: answered with nothing")
                    checked += 1
        finally:
            for patcher in patches:
                patcher.stop()
        self.assertGreater(checked, 50, "the walk paired almost nothing")
        self.assertEqual([], failures,
                         f"{len(failures)} formatter(s) failed")

    def test_every_formatter_answers_for_an_error(self):
        """Any tool can fail, and its formatter has to say so."""
        failures = []
        for name, formatter in sorted(bridge.FORMATTERS.items()):
            try:
                answer = formatter(
                    {"success": False,
                     "error": {"code": "NO_SUCH_THING", "message": "no"}},
                    **{})
            except Exception as exc:  # noqa: BLE001
                failures.append(f"{name}: {type(exc).__name__}: {exc}")
                continue
            if answer is None:
                failures.append(f"{name}: answered with nothing")
        self.assertEqual([], failures,
                         f"{len(failures)} formatter(s) failed on an error")

    def test_the_catalogue_is_complete(self):
        self.assertEqual(134, len(bridge.FORMATTERS))


if __name__ == "__main__":
    unittest.main()
