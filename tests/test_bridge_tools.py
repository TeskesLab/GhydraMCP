"""Every bridge tool, and what it does when the instance is not there.

The CLI had the same gap and the same defect: a handler that names a class it
does not import raises a `NameError` in the middle of reporting an error, and
the caller sees a stack trace instead of the reason. The surface-parity suite
checked that every registered tool was **callable** — it never called one.

This calls every tool with nothing serving and asserts that **none of them
raises**. A tool may answer with an error envelope (that is how it reports a
failure) or with a result; what it may not do is let an exception out.

The network is cut at the HTTP adapter, so no tool waits for a socket, and the
tools that write a file (the mission, the runbook, the evidence) write it into
a temporary directory.
"""

import os
import shutil
import socket
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bridge_mcp_hydra as bridge  # noqa: E402

#: A plausible value per parameter name. The point is not the value but that the
#: tool gets far enough to reach its failure handling.
VALUES = {
    "address": "0x401000",
    "addresses": "0x401000",
    "name": "main",
    "new_name": "renamed",
    "old_name": "old",
    "length": 16,
    "size": 16,
    "count": 5,
    "value": "5",
    "type": "uint32_t",
    "data_type": "uint32_t",
    "category": "/custom",
    "field_name": "field",
    "field_type": "uint32_t",
    "struct_name": "MyStruct",
    "enum_name": "MyEnum",
    "union_name": "MyUnion",
    "datatype": "uint32_t",
    "format": "json",
    "output": "",
    "path": "",
    "file": "",
    "label": "label",
    "comment": "a comment",
    "signature": "int main(void)",
    "timeout": 5,
    "port": 8192,
    "b_port": 8193,
    "ports": [8192],
    "max_functions": 1,
    "max_strings": 1,
    "depth": 1,
    "max_depth": 1,
    "limit": 5,
    "offset": 0,
    "query": "test",
    "goal": "what does this binary do",
    "source": "recv",
    "sink": "system",
    "kind": "overview",
    "match": "main",
    "tool": "GetAllRegisters",
    "arg": "a=1",
    "json_args": "{}",
    "id": "m1",
    "binary": "sample.exe",
    "binary_path": "sample.exe",
    "new_type": "uint32_t",
    "new_comment": "a comment",
    "code": "0x401000",
    "memory": "0x401000",
    "reference": "0x401000",
    "to": "0x401000",
    "from_function": "caller",
    "to_function": "callee",
    "key": "a",
    "fields": [],
    "values": {},
    "width": 2,
    "height": 2,
    "reason": "because",
    "group": "all",
    "session_id": "s1",
    "task_id": "t1",
    "job_id": "j1",
    "function": "main",
    "variable_name": "v",
    "bytes_data": "00",
    "steps": [],
    "other_executable": "other.exe",
}


def _value_for(name):
    return VALUES.get(name, "1")


def _no_network():
    """Nothing answers, and nothing waits for an answer."""
    import requests

    def refused(*arguments, **keywords):
        raise requests.exceptions.ConnectionError("the network is cut in this test")

    def no_socket(*arguments, **keywords):
        raise OSError("the network is cut in this test")

    def no_dns(*arguments, **keywords):
        raise OSError("the network is cut in this test")

    return [
        mock.patch.object(requests.adapters.HTTPAdapter, "send", refused),
        mock.patch.object(requests, "get", refused),
        mock.patch.object(requests, "post", refused),
        mock.patch.object(requests, "request", refused),
        mock.patch.object(socket, "create_connection", no_socket),
        mock.patch.object(socket, "getaddrinfo", no_dns),
    ]


class BridgeToolTests(unittest.TestCase):
    """No tool lets an exception out when nothing is serving."""

    def _tools(self):
        return bridge.mcp._tool_manager._tools

    def _call_arguments(self, tool):
        """The arguments a tool needs, from its signature."""
        import inspect

        arguments = {}
        for parameter in inspect.signature(tool.fn).parameters.values():
            if parameter.default is not inspect._empty:
                continue
            arguments[parameter.name] = _value_for(parameter.name)
        return arguments

    #: A failure a tool may raise on purpose: the MCP layer turns it into an
    #: error answer for the agent, with the message the tool wrote. The
    #: bridge refuses a call with no active instance exactly this way.
    ALLOWED = (ValueError,)

    def _walk(self):
        """Every tool, called with nothing serving."""
        failures = []
        called = 0
        for name, tool in sorted(self._tools().items()):
            try:
                tool.fn(**self._call_arguments(tool))
            except self.ALLOWED as exc:
                # A deliberate refusal: it must say why.
                if not str(exc).strip():
                    failures.append(f"{name}: refused without a reason")
            except Exception as exc:  # noqa: BLE001 - that is what is measured
                failures.append(f"{name}: {type(exc).__name__}: {exc}")
            called += 1
        return called, failures

    def test_no_tool_raises_when_nothing_is_serving(self):
        workspace = tempfile.mkdtemp(prefix="ghydra-bridge-walk-")
        started = time.perf_counter()
        try:
            with mock.patch.dict(os.environ,
                                 {"GHYDRA_STATE_DIR": workspace}):
                patches = _no_network()
                for patcher in patches:
                    patcher.start()
                try:
                    with mock.patch("os.getcwd", return_value=workspace):
                        called, failures = self._walk()
                finally:
                    for patcher in patches:
                        patcher.stop()
        finally:
            shutil.rmtree(workspace, ignore_errors=True)
        took = time.perf_counter() - started
        self.assertGreater(called, 100, "the walk found almost no tools")
        self.assertEqual([], failures,
                         f"{len(failures)} tool(s) let an exception out")
        self.assertLess(took, 180.0,
                        f"the walk took {took:.0f}s; it is meant to be cheap")

    def test_the_walk_reaches_every_tool(self):
        """The guard above is only as good as the walk."""
        tools = self._tools()
        self.assertEqual(134, len(tools))

    def test_a_tool_without_parameters_says_so(self):
        """A missing parameter is an answer with a code, not a crash.

        The MCP surface answers with text, so the code is in the text.
        """
        answer = self._tools()["functions_get"].fn()
        self.assertIsInstance(answer, str)
        self.assertIn("MISSING_PARAMETER", answer)

    def test_a_refusal_carries_its_reason(self):
        """The MCP layer hands the message to the agent; an empty one says nothing."""
        with mock.patch.object(bridge, "_get_instance_port",
                               side_effect=ValueError("no active instance")):
            with self.assertRaises(ValueError) as caught:
                self._tools()["functions_get"].fn(address="0x401000")
        self.assertIn("no active instance", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
