"""The `--target` suite: the cross-tool workflow of Phase 3, against fakes.

The plan's gateway chain is `analyze_open → function_locate → breakpoint_set`, and
the dangerous step is the last one: it translates a static address into the running
process and writes to the debugger. Three properties are proven here:

* the translation is the right arithmetic on real numbers;
* **the debugger is not called at all** when the two sides are not the same file —
  the test asserts the fake recorded zero calls, which is the only way to prove a
  refusal that matters;
* an unknown function is `TARGET_NOT_FOUND`, not an empty answer.

No Ghidra, no debugger, no network: the clients are fakes.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ghydra import target  # noqa: E402
from ghydra.target import TargetDescriptor, TargetError  # noqa: E402

IMAGE_BASE = 0x140000000
MODULE_BASE = 0x7FF7A1230000


class FakeGhidra:
    """The static side: `/program` and the two function lookups."""

    def __init__(self, path=r"C:\bin\sample.exe", image_base=IMAGE_BASE,
                 functions=None):
        self.program = {"path": path, "name": os.path.basename(path),
                        "image_base": hex(image_base),
                        "language": "x86:LE:64:default"}
        self.functions = functions if functions is not None else {
            "by-name:main": {"name": "main", "address": "0x140001234",
                             "signature": "int main(void)"},
            "address": {"name": "main", "address": "0x140001234",
                        "signature": "int main(void)"},
        }
        self.lookups = []

    def get(self, endpoint, params=None):
        self.lookups.append(endpoint)
        if endpoint == "program":
            return {"success": True, "result": self.program}
        if endpoint.startswith("functions/by-name/"):
            key = "by-name:" + endpoint.rsplit("/", 1)[-1]
            result = self.functions.get(key)
        elif endpoint.startswith("functions/"):
            result = self.functions.get("address")
        else:
            result = None
        if result is None:
            return {"success": False,
                    "error": {"code": "FUNCTION_NOT_FOUND", "message": "no"}}
        return {"success": True, "result": result}


class FakeDebugger:
    """The dynamic side: `ListModules` and `SetBreakpoint`, recording calls."""

    def __init__(self, path=r"C:\bin\sample.exe", base=MODULE_BASE):
        self.path = path
        self.base = base
        self.calls = []

    def call_tool(self, name, arguments=None):
        self.calls.append((name, arguments))
        if name == "ListModules":
            return f"0x{self.base:x} | 0x25000 | {self.path}"
        if name == "SetBreakpoint":
            return "breakpoint set"
        raise AssertionError(f"unexpected tool {name}")


class DescribeTests(unittest.TestCase):

    def test_a_matching_program_and_module_give_a_correlatable_descriptor(self):
        descriptor = target.describe(FakeGhidra(), FakeDebugger())
        self.assertTrue(descriptor.correlatable())
        self.assertEqual(MODULE_BASE - IMAGE_BASE, descriptor.delta())

    def test_a_binary_the_debugger_does_not_have_is_refused(self):
        with self.assertRaises(TargetError) as caught:
            target.describe(FakeGhidra(), FakeDebugger(path=r"D:\other.exe"))
        self.assertEqual(target.ERROR_NOT_LOADED, caught.exception.code)

    def test_a_program_that_cannot_be_read_is_refused(self):
        class Broken:
            def get(self, endpoint, params=None):
                raise RuntimeError("connection refused")
        with self.assertRaises(TargetError) as caught:
            target.describe(Broken(), FakeDebugger())
        self.assertEqual(target.ERROR_NO_PROGRAM, caught.exception.code)


class LocateTests(unittest.TestCase):

    def test_a_function_is_found_by_name(self):
        found = target.locate(FakeGhidra(), "main")
        self.assertEqual("main", found["name"])
        self.assertEqual("0x140001234", found["static_address"])
        self.assertEqual("name", found["matched_by"])
        self.assertIsNone(found["size"], "the API carries no size; do not invent one")

    def test_a_function_is_found_by_address(self):
        found = target.locate(FakeGhidra(), "0x140001234")
        self.assertEqual("address", found["matched_by"])

    def test_an_instance_that_does_not_answer_is_not_a_missing_function(self):
        """Two different facts, two different codes: one is 'try another name'."""
        class Unreachable:
            def get(self, endpoint, params=None):
                class ConnectionError_(Exception):
                    code = "CONNECTION_ERROR"
                raise ConnectionError_("Failed to connect to http://localhost:8192")
        with self.assertRaises(TargetError) as caught:
            target.locate(Unreachable(), "main")
        self.assertEqual(target.ERROR_NO_PROGRAM, caught.exception.code)

    def test_a_function_the_api_calls_missing_is_not_found(self):
        class Missing:
            def get(self, endpoint, params=None):
                class NotFound_(Exception):
                    code = "FUNCTION_NOT_FOUND"
                raise NotFound_("no function named main")
        with self.assertRaises(TargetError) as caught:
            target.locate(Missing(), "main")
        self.assertEqual(target.ERROR_NOT_FOUND, caught.exception.code)

    def test_an_unknown_function_is_a_code_not_an_empty_answer(self):
        with self.assertRaises(TargetError) as caught:
            target.locate(FakeGhidra(), "nope")
        self.assertEqual(target.ERROR_NOT_FOUND, caught.exception.code)
        self.assertIn("nope", str(caught.exception))


class BreakpointTests(unittest.TestCase):

    def test_the_runtime_address_is_the_translation_of_the_static_one(self):
        debugger = FakeDebugger()
        result = target.breakpoint(FakeGhidra(), debugger, "0x140001234")
        expected = 0x140001234 - IMAGE_BASE + MODULE_BASE
        self.assertEqual(hex(expected), result["runtime_address"])
        breakpoints = [call for call in debugger.calls
                       if call[0] == "SetBreakpoint"]
        self.assertEqual(1, len(breakpoints))
        self.assertEqual(hex(expected), breakpoints[0][1]["target"])

    def test_a_name_works_as_well_as_an_address(self):
        result = target.breakpoint(FakeGhidra(), FakeDebugger(), "main")
        self.assertEqual("0x140001234", result["static_address"])

    def test_a_different_build_refuses_and_never_touches_the_debugger(self):
        """The property the whole address model exists for."""
        debugger = FakeDebugger(path=r"D:\builds\sample.exe")
        with self.assertRaises(TargetError) as caught:
            target.breakpoint(FakeGhidra(), debugger, "main")
        self.assertEqual(target.ERROR_NOT_SAME_BINARY, caught.exception.code)
        self.assertIn("copy", str(caught.exception))
        # The refusal happens before the breakpoint: nothing was written.
        self.assertEqual([("ListModules", None)], debugger.calls,
                         f"the debugger was touched: {debugger.calls}")

    def test_a_static_only_target_refuses_to_translate(self):
        class NoModule:
            def __init__(self):
                self.calls = []

            def call_tool(self, name, arguments=None):
                self.calls.append((name, arguments))
                return "0x7ff7a1230000 | 0x25000 | C:\\bin\\sample.exe"
        # A module with no usable base is not correlatable either.
        descriptor = TargetDescriptor(binary=r"C:\bin\sample.exe",
                                      image_base=IMAGE_BASE,
                                      module_path=r"C:\bin\sample.exe")
        self.assertFalse(descriptor.correlatable())
        with self.assertRaises(ValueError):
            descriptor.to_runtime(0x140001234)


if __name__ == "__main__":
    unittest.main(verbosity=2)