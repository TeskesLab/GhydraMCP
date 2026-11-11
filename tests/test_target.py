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


def _hex_address(text):
    """The address a path segment names, or None when it names none.

    Ghidra reads an address as hexadecimal, so `add` and `dec` are addresses —
    of a function that does not exist. A qualified name is not: `math::add`
    carries a namespace, not an address space.
    """
    text = (text or "").strip()
    if "::" in text:
        return None
    if text.lower().startswith("0x"):
        text = text[2:]
    if not text or any(character not in "0123456789abcdefABCDEF"
                       for character in text):
        return None
    return "%x" % int(text, 16)


class FakeGhidra:
    """The static side: `/program` and the two function lookups.

    The shape is the one the server produces: the address route parses its
    segment as an address and answers 400 `BAD_REQUEST` when the segment is
    not one, and the by-name route answers the function or 404.
    """

    def __init__(self, path=r"C:\bin\sample.exe", image_base=IMAGE_BASE,
                 functions=None):
        # The shape `ProgramResource.getCurrentProgram()` actually emits:
        # `imageBase`, from `Address.toString()`, which is unprefixed hexadecimal.
        self.program = {"path": path, "name": os.path.basename(path),
                        "imageBase": f"{image_base:x}",
                        "language": "x86:LE:64:default"}
        self.functions = functions if functions is not None else {
            "by-name:main": {"name": "main", "address": "140001234",
                             "signature": "int main(void)"},
            "address:140001234": {"name": "main", "address": "140001234",
                                  "signature": "int main(void)"},
        }
        self.lookups = []

    def get(self, endpoint, params=None):
        from urllib.parse import unquote

        self.lookups.append(endpoint)
        if endpoint == "program":
            return {"success": True, "result": self.program}
        if endpoint.endswith("/decompile"):
            return {"success": True,
                    "result": {"functionName": "main",
                               "functionAddress": "140001234",
                               "decompilation": "int main(void) { return 0; }",
                               "success": True}}
        if endpoint.startswith("functions/by-name/"):
            # A name that goes into a URL path is percent-encoded.
            key = "by-name:" + unquote(endpoint.rsplit("/", 1)[-1])
            result = self.functions.get(key)
        elif endpoint.startswith("functions/"):
            text = endpoint.rsplit("/", 1)[-1]
            parsed = _hex_address(text)
            if parsed is None:
                # The server parses the segment as an address and a name is
                # not one.
                return {"success": False,
                        "error": {"code": "BAD_REQUEST",
                                  "message": "Invalid address: " + text}}
            result = self.functions.get("address:" + parsed)
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
        if name == "RunToAddress":
            return "[state] paused at the address"
        if name == "GetAllRegisters":
            return "RAX=0x1 RBX=0x2 RCX=0x3"
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


class WireFormatTests(unittest.TestCase):
    """The producer's wire format, which the first fixtures did not use.

    `ProgramResource` emits `imageBase` and `FunctionDto` emits
    `getEntryPoint().toString()`: both are **unprefixed hexadecimal**. Fixtures
    written with `image_base` and `0x` made the code pass against a shape no
    instance ever sends.
    """

    def test_the_image_base_comes_from_the_camel_case_field(self):
        descriptor = target.describe(FakeGhidra(), FakeDebugger())
        self.assertEqual(IMAGE_BASE, descriptor.image_base)
        self.assertTrue(descriptor.correlatable())

    def test_a_64_bit_address_is_hexadecimal_not_decimal(self):
        """`140001234` as base 0 is decimal 140001234, i.e. `0x8583FD2`."""
        found = target.locate(FakeGhidra(), "main")
        self.assertEqual("0x140001234", found["static_address"])
        self.assertNotEqual("0x8583fd2", found["static_address"])

    def test_a_32_bit_address_keeps_its_leading_zeros_and_still_parses(self):
        """`00401000` is not a Python literal: `int(text, 0)` rejects it."""
        functions = {
            "by-name:start": {"name": "start", "address": "00401000",
                              "signature": "void start(void)"},
            "address:401000": {"name": "start", "address": "00401000",
                        "signature": "void start(void)"},
        }
        found = target.locate(FakeGhidra(functions=functions), "start")
        self.assertEqual("0x401000", found["static_address"])

    def test_an_address_with_a_letter_in_it_parses(self):
        functions = {
            "address:14000abcd": {"name": "f", "address": "14000abcd",
                        "signature": "void f(void)"},
        }
        found = target.locate(FakeGhidra(functions=functions), "0x14000abcd")
        self.assertEqual("0x14000abcd", found["static_address"])

    def test_an_address_space_prefix_keeps_the_offset(self):
        functions = {
            "by-name:ext": {"name": "ext", "address": "EXTERNAL:00000010",
                            "signature": "void ext(void)"},
            "address:10": {"name": "ext", "address": "EXTERNAL:00000010",
                        "signature": "void ext(void)"},
        }
        found = target.locate(FakeGhidra(functions=functions), "ext")
        self.assertEqual("0x10", found["static_address"])

    def test_a_caller_may_write_the_address_with_or_without_the_prefix(self):
        ghidra = FakeGhidra()
        for written in ("0x140001234", "140001234"):
            found = target.locate(ghidra, written)
            self.assertEqual("address", found["matched_by"], written)
            self.assertEqual("0x140001234", found["static_address"], written)

    def test_the_breakpoint_translates_the_real_wire_address(self):
        """The P1 in full: a real-shaped payload used to refuse every breakpoint."""
        debugger = FakeDebugger()
        result = target.breakpoint(FakeGhidra(), debugger, "main")
        self.assertEqual("0x140001234", result["static_address"])
        self.assertEqual(hex(0x140001234 - IMAGE_BASE + MODULE_BASE),
                         result["runtime_address"])
        self.assertEqual([("ListModules", None),
                          ("SetBreakpoint", {"target": result["runtime_address"]})],
                         debugger.calls)


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

class DecompileTests(unittest.TestCase):
    """`decompile`: the code comes from the static side, addressed statically."""

    def test_the_code_comes_back_with_both_addresses(self):
        answer = target.decompile(FakeGhidra(), "main")
        self.assertIn("int main(void)", answer["code"])
        self.assertEqual("0x140001234", answer["static_address"])
        self.assertEqual("main", answer["function"])

    def test_a_name_and_an_address_give_the_same_answer(self):
        by_name = target.decompile(FakeGhidra(), "main")
        by_address = target.decompile(FakeGhidra(), "0x140001234")
        self.assertEqual(by_name["code"], by_address["code"])

    def test_a_decompiler_that_returns_nothing_is_a_code(self):
        class Silent(FakeGhidra):
            def get(self, endpoint, params=None):
                if endpoint.endswith("/decompile"):
                    return {"success": True, "result": {"decompilation": None}}
                return super().get(endpoint, params)

        with self.assertRaises(TargetError) as caught:
            target.decompile(Silent(), "main")
        self.assertEqual(target.ERROR_NO_CODE, caught.exception.code)


class RunToTests(unittest.TestCase):
    """`run_to`: resume to an address, then report the registers."""

    def test_the_address_is_translated_and_the_registers_read(self):
        debugger = FakeDebugger()
        answer = target.run_to(FakeGhidra(), debugger, "main", timeout_ms=5000)
        expected = hex(0x140001234 - IMAGE_BASE + MODULE_BASE)
        self.assertEqual(expected, answer["runtime_address"])
        self.assertIn("RAX", answer["registers"])
        run_calls = [call for call in debugger.calls if call[0] == "RunToAddress"]
        self.assertEqual(1, len(run_calls))
        self.assertEqual(expected, run_calls[0][1]["address"])
        self.assertEqual(5000, run_calls[0][1]["timeoutMs"])

    def test_the_timeout_is_below_the_client_read_timeout(self):
        """The server must answer before the client gives up; 30s vs 30s is a race."""
        self.assertLess(target.RUN_TO_TIMEOUT_MS, 30_000)

    def test_a_different_build_resumes_nothing(self):
        debugger = FakeDebugger(path=r"D:\builds\sample.exe")
        with self.assertRaises(TargetError) as caught:
            target.run_to(FakeGhidra(), debugger, "main")
        self.assertEqual(target.ERROR_NOT_SAME_BINARY, caught.exception.code)
        self.assertEqual([("ListModules", None)], debugger.calls)

    def test_a_non_positive_timeout_is_refused(self):
        with self.assertRaises(TargetError) as caught:
            target.run_to(FakeGhidra(), FakeDebugger(), "main", timeout_ms=0)
        self.assertEqual(target.ERROR_BAD_ADDRESS, caught.exception.code)


class DryRunWorkflowTests(unittest.TestCase):
    """The workflow itself stops before the write, not only the command."""

    def test_breakpoint_does_not_write_but_still_translates(self):
        debugger = FakeDebugger()
        result = target.breakpoint(FakeGhidra(), debugger, "main", dry_run=True)
        self.assertEqual([("ListModules", None)], debugger.calls)
        self.assertTrue(result["dry_run"])
        self.assertEqual("SetBreakpoint", result["plan"]["tool"])
        self.assertEqual(hex(0x140001234 - IMAGE_BASE + MODULE_BASE),
                         result["plan"]["arguments"]["target"])

    def test_breakpoint_writes_without_the_flag(self):
        debugger = FakeDebugger()
        result = target.breakpoint(FakeGhidra(), debugger, "main")
        self.assertFalse(result["dry_run"])
        self.assertIn("SetBreakpoint", [name for name, _ in debugger.calls])

    def test_run_to_does_not_resume_under_the_flag(self):
        debugger = FakeDebugger()
        result = target.run_to(FakeGhidra(), debugger, "main", dry_run=True)
        names = [name for name, _ in debugger.calls]
        self.assertNotIn("RunToAddress", names)
        self.assertNotIn("GetAllRegisters", names)
        self.assertIsNone(result["registers"])
        self.assertEqual("RunToAddress", result["plan"]["tool"])

    def test_a_dry_run_still_refuses_a_different_build(self):
        """The refusal is about identity, so it comes before the flag matters."""
        debugger = FakeDebugger(path=r"D:\builds\sample.exe")
        with self.assertRaises(TargetError) as caught:
            target.breakpoint(FakeGhidra(), debugger, "main", dry_run=True)
        self.assertEqual(target.ERROR_NOT_SAME_BINARY, caught.exception.code)
        self.assertEqual([("ListModules", None)], debugger.calls)


class ExternalAddressTests(unittest.TestCase):
    """An address that is not in the image never reaches the debugger.

    `EXTERNAL:00000010` is an external symbol index. Dropping the space
    prefix made it `0x10`, the identity guard passed, and the debugger was
    told to set a breakpoint at `image_base + 0x10` — an address in the module
    that has nothing to do with the symbol.
    """

    def _external(self):
        return FakeGhidra(functions={
            "by-name:ext": {"name": "ext", "address": "EXTERNAL:00000010",
                             "signature": "void ext(void)"},
            "address:10": {"name": "ext", "address": "EXTERNAL:00000010",
                            "signature": "void ext(void)"},
        })

    def test_the_space_is_kept(self):
        found = target.locate(self._external(), "ext")
        self.assertEqual("EXTERNAL", found["address_space"])

    def test_a_breakpoint_at_an_external_address_is_refused(self):
        debugger = FakeDebugger()
        with self.assertRaises(target.TargetError) as caught:
            target.breakpoint(self._external(), debugger, "ext")
        self.assertEqual(target.ERROR_NOT_IN_IMAGE, caught.exception.code)
        # Neither the write nor the read happened.
        self.assertEqual([], [call for call in debugger.calls
                              if call[0] != "ListModules"])

    def test_a_run_to_an_external_address_is_refused(self):
        debugger = FakeDebugger()
        with self.assertRaises(target.TargetError) as caught:
            target.run_to(self._external(), debugger, "ext")
        self.assertEqual(target.ERROR_NOT_IN_IMAGE, caught.exception.code)
        self.assertEqual([], [call for call in debugger.calls
                              if call[0] != "ListModules"])

    def test_a_dry_run_refuses_it_too(self):
        """A preview may not report a plan it would refuse to execute."""
        debugger = FakeDebugger()
        with self.assertRaises(target.TargetError):
            target.breakpoint(self._external(), debugger, "ext", dry_run=True)
        self.assertEqual([], [call for call in debugger.calls
                              if call[0] != "ListModules"])


class HexadecimalNameTests(unittest.TestCase):
    """A name that reads as hexadecimal is a name.

    `add`, `dec` and `f` are hexadecimal to the wire parser, and `math::add`
    is a qualified name whose last colon is not an address space. All four
    went to `GET /functions/{name}` and came back not found, while
    `GET /functions/by-name/{name}` had the function all along.
    """

    def _with(self, name):
        return FakeGhidra(functions={
            "by-name:" + name: {"name": name, "address": "140001234",
                                "signature": "int %s(void)" % name},
            "address:140001234": {"name": name, "address": "140001234",
                                  "signature": "int %s(void)" % name},
        })

    def test_a_hexadecimal_name_is_found_by_name(self):
        for name in ("add", "dec", "f"):
            with self.subTest(name=name):
                found = target.locate(self._with(name), name)
                self.assertEqual(name, found["name"])
                self.assertEqual("name", found["matched_by"])

    def test_a_qualified_name_is_found_by_name(self):
        found = target.locate(self._with("math::add"), "math::add")
        self.assertEqual("math::add", found["name"])
        self.assertEqual("name", found["matched_by"])

    def test_an_address_is_still_an_address(self):
        found = target.locate(self._with("main"), "0x140001234")
        self.assertEqual("address", found["matched_by"])

    def test_a_bare_hexadecimal_address_is_still_an_address(self):
        found = target.locate(self._with("main"), "140001234")
        self.assertEqual("address", found["matched_by"])


class TwinImportTruncationTests(unittest.TestCase):
    """A capped import listing does not claim that an import was removed.

    `build()` capped the imports by the same limit as the functions and wrote
    no truncation flag for them, so the comparison read a flag that was never
    written and reported the removal of an import it had simply not read.
    """

    class FakeClient:
        def __init__(self, imports):
            self.imports = imports
            self.base_url = "http://127.0.0.1:8192"

        def get(self, endpoint, params=None):
            if endpoint == "program":
                return {"success": True, "result": {
                    "name": "sample", "executablePath": "C:/bin/sample.exe",
                    "imageBase": "140000000", "language": "x86:LE:64:default",
                    "statistics": {"functionCount": 1, "stringCount": 0}}}
            if endpoint == "symbols/imports":
                # The server honours the limit of a listing.
                limit = (params or {}).get("limit")
                names = self.imports if limit is None else self.imports[:int(limit)]
                return {"success": True, "result": [
                    {"name": name} for name in names]}
            return {"success": True, "result": []}

    def test_the_import_truncation_is_recorded(self):
        from ghydra import twin

        document = twin.build(self.FakeClient(["A", "B", "C"]),
                              max_functions=2, max_strings=100)
        self.assertTrue(document["truncated"]["imports"])

    def test_a_capped_import_listing_makes_no_removal_claim(self):
        from ghydra import twin

        whole = twin.build(self.FakeClient(["A", "B", "C"]),
                           max_functions=10, max_strings=100)
        capped = twin.build(self.FakeClient(["A", "B", "C"]),
                            max_functions=2, max_strings=100)
        report = twin.diff(whole, capped)
        removed = report.get("imports", {}).get("removed", [])
        not_seen = report.get("imports", {}).get("removed_not_seen", [])
        self.assertEqual([], removed)
        self.assertIn("C", not_seen)
        self.assertFalse(report.get("complete", True))


if __name__ == "__main__":
    unittest.main(verbosity=2)