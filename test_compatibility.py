#!/usr/bin/env python3
"""Tests for the 11.x / 12.2 compatibility work (I3).

Needs neither Ghidra nor a running server: the Java contract is checked from
the sources, and the bridge half is pure Python. The Java sources are also
compiled by javac in the round's verification, and there is a JUnit test in
src/test/java that exercises CompatibilityService.report() for real.

Run with:  python test_compatibility.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bridge_mcp_hydra as bridge

ROOT = os.path.dirname(os.path.abspath(__file__))
JAVA = "src/main/java/eu/starsong/ghidra"


def _read(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as handle:
        return handle.read()


class JavaContractTests(unittest.TestCase):
    """The empty-body 500 came from these four places; keep them in step."""

    def test_set_field_name_is_resolved_reflectively(self):
        util = _read(f"{JAVA}/util/GhidraUtil.java")
        self.assertIn("public static void setFieldName(DataTypeComponent", util)
        self.assertIn('getMethod("setFieldName", String.class)', util)
        self.assertIn("InvocationTargetException", util)
        structs = _read(f"{JAVA}/service/StructService.java")
        self.assertIn("GhidraUtil.setFieldName(component, updatedName)", structs)
        # A direct call site carries the return type in its descriptor and
        # fails on the other Ghidra series with NoSuchMethodError.
        self.assertNotIn("component.setFieldName(", structs)

    def test_transaction_helper_catches_errors_not_just_exceptions(self):
        helper = _read(f"{JAVA}/util/TransactionHelper.java")
        self.assertIn("AtomicReference<Throwable> exception", helper)
        self.assertIn("catch (Throwable e)", helper)
        self.assertIn("instanceof LinkageError", helper)
        self.assertIn("new IncompatibleGhidraBuildException(", helper)
        self.assertIn("instanceof Error error", helper)

    def test_server_maps_the_error_to_a_structured_500(self):
        server = _read(f"{JAVA}/server/GhydraServer.java")
        self.assertIn("app.exception(IncompatibleGhidraBuildException.class", server)
        self.assertIn('"INCOMPATIBLE_GHIDRA_BUILD"', server)
        self.assertIn("INTERNAL_SERVER_ERROR", server)
        self.assertIn("CompatibilityService.logAtStartup()", server)
        self.assertTrue(os.path.isfile(os.path.join(
            ROOT, f"{JAVA}/util/IncompatibleGhidraBuildException.java")))

    def test_startup_probe_is_exposed_in_capabilities(self):
        compat = _read(f"{JAVA}/service/CompatibilityService.java")
        for needle in ("logAtStartup", "returnTypeOf", "removeOverloads",
                       "COMPILED_AGAINST", "set_field_name_return", "compatible"):
            with self.subTest(needle=needle):
                self.assertIn(needle, compat)
        caps = _read(f"{JAVA}/service/CapabilityService.java")
        self.assertIn("CompatibilityService.report(", caps)
        self.assertIn('data.put("compatibility"', caps)


class BridgeCompatibilityTests(unittest.TestCase):
    """The agent sees the mismatch instead of an empty 500."""

    def test_formatter_flags_a_mismatch(self):
        text = bridge.format_capabilities({
            "success": True,
            "result": {
                "plugin_version": "v3.0.0", "api_version": 3000,
                "ghidra_version": "12.2", "java_version": "25",
                "compatibility": {
                    "compatible": False,
                    "compiled_against": "12.0.1",
                    "set_field_name_return": "DataTypeComponent",
                    "remedy": "Rebuild the extension with GHIDRA_HOME=<this installation>.",
                },
            },
        })
        self.assertIn("compatibility: MISMATCH", text)
        self.assertIn("setFieldName returns DataTypeComponent", text)
        self.assertIn("remedy:", text)
        self.assertIn("GHIDRA_HOME", text)

    def test_formatter_reports_a_healthy_build(self):
        text = bridge.format_capabilities({
            "success": True,
            "result": {
                "plugin_version": "v3.0.0", "api_version": 3000,
                "compatibility": {"compatible": True,
                                  "compiled_against": "12.0.1",
                                  "set_field_name_return": "void"},
            },
        })
        self.assertIn("compatibility: ok", text)
        self.assertNotIn("MISMATCH", text)

    def test_negotiation_keeps_the_compatibility_report(self):
        info, error = bridge.negotiate_capabilities({
            "plugin_version": "v3.0.0", "api_version": 3000,
            "compatibility": {"compatible": False, "remedy": "rebuild"},
        })
        self.assertIsNone(error)
        self.assertFalse(info["compatibility"]["compatible"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
