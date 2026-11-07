#!/usr/bin/env python3
"""Tests for capability negotiation (I2).

Needs neither Ghidra nor an MCP client: the negotiation helper is pure, and
the REST/CLI/bridge contract is checked from the source files. This is what
makes the endpoint testable in CI without a live CodeBrowser.

Run with:  python test_capabilities.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bridge_mcp_hydra as bridge

ROOT = os.path.dirname(os.path.abspath(__file__))


def _read(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as handle:
        return handle.read()


class NegotiationTests(unittest.TestCase):
    """The pure half: normalise a payload, reject an incompatible API version."""

    def test_compatible_full_payload(self):
        info, error = bridge.negotiate_capabilities({
            "plugin_version": "v3.0.0", "api_version": 3000,
            "ghidra_version": "12.1.2", "java_version": "21.0.13",
            "headless": True, "features": {"scripts": False},
            "limits": {"max_batch_targets": 200},
        }, "http://localhost:8192")
        self.assertIsNone(error)
        self.assertEqual(3000, info["api_version"])
        self.assertTrue(info["headless"])
        self.assertEqual({"scripts": False}, info["features"])
        self.assertEqual({"max_batch_targets": 200}, info["limits"])

    def test_legacy_plugin_version_payload_still_negotiates(self):
        """An older plugin has no /capabilities; its /plugin-version answer works."""
        info, error = bridge.negotiate_capabilities(
            {"plugin_version": "v3.0.0", "api_version": 3000})
        self.assertIsNone(error)
        self.assertEqual("unknown", info["ghidra_version"])
        self.assertEqual({}, info["features"])
        self.assertEqual({}, info["limits"])

    def test_mismatch_is_actionable(self):
        info, error = bridge.negotiate_capabilities({
            "plugin_version": "v2.0.0", "api_version": 2000,
            "ghidra_version": "11.4", "java_version": "21",
        }, "http://localhost:8192")
        self.assertIsNone(info)
        for needle in ("2000", "3000", "v2.0.0", "11.4", "21",
                       "http://localhost:8192", "GET /capabilities"):
            with self.subTest(needle=needle):
                self.assertIn(needle, error)

    def test_formatter_shows_versions_features_and_limits(self):
        text = bridge.format_capabilities({
            "success": True,
            "result": {
                "plugin_version": "v3.0.0", "api_version": 3000,
                "ghidra_version": "12.1.2", "java_version": "21.0.13",
                "headless": False,
                "features": {"scripts": True, "dev_shutdown": False},
                "limits": {"max_batch_targets": 200},
            },
        })
        for needle in ("v3.0.0", "3000", "12.1.2",
                       "features on: scripts", "features off: dev_shutdown",
                       "max_batch_targets=200"):
            with self.subTest(needle=needle):
                self.assertIn(needle, text)


class SurfaceContractTests(unittest.TestCase):
    """The three surfaces expose the same capability, without a live Ghidra."""

    def test_bridge_registers_tool_and_formatter(self):
        registered = getattr(bridge.mcp._tool_manager, "_tools", {})
        self.assertIn("instances_capabilities", registered)
        self.assertIs(bridge.format_capabilities,
                      bridge.FORMATTERS.get("instances_capabilities"))

    def test_rest_endpoint_exists_on_the_root_resource(self):
        root = _read("src/main/java/eu/starsong/ghidra/resource/RootResource.java")
        self.assertIn('app.get("/capabilities"', root)
        self.assertIn("CapabilityService.describe(ctx)", root)
        service = _read(
            "src/main/java/eu/starsong/ghidra/service/CapabilityService.java")
        for needle in ("api_version", "features", "limits", "headless"):
            with self.subTest(needle=needle):
                self.assertIn(needle, service)
        # RootResource is registered in the shared factory, so the headless and
        # CodeBrowser instances serve the same endpoint (the 404-in-one bug).
        factory = _read(
            "src/main/java/eu/starsong/ghidra/server/GhydraServerFactory.java")
        self.assertIn("new RootResource(", factory)

    def test_cli_command_and_all_three_formatters(self):
        from ghydra.cli import instances
        self.assertTrue(callable(getattr(instances, "capabilities", None)))
        from ghydra.formatters.base import BaseFormatter
        from ghydra.formatters.json_formatter import JSONFormatter
        from ghydra.formatters.table_formatter import TableFormatter
        self.assertIn("format_capabilities", BaseFormatter.__abstractmethods__)
        for cls in (JSONFormatter, TableFormatter):
            with self.subTest(formatter=cls.__name__):
                self.assertTrue(callable(getattr(cls, "format_capabilities", None)))
                self.assertNotIn(
                    "format_capabilities", getattr(cls, "__abstractmethods__", set()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
