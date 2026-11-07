#!/usr/bin/env python3
"""Tests for progressive tool discovery (I15).

No Ghidra, no network: the group map, the catalogue, the profile switch and
the four meta-tools are exercised directly. The live tool manager is restored
after every test that mutates it.

Run with:  python test_tool_groups.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bridge_mcp_hydra as bridge  # noqa: E402


class GroupMapTests(unittest.TestCase):
    def test_every_group_names_only_known_namespaces(self):
        namespaces = {bridge._tool_namespace(name)
                      for name in bridge._tool_catalog()}
        for group, members in bridge._TOOL_GROUPS.items():
            with self.subTest(group=group):
                self.assertIsInstance(members, set)
                self.assertTrue(members)
                for namespace in members:
                    self.assertIn(namespace, namespaces,
                                  f"group '{group}' names a namespace no "
                                  f"tool uses: {namespace}")

    def test_the_meta_namespace_is_in_core(self):
        self.assertIn(bridge._META_NAMESPACE, bridge._TOOL_GROUPS["core"])

    def test_a_tool_maps_to_a_group(self):
        self.assertEqual("functions", bridge._tool_group("functions_decompile"))
        self.assertEqual("types", bridge._tool_group("structs_create"))
        self.assertEqual("kuna", bridge._tool_group("kuna_export_start"))
        self.assertEqual("x64dbg", bridge._tool_group("x64dbg_call"))
        # The meta namespace lives in core, so the meta-tools are always loaded.
        self.assertEqual("core", bridge._tool_group("tools_search"))

    def test_an_unknown_namespace_falls_back_to_core(self):
        self.assertEqual("core", bridge._tool_group("mystery_tool"))


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.original = dict(bridge.mcp._tool_manager._tools)
        self.original_groups = set(bridge._loaded_groups)
        bridge._tool_stash.clear()

    def tearDown(self):
        bridge.mcp._tool_manager._tools.clear()
        bridge.mcp._tool_manager._tools.update(self.original)
        bridge._tool_stash.clear()
        bridge._loaded_groups = self.original_groups

    def test_a_profile_hides_the_other_groups(self):
        report = bridge.apply_tool_groups("core")
        self.assertTrue(report["success"])
        visible = set(bridge.mcp._tool_manager._tools)
        self.assertIn("programs_overview", visible)
        self.assertNotIn("structs_create", visible)
        self.assertNotIn("kuna_decompile", visible)
        self.assertGreater(len(visible), 5)

    def test_the_meta_tools_survive_every_profile(self):
        bridge.apply_tool_groups("scripts")
        visible = set(bridge.mcp._tool_manager._tools)
        for name in ("tools_search", "tools_groups", "tools_load_group",
                     "tools_unload_group"):
            with self.subTest(tool=name):
                self.assertIn(name, visible)

    def test_an_unknown_group_is_refused_not_guessed(self):
        report = bridge.apply_tool_groups("core,nonsense")
        self.assertFalse(report["success"])
        self.assertEqual("TOOL_GROUP_UNKNOWN", report["error"]["code"])

    def test_loading_a_group_restores_its_tools(self):
        bridge.apply_tool_groups("core")
        self.assertNotIn("structs_create", bridge.mcp._tool_manager._tools)
        loaded = bridge.tools_load_group.__wrapped__(group="types")
        self.assertTrue(loaded["success"])
        self.assertIn("structs_create", bridge.mcp._tool_manager._tools)
        self.assertIn("types", bridge._loaded_groups)

    def test_unloading_removes_but_keeps_core(self):
        bridge.apply_tool_groups(None)  # everything
        removed = bridge.tools_unload_group.__wrapped__(group="kuna")
        self.assertTrue(removed["success"])
        self.assertNotIn("kuna_decompile", bridge.mcp._tool_manager._tools)
        refused = bridge.tools_unload_group.__wrapped__(group="core")
        self.assertFalse(refused["success"])
        self.assertEqual("TOOL_GROUP_CORE", refused["error"]["code"])

    def test_unloading_meta_tools_is_impossible(self):
        bridge.apply_tool_groups(None)
        bridge.tools_unload_group.__wrapped__(group="scripts")
        # the meta namespace lives in core; a scripts unload must not touch it
        self.assertTrue(bridge._tool_loaded("tools_search"))


class MetaToolTests(unittest.TestCase):
    def setUp(self):
        self.original = dict(bridge.mcp._tool_manager._tools)
        self.original_groups = set(bridge._loaded_groups)
        bridge._tool_stash.clear()

    def tearDown(self):
        bridge.mcp._tool_manager._tools.clear()
        bridge.mcp._tool_manager._tools.update(self.original)
        bridge._tool_stash.clear()
        bridge._loaded_groups = self.original_groups

    def test_all_four_meta_tools_are_registered_and_formatted(self):
        for name in ("tools_groups", "tools_search", "tools_load_group",
                     "tools_unload_group"):
            with self.subTest(tool=name):
                self.assertTrue(hasattr(getattr(bridge, name), "__wrapped__"))
                self.assertIn(name, bridge.FORMATTERS)

    def test_the_groups_tool_counts_every_group(self):
        raw = bridge.tools_groups.__wrapped__()
        self.assertTrue(raw["success"])
        groups = {g["group"]: g for g in raw["result"]["groups"]}
        self.assertEqual(set(bridge._TOOL_GROUPS), set(groups))
        self.assertTrue(all(g["tools"] > 0 for g in groups.values()))
        self.assertEqual(len(bridge._tool_catalog()),
                         raw["result"]["total_tools"])

    def test_search_finds_a_hidden_tool_and_says_how_to_load_it(self):
        bridge.apply_tool_groups("core")
        raw = bridge.tools_search.__wrapped__(query="struct")
        self.assertTrue(raw["success"])
        matches = raw["result"]["matches"]
        self.assertTrue(matches)
        struct = next(m for m in matches if m["name"] == "structs_create")
        self.assertEqual("types", struct["group"])
        self.assertFalse(struct["loaded"])

    def test_search_matches_summaries_and_groups(self):
        raw = bridge.tools_search.__wrapped__(query="decompile", limit=50)
        names = [m["name"] for m in raw["result"]["matches"]]
        self.assertIn("functions_decompile", names)
        self.assertIn("functions_batch_decompile", names)

    def test_search_respects_the_limit(self):
        raw = bridge.tools_search.__wrapped__(query="", limit=3)
        self.assertEqual(3, len(raw["result"]["matches"]))

    def test_the_formatter_renders_groups_and_matches(self):
        text = bridge.format_tool_groups(bridge.tools_groups.__wrapped__())
        self.assertIn("Tool groups", text)
        self.assertIn("core", text)
        search = bridge.format_tool_matches(
            bridge.tools_search.__wrapped__(query="struct", limit=5))
        self.assertIn("structs_create", search)


if __name__ == "__main__":
    unittest.main(verbosity=2)
