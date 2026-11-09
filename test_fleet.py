#!/usr/bin/env python3
"""Tests for fleet queries (R7).

No Ghidra and no network: each "instance" is a fake client keyed by port. What
these tests pin down is the contract that makes a fleet answer trustworthy —
the merge is by file identity and not by port, a port that does not answer is
reported instead of dropped, and an absence is only claimed from a complete
listing.

Run with:  python test_fleet.py
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bridge_mcp_hydra as bridge  # noqa: E402
from ghydra import fleet  # noqa: E402
from ghydra.cli.fleet_cmd import fleet as fleet_cmd  # noqa: E402


class Member:
    """One instance: a program plus whatever the question needs."""

    def __init__(self, program=None, functions=None, imports=None,
                 strings=None, xrefs=0, fail_program=False):
        self.program = program
        self.functions = functions or {}
        self.imports = imports or []
        self.strings = strings or []
        self.xrefs = xrefs
        self.fail_program = fail_program
        self.calls = []

    def get(self, endpoint, params=None):
        self.calls.append(endpoint)
        params = params or {}
        if endpoint == "program":
            if self.fail_program or not self.program:
                return {"success": False, "error": {"code": "NO_PROGRAM"}}
            return {"success": True, "result": dict(self.program)}
        if endpoint.startswith("functions/by-name/"):
            name = endpoint.rsplit("/", 1)[-1]
            if name in self.functions:
                return {"success": True,
                        "result": {"name": name, "address": self.functions[name]}}
            return {"success": False, "error": {"code": "FUNCTION_NOT_FOUND"}}
        if endpoint == "symbols/imports":
            return self._page([{"name": value} for value in self.imports], params)
        if endpoint == "strings":
            return self._page([{"value": value} for value in self.strings], params)
        if endpoint.startswith("xrefs/to-name/"):
            return {"success": True, "result": [{"address": "0x1"}] * self.xrefs,
                    "meta": {"total": self.xrefs}}
        return {"success": True, "result": {}}

    def _page(self, items, params):
        offset = params.get("offset", 0)
        limit = params.get("limit", 1000)
        page = items[offset:offset + limit]
        return {"success": True, "result": page, "meta": {"total": len(items)}}


def program(name, program_id=None, path=None):
    return {"name": name,
            "programId": program_id if program_id is not None else f"proj:/{name}",
            "path": path if path is not None else f"/tmp/{name}",
            "executablePath": path if path is not None else f"/tmp/{name}",
            "imageBase": "0x400000", "language": "x86:LE:64:default",
            "statistics": {"functionCount": 10, "symbolCount": 20}}


class IdentityTests(unittest.TestCase):
    def test_the_program_id_is_the_identity(self):
        self.assertEqual("proj:/a.exe",
                         fleet.program_identity_of({"programId": "proj:/a.exe",
                                                    "path": "/other"}))

    def test_the_path_is_the_fallback(self):
        self.assertEqual("/tmp/a.exe",
                         fleet.program_identity_of({"path": "/tmp/a.exe"}))

    def test_an_unknown_program_has_no_identity(self):
        self.assertEqual("", fleet.program_identity_of({}))
        self.assertEqual("", fleet.program_identity_of(None))

    def test_an_unanswerable_instance_is_unreachable(self):
        member = fleet.collect_member(Member(fail_program=True), 8192)
        self.assertFalse(member["reachable"])
        self.assertEqual("NO_PROGRAM", member["error"])


class AskTests(unittest.TestCase):
    def test_overview_reports_the_program_facts(self):
        answer = fleet.ask(Member(program=program("a.exe")), "overview")
        self.assertTrue(answer["ok"])
        self.assertEqual("a.exe", answer["detail"]["name"])

    def test_a_present_function_carries_its_address(self):
        answer = fleet.ask(Member(program=program("a"), functions={"main": "0x401000"}),
                           "has_function", "main")
        self.assertTrue(answer["present"])
        self.assertEqual("0x401000", answer["detail"]["address"])

    def test_a_missing_function_is_a_clean_negative(self):
        answer = fleet.ask(Member(program=program("a")), "has_function", "main")
        self.assertTrue(answer["ok"])
        self.assertFalse(answer["present"])

    def test_an_import_is_matched_case_insensitively(self):
        answer = fleet.ask(Member(program=program("a"), imports=["CreateFileW"]),
                           "has_import", "createfilew")
        self.assertTrue(answer["present"])
        self.assertEqual(["CreateFileW"], answer["detail"]["matched"])

    def test_a_string_is_matched_as_text(self):
        answer = fleet.ask(Member(program=program("a"), strings=["GET /api/v1"]),
                           "has_string", "/api/v1")
        self.assertTrue(answer["present"])

    def test_a_truncated_listing_is_marked_not_claimed_absent(self):
        class Endless(Member):
            def _page(self, items, params):
                page = [{"name": f"api{i}"} for i in range(1000)]
                return {"success": True, "result": page,
                        "meta": {"total": 10 ** 9}}

        answer = fleet.ask(Endless(program=program("a")), "has_import", "CreateRemoteThread")
        self.assertFalse(answer["present"])
        self.assertFalse(answer["complete"])

    def test_xrefs_report_a_count(self):
        answer = fleet.ask(Member(program=program("a"), xrefs=3), "xrefs_to", "strlen")
        self.assertEqual(3, answer["detail"]["count"])
        self.assertTrue(answer["present"])


class QueryTests(unittest.TestCase):
    def test_every_member_is_one_row(self):
        members = {8192: Member(program=program("a.exe"), functions={"main": "0x1"}),
                   8193: Member(program=program("b.exe"), functions={})}
        report = fleet.query(members, "has_function", "main")["result"]
        self.assertEqual(2, report["count"])
        self.assertEqual(1, report["with_it"])
        self.assertEqual(1, report["without_it"])

    def test_two_ports_serving_the_same_program_are_one_row(self):
        shared = program("a.exe", program_id="proj:/a.exe")
        members = {8192: Member(program=shared, functions={"main": "0x1"}),
                   8193: Member(program=dict(shared), functions={"main": "0x1"})}
        report = fleet.query(members, "has_function", "main")["result"]
        self.assertEqual(1, report["count"])
        self.assertEqual([8192, 8193], report["binaries"][0]["ports"])

    def test_the_same_name_in_two_projects_does_not_merge(self):
        members = {8192: Member(program=program("a.exe", program_id="p1:/a.exe")),
                   8191: Member(program=program("a.exe", program_id="p2:/a.exe"))}
        report = fleet.query(members, "overview")["result"]
        self.assertEqual(2, report["count"])

    def test_ports_that_disagree_are_reported(self):
        shared = program("a.exe", program_id="proj:/a.exe")
        members = {8192: Member(program=shared, functions={"main": "0x1"}),
                   8193: Member(program=dict(shared), functions={})}
        report = fleet.query(members, "has_function", "main")["result"]
        self.assertEqual(1, report["count"])
        self.assertTrue(report["binaries"][0]["disagreements"])

    def test_an_unreachable_port_is_reported_not_dropped(self):
        members = {8192: Member(program=program("a.exe")),
                   8193: Member(program=None)}
        report = fleet.query(members, "overview")["result"]
        self.assertEqual(1, report["count"])
        self.assertEqual([8193], [item["port"] for item in report["unreachable"]])
        self.assertFalse(report["ok"])

    def test_an_unknown_kind_is_refused(self):
        report = fleet.query({8192: Member(program=program("a"))}, "smells_bad")
        self.assertFalse(report["success"])
        self.assertEqual("FLEET_UNKNOWN_KIND", report["error"]["code"])

    def test_the_text_marks_every_row(self):
        members = {8192: Member(program=program("a.exe"), functions={"main": "0x1"}),
                   8193: Member(program=program("b.exe")),
                   8194: Member(program=None)}
        text = fleet.to_text(fleet.query(members, "has_function", "main"))
        self.assertIn("[YES]", text)
        self.assertIn("[no ]", text)
        self.assertIn("[---] port 8194", text)


class ParityTests(unittest.TestCase):
    """The bridge carries the same query; both must produce the same report."""

    def _both(self, members, kind="has_function", target="main"):
        with mock.patch.object(
                bridge, "safe_get",
                side_effect=lambda port, endpoint, params=None: members[port].get(
                    endpoint, params)):
            from_bridge = bridge._fleet_query(sorted(members), kind, target)
        from_cli = fleet.query(members, kind, target)
        return from_cli, from_bridge

    def test_the_report_agrees(self):
        members = {8192: Member(program=program("a.exe"), functions={"main": "0x1"}),
                   8193: Member(program=program("b.exe")),
                   8194: Member(program=None)}
        self.assertEqual(self._both(members)[0], self._both(members)[1])

    def test_the_merge_agrees(self):
        shared = program("a.exe", program_id="proj:/a.exe")
        members = {8192: Member(program=shared, functions={"main": "0x1"}),
                   8193: Member(program=dict(shared), functions={"main": "0x1"})}
        cli, br = self._both(members)
        self.assertEqual(cli, br)
        self.assertEqual(1, br["result"]["count"])

    def test_the_identity_helper_agrees(self):
        for value in ({"programId": "p"}, {"path": "/x"}, {}, None,
                      {"executablePath": "/y", "imageBase": "0x1"}):
            with self.subTest(value=value):
                self.assertEqual(fleet.program_identity_of(value),
                                 bridge._fleet_identity_of(value))


class BridgeToolTests(unittest.TestCase):
    def test_the_tool_is_registered_with_a_formatter_in_its_own_group(self):
        tools = set(getattr(bridge.mcp._tool_manager, "_tools", {}))
        self.assertIn("fleet_query", tools)
        self.assertIn("fleet_query", bridge.FORMATTERS)
        self.assertEqual("fleet", bridge._tool_group("fleet_query"))

    def test_the_tool_answers_across_ports(self):
        members = {8192: Member(program=program("a.exe"), functions={"main": "0x1"}),
                   8193: Member(program=program("b.exe"))}
        with mock.patch.object(
                bridge, "safe_get",
                side_effect=lambda port, endpoint, params=None: members[port].get(
                    endpoint, params)):
            result = bridge.fleet_query.__wrapped__("has_function", "8192,8193", "main")
        self.assertTrue(result["success"], result)
        self.assertEqual(2, result["result"]["count"])

    def test_bad_ports_are_refused(self):
        result = bridge.fleet_query.__wrapped__("overview", "abc")
        self.assertFalse(result["success"])
        self.assertEqual("FLEET_BAD_PORTS", result["error"]["code"])

    def test_an_empty_port_list_is_refused(self):
        result = bridge.fleet_query.__wrapped__("overview", "")
        self.assertEqual("FLEET_BAD_PORTS", result["error"]["code"])

    def test_a_question_that_needs_a_target_says_so(self):
        result = bridge.fleet_query.__wrapped__("has_function", "8192")
        self.assertEqual("FLEET_MISSING_TARGET", result["error"]["code"])

    def test_the_formatter_renders_the_rows_and_the_unreachable(self):
        members = {8192: Member(program=program("a.exe"), functions={"main": "0x1"}),
                   8193: Member(program=None)}
        with mock.patch.object(
                bridge, "safe_get",
                side_effect=lambda port, endpoint, params=None: members[port].get(
                    endpoint, params)):
            result = bridge.fleet_query.__wrapped__("has_function", "8192,8193", "main")
        text = bridge.format_fleet_query(result)
        self.assertIn("Fleet: has_function main", text)
        self.assertIn("[YES]", text)
        self.assertIn("[---] port 8193", text)

    def test_the_formatter_renders_an_error(self):
        failure = {"success": False,
                   "error": {"code": "FLEET_UNKNOWN_KIND", "message": "nope"}}
        self.assertIn("FLEET_UNKNOWN_KIND", bridge.format_fleet_query(failure))


class CliTests(unittest.TestCase):
    def _invoke(self, args, members=None):
        from click.testing import CliRunner
        members = members or {
            8192: Member(program=program("a.exe"), functions={"main": "0x1"}),
            8193: Member(program=program("b.exe")),
        }
        fake_client = mock.Mock(host="localhost")
        with mock.patch("ghydra.cli.fleet_cmd.GhidraHTTPClient",
                        side_effect=lambda host, port, timeout: members[port]):
            return CliRunner().invoke(fleet_cmd, args, obj={
                'client': fake_client,
                'config': mock.Mock(timeout=10),
                'formatter': mock.Mock(),
                'output_json': False,
            })

    def test_has_function_answers_across_the_fleet(self):
        result = self._invoke(["has-function", "main", "--ports", "8192,8193"])
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn("[YES]", result.output)
        self.assertIn("[no ]", result.output)

    def test_overview_lists_the_binaries(self):
        result = self._invoke(["overview", "--ports", "8192,8193"])
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn("binaries: 2", result.output)

    def test_an_unreachable_member_does_not_fail_the_command(self):
        members = {8192: Member(program=program("a.exe")),
                   8193: Member(program=None)}
        result = self._invoke(["overview", "--ports", "8192,8193"], members)
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn("did not answer", result.output)

    def test_a_bad_port_exits_two(self):
        result = self._invoke(["overview", "--ports", "abc"])
        self.assertEqual(2, result.exit_code)

    def test_no_ports_exits_two(self):
        result = self._invoke(["overview", "--ports", ","])
        self.assertEqual(2, result.exit_code)


if __name__ == "__main__":
    unittest.main(verbosity=2)