#!/usr/bin/env python3
"""Tests for mission mode (R8).

No Ghidra and no network: a fake client answers the endpoints the plan reads.
What these tests pin down is the contract that makes a dossier trustworthy —
the budget stops the mission instead of running past it, a doubt becomes an
`unknown` finding instead of a question, and a conclusion whose evidence moved
is reported as `unverified` rather than kept.

Run with:  python tests/test_mission.py
"""

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

# The tests live in tests/; the code and the repository are one level up.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bridge_mcp_hydra as bridge  # noqa: E402
from ghydra import mission as M  # noqa: E402
from ghydra.cli.mission_cmd import mission as mission_cmd  # noqa: E402


class FakeClient:
    """The endpoints the plan reads, answered from dictionaries."""

    def __init__(self, program=None, imports=None, strings=None,
                 taint_client=None, inspect=None, fail=None, drift=None):
        self.program = program if program is not None else {
            "name": "sample.exe", "path": "/tmp/sample.exe",
            "image_base": "0x400000", "language": "x86:LE:64:default"}
        self.imports = imports if imports is not None else [
            {"name": "socket"}, {"name": "recv"}, {"name": "system"}]
        self.strings = strings if strings is not None else [
            {"value": "GET /api/v1"}]
        self.taint_client = taint_client
        self.inspect = inspect or {"address": "0x401000", "symbol": "main"}
        self.fail = set(fail or ())
        self.drift = drift or set()
        self.calls = []

    def get(self, endpoint, params=None):
        self.calls.append(endpoint)
        if endpoint in self.fail:
            return {"success": False, "error": {"code": "MISSION_TEST_FAILURE"}}
        if endpoint == "program":
            return {"success": True, "result": dict(self.program)}
        if endpoint == "symbols/imports":
            return {"success": True, "result": list(self.imports),
                    "meta": {"total": len(self.imports)}}
        if endpoint == "strings":
            if "strings" in self.drift:
                return {"success": True, "result": [{"value": "changed"}],
                        "meta": {"total": 1}}
            return {"success": True, "result": list(self.strings),
                    "meta": {"total": len(self.strings)}}
        if endpoint.startswith("inspect/address/"):
            return {"success": True, "result": dict(self.inspect)}
        if endpoint.startswith(("functions/by-name/", "xrefs/to-name/",
                                "functions/containing/", "analysis/call-path")):
            if self.taint_client is not None:
                return self.taint_client.get(endpoint, params)
        if endpoint.startswith("functions/") and endpoint.endswith("/pcode"):
            if self.taint_client is not None:
                return self.taint_client.get(endpoint, params)
        return {"success": True, "result": {}}


class TaintClient:
    """A minimal source-to-sink world for the taint step."""

    def get(self, endpoint, params=None):
        params = params or {}
        if endpoint == "functions/by-name/recv":
            return {"success": True, "result": {"name": "recv", "address": "0x5000"}}
        if endpoint == "functions/by-name/system":
            return {"success": True, "result": {"name": "system", "address": "0x6000"}}
        if endpoint == "xrefs/to-name/recv":
            # The live endpoint answers `{name, symbols, references, total}`,
            # and the DTO's fields are camelCase.
            return {"success": True, "result": {
                "name": "recv", "symbols": [{"name": "recv",
                                             "address": "0x5000"}],
                "references": [{"fromAddress": "0x401010",
                                "toAddress": "0x5000",
                                "refType": "UNCONDITIONAL_CALL",
                                "fromFunction": "caller",
                                "fromFunctionAddress": "0x401000"}],
                "total": 1}}
        if endpoint == "xrefs/to-name/system":
            return {"success": True, "result": {
                "name": "system", "symbols": [{"name": "system",
                                               "address": "0x6000"}],
                "references": [{"fromAddress": "0x401020",
                                "toAddress": "0x6000",
                                "refType": "UNCONDITIONAL_CALL",
                                "fromFunction": "caller",
                                "fromFunctionAddress": "0x401000"}],
                "total": 1}}
        if endpoint == "functions/0x401000/pcode":
            # `PcodeOp.CALL` is 7 (verified with `javap -p -constants` against
            # the committed SoftwareModeling.jar); 57 is `FLOAT_CEIL`.
            return {"success": True, "result": {"operations": [
                {"address": "0x401010", "opcode": 7, "inputs": ["recv", "1"]},
                {"address": "0x401020", "opcode": 7, "inputs": ["system", "1"]}]}}
        if endpoint == "analysis/call-path":
            return {"success": True, "result": {"path": ["0x401000"]}}
        return {"success": True, "result": []}


class HintTests(unittest.TestCase):
    def test_a_source_and_a_sink_are_read_from_the_words(self):
        hints = M.parse_goal("does data from recv reach system?")
        self.assertEqual({"source": "recv", "sink": "system"}, hints)

    def test_an_address_and_a_function_are_read(self):
        self.assertEqual({"address": "0x401000"}, M.parse_goal("what is at 0x401000"))
        self.assertEqual({"function": "main"},
                         M.parse_goal("o que faz esta funcao main"))

    def test_a_goal_with_no_hints_is_left_alone(self):
        self.assertEqual({}, M.parse_goal("what does this binary do"))


class BudgetTests(unittest.TestCase):
    def test_the_calls_are_counted(self):
        budget = M.Budget(max_calls=2)
        self.assertIsNone(budget.exhausted())
        budget.spend("program", {"success": True})
        budget.spend("program", {"success": True})
        self.assertIn("call budget", budget.exhausted() or "")

    def test_tokens_are_estimated_from_the_payload(self):
        budget = M.Budget(max_calls=10, max_tokens=10)
        budget.spend("program", {"result": "x" * 400})
        self.assertGreaterEqual(budget.tokens, 100)
        self.assertIn("token budget", budget.exhausted() or "")

    def test_the_report_carries_what_was_spent(self):
        budget = M.Budget(max_calls=5)
        budget.spend("program", {})
        data = budget.as_dict()
        self.assertEqual(1, data["calls"])
        self.assertEqual(5, data["max_calls"])


class PlanTests(unittest.TestCase):
    def _mission(self, client, goal="what does this binary do", **budget):
        current = M.Mission(goal, budget=M.Budget(**budget) if budget else M.Budget())
        with mock.patch.object(M, "mission_path",
                               return_value=os.path.join(tempfile.gettempdir(),
                                                         "mission-test.json")):
            M.run(client, current)
        return current

    def test_the_plan_reads_the_program_and_the_capability_leads(self):
        current = self._mission(FakeClient())
        titles = [f["title"] for f in current.findings]
        self.assertIn("Program fingerprint", titles)
        self.assertEqual("sample.exe", current.program["name"])
        self.assertTrue(all(f["id"].startswith("EV-") for f in current.findings))

    def test_a_goal_without_source_and_sink_records_an_unknown(self):
        current = self._mission(FakeClient())
        unknowns = [f for f in current.findings if f["status"] == M.STATUS_UNKNOWN]
        self.assertTrue(unknowns)
        self.assertTrue(any("no source and sink" in (f["detail"] or "")
                            for f in unknowns))

    def test_the_budget_stops_the_plan_and_says_what_was_skipped(self):
        # The budget only pays for the first step.
        current = self._mission(FakeClient(), max_calls=1)
        self.assertTrue(current.skipped, current.steps)
        self.assertIn("capabilities", current.skipped)

    def test_a_failed_program_ends_the_mission_with_a_reason(self):
        current = self._mission(FakeClient(fail={"program"}))
        self.assertEqual(M.ERROR_NO_PROGRAM, current.failed)
        self.assertTrue(current.skipped)

    def test_a_taint_hypothesis_becomes_a_vulnerability_finding(self):
        client = FakeClient(taint_client=TaintClient())
        current = self._mission(client, goal="does data from recv reach system?")
        vulnerabilities = [f for f in current.findings if f["kind"] == "vulnerability"]
        self.assertEqual(1, len(vulnerabilities))
        self.assertIn("recv -> system", vulnerabilities[0]["title"])

    def test_no_taint_path_is_an_unknown_not_a_clean_bill(self):
        client = FakeClient(taint_client=TaintClient())
        with mock.patch.object(M.taint_helper, "find_hypotheses",
                               return_value={"hypotheses": []}):
            current = self._mission(client, goal="does data from recv reach system?")
        self.assertTrue(any("not proof of safety" in (f["detail"] or "")
                            for f in current.findings))

    def test_an_address_in_the_goal_is_inspected(self):
        current = self._mission(FakeClient(), goal="what is at 0x401000")
        self.assertTrue(any("Address context" in f["title"] for f in current.findings))


class VerificationTests(unittest.TestCase):
    def _run_and_verify(self, client):
        current = M.Mission("what does this binary do")
        with mock.patch.object(M, "mission_path",
                               return_value=os.path.join(tempfile.gettempdir(),
                                                         "mission-test.json")):
            M.run(client, current)
        return current, M.verify(client, current)

    def test_unchanged_evidence_verifies_the_findings(self):
        current, verification = self._run_and_verify(FakeClient())
        self.assertTrue(verification["ok"], verification)
        self.assertGreater(verification["checked"], 0)
        statuses = {f["status"] for f in current.findings
                    if f["status"] != M.STATUS_UNKNOWN}
        self.assertEqual({M.STATUS_VERIFIED}, statuses)

    def test_evidence_that_moved_marks_the_finding_unverified(self):
        client = FakeClient()
        current = M.Mission("what does this binary do")
        with mock.patch.object(M, "mission_path",
                               return_value=os.path.join(tempfile.gettempdir(),
                                                         "mission-test.json")):
            M.run(client, current)
        # the program fingerprint is the one evidence every mission has
        client.program = {"name": "rewritten.exe", "image_base": "0x400000"}
        verification = M.verify(client, current)
        self.assertFalse(verification["ok"])
        self.assertTrue(verification["unverified"])

    def test_an_unknown_finding_is_never_verified(self):
        current = self._run_and_verify(FakeClient())[0]
        self.assertTrue(any(f["status"] == M.STATUS_UNKNOWN for f in current.findings))


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "m.json")

    def test_a_checkpoint_round_trips(self):
        current = M.Mission("what does this binary do")
        current.add_finding("data", "x", "y", evidence=[
            {"endpoint": "program", "digest": "abc", "params": None}])
        current.program = {"name": "sample.exe"}
        current.next_step = 2
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(current.as_dict()))
        loaded = M.Mission.load(self.path)
        self.assertEqual(current.id, loaded.id)
        self.assertEqual(1, len(loaded.findings))
        self.assertEqual(2, loaded.next_step)
        self.assertEqual("sample.exe", loaded.program["name"])

    def test_a_resume_continues_from_the_checkpoint(self):
        client = FakeClient()
        current = M.Mission("what does this binary do", budget=M.Budget(max_calls=1))
        with mock.patch.object(M, "mission_path", return_value=self.path):
            M.run(client, current)
        self.assertEqual(1, current.next_step)
        resumed = M.Mission.load(self.path)
        self.assertEqual(1, resumed.next_step)
        # A checkpoint that stopped on its budget is the one worth continuing,
        # so a resume may ask for more calls.
        resumed.budget.max_calls = 10
        with mock.patch.object(M, "mission_path", return_value=self.path):
            M.run(client, resumed, resume=True)
        self.assertGreaterEqual(resumed.next_step, 2)

    def test_a_bad_checkpoint_is_refused(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write("not json")
        with self.assertRaises(ValueError):
            M.Mission.load(self.path)

    def test_a_file_that_is_not_a_mission_is_refused(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"something": "else"}))
        with self.assertRaises(ValueError):
            M.Mission.load(self.path)


class DossierTests(unittest.TestCase):
    def test_the_dossier_names_the_budget_the_findings_and_the_unknowns(self):
        current = M.Mission("does data from recv reach system?")
        current.add_finding("data", "Program fingerprint", '{"name": "x"}',
                            evidence=[{"endpoint": "program", "digest": "d" * 32}])
        current.add_unknown("What is this binary?", "the program could not be read")
        text = M.to_markdown(current, {"checked": 1, "verified": 1,
                                       "unverified": [], "ok": True})
        self.assertIn("# Mission: does data from recv reach system?", text)
        self.assertIn("budget:", text)
        self.assertIn("EV-0001", text)
        self.assertIn("evidence: `program`", text)
        self.assertIn("## Verification", text)
        self.assertIn("every conclusion still holds", text)
        self.assertIn("## Not determined", text)
        self.assertIn("the program could not be read", text)

    def test_an_unverified_finding_is_called_out(self):
        current = M.Mission("goal")
        current.add_finding("data", "x", evidence=[{"endpoint": "program",
                                                    "digest": "d"}])
        text = M.to_markdown(current, {"checked": 1, "verified": 0,
                                       "unverified": ["EV-0001"], "ok": False})
        self.assertIn("unverified: EV-0001", text)

    def test_saving_the_dossier_writes_the_markdown(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        current = M.Mission("goal")
        target = os.path.join(tmp.name, "dossier.md")
        path = M.save_dossier(current, None, target)
        self.assertEqual(target, path)
        self.assertTrue(open(path, encoding="utf-8").read().startswith("# Mission:"))


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.checkpoint = os.path.join(self.tmp.name, "m.json")
        self.dossier = os.path.join(self.tmp.name, "dossier.md")

    def _invoke(self, args, client=None):
        from click.testing import CliRunner
        return CliRunner().invoke(mission_cmd, args, obj={
            'client': client or FakeClient(),
            'formatter': mock.Mock(),
            'output_json': False,
        })

    def _patch(self):
        return mock.patch.object(M, "mission_path", return_value=self.checkpoint)

    def test_start_writes_a_dossier_and_exits_zero(self):
        with self._patch():
            result = self._invoke(["start", "-g", "what does this binary do",
                                   "-o", self.dossier])
        self.assertEqual(0, result.exit_code, result.output)
        text = open(self.dossier, encoding="utf-8").read()
        self.assertIn("# Mission:", text)
        self.assertIn("## Findings", text)

    def test_start_exits_one_when_a_conclusion_is_unverified(self):
        client = FakeClient()
        with self._patch(), mock.patch(
                "ghydra.cli.mission_cmd.verify",
                return_value={"checked": 1, "verified": 0,
                              "unverified": ["EV-0001"], "ok": False}):
            result = self._invoke(["start", "-g", "x", "-o", self.dossier], client)
        self.assertEqual(1, result.exit_code, result.output)

    def test_no_verify_skips_the_reread(self):
        with self._patch(), mock.patch.object(M, "verify") as checked:
            result = self._invoke(["start", "-g", "x", "-o", self.dossier,
                                   "--no-verify"])
        self.assertEqual(0, result.exit_code, result.output)
        checked.assert_not_called()

    def test_resume_continues_a_checkpoint(self):
        with self._patch():
            self._invoke(["start", "-g", "x", "-o", self.dossier,
                          "--max-calls", "1"])
            result = self._invoke(["resume", self.checkpoint, "-o", self.dossier])
        self.assertEqual(0, result.exit_code, result.output)

    def test_show_reads_without_calling_anything(self):
        with self._patch():
            self._invoke(["start", "-g", "x", "-o", self.dossier])
        never = mock.Mock()
        never.get.side_effect = AssertionError("show must not call the API")
        result = self._invoke(["show", self.checkpoint], never)
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn("# Mission:", result.output)

    def test_a_missing_checkpoint_exits_two(self):
        result = self._invoke(["resume", os.path.join(self.tmp.name, "nope.json")])
        self.assertEqual(2, result.exit_code)

class BridgeParityTests(unittest.TestCase):
    """The bridge duplicates the plan; both sides must report the same thing."""

    def _bridge_run(self, client, goal="what does this binary do", **budget):
        with mock.patch.object(
                bridge, "safe_get",
                side_effect=lambda port, endpoint, params=None: client.get(
                    endpoint, params)), \
                mock.patch.object(bridge, "_get_instance_port",
                                  side_effect=lambda port=None: 8192), \
                mock.patch.object(bridge, "_mission_dir",
                                  return_value=tempfile.gettempdir()):
            mission = bridge._Mission(
                goal,
                bridge._MissionBudget(budget.get("max_calls", 60),
                                      budget.get("max_tokens", 200000)),
                8192)
            bridge._mission_run(mission)
            return mission

    def _cli_run(self, client, goal="what does this binary do", **budget):
        current = M.Mission(goal, budget=M.Budget(
            budget.get("max_calls", 60), budget.get("max_tokens", 200000)))
        with mock.patch.object(M, "mission_path",
                               return_value=os.path.join(tempfile.gettempdir(),
                                                         "mission-parity.json")):
            M.run(client, current)
        return current

    def test_the_hints_agree(self):
        for goal in ("does data from recv reach system?",
                     "what is at 0x401000",
                     "o que faz esta funcao main",
                     "what does this binary do"):
            with self.subTest(goal=goal):
                self.assertEqual(M.parse_goal(goal), bridge._mission_parse_goal(goal))

    def test_the_findings_agree(self):
        cli = self._cli_run(FakeClient())
        br = self._bridge_run(FakeClient())
        self.assertEqual([(f["kind"], f["title"], f["confidence"]) for f in cli.findings],
                         [(f["kind"], f["title"], f["confidence"]) for f in br.findings])
        self.assertEqual(cli.program, br.program)

    def test_a_goal_without_hints_leaves_the_same_unknown(self):
        cli = self._cli_run(FakeClient())
        br = self._bridge_run(FakeClient())
        cli_unknowns = [f["title"] for f in cli.findings if f["status"] == "unknown"]
        br_unknowns = [f["title"] for f in br.findings if f["status"] == "unknown"]
        self.assertEqual(cli_unknowns, br_unknowns)

    def test_the_budget_stops_both_at_the_same_step(self):
        cli = self._cli_run(FakeClient(), max_calls=1)
        br = self._bridge_run(FakeClient(), max_calls=1)
        self.assertEqual(cli.skipped, br.skipped)

    def test_a_failed_program_stops_both(self):
        cli = self._cli_run(FakeClient(fail={"program"}))
        br = self._bridge_run(FakeClient(fail={"program"}))
        self.assertEqual(cli.failed, br.failed)

    def test_the_taint_finding_agrees(self):
        goal = "does data from recv reach system?"
        client = lambda: FakeClient(taint_client=TaintClient())
        cli = self._cli_run(client(), goal)
        br = self._bridge_run(client(), goal)
        self.assertEqual(
            [f["title"] for f in cli.findings if f["kind"] == "vulnerability"],
            [f["title"] for f in br.findings if f["kind"] == "vulnerability"])


class BridgeToolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.target = os.path.join(self.tmp.name, "dossier.md")

    def _invoke(self, client, goal="what does this binary do", **kwargs):
        with mock.patch.object(
                bridge, "safe_get",
                side_effect=lambda port, endpoint, params=None: client.get(
                    endpoint, params)), \
                mock.patch.object(bridge, "_get_instance_port",
                                  side_effect=lambda port=None: 8192):
            return bridge.mission_start.__wrapped__(goal, **kwargs)

    def test_the_tool_is_registered_with_a_formatter_in_core(self):
        tools = set(getattr(bridge.mcp._tool_manager, "_tools", {}))
        self.assertIn("mission_start", tools)
        self.assertIn("mission_start", bridge.FORMATTERS)
        self.assertEqual("core", bridge._tool_group("mission_start"))

    def test_the_tool_writes_a_dossier_and_reports_verification(self):
        result = self._invoke(FakeClient(), output=self.target)
        self.assertTrue(result["success"], result)
        self.assertTrue(result["result"]["verification"]["ok"])
        text = open(self.target, encoding="utf-8").read()
        self.assertIn("# Mission:", text)
        self.assertIn("## Verification", text)
        self.assertIn("EV-0001", text)

    def test_a_moved_evidence_is_unverified_and_reported(self):
        client = FakeClient()
        with mock.patch.object(
                bridge, "safe_get",
                side_effect=lambda port, endpoint, params=None: client.get(
                    endpoint, params)), \
                mock.patch.object(bridge, "_get_instance_port",
                                  side_effect=lambda port=None: 8192):
            mission = bridge._Mission("goal", bridge._MissionBudget(60, 200000), 8192)
            bridge._mission_run(mission)
            client.program = {"name": "rewritten.exe"}
            verification = bridge._mission_verify(mission)
        self.assertFalse(verification["ok"])
        self.assertTrue(verification["unverified"])

    def test_verify_can_be_skipped(self):
        result = self._invoke(FakeClient(), output=self.target, verify=False)
        self.assertIsNone(result["result"]["verification"])

    def test_the_formatter_renders_the_dossier(self):
        result = self._invoke(FakeClient(), output=self.target)
        rendered = bridge.format_mission_start(result)
        self.assertIn("# Mission:", rendered)
        self.assertIn("## Not determined", rendered)

    def test_an_error_answer_renders_as_the_error(self):
        failure = {"success": False,
                   "error": {"code": "MISSION_IO", "message": "no disk"}}
        self.assertIn("MISSION_IO", bridge.format_mission_start(failure))


class FingerprintTests(unittest.TestCase):
    """The dossier's program line, with the producer's payload.

    The mission read `path` but stored it under `path` while its own renderer
    read `executable_path` — so every dossier printed "(no path)".
    """

    def test_the_dossier_prints_the_path(self):
        # The core module is addressed through the package the mission itself
        # comes from, so the name cannot be mistyped here.
        cache = __import__(M.__name__.rsplit(".", 1)[0] + ".core.cache",
                           fromlist=["cache"])
        fingerprint_from_program = cache.fingerprint_from_program
        payload = {"name": "sample.exe", "path": "/tmp/sample.exe",
                   "imageBase": "0x400000"}
        current = M.Mission("what is this binary")
        current.program = fingerprint_from_program(payload)
        text = M.to_markdown(current)
        self.assertIn("/tmp/sample.exe", text)
        self.assertNotIn("no path", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)