"""Bounded BSim consumer semantics over loopback HTTP and actual MCP stdio.

This small corpus exercises consumer selection, scope, pagination, partial evidence
and errors. It does not substitute for native database/signature integration tests.
"""
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from contextlib import asynccontextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from click.testing import CliRunner
from ghydra.cli.bsim_cmd import bsim
from ghydra.cli.main import cli
from ghydra.client.http_client import GhidraHTTPClient
from ghydra.config import ConfigManager
from ghydra.formatters.json_formatter import JSONFormatter
from ghydra.formatters.table_formatter import TableFormatter


FILTERS = {"executable": "codec & β.so", "architecture": "x86:LE:64:default",
           "compiler": "gcc:default", "categories": {"Library": "libc=stable&β", "Version": "1.0"}}


class BatchCorpus:
    """Deterministic local corpus, not a forwarding/echo endpoint."""
    def __init__(self):
        self.requests = []
        self.modification = 17
        self.source_program_id = "program-instance-1"
        self.sources = {
            "overlay:1000": ("ns::same", 0.96, None),
            "ram:1000": ("ns::same", 0.81, None),
            "ram:2000": ("ns::higher", 0.93, None),
            "ram:3000": ("ns::thunk", 0, "thunk"),
            "ram:4000": ("ns::undecodable", 0, "signature generation failed"),
            "ram:5000": ("ns::below_floor", 0.4, None),
        }
        # Address order is explicit, independent of the rank of the selected rows.
        self.order = ["ram:1000", "ram:2000", "ram:3000", "ram:4000", "ram:5000", "overlay:1000"]
        self.candidates = []
        for source, (_, score, reason) in self.sources.items():
            if reason:
                continue
            for suffix, metadata, similarity in (
                    ("selected", FILTERS, score),
                    ("outside_scope", {**FILTERS, "categories": {**FILTERS["categories"], "Version": "2.0"}}, 0.99),
                    ("literal_null", {**FILTERS, "executable": "null"}, score),
                    ("literal_true", {**FILTERS, "executable": "true"}, score),
                    ("literal_false", {**FILTERS, "executable": "false"}, score)):
                self.candidates.append({**metadata, "source": source, "function": "decode_" + suffix,
                    "address": "2000", "similarity": similarity, "significance": 12.0,
                    "match_id": source + "/" + suffix, "reference_available": False})
        state = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def respond(self, result=None, code=None, links=None):
                envelope = ({"success": False, "error": {"code": code, "message": code}} if code else
                            {"success": True, "result": result, "_links": links or {}})
                data = json.dumps(envelope, ensure_ascii=False).encode()
                self.send_response(400 if code else 200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                url = urlsplit(self.path)
                params = {key: values[0] for key, values in parse_qs(url.query, keep_blank_values=True).items()}
                state.requests.append((url.path, params))
                if url.path in ("/capabilities", "/plugin-version"):
                    return self.respond({"plugin_version": "v3.2.0", "api_version": 3000})
                if url.path == "/program":
                    return self.respond({"name": "target"})
                if url.path not in ("/bsim/overview", "/bsim/batch-query"):
                    return self.respond(code="UNEXPECTED_ENDPOINT")
                if ("expected_program" in params and params["expected_program"] != state.source_program_id
                        or "expected_modification" in params and
                        int(params["expected_modification"]) != state.modification):
                    return self.respond(code="BSIM_MATCH_STALE")
                if (url.path == "/bsim/overview" and int(params.get("offset", 0)) > 0
                        and "expected_modification" in params and "expected_program" not in params):
                    return self.respond(code="BSIM_BATCH_INVALID")
                filters: dict[str, Any] = {key: params[key] for key in ("executable", "architecture", "compiler") if key in params}
                if "categories" in params:
                    filters["categories"] = json.loads(params["categories"])
                if any(key not in ("Library", "Version") for key in filters.get("categories", {})):
                    return self.respond(code="BSIM_FILTER_INVALID")
                overview = url.path.endswith("overview")
                limit = int(params.get("max_matches", 1 if overview else 3))
                offset, page_size = int(params.get("offset", 0)), int(params.get("max_functions", 50))
                if overview:
                    sources = state.order[offset:offset + page_size]
                else:
                    sources = [state.canonical(address) for address in json.loads(params["addresses"])]
                    if len(set(sources)) != len(sources):
                        return self.respond(code="BSIM_BATCH_INVALID")
                rows = []
                searched = 0
                for source in sources:
                    info = state.sources.get(source)
                    row = {"source_address": source, "function": info[0] if info else None,
                           "source_modification": state.modification, "success": True,
                           "status": "no_match", "matches": [], "returned": 0, "complete": True}
                    if not info:
                        row.update(success=False, status="error", complete=False,
                                   reason="No function at exact entry", code="BSIM_SOURCE_NOT_FOUND")
                    elif info[2]:
                        row.update(success=False, status="skipped" if info[2] == "thunk" else "error",
                                   complete=False, reason=info[2], code="BSIM_SOURCE_SKIPPED" if info[2] == "thunk" else "BSIM_SIGNATURE_MISSING")
                    else:
                        searched += 1
                        matches = [record for record in state.candidates if record["source"] == source
                            and record["similarity"] >= float(params.get("min_similarity", 0.7))
                            and record["significance"] >= float(params.get("min_significance", 0))
                            and all(record[key] == value for key, value in filters.items() if key != "categories")
                            and all(record["categories"].get(key) == value for key, value in filters.get("categories", {}).items())]
                        matches.sort(key=lambda match: (-match["similarity"], -match["significance"], match["match_id"]))
                        row.update(status="matched" if matches else "no_match", matches=matches[:limit],
                                   returned=min(limit, len(matches)), complete=len(matches) < limit)
                        if not matches:
                            row["reason"] = "No qualifying candidates in this exact query scope"
                    rows.append(row)
                if overview:
                    rows.sort(key=lambda row: (-(row["matches"][0]["similarity"] if row["matches"] else -1),
                                               -(row["matches"][0]["significance"] if row["matches"] else -1), row["source_address"]))
                more = overview and offset + len(sources) < len(state.order)
                result = {"mode": "overview" if overview else "batch", "program": "target",
                    "source_program_id": state.source_program_id,
                    "source_modification": state.modification, "filters": filters,
                    "available_categories": ["Library", "Version"], "max_matches": limit,
                    "min_similarity": float(params.get("min_similarity", 0.7)),
                    "min_significance": float(params.get("min_significance", 0)),
                    "results": rows, "scanned": len(sources), "searched": searched,
                    "complete": not more and all(row["complete"] for row in rows)}
                links = {}
                if overview:
                    result.update(offset=offset, max_functions=page_size,
                                  next_offset=offset + len(sources) if more else None, has_more=more)
                    if more:
                        next_params = {**params, "offset": result["next_offset"],
                                       "expected_program": state.source_program_id,
                                       "expected_modification": state.modification}
                        links["next"] = {"href": "/bsim/overview?" + urlencode(next_params), "method": "GET"}
                self.respond(result, links=links)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @staticmethod
    def canonical(address):
        space, separator, offset = address.rpartition(":")
        return (space if separator else "ram") + ":" + format(int(offset, 16), "x")

    def queries(self):
        return [(path, params) for path, params in self.requests if path.startswith("/bsim/")]

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


def filter_flags():
    flags = []
    for key, value in FILTERS.items():
        if key == "categories":
            for name, category_value in value.items():
                flags += ["--category", name + "=" + category_value]
        else:
            flags += ["--" + key, value]
    return flags


class BSimBatchCLI(unittest.TestCase):
    def setUp(self):
        self.worker = BatchCorpus()
        self.addCleanup(self.worker.close)
        self.client = GhidraHTTPClient(host="127.0.0.1", port=self.worker.port, timeout=2)
        self.addCleanup(self.client.close)

    def invoke(self, *args, raw=False):
        return CliRunner().invoke(bsim, list(args), obj={"client": self.client,
            "formatter": JSONFormatter() if raw else TableFormatter(use_colors=False), "output_json": raw})

    def test_page_selection_ranking_and_stamped_continuation(self):
        result = self.invoke("overview", "--max-functions", "2", *filter_flags(), raw=True)
        self.assertEqual(0, result.exit_code, result.output)
        page = json.loads(result.output)["result"]
        self.assertEqual(["ram:2000", "ram:1000"], [row["source_address"] for row in page["results"]])
        self.assertNotIn("overlay:1000", result.output)
        self.assertEqual(2, page["next_offset"])
        self.assertEqual(self.worker.source_program_id, page["source_program_id"])
        self.assertFalse(page["complete"])
        self.assertEqual(FILTERS, page["filters"])
        human = self.invoke("overview", "--max-functions", "2", "--profile", "corpus", *filter_flags())
        for text in ("page-local, not global", "ram:1000/selected", "0.93", "Next:",
                     "--offset 2", "--expected-modification 17", "--expected-program program-instance-1",
                     "--profile corpus", "--category", "incomplete"):
            self.assertIn(text, human.output)
        second = self.invoke("overview", "--offset", "2", "--max-functions", "3",
                             "--expected-modification", "17", "--expected-program", page["source_program_id"],
                             *filter_flags(), raw=True)
        rows = json.loads(second.output)["result"]["results"]
        self.assertEqual({"skipped", "error", "no_match"}, {row["status"] for row in rows})
        self.assertEqual(1, json.loads(second.output)["result"]["searched"])
        self.worker.modification += 1
        stale = self.invoke("overview", "--offset", "2", "--expected-modification", "17",
                            "--expected-program", page["source_program_id"])
        self.assertNotEqual(0, stale.exit_code)
        self.assertIn("BSIM_MATCH_STALE", stale.output)

    def test_exact_program_instance_binding_survives_identical_name_and_stamp(self):
        first = json.loads(self.invoke("overview", "--max-functions", "2", raw=True).output)["result"]
        self.worker.source_program_id = "program-instance-2"
        stale = self.invoke("overview", "--offset", "2", "--expected-modification",
                            str(first["source_modification"]), "--expected-program", first["source_program_id"])
        self.assertNotEqual(0, stale.exit_code)
        self.assertIn("BSIM_MATCH_STALE", stale.output)
        batch = self.invoke("batch-query", "--address", "ram:1000",
                            "--expected-program", first["source_program_id"])
        self.assertIn("BSIM_MATCH_STALE", batch.output)
        missing = self.invoke("overview", "--offset", "2", "--expected-modification", "17")
        self.assertIn("BSIM_BATCH_INVALID", missing.output)
        # Opaque IDs remain exact text, even if a JSON decoder could coerce them.
        self.worker.source_program_id = "null"
        valid = self.invoke("batch-query", "--address", "ram:1000", "--expected-program", "null", raw=True)
        self.assertEqual(0, valid.exit_code, valid.output)
        self.assertEqual("null", json.loads(valid.output)["result"]["source_program_id"])

    def test_explicit_sources_keep_spaces_and_errors_separate(self):
        result = self.invoke("batch-query", "--address", "ram:1000", "--address", "overlay:1000",
                             "--address", "dead", *filter_flags(), raw=True)
        self.assertEqual(0, result.exit_code, result.output)
        page = json.loads(result.output)["result"]
        ram, overlay, missing = page["results"]
        self.assertEqual("ns::same", ram["function"])
        self.assertEqual(ram["function"], overlay["function"])
        self.assertNotEqual(ram["matches"][0]["match_id"], overlay["matches"][0]["match_id"])
        self.assertEqual("error", missing["status"])
        self.assertEqual([], missing["matches"])
        self.assertEqual("BSIM_SOURCE_NOT_FOUND", missing["code"])
        self.assertEqual(3, page["scanned"])
        self.assertEqual(2, page["searched"])
        self.assertFalse(page["complete"])
        self.assertTrue(ram["complete"])
        self.assertNotIn("outside_scope", result.output)
        human = self.invoke("batch-query", "--address", "ram:4000", "--address", "dead")
        self.assertIn("signature generation failed", human.output)
        self.assertIn("BSIM_SOURCE_NOT_FOUND", human.output)
        self.assertIn("explicit source entries only", human.output)

    def test_bad_requests_stop_before_http_and_resolved_duplicates_fail_closed(self):
        invalid = [
            ["overview", "--max-functions", "100", "--max-matches", "3"],
            ["overview", "--max-functions", "0"], ["overview", "--offset", "-1"],
            ["overview", "--min-similarity", "nan"], ["overview", "--min-significance", "inf"],
            ["batch-query", "--address", ""], ["batch-query", "--address", "not-an-address"],
            ["batch-query", "--address", "1000", "--address", "1000"],
            ["batch-query", "--address", "1000", "--max-matches", "0"],
            ["batch-query", "--address", "1000", "--compiler", " "],
            ["overview", "--category", "Library=x", "--category", "Library=y"],
            ["overview", "--expected-program", " "],
        ]
        for args in invalid:
            with self.subTest(args=args):
                before = len(self.worker.queries())
                result = self.invoke(*args)
                self.assertNotEqual(0, result.exit_code, result.output)
                self.assertEqual(before, len(self.worker.queries()))
        duplicate = self.invoke("batch-query", "--address", "1000", "--address", "ram:01000")
        self.assertNotEqual(0, duplicate.exit_code)
        self.assertIn("BSIM_BATCH_INVALID", duplicate.output)
        unknown = self.invoke("overview", "--category", "Missing=value")
        self.assertIn("BSIM_FILTER_INVALID", unknown.output)
        self.assertEqual(2, len(self.worker.queries()), "no unfiltered retry")

    def test_root_json_flag_reaches_both_formatter_methods(self):
        with tempfile.TemporaryDirectory() as home, patch.object(ConfigManager, "CONFIG_FILE", Path(home) / "config.json"):
            for command in (["overview", "--max-functions", "2"], ["batch-query", "--address", "ram:1000"]):
                for flags in (["--json", *command], [*command, "--json"]):
                    # The real root creates the real HTTP client; only config path is isolated.
                    result = CliRunner().invoke(cli, ["--host", "127.0.0.1", "--port", str(self.worker.port),
                        "bsim", *flags], env={"GHYDRA_JSON": "", "GHYDRA_TELEMETRY": "0"})
                    self.assertEqual(0, result.exit_code, result.output)
                    payload = json.loads(result.output)
                    self.assertTrue(payload["success"])
                    self.assertIn("results", payload["result"])
                    self.assertNotIn("Next:", result.output)



@asynccontextmanager
async def mcp_session(worker, output="text"):
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    root = str(Path(__file__).resolve().parents[1])
    launcher = (f"import sys; sys.path.insert(0, {root!r}); import bridge_mcp_hydra as b; "
        f"b.DEFAULT_GHIDRA_PORT={worker.port}; b.QUICK_DISCOVERY_RANGE=range({worker.port},{worker.port + 1}); "
        "b.FULL_DISCOVERY_RANGE=b.QUICK_DISCOVERY_RANGE; b.main()")
    with tempfile.TemporaryDirectory(prefix="ghydra-bsim-batch-") as home:
        params = StdioServerParameters(command=sys.executable, args=["-c", launcher], env={
            "HOME": home, "GHYDRA_STATE_DIR": home, "GHIDRA_HYDRA_HOST": "127.0.0.1",
            "GHYDRA_MCP_OUTPUT": output, "GHYDRA_TELEMETRY": "0"})
        async with stdio_client(params) as (reader, writer):
            async with ClientSession(reader, writer) as session:
                await session.initialize()
                yield session


async def call(session, worker, tool, **arguments):
    response = await session.call_tool(tool, arguments={"port": worker.port, "profile": "corpus", **arguments})
    return "\n".join(part.text for part in response.content if part.type == "text")


class BSimBatchMCP(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.worker = BatchCorpus()
        self.addCleanup(self.worker.close)

    async def test_stdio_text_selection_scope_errors_and_next_link(self):
        async with mcp_session(self.worker) as session:
            tools = {tool.name: tool for tool in (await session.list_tools()).tools}
            for name in ("bsim_overview", "bsim_batch_query"):
                self.assertIn(name, tools)
                self.assertIn("expected_modification", tools[name].inputSchema["properties"])
                self.assertIn("expected_program", tools[name].inputSchema["properties"])
            self.assertEqual(["addresses"], tools["bsim_batch_query"].inputSchema["required"])
            filters = {**FILTERS, "categories": json.dumps(FILTERS["categories"], ensure_ascii=False)}
            page = await call(session, self.worker, "bsim_overview", max_functions=2, **filters)
            for text in ("ram:2000/selected", "ram:1000/selected", "page-local, not global", "incomplete",
                         "Next:", "bsim_overview(", "expected_modification=17",
                         'expected_program="program-instance-1"', "max_functions=2", "categories="):
                self.assertIn(text, page)
            self.assertNotIn("outside_scope", page)
            self.assertNotIn("overlay:1000", page)
            self.assertEqual(["/bsim/overview"], [path for path, _ in self.worker.queries()])
            batch = await call(session, self.worker, "bsim_batch_query",
                addresses='["ram:1000","overlay:1000","dead","ram:3000","ram:4000"]', **filters)
            for text in ("ram:1000/selected", "overlay:1000/selected", "explicit source entries only",
                         "BSIM_SOURCE_NOT_FOUND", "skipped", "signature generation failed", "complete: no"):
                self.assertIn(text, batch)
            self.assertNotIn("outside_scope", batch)
            empty = await call(session, self.worker, "bsim_batch_query", addresses='["ram:1000"]', executable="absent")
            self.assertIn("no_match", empty)
            self.assertIn("exact query scope", empty)
            self.worker.modification += 1
            stale = await call(session, self.worker, "bsim_overview", offset=2,
                               expected_modification=17, expected_program=self.worker.source_program_id)
            self.assertIn("BSIM_MATCH_STALE", stale)

    async def test_exact_instance_continuation_and_opaque_json_literal_identity(self):
        async with mcp_session(self.worker, "json") as session:
            first = json.loads(await call(session, self.worker, "bsim_overview", max_functions=2))["result"]
            second = json.loads(await call(session, self.worker, "bsim_overview",
                offset=first["next_offset"], max_functions=2,
                expected_modification=first["source_modification"],
                expected_program=first["source_program_id"]))
            self.assertTrue(second["success"])
            self.worker.source_program_id = "replacement-instance"
            for tool, selection in (("bsim_overview", {"offset": 2}),
                                    ("bsim_batch_query", {"addresses": '["ram:1000"]'})):
                stale = await call(session, self.worker, tool, **selection,
                                   expected_modification=first["source_modification"],
                                   expected_program=first["source_program_id"])
                self.assertIn("BSIM_MATCH_STALE", stale)
            self.worker.source_program_id = "null"
            valid = json.loads(await call(session, self.worker, "bsim_batch_query",
                                         addresses='["ram:1000"]', expected_program="null"))
            self.assertTrue(valid["success"])
            self.assertEqual("null", self.worker.queries()[-1][1]["expected_program"])
            self.assertEqual("null", valid["result"]["source_program_id"])

    async def test_raw_json_inputs_validate_before_http_without_fastmcp_predecoding(self):
        async with mcp_session(self.worker) as session:
            invalid = ("", " ", "[", "{}", "null", "[]", '[""]', '[" "]', '[null]', '[1]',
                       '["not-an-address"]', '["ram:1000","ram:1000"]', json.dumps(["1000"] * 101),
                       '["' + "a" * 16385 + '"]', "[" * 2000 + "]" * 2000)
            for addresses in invalid:
                with self.subTest(addresses=addresses[:50]):
                    before = len(self.worker.queries())
                    text = await call(session, self.worker, "bsim_batch_query", addresses=addresses)
                    self.assertIn("BSIM_BATCH_INVALID", text)
                    self.assertEqual(before, len(self.worker.queries()))
            for tool, args in (("bsim_overview", {}), ("bsim_batch_query", {"addresses": '["ram:1000"]'})):
                for filters in ({"compiler": " "}, {"executable": ""}, {"architecture": ""},
                                {"categories": " "}, {"categories": "[]"},
                                {"categories": '{"Library":"x","Library":"y"}'},
                                {"categories": '{"Library":null}'}):
                    before = len(self.worker.queries())
                    text = await call(session, self.worker, tool, **args, **filters)
                    self.assertIn("BSIM_BATCH_INVALID", text)
                    self.assertEqual(before, len(self.worker.queries()))
            for args in ({"max_functions": 100, "max_matches": 3}, {"offset": -1},
                         {"max_functions": 0}, {"max_matches": 11}, {"min_similarity": 1.1},
                         {"min_significance": -1}, {"expected_program": ""}, {"expected_program": " "}):
                before = len(self.worker.queries())
                self.assertIn("BSIM_BATCH_INVALID", await call(session, self.worker, "bsim_overview", **args))
                self.assertEqual(before, len(self.worker.queries()))
            before = len(self.worker.queries())
            addresses = json.dumps([f"ram:{value:x}" for value in range(68)])
            self.assertIn("BSIM_BATCH_INVALID", await call(session, self.worker, "bsim_batch_query", addresses=addresses))
            self.assertEqual(before, len(self.worker.queries()))
            for literal in ("null", "true", "false"):
                text = await call(session, self.worker, "bsim_batch_query", addresses='["ram:1000"]', executable=literal)
                self.assertIn("decode_literal_" + literal, text)
                self.assertNotIn("decode_selected", text)
                self.assertEqual(literal, self.worker.queries()[-1][1]["executable"])
            duplicate = await call(session, self.worker, "bsim_batch_query", addresses='["1000","ram:01000"]')
            self.assertIn("BSIM_BATCH_INVALID", duplicate)
            before = len(self.worker.queries())
            unknown = await call(session, self.worker, "bsim_overview", categories='{"Missing":"x"}')
            self.assertIn("BSIM_FILTER_INVALID", unknown)
            self.assertEqual(before + 1, len(self.worker.queries()))

    async def test_stdio_json_output_preserves_bounded_result_evidence(self):
        async with mcp_session(self.worker, "json") as session:
            filters = {**FILTERS, "categories": json.dumps(FILTERS["categories"], ensure_ascii=False)}
            text = await call(session, self.worker, "bsim_batch_query", addresses='["overlay:1000","ram:1000"]', **filters)
            result = json.loads(text)["result"]
            self.assertEqual(FILTERS, result["filters"])
            self.assertEqual(["overlay:1000", "ram:1000"], [row["source_address"] for row in result["results"]])
            self.assertTrue(result["complete"])
            page = json.loads(await call(session, self.worker, "bsim_overview", max_functions=2, **filters))
            self.assertEqual(2, page["result"]["next_offset"])
            self.assertIn("expected_modification=17", page["api_links"]["next"])
            self.assertIn("expected_program=program-instance-1", page["api_links"]["next"])
            self.assertEqual("program-instance-1", page["result"]["source_program_id"])
            self.assertFalse(page["result"]["complete"])


if __name__ == "__main__":
    unittest.main()
