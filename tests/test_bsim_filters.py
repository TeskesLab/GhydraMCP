"""BSim filter consumers over loopback HTTP and real MCP stdio.

The fixture checks transport predicates and supplies scoped-empty evidence; native
BSim pre-limit database semantics are covered separately, not simulated here.
"""
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from click.testing import CliRunner
from ghydra.cli.bsim_cmd import bsim
from ghydra.client.http_client import GhidraHTTPClient
from ghydra.formatters.table_formatter import TableFormatter


FILTERS = {
    "executable": "lib & codec=β.so",
    "architecture": "x86:LE:64:default",
    "compiler": "gcc:default",
    "categories": {"Library": "libc=stable&β", "Version": "1.0"},
}


class QueryFixture:
    def __init__(self):
        self.requests = []
        state = self
        corpus = []
        for suffix, overrides in (
                ("selected", {}),
                ("other-version", {"categories": {**FILTERS["categories"], "Version": "2.0"}}),
                ("other-library", {"categories": {**FILTERS["categories"], "Library": "other"}}),
                ("other-executable", {"executable": "other.so"}),
                ("other-architecture", {"architecture": "ARM:LE:32:v8"}),
                ("other-compiler", {"compiler": "other"})):
            corpus.append({**FILTERS, **overrides, "function": "decode_" + suffix})

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def respond(self, result=None, code=None):
                payload = ({"success": False, "error": {"code": code,
                            "message": "Unknown category metadata: Missing"}} if code else
                           {"success": True, "result": result})
                data = json.dumps(payload).encode()
                self.send_response(400 if code else 200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                url = urlsplit(self.path)
                params = parse_qs(url.query, keep_blank_values=True)
                state.requests.append((url.path, params))
                if url.path == "/capabilities":
                    return self.respond({"plugin_version": "v3.2.0", "api_version": 3000})
                if url.path == "/program":
                    return self.respond({"name": "target"})
                if url.path != "/bsim/query":
                    return self.respond(code="UNEXPECTED_ENDPOINT")
                filters: dict[str, Any] = {key: params[key][0] for key in
                                          ("executable", "architecture", "compiler") if key in params}
                if "categories" in params:
                    filters["categories"] = json.loads(params["categories"][0])
                    if "Missing" in filters["categories"]:
                        return self.respond(code="BSIM_FILTER_INVALID")
                matches = []
                for record in corpus:
                    if any(record[key] != value for key, value in filters.items()
                           if key != "categories"):
                        continue
                    if any(record["categories"].get(key) != value
                           for key, value in filters.get("categories", {}).items()):
                        continue
                    matches.append({"function": record["function"], "address": "2000",
                        "similarity": 1.0, "significance": 12.0,
                        "executable": record["executable"], "match_id": record["function"],
                        "reference_available": False})
                self.respond({"function": "main", "address": "1000", "database": "fixture-corpus",
                    "min_similarity": 0.7, "min_significance": 0, "filters": filters,
                    "available_categories": ["Library", "Version"],
                    "returned": len(matches), "total_considered": len(matches), "matches": matches,
                    "reason": "No stored function met the query predicates." if not matches else None})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_port

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def queries(self):
        return [params for path, params in self.requests if path == "/bsim/query"]


def assert_search_scope(test, text, filters):
    start = text.index("{")
    actual, _ = json.JSONDecoder().raw_decode(text[start:])
    test.assertEqual(filters, actual)


class BSimFilterCLI(unittest.TestCase):
    def setUp(self):
        self.worker = QueryFixture()
        self.addCleanup(self.worker.close)
        self.client = GhidraHTTPClient(host="127.0.0.1", port=self.worker.port, timeout=2)
        self.addCleanup(self.client.close)

    def query(self, *flags):
        return CliRunner().invoke(bsim, ["query", "--name", "main", "--profile", "corpus", *flags],
            obj={"client": self.client, "formatter": TableFormatter(use_colors=False),
                 "output_json": False})

    def test_exact_predicates_select_only_the_requested_candidate(self):
        flags = []
        for key in ("executable", "architecture", "compiler"):
            flags += ["--" + key, FILTERS[key]]
        for key, value in FILTERS["categories"].items():
            flags += ["--category", key + "=" + value]
        result = self.query(*flags)
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn("decode_selected", result.output)
        self.assertNotIn("decode_other", result.output)
        assert_search_scope(self, result.output, FILTERS)
        absent = self.query("--executable", "absent.so")
        self.assertEqual(0, absent.exit_code, absent.output)
        self.assertNotIn("decode_", absent.output)
        assert_search_scope(self, absent.output, {"executable": "absent.so"})

    def test_invalid_and_duplicate_categories_never_send_http(self):
        for flags in (("--category", "Library=libc", "--category", "Library=other"),
                      ("--category", "=value"), ("--category", "Library="),
                      ("--category", "Library"), ("--category", "  =value"),
                      ("--category", "Library=  "), ("--compiler", "  ")):
            with self.subTest(flags=flags):
                result = self.query(*flags)
                self.assertNotEqual(0, result.exit_code)
                self.assertEqual([], self.worker.requests)

    def test_unknown_category_is_reported_without_unfiltered_retry(self):
        result = self.query("--category", "Missing=value")
        self.assertNotEqual(0, result.exit_code)
        self.assertEqual(1, len(self.worker.queries()))

    def test_unfiltered_query_keeps_all_candidates(self):
        result = self.query()
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn("decode_selected", result.output)
        self.assertIn("decode_other-executable", result.output)
        self.assertIn("decode_other-architecture", result.output)


class BSimFilterMCP(unittest.IsolatedAsyncioTestCase):
    async def test_stdio_preserves_exact_values_and_rejects_ambiguous_categories(self):
        from mcp.client.session import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        worker = QueryFixture()
        self.addCleanup(worker.close)
        root = str(Path(__file__).resolve().parents[1])
        launcher = (
            f"import sys; sys.path.insert(0, {root!r}); "
            "import bridge_mcp_hydra as b; "
            f"b.DEFAULT_GHIDRA_PORT={worker.port}; "
            f"b.QUICK_DISCOVERY_RANGE=range({worker.port},{worker.port + 1}); "
            "b.FULL_DISCOVERY_RANGE=b.QUICK_DISCOVERY_RANGE; b.main()"
        )
        with tempfile.TemporaryDirectory(prefix="ghydra-bsim-filter-test-") as home:
            parameters = StdioServerParameters(command=sys.executable, args=["-c", launcher], env={
                "HOME": home, "GHYDRA_STATE_DIR": home, "GHIDRA_HYDRA_HOST": "127.0.0.1",
                "GHYDRA_MCP_OUTPUT": "text", "GHYDRA_TELEMETRY": "0",
            })
            async with stdio_client(parameters) as (reader, writer):
                async with ClientSession(reader, writer) as session:
                    await session.initialize()
                    await session.list_tools()

                    async def query(**filters):
                        response = await session.call_tool("bsim_query", arguments={
                            "port": worker.port, "profile": "corpus", "name": "main", **filters})
                        return "\n".join(part.text for part in response.content if part.type == "text")

                    for key in ("executable", "architecture", "compiler", "categories"):
                        for value in ("", " "):
                            with self.subTest(filter=key, value=value):
                                before = len(worker.queries())
                                text = await query(**{key: value})
                                self.assertIn("BSIM_FILTER_INVALID", text)
                                self.assertEqual(before, len(worker.queries()))

                    for malformed in ('{', '[]', 'null', '{"Library":1}', '{"Library":{}}',
                                      '{"": "libc"}', '{"Library":" "}',
                                      '{"Library":"libc","Library":"other"}'):
                        with self.subTest(categories=malformed):
                            before = len(worker.queries())
                            text = await query(categories=malformed)
                            self.assertIn("BSIM_FILTER_INVALID", text)
                            self.assertEqual(before, len(worker.queries()))
                    text = await query(**{**FILTERS,
                        "categories": json.dumps(FILTERS["categories"], ensure_ascii=False)})
                    self.assertIn("decode_selected", text)
                    self.assertNotIn("decode_other", text)
                    assert_search_scope(self, text, FILTERS)
                    for literal_name in ("null", "true", "false"):
                        text = await query(executable=literal_name)
                        self.assertNotIn("decode_", text)
                        assert_search_scope(self, text, {"executable": literal_name})
                    before = len(worker.queries())
                    text = await query(categories='{"Missing":"value"}')
                    self.assertIn("BSIM_FILTER_INVALID", text)
                    self.assertEqual(before + 1, len(worker.queries()))
                    text = await query()
                    self.assertIn("decode_selected", text)
                    self.assertIn("decode_other-executable", text)
                    self.assertIn("decode_other-architecture", text)


if __name__ == "__main__":
    unittest.main()
