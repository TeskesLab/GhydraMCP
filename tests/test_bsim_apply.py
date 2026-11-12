"""Consumer-visible two-step BSim workflow over real loopback HTTP.

The fixture speaks the native transport contract; it does not execute Ghidra or
claim to test native type/transaction validation. These tests exercise command
refusals, unchanged preparation, separate explicit application, and full output.
"""
import json
import os
import sys
import threading
import unittest
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from click.testing import CliRunner
from ghydra.cli.bsim_cmd import bsim
from ghydra.client.http_client import GhidraHTTPClient
from ghydra.formatters.json_formatter import JSONFormatter
from ghydra.formatters.table_formatter import TableFormatter


MATCH_ID = "chosen-row"
TOKEN = "opaque-native-token"
ARCHIVE = "INTERNAL_NATIVE_ARCHIVE_NOT_FOR_DISPLAY"
REFERENCE = {
    "match_id": MATCH_ID, "identity_verified": True, "profile": "reference",
    "path": "/reference", "version": 7,
    "identity": {"repository_url": "ghidra://approved/repository/reference",
                 "executable_md5": "b" * 32, "address": "ram::2000",
                 "selected_address": "2000", "indexed_function": "parse"},
    "abi": {"language": "x86:LE:64:default", "compiler": "gcc", "pointer_size": 8},
    "function": {"name": "parse", "namespace": ["protocol"], "varargs": False},
    "archive": {"format": "ghidra-gdt-v1", "gdt_base64": ARCHIVE,
                "sha256": "c" * 64, "size": 32, "root_type": "/parse"},
}
PREVIEW = {
    "before": {"name": "FUN_1000", "prototype": "undefined FUN_1000(void)"},
    "after": {"name": "parse", "namespace": ["protocol"],
              "prototype": "Node * parse(Node * input, int count)"},
    "types": [{"path": "/protocol/Node", "action": "import", "length": 16,
               "components": [{"name": "next", "type": "Node *", "offset": 0}]}],
    "reference": {key: REFERENCE[key] for key in ("identity", "profile", "path", "version")},
    "abi": REFERENCE["abi"], "comments_transferred": False,
    "selection_identity_checked": True, "archive_sha256": "c" * 64,
}


class WorkflowFixture:
    def __init__(self):
        self.requests = []
        self.reference_available = True
        self.export_denied = False
        self.stale = False
        self.prepared = False
        self.applied = False
        self.servers = []
        self.threads = []

    def start(self, role):
        state = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def respond(self, result=None, code=None):
                payload = ({"success": False, "error": {"code": code,
                            "message": "Native worker refused this operation."}} if code else
                           {"success": True, "result": result})
                data = json.dumps(payload).encode()
                self.send_response(409 if code else 200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                path = urlsplit(self.path)
                query = parse_qs(path.query)
                state.requests.append((role, "GET", path.path))
                if path.path == "/capabilities":
                    return self.respond({"plugin_version": "v3.2.0", "api_version": 3000})
                if path.path == "/program":
                    return self.respond({"name": role})
                if role == "target" and path.path == f"/bsim/matches/{MATCH_ID}/selection":
                    if query.get("profile") != ["corpus"]:
                        return self.respond(code="CONNECTION_PERMISSION_DENIED")
                    return self.respond({"selection": {"match_id": MATCH_ID, "profile": "corpus",
                        "target": {"address": "1000", "modification": 10, "md5": "a" * 32},
                        "match": {"reference_available": state.reference_available,
                                  "repository_url": REFERENCE["identity"]["repository_url"],
                                  "executable_md5": "b" * 32, "address": "2000",
                                  "function": "parse"}}})
                if role == "reference" and path.path == "/repositories/export-match":
                    if state.export_denied or query.get("profile") != ["reference"]:
                        return self.respond(code="CONNECTION_PERMISSION_DENIED")
                    if query.get("match_id") != [MATCH_ID] or query.get("address") != ["2000"]:
                        return self.respond(code="BSIM_APPLY_INVALID")
                    return self.respond(REFERENCE)
                self.respond(code="UNEXPECTED_ENDPOINT")

            def do_POST(self):
                path = urlsplit(self.path)
                state.requests.append((role, "POST", path.path))
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if role != "target" or parse_qs(path.query).get("profile") != ["corpus"]:
                    return self.respond(code="CONNECTION_PERMISSION_DENIED")
                if path.path == f"/bsim/matches/{MATCH_ID}/prepare-apply":
                    if set(payload) != {"reference"} or payload["reference"]["match_id"] != MATCH_ID:
                        return self.respond(code="BSIM_APPLY_INVALID")
                    state.prepared = True
                    return self.respond({"apply_token": TOKEN, "match_id": MATCH_ID,
                                         "prepared": True, "applied": False, "preview": PREVIEW})
                if path.path == f"/bsim/matches/{MATCH_ID}/apply":
                    if (not state.prepared or state.applied or state.stale or
                            payload != {"apply_token": TOKEN}):
                        return self.respond(code="BSIM_APPLY_TOKEN")
                    state.applied = True
                    return self.respond({"applied": True, "match_id": MATCH_ID, "summary": PREVIEW})
                self.respond(code="UNEXPECTED_ENDPOINT")

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.servers.append(server)
        self.threads.append(thread)
        return server.server_port

    def close(self):
        for server in self.servers:
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join()


class BSimApplicationConsumers(unittest.TestCase):
    def setUp(self):
        self.worker = WorkflowFixture()
        self.addCleanup(self.worker.close)
        self.target_port = self.worker.start("target")
        self.reference_port = self.worker.start("reference")
        self.client = GhidraHTTPClient(host="127.0.0.1", port=self.target_port, timeout=2)
        self.addCleanup(self.client.close)

    def cli(self, command, formatter=None):
        return CliRunner().invoke(bsim, command + ["--profile", "corpus"], obj={
            "client": self.client, "formatter": formatter or JSONFormatter(), "output_json": True})

    def prepare(self, formatter=None):
        return self.cli(["prepare-apply", MATCH_ID, "--reference-profile", "reference",
                         "--reference-port", str(self.reference_port)], formatter)

    def apply(self, formatter=None):
        return self.cli(["apply-match", MATCH_ID, "--apply-token", TOKEN], formatter)

    def assert_no_archive(self, text):
        self.assertNotIn(ARCHIVE, text)
        self.assertNotIn("gdt_base64", text)

    def test_cli_prepares_without_apply_then_explicitly_applies_once(self):
        prepared = self.prepare()
        self.assertEqual(0, prepared.exit_code, prepared.output)
        result = json.loads(prepared.output)["result"]
        self.assertEqual(TOKEN, result["apply_token"])
        self.assertEqual(PREVIEW, result["preview"])
        self.assertFalse(result["applied"])
        self.assertFalse(self.worker.applied)
        self.assert_no_archive(prepared.output)
        count = len(self.worker.requests)
        applied = self.apply()
        self.assertEqual(0, applied.exit_code, applied.output)
        self.assertEqual({"applied": True, "match_id": MATCH_ID, "summary": PREVIEW},
                         json.loads(applied.output)["result"])
        self.assert_no_archive(applied.output)
        self.assertEqual([("target", "POST", f"/bsim/matches/{MATCH_ID}/apply")],
                         self.worker.requests[count:])
        replay = self.apply()
        self.assertEqual(1, replay.exit_code, replay.output)
        self.assertIn("BSIM_APPLY_TOKEN", replay.output)
        self.assertNotIn('"applied": true', replay.output)

    def test_cli_reference_denial_stops_before_preparation_or_application(self):
        self.worker.export_denied = True
        refused = self.prepare()
        self.assertEqual(1, refused.exit_code, refused.output)
        self.assertIn("CONNECTION_PERMISSION_DENIED", refused.output)
        self.assertFalse(self.worker.prepared)
        self.assertFalse(self.worker.applied)
        self.assertFalse(any(method == "POST" for _, method, _ in self.worker.requests))
        self.assert_no_archive(refused.output)

    def test_cli_unavailable_selected_reference_never_contacts_reference_worker(self):
        self.worker.reference_available = False
        refused = self.prepare()
        self.assertEqual(1, refused.exit_code, refused.output)
        self.assertIn("BSIM_REFERENCE_UNAVAILABLE", refused.output)
        self.assertEqual([("target", "GET", f"/bsim/matches/{MATCH_ID}/selection")],
                         self.worker.requests)

    def test_cli_stale_preview_is_reported_without_requery_or_success(self):
        self.assertEqual(0, self.prepare().exit_code)
        self.worker.stale = True
        count = len(self.worker.requests)
        refused = self.apply(TableFormatter(use_colors=False))
        self.assertEqual(1, refused.exit_code, refused.output)
        self.assertIn("BSIM_APPLY_TOKEN", refused.output)
        self.assertNotIn("Applied prepared", refused.output)
        self.assertFalse(self.worker.applied)
        self.assertEqual([("target", "POST", f"/bsim/matches/{MATCH_ID}/apply")],
                         self.worker.requests[count:])

    def test_cli_table_retains_preview_token_types_and_explicit_application_boundary(self):
        preview = self.prepare(TableFormatter(use_colors=False))
        self.assertEqual(0, preview.exit_code, preview.output)
        for evidence in (TOKEN, "No changes applied", "FUN_1000", "Node", "next", "comments_transferred"):
            self.assertIn(evidence, preview.output)
        self.assertFalse(self.worker.applied)
        self.assert_no_archive(preview.output)
        applied = self.apply(TableFormatter(use_colors=False))
        self.assertEqual(0, applied.exit_code, applied.output)
        self.assertIn("Applied prepared signature and types.", applied.output)
        self.assertIn("FUN_1000", applied.output)
        self.assertIn("next", applied.output)

    def test_cli_global_dry_run_never_exports_archive_or_applies(self):
        self.client.dry_run = True
        for result in (self.prepare(TableFormatter(use_colors=False)),
                       self.apply(TableFormatter(use_colors=False))):
            self.assertEqual(0, result.exit_code, result.output)
            self.assertIn("Dry run", result.output)
            self.assert_no_archive(result.output)
            self.assertNotIn("Applied prepared", result.output)
        self.assertFalse(self.worker.prepared)
        self.assertFalse(self.worker.applied)
        self.assertEqual([("target", "GET", f"/bsim/matches/{MATCH_ID}/selection")],
                         self.worker.requests)

    def test_mcp_text_surfaces_preview_then_separate_application_and_native_refusal(self):
        import bridge_mcp_hydra as bridge

        with ExitStack() as stack:
            stack.enter_context(patch.object(bridge, "active_instances", {}))
            stack.enter_context(patch.object(bridge, "ghidra_host", "127.0.0.1"))
            stack.enter_context(patch.object(bridge, "RAW_OUTPUT", False))
            stack.enter_context(patch.dict(os.environ, {"GHYDRA_TELEMETRY": "0"}))
            preview = bridge.bsim_prepare_apply(MATCH_ID, "reference", self.reference_port,
                                                profile="corpus", port=self.target_port)
            for evidence in (TOKEN, "No changes applied", "FUN_1000", "next", "comments_transferred"):
                self.assertIn(evidence, preview)
            self.assert_no_archive(preview)
            self.assertFalse(self.worker.applied)
            count = len(self.worker.requests)
            applied = bridge.bsim_apply_match(MATCH_ID, TOKEN, profile="corpus", port=self.target_port)
            self.assertIn("Applied prepared signature and types.", applied)
            self.assertIn("next", applied)
            self.assert_no_archive(applied)
            self.assertEqual([("target", "POST", f"/bsim/matches/{MATCH_ID}/apply")],
                             self.worker.requests[count:])
            replay = bridge.bsim_apply_match(MATCH_ID, TOKEN, profile="corpus", port=self.target_port)
            self.assertIn("BSIM_APPLY_TOKEN", replay)
            self.assertNotIn("Applied prepared", replay)

    def test_mcp_reference_denial_does_not_prepare_or_apply(self):
        import bridge_mcp_hydra as bridge

        self.worker.export_denied = True
        with patch.object(bridge, "active_instances", {}), \
                patch.object(bridge, "ghidra_host", "127.0.0.1"), \
                patch.object(bridge, "RAW_OUTPUT", False), \
                patch.dict(os.environ, {"GHYDRA_TELEMETRY": "0"}):
            refused = bridge.bsim_prepare_apply(MATCH_ID, "reference", self.reference_port,
                                                profile="corpus", port=self.target_port)
        self.assertIn("CONNECTION_PERMISSION_DENIED", refused)
        self.assertFalse(self.worker.prepared)
        self.assertFalse(self.worker.applied)
        self.assertFalse(any(method == "POST" for _, method, _ in self.worker.requests))


if __name__ == "__main__":
    unittest.main()
