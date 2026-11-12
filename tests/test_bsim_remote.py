"""A denied remote ingest must fail, not report a successful zero insert."""
import os
import sys
import unittest
from unittest.mock import Mock
import json
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from click.testing import CliRunner
from ghydra.cli.bsim_cmd import bsim
from ghydra.client.exceptions import GhidraError


class BSimRemoteTests(unittest.TestCase):
    def test_permission_failure_is_not_reported_as_successful_ingest(self):
        client = Mock()
        client.post.side_effect = GhidraError('connection permission denied')
        result = CliRunner().invoke(bsim, ['ingest', '--profile', 'read-only'], obj={
            'client': client, 'formatter': Mock(), 'output_json': True,
        })
        self.assertEqual(1, result.exit_code)
        self.assertNotIn('inserted:', result.output)


class BSimMcpRemoteTests(unittest.IsolatedAsyncioTestCase):
    """Opt-in real stdio/HTTP/native test using an existing query-only profile."""

    async def test_remote_query_and_write_denial_through_mcp(self):
        profile = os.environ.get("GHYDRAMCP_BSIM_PROFILE")
        function = os.environ.get("GHYDRAMCP_BSIM_FUNCTION")
        port = os.environ.get("GHYDRAMCP_TEST_PORT")
        if not profile or not function or not port:
            self.skipTest("Set GHYDRAMCP_BSIM_PROFILE, GHYDRAMCP_BSIM_FUNCTION and GHYDRAMCP_TEST_PORT")
        from mcp.client.session import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        worker_port = int(port)
        root = str(Path(__file__).resolve().parents[1])
        launcher = (
            f"import sys; sys.path.insert(0, {root!r}); "
            "import bridge_mcp_hydra as b; "
            f"b.DEFAULT_GHIDRA_PORT={worker_port}; "
            f"b.QUICK_DISCOVERY_RANGE=range({worker_port},{worker_port + 1}); "
            "b.FULL_DISCOVERY_RANGE=b.QUICK_DISCOVERY_RANGE; b.main()"
        )
        with tempfile.TemporaryDirectory(prefix="ghydra-bsim-mcp-test-") as home:
            parameters = StdioServerParameters(command=sys.executable, args=["-c", launcher], env={
                "HOME": home, "GHYDRA_STATE_DIR": home,
                "GHIDRA_HYDRA_HOST": os.environ.get("GHYDRAMCP_TEST_HOST", "127.0.0.1"),
                "GHYDRA_MCP_OUTPUT": "json", "GHYDRA_TELEMETRY": "0",
            })
            async with stdio_client(parameters) as (reader, writer):
                async with ClientSession(reader, writer) as session:
                    await session.initialize()

                    async def call(tool_name, **parameters):
                        response = await session.call_tool(tool_name, arguments={"port": worker_port, **parameters})
                        self.assertFalse(response.isError, response.content)
                        return json.loads(next(part.text for part in response.content if part.type == "text"))

                    catalog = await call("connections_list")
                    selected = next(row for row in catalog["result"] if row["id"] == profile)
                    self.assertIn("query", selected["permissions"])
                    self.assertNotIn("ingest", selected["permissions"],
                                     "This read-only test must never use an ingest-enabled profile")
                    result = await call("bsim_query", profile=profile, name=function, max_matches=3)
                    self.assertTrue(result["success"], result)
                    self.assertTrue(result["result"]["success"], result)
                    self.assertEqual(function, result["result"]["function"])
                    self.assertLessEqual(result["result"]["returned"], 3)
                    reference_profile = os.environ.get("GHYDRAMCP_REFERENCE_PROFILE")
                    reference_port = os.environ.get("GHYDRAMCP_REFERENCE_PORT")
                    if reference_profile and reference_port:
                        import requests
                        host = os.environ.get("GHYDRAMCP_TEST_HOST", "127.0.0.1")
                        reference_url = f"http://{host}:{int(reference_port)}/program"
                        before_reference = requests.get(reference_url, timeout=30).json()["result"]
                        before_target = await call("functions_get", name=function)
                        candidates = await call("bsim_query", profile=profile, name=function, max_matches=200)
                        expected_md5 = os.environ.get("GHYDRAMCP_REFERENCE_MD5")
                        selected = next((row for row in candidates["result"]["matches"]
                            if row.get("reference_available") and (not expected_md5
                                or row.get("executable_md5") == expected_md5)), None)
                        if selected is None:
                            self.fail("A resolvable positive match is required")
                        comparison = await call("bsim_compare_match", match_id=selected["match_id"],
                            profile=profile, reference_profile=reference_profile,
                            reference_port=int(reference_port))
                        self.assertTrue(comparison["success"], comparison)
                        compared = comparison["result"]
                        self.assertTrue(compared["identity_verified"])
                        self.assertFalse(compared["applied"])
                        self.assertEqual(selected["executable_md5"],
                            compared["target_reference"]["program"]["md5"])
                        self.assertTrue(compared["comparison"]["code"]["complete"], compared)
                        after_target = await call("functions_get", name=function)
                        self.assertEqual(before_target["result"], after_target["result"])
                        after_reference = requests.get(reference_url, timeout=30).json()["result"]
                        self.assertEqual(before_reference, after_reference,
                            "Reference inspection must preserve the active reference program")
                    naming = await call("bsim_apply_names", profile=profile, name=function, dry_run=True)
                    if naming["success"]:
                        self.assertFalse(naming["result"]["applied"])
                    else:
                        self.assertEqual("BSIM_NO_MATCH", naming["error"]["code"], naming)
                    denied = await call("bsim_ingest", profile=profile, max_functions=1)
                    self.assertFalse(denied["success"], denied)
                    self.assertEqual("CONNECTION_PERMISSION_DENIED", denied["error"]["code"], denied)


if __name__ == '__main__':
    unittest.main()
