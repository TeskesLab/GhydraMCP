# Testing GhydraMCP


<!-- toc -->

- [Prerequisites](#prerequisites)
- [Where the suites live](#where-the-suites-live)
- [Running All Tests](#running-all-tests)
- [HTTP API Tests](#http-api-tests)
- [MCP Bridge Tests](#mcp-bridge-tests)
- [Kuna Integration Tests](#kuna-integration-tests)
- [Troubleshooting](#troubleshooting)
- [Adding New Tests](#adding-new-tests)
- [Java Unit Tests](#java-unit-tests)
- [Java Integration Tests (GhidraScript)](#java-integration-tests-ghidrascript)

<!-- /toc -->

This document describes how to test the GhydraMCP plugin and bridge.

## Prerequisites

- Python 3.11 or higher
- Ghidra with the GhydraMCP plugin installed and running
- The `requests` Python package (`pip install requests`)

## Where the suites live

The suites are the `test_*.py` files in [`tests/`](../tests/). The runner stays at
the repository root because CI and the documentation call `python run_tests.py`
there; it builds every suite command from one helper, so a suite only has to
exist in `tests/` to be runnable.

## Running All Tests

The easiest way to run all tests is to use the test runner script:

```bash
python run_tests.py
```

This runs every suite and prints a summary.

You can also run specific test suites:

```bash
python run_tests.py --http       # HTTP API tests
python run_tests.py --mcp        # MCP bridge tests
python run_tests.py --data       # data operations tests
python run_tests.py --comments   # comment tests
python run_tests.py --port       # Javalin port edge-case tests
python run_tests.py --kuna       # Kuna integration tests
python run_tests.py --x64dbg     # x64dbg integration tests

> **The x64dbg fixture listens with a backlog of 128, not the default 5.** A burst
> of connections fills a 5-deep queue, the OS drops the SYN, and the client sees a
> server that never came up — the same symptom as a dead debugger. It is not port
> exhaustion: the dynamic range here is 16 384 ports and a full run leaves about 5
> connections in TIME_WAIT, so the *queue* was the limit. The fixture also waits
> until the port actually answers before a test uses it (a started thread is not an
> accepting one), and keeps its own side of a reset: set
> `GHYDRA_X64DBG_TEST_LOG=<file>` to see the half of a failed run that the client
> never sees.
python run_tests.py --headless   # headless runner, report and annotations
python run_tests.py --evidence   # evidence ledger and sessions
python run_tests.py --triage     # target triage
python run_tests.py --rea        # REA parity
python run_tests.py --surface    # global tool/formatter contract
python run_tests.py --capabilities # capability negotiation contract
python run_tests.py --scripts      # MCP/CLI scripting behavior with a local HTTP fixture
python run_tests.py --compatibility # 11.x/12.2 compatibility contract
python run_tests.py --runner        # test-runner contract
python run_tests.py --docs          # documentation drift guard
python run_tests.py --capability-summary # ATT&CK/MBC triage contract
python run_tests.py --tasks         # background task registry (async_mode)
python run_tests.py --errors        # error.code contract + CLI entrypoint (I4/I9)
python run_tests.py --context-pack  # budgeted dossier (R3) + actionable links (I8)
python run_tests.py --tool-groups   # progressive tool discovery (I15)
python run_tests.py --telemetry     # local telemetry recorder/summary (I14)
python run_tests.py --assertions    # ghydra assert: SARIF/JUnit reports (I16)
python run_tests.py --read-only     # read-only mode, dry-run and the audit trail (I12)
python run_tests.py --runbook       # reproducible runbooks and analysis_diff (R6)
python run_tests.py --taint         # source-to-sink hypotheses (R5)
python run_tests.py --mission       # mission mode: budget, dossier, resume (R8)
python run_tests.py --cache         # the decompile cache (I11)
python run_tests.py --fleet         # fleet queries across instances (R7)
python run_tests.py --core          # the single core and its generated copy (I1)
python run_tests.py --twin          # the digital twin: snapshots, offline queries, diff (R2)
python run_tests.py --examples      # the examples really run (offline twin, asserts, index)
python run_tests.py --contract      # the unification contract: vocabulary, address model, codes
python run_tests.py --mcp-config   # the combined client configuration (Phase 2)
python run_tests.py --target       # the cross-tool workflow of Phase 3
python run_tests.py --gateway      # the workflow as MCP tools (Phase 3)
python run_tests.py --doctor        # the doctor: what is missing on this machine
python run_tests.py --launcher      # the JDK, the installation and the headless command
python run_tests.py --progress      # the progress reporter: what a long step is doing
python run_tests.py --cli-failures  # every command, with nothing serving: none may crash
python run_tests.py --bridge-tools  # every bridge tool, called with nothing serving
python run_tests.py --formatters    # every formatter, with the answer of its own tool
python run_tests.py --no-ghidra     # ALL suites that need no Ghidra (CI's set)
python run_tests.py --surface --scripts   # several flags can be combined
```

> `run_tests.py` accepts any number of suite flags in one invocation and reports
> each one separately. `--no-ghidra` expands to the suites that always execute
> (`--kuna`, `--x64dbg`, `--surface`, `--capabilities`, `--scripts`,
> `--compatibility`, `--runner`, `--docs`, `--capability-summary`, `--tasks`,
> `--errors`, `--context-pack`, `--tool-groups`, `--telemetry`, `--assertions`, `--read-only`, `--runbook`, `--taint`, `--mission`, `--cache`, `--fleet`, `--core`, `--twin`, `--examples`); both CI workflows run exactly that
> set on every push and pull request, so a green result is real evidence rather than a
> summary made of skipped suites. `--require-live` probes `/plugin-version` first
> and refuses to run when no Ghidra is serving.

> **Every suite skips itself when Ghidra is not running.** Each `setUp` calls
> `skipTest("Ghidra not running")`, so a green summary does not prove anything unless the
> tests actually executed — check the output for skips before trusting a pass.
>
> `--kuna`, `--x64dbg`, `--surface`, `--capabilities`, `--scripts`, `--compatibility`
> `--runner`, `--docs`, `--capability-summary`, `--tasks`, `--errors`,
> `--context-pack`, `--tool-groups`, `--telemetry`, `--assertions`, `--read-only`, `--runbook`, `--taint`, `--mission`, `--cache`, `--fleet`, `--core`, `--twin` and `--examples` are the exceptions: they need neither Ghidra
> nor their respective binaries, so they always run
> and always give a signal. `--rea` is
> half contract (no Ghidra) and half live. `python run_tests.py --require-live`
> probes `/plugin-version` first and refuses to run without a live instance, so a
> green summary cannot be made of skipped suites. The `--scripts` suite now also
> drives the bridge and CLI against a local HTTP fixture.

## HTTP API Tests

The `test_http_api.py` script tests the HTTP API exposed by the Java plugin. It verifies that the endpoints return the expected JSON structure and that the response format is consistent.

### Running the HTTP API Tests

1. Make sure Ghidra is running with the GhydraMCP plugin loaded
2. Run the tests:

```bash
python test_http_api.py
```

The tests will automatically skip if Ghidra is not running or if the plugin is not responding.

### What's Being Tested

- Basic connectivity to the plugin
- Response format and structure
- JSON structure consistency
- Required fields in responses
- Error handling

## MCP Bridge Tests

The `test_mcp_client.py` script tests the MCP bridge functionality using the MCP client library. It verifies that the bridge responds correctly to MCP requests and that the response format is consistent.

### Running the MCP Bridge Tests

1. Make sure Ghidra is running with the GhydraMCP plugin loaded
2. Run the tests:

```bash
python test_mcp_client.py
```

The test script will:
1. Connect to the bridge using the MCP client
2. Initialize the session
3. List the available tools
4. Call the instances_list tool
5. Call the instances_discover tool
6. Call the functions_list tool

### What's Being Tested

- MCP protocol communication
- Tool availability and structure
- Response format and structure
- JSON structure consistency
- Required fields in responses
- Proper initialization of the MCP session
- Ability to call tools and receive responses
- Mutating operations (tested by changing and reverting):
  - Function renaming
  - Comment addition/removal

## Kuna Integration Tests

The `test_kuna.py` script covers the Kuna decompiler integration. It needs **neither** a running
Ghidra **nor** the Kuna binary, so it is the one suite that always gives a signal:

```bash
python run_tests.py --kuna
```

### What's Being Tested

- The opt-in precedence: the config file wins over `GHYDRA_KUNA`, and a config file that never
  mentions `enabled` (or sets it to `null`) leaves the decision to the environment
- The bridge and the CLI agree on that decision
- Every `kuna_*` bridge tool has a `FORMATTERS` entry (a missing key silently degrades the
  output to "Done") and is registered in the MCP server
- No `kuna_*` tool takes a `port` — they are local
- With the integration off, every tool refuses instead of running the binary
- The formatters survive an empty payload and report errors
- The CLI commands run, and the formatters handle every payload shape
- The export readers slice the C and the disassembly out of an export directory, and defer an
  unfinished trailing index record

## Troubleshooting

### HTTP API Tests

- If tests are skipped with "Ghidra server not running or not accessible", make sure Ghidra is running and the GhydraMCP plugin is loaded.
- If tests fail with connection errors, check that the plugin is listening on the expected port (default: 8192).

### MCP Bridge Tests

- If tests are skipped with "Failed to start MCP bridge process", check that the bridge script is executable and that all dependencies are installed.
- If tests fail with JSON parsing errors, check that the bridge is responding with valid JSON.

## Adding New Tests

### HTTP API Tests

To add a new test for an HTTP endpoint:

1. Add a new test method to the `GhydraMCPHttpApiTests` class
2. Use the `requests` library to make HTTP requests to the endpoint
3. Verify the response using assertions

Example:

```python
def test_new_endpoint(self):
    """Test the /new_endpoint endpoint"""
    response = requests.get(f"{BASE_URL}/new_endpoint")
    self.assertEqual(response.status_code, 200)

    # Verify response is valid JSON
    data = response.json()

    # Check required fields in the standard response format
    self.assertIn("success", data)
    self.assertTrue(data["success"])
    self.assertIn("timestamp", data)
    self.assertIn("instance", data)
    self.assertIn("result", data)
```

### MCP Bridge Tests

To add a new test for an MCP tool:

1. Add a new test method to the `MCPBridgeTests` class
2. Use the MCP client helper in `test_mcp_bridge.py` to send a request to the bridge
3. Verify the response using assertions

Example:

```python
def test_new_tool(self):
    """Test the new_tool tool"""
    response = self.send_mcp_request("call_tool", {
        "name": "new_tool",
        "arguments": {
            "param1": "value1",
            "param2": "value2"
        }
    })

    # Check basic response structure
    self.assertIn("result", response)
    self.assertIn("content", response["result"])

    # Parse the content
    content = response["result"]["content"]
    self.assertIsInstance(content, list)
    self.assertGreaterEqual(len(content), 1)
```

## Java Unit Tests

```bash
mvn test
```

These run under JUnit with no Ghidra needed, but they only cover pure logic — `GhidraUtil`
address/type parsing and the like. Anything that needs a live `Program` (transactions, the
listing, data types) is **not** covered here, because the plugin's Ghidra dependencies are
system-scoped jars in `lib/` and constructing a `Program` needs Ghidra's full runtime
classpath plus its test framework, which Ghidra does not ship.

## Java Integration Tests (GhidraScript)

Service-level tests that do need a real `Program` live in `src/test/ghidra/` as GhidraScripts
and run headless. They are outside `src/test/java`, so `mvn test` ignores them.

```bash
# Any binary works; the test derives its own addresses from the program's layout.
analyzeHeadless /tmp/RawImageTest RawImageTest \
    -import /path/to/some-binary \
    -scriptPath src/test/ghidra \
    -postScript TestRawImage
```

- `TestRawImage` — exercises `RawImageService`: pixel-format byte math across RGB565 /
  ARGB8888 / 1bpp, single-address cleanup, whole-program sweeps, idempotency, the
  refuse-to-clear-non-RawImage guard, and that every bad input raises
  `IllegalArgumentException` (which the HTTP layer maps to `400`, not `500`).
- `TestPyGhidraScript` — executes real Java and Python 3 source, arguments and error
  diagnostics; checks language precedence, existing-script preservation and cleanup
  including Python bytecode caches. Run it from the Script Manager in a Ghidra
  instance launched with `pyghidraRun` and this extension installed. A plain
  `analyzeHeadless` run can exercise Java but skips Python when its runtime is not
  initialized; a Python skip is not proof that the regression passed.
  Capture assertions require Ghidra 12+; Ghidra 11 reports an explicit skip because
  its script API has no separate error writer.

Each script throws on the first failed assertion, so headless reports `SCRIPT ERROR` and a
non-zero exit — usable as a CI gate:

```bash
analyzeHeadless ... -postScript TestRawImage && echo PASS || echo FAIL
```

Note this requires the plugin to be **installed** in the Ghidra you point at, because the
scripts import classes from the extension jar.