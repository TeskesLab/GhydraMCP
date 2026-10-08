# Testing GhydraMCP

This document describes how to test the GhydraMCP plugin and bridge.

## Prerequisites

- Python 3.11 or higher
- Ghidra with the GhydraMCP plugin installed and running
- The `requests` Python package (`pip install requests`)

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
```

> **Every suite skips itself when Ghidra is not running.** Each `setUp` calls
> `skipTest("Ghidra not running")`, so a green summary does not prove anything unless the
> tests actually executed — check the output for skips before trusting a pass.

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
4. Call the list_instances tool
5. Call the discover_instances tool
6. Call the list_functions tool

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
    self.assertIn("port", data)
```

### MCP Bridge Tests

To add a new test for an MCP tool:

1. Add a new test method to the `MCPBridgeTests` class
2. Use the `send_mcp_request` method to send an MCP request to the bridge
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

Each script throws on the first failed assertion, so headless reports `SCRIPT ERROR` and a
non-zero exit — usable as a CI gate:

```bash
analyzeHeadless ... -postScript TestRawImage && echo PASS || echo FAIL
```

Note this requires the plugin to be **installed** in the Ghidra you point at, because the
scripts import classes from the extension jar.