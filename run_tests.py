#!/usr/bin/env python3
"""
Test runner for GhydraMCP tests.
This script runs both the HTTP API tests and the MCP bridge tests.
"""
import os
import subprocess
import sys
import unittest
import time

def print_header(text):
    """Print a header with the given text"""
    print("\n" + "=" * 80)
    print(f" {text} ".center(80, "="))
    print("=" * 80 + "\n")

def run_http_api_tests():
    """Run the HTTP API tests"""
    print_header("Running HTTP API Tests")
    
    # Import and run the tests
    try:
        from test_http_api import GhydraMCPHttpApiTests
        
        # Create a test suite with all tests from GhydraMCPHttpApiTests
        suite = unittest.TestLoader().loadTestsFromTestCase(GhydraMCPHttpApiTests)
        
        # Run the tests
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        
        return result.wasSuccessful()
    except ImportError:
        print("Error: Could not import test_http_api.py")
        return False
    except Exception as e:
        print(f"Error running HTTP API tests: {str(e)}")
        return False

def run_mcp_bridge_tests():
    """Run the MCP bridge tests using the MCP client"""
    print_header("Running MCP Bridge Tests")
    
    try:
        # Run the MCP client test script
        import subprocess
        import sys
        
        print("Running MCP client test script...")
        result = subprocess.run(
            [sys.executable, "test_mcp_client.py"],
            capture_output=True,
            text=True
        )
        
        # Print the output
        if result.stdout:
            print("STDOUT:")
            print(result.stdout)
        
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        
        # Return True if the process exited with code 0
        return result.returncode == 0
    except Exception as e:
        print(f"Error running MCP bridge tests: {str(e)}")
        return False

def run_data_tests():
    """Run the data operations tests."""
    print_header("Running Data Operations Tests")
    
    try:
        result = subprocess.run(
            [sys.executable, "test_data_operations.py"],
            capture_output=True,
            text=True
        )
        
        if result.stdout:
            print("STDOUT:")
            print(result.stdout)
        
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        
        return result.returncode == 0
    except Exception as e:
        print(f"Error running data operations tests: {str(e)}")
        return False

def run_port_tests():
    """Run the Javalin-port edge-case tests."""
    print_header("Running Javalin Port Edge-Case Tests")
    try:
        result = subprocess.run(
            [sys.executable, "test_javalin_port.py"],
            capture_output=True,
            text=True
        )
        if result.stdout:
            print("STDOUT:")
            print(result.stdout)
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        return result.returncode == 0
    except Exception as e:
        print(f"Error running port edge-case tests: {str(e)}")
        return False

def run_comment_tests():
    """Run the comment functionality tests."""
    print_header("Running Comment Tests")
    
    try:
        result = subprocess.run(
            [sys.executable, "test_comments.py"],
            capture_output=True,
            text=True
        )
        
        if result.stdout:
            print("STDOUT:")
            print(result.stdout)
        
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        
        return result.returncode == 0
    except Exception as e:
        print(f"Error running comment tests: {str(e)}")
        return False

def run_kuna_tests():
    """Run the Kuna integration tests."""
    print_header("Running Kuna Tests")

    try:
        result = subprocess.run(
            [sys.executable, "test_kuna.py"],
            capture_output=True,
            text=True
        )

        if result.stdout:
            print("STDOUT:")
            print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        return result.returncode == 0
    except Exception as e:
        print(f"Error running Kuna tests: {str(e)}")
        return False

def run_x64dbg_tests():
    """Run the x64dbg integration tests."""
    print_header("Running x64dbg Integration Tests")

    try:
        result = subprocess.run(
            [sys.executable, "test_x64dbg.py"],
            capture_output=True,
            text=True
        )

        if result.stdout:
            print("STDOUT:")
            print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        return result.returncode == 0
    except Exception as e:
        print(f"Error running x64dbg tests: {str(e)}")
        return False


def run_headless_tests():
    """Run the headless runner, report and annotation tests."""
    print_header("Running Headless Tests")

    try:
        result = subprocess.run(
            [sys.executable, "test_headless.py"],
            capture_output=True,
            text=True
        )

        if result.stdout:
            print("STDOUT:")
            print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        return result.returncode == 0
    except Exception as e:
        print(f"Error running headless tests: {str(e)}")
        return False


def run_evidence_tests():
    """Run the evidence ledger and session tests."""
    print_header("Running Evidence and Session Tests")

    try:
        result = subprocess.run(
            [sys.executable, "test_evidence.py"],
            capture_output=True,
            text=True
        )

        if result.stdout:
            print("STDOUT:")
            print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        return result.returncode == 0
    except Exception as e:
        print(f"Error running evidence tests: {str(e)}")
        return False


def run_triage_tests():
    """Run the target triage tests."""
    print_header("Running Target Triage Tests")

    try:
        result = subprocess.run(
            [sys.executable, "test_triage.py"],
            capture_output=True,
            text=True
        )

        if result.stdout:
            print("STDOUT:")
            print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        return result.returncode == 0
    except Exception as e:
        print(f"Error running triage tests: {str(e)}")
        return False


def run_rea_parity_tests():
    """Run the tests for the four gaps closed against the REA."""
    print_header("Running REA Parity Tests")

    try:
        result = subprocess.run(
            [sys.executable, "test_rea_parity.py"],
            capture_output=True,
            text=True
        )

        if result.stdout:
            print("STDOUT:")
            print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        return result.returncode == 0
    except Exception as e:
        print(f"Error running REA parity tests: {str(e)}")
        return False


def run_surface_parity_tests():
    """Run the global tool/formatter contract tests (no Ghidra needed)."""
    print_header("Running Surface Parity Tests")

    try:
        result = subprocess.run(
            [sys.executable, "test_surface_parity.py"],
            capture_output=True,
            text=True
        )

        if result.stdout:
            print("STDOUT:")
            print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        return result.returncode == 0
    except Exception as e:
        print(f"Error running surface parity tests: {str(e)}")
        return False


def run_capabilities_tests():
    """Run the capability negotiation contract tests (no Ghidra needed)."""
    print_header("Running Capability Negotiation Tests")

    try:
        result = subprocess.run(
            [sys.executable, "test_capabilities.py"],
            capture_output=True,
            text=True
        )

        if result.stdout:
            print("STDOUT:")
            print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        return result.returncode == 0
    except Exception as e:
        print(f"Error running capability negotiation tests: {str(e)}")
        return False


def run_compatibility_tests():
    """Run the 11.x/12.2 compatibility contract tests (no Ghidra needed)."""
    print_header("Running Ghidra Compatibility Tests")

    try:
        result = subprocess.run(
            [sys.executable, "test_compatibility.py"],
            capture_output=True,
            text=True
        )

        if result.stdout:
            print("STDOUT:")
            print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        return result.returncode == 0
    except Exception as e:
        print(f"Error running Ghidra compatibility tests: {str(e)}")
        return False


def run_scripts_tests():
    """Run the ad-hoc Java/Python script execution contract tests (no Ghidra)."""
    print_header("Running Script Execution Contract Tests")

    try:
        result = subprocess.run(
            [sys.executable, "test_scripts.py"],
            capture_output=True,
            text=True
        )

        if result.stdout:
            print("STDOUT:")
            print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        return result.returncode == 0
    except Exception as e:
        print(f"Error running script execution tests: {str(e)}")
        return False


def run_runner_tests():
    """Run the test-runner contract tests (no Ghidra needed)."""
    print_header("Running Test Runner Contract Tests")

    try:
        result = subprocess.run(
            [sys.executable, "test_runner.py"],
            capture_output=True,
            text=True
        )

        if result.stdout:
            print("STDOUT:")
            print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        return result.returncode == 0
    except Exception as e:
        print(f"Error running test runner contract tests: {str(e)}")
        return False


def run_docs_tests():
    """Run the documentation drift guard tests (no Ghidra needed)."""
    print_header("Running Documentation Drift Guard Tests")

    try:
        result = subprocess.run(
            [sys.executable, "test_docs.py"],
            capture_output=True,
            text=True
        )

        if result.stdout:
            print("STDOUT:")
            print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        return result.returncode == 0
    except Exception as e:
        print(f"Error running documentation guard tests: {str(e)}")
        return False


def run_capability_summary_tests():
    """Run the capability triage (R4) contract tests (no Ghidra needed)."""
    print_header("Running Capability Triage Tests")

    try:
        result = subprocess.run(
            [sys.executable, "test_capabilities_summary.py"],
            capture_output=True,
            text=True
        )

        if result.stdout:
            print("STDOUT:")
            print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        return result.returncode == 0
    except Exception as e:
        print(f"Error running capability triage tests: {str(e)}")
        return False


def run_tasks_tests():
    """Run the background task registry tests (no Ghidra needed)."""
    print_header("Running Background Task Tests")

    try:
        result = subprocess.run(
            [sys.executable, "test_tasks.py"],
            capture_output=True,
            text=True
        )

        if result.stdout:
            print("STDOUT:")
            print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        return result.returncode == 0
    except Exception as e:
        print(f"Error running background task tests: {str(e)}")
        return False


def run_errors_tests():
    """Run the error contract and CLI entrypoint tests (no Ghidra needed)."""
    print_header("Running Error Contract Tests")

    try:
        result = subprocess.run(
            [sys.executable, "test_errors.py"],
            capture_output=True,
            text=True
        )

        if result.stdout:
            print("STDOUT:")
            print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        return result.returncode == 0
    except Exception as e:
        print(f"Error running error contract tests: {str(e)}")
        return False


def run_context_pack_tests():
    """Run the context pack (R3) and actionable links (I8) tests."""
    print_header("Running Context Pack Tests")

    try:
        result = subprocess.run(
            [sys.executable, "test_context_pack.py"],
            capture_output=True,
            text=True
        )

        if result.stdout:
            print("STDOUT:")
            print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        return result.returncode == 0
    except Exception as e:
        print(f"Error running context pack tests: {str(e)}")
        return False


def run_tool_groups_tests():
    """Run the progressive tool discovery (I15) tests."""
    print_header("Running Tool Group Tests")

    try:
        result = subprocess.run(
            [sys.executable, "test_tool_groups.py"],
            capture_output=True,
            text=True
        )

        if result.stdout:
            print("STDOUT:")
            print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        return result.returncode == 0
    except Exception as e:
        print(f"Error running tool group tests: {str(e)}")
        return False


def run_telemetry_tests():
    """Run the local telemetry (I14) tests."""
    print_header("Running Telemetry Tests")

    try:
        result = subprocess.run(
            [sys.executable, "test_telemetry.py"],
            capture_output=True,
            text=True
        )

        if result.stdout:
            print("STDOUT:")
            print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        return result.returncode == 0
    except Exception as e:
        print(f"Error running telemetry tests: {str(e)}")
        return False


def require_live_ghidra():
    """Refuse a run that would be a green summary made of skipped suites."""
    host = os.environ.get("GHYDRAMCP_TEST_HOST", "localhost")
    port = int(os.environ.get("GHYDRAMCP_TEST_PORT", "8192"))
    try:
        import requests
        return requests.get(f"http://{host}:{port}/plugin-version", timeout=2).ok
    except Exception:
        return False


def run_all_tests():
    """Run all tests"""
    print_header("GhydraMCP Test Suite")

    # Run test suites
    http_api_success = run_http_api_tests()
    mcp_bridge_success = run_mcp_bridge_tests()
    data_tests_success = run_data_tests()
    comment_tests_success = run_comment_tests()
    port_tests_success = run_port_tests()
    kuna_success = run_kuna_tests()
    x64dbg_success = run_x64dbg_tests()
    headless_success = run_headless_tests()
    evidence_success = run_evidence_tests()
    triage_success = run_triage_tests()
    rea_parity_success = run_rea_parity_tests()
    surface_parity_success = run_surface_parity_tests()
    capabilities_success = run_capabilities_tests()
    scripts_success = run_scripts_tests()
    compatibility_success = run_compatibility_tests()
    runner_success = run_runner_tests()
    docs_success = run_docs_tests()
    capability_summary_success = run_capability_summary_tests()
    tasks_success = run_tasks_tests()
    errors_success = run_errors_tests()
    context_pack_success = run_context_pack_tests()
    tool_groups_success = run_tool_groups_tests()
    telemetry_success = run_telemetry_tests()

    # Print a summary
    print_header("Test Summary")
    print(f"HTTP API Tests: {'PASSED' if http_api_success else 'FAILED'}")
    print(f"MCP Bridge Tests: {'PASSED' if mcp_bridge_success else 'FAILED'}")
    print(f"Data Operations Tests: {'PASSED' if data_tests_success else 'FAILED'}")
    print(f"Comment Tests: {'PASSED' if comment_tests_success else 'FAILED'}")
    print(f"Javalin Port Edge-Case Tests: {'PASSED' if port_tests_success else 'FAILED'}")
    print(f"Kuna Tests: {'PASSED' if kuna_success else 'FAILED'}")
    print(f"x64dbg Tests: {'PASSED' if x64dbg_success else 'FAILED'}")
    print(f"Headless Tests: {'PASSED' if headless_success else 'FAILED'}")
    print(f"Evidence and Session Tests: {'PASSED' if evidence_success else 'FAILED'}")
    print(f"Target Triage Tests: {'PASSED' if triage_success else 'FAILED'}")
    print(f"REA Parity Tests: {'PASSED' if rea_parity_success else 'FAILED'}")
    print(f"Surface Parity Tests: {'PASSED' if surface_parity_success else 'FAILED'}")
    print(f"Capability Negotiation Tests: {'PASSED' if capabilities_success else 'FAILED'}")
    print(f"Script Execution Contract Tests: {'PASSED' if scripts_success else 'FAILED'}")
    print(f"Ghidra Compatibility Tests: {'PASSED' if compatibility_success else 'FAILED'}")
    print(f"Test Runner Contract Tests: {'PASSED' if runner_success else 'FAILED'}")
    print(f"Documentation Drift Guard Tests: {'PASSED' if docs_success else 'FAILED'}")
    print(f"Capability Triage Tests: {'PASSED' if capability_summary_success else 'FAILED'}")
    print(f"Background Task Tests: {'PASSED' if tasks_success else 'FAILED'}")
    print(f"Error Contract Tests: {'PASSED' if errors_success else 'FAILED'}")
    print(f"Context Pack Tests: {'PASSED' if context_pack_success else 'FAILED'}")
    print(f"Tool Group Tests: {'PASSED' if tool_groups_success else 'FAILED'}")
    print(f"Telemetry Tests: {'PASSED' if telemetry_success else 'FAILED'}")
    print(f"Overall: {'PASSED' if (http_api_success and mcp_bridge_success and data_tests_success and comment_tests_success and port_tests_success and kuna_success and x64dbg_success and headless_success and evidence_success and triage_success and rea_parity_success and surface_parity_success and capabilities_success and scripts_success and compatibility_success and runner_success and docs_success and capability_summary_success and tasks_success and errors_success and context_pack_success and tool_groups_success and telemetry_success) else 'FAILED'}")

    return (http_api_success and mcp_bridge_success and data_tests_success
            and comment_tests_success and port_tests_success and kuna_success
            and x64dbg_success and headless_success and evidence_success
            and triage_success and rea_parity_success and surface_parity_success
            and capabilities_success and scripts_success and compatibility_success
            and runner_success and docs_success and capability_summary_success
            and tasks_success and errors_success and context_pack_success and tool_groups_success and telemetry_success)

# Suites that need neither a live Ghidra nor any external binary. CI runs
# exactly these on every push: a green result here is real evidence, not a
# summary made of suites that skipped themselves.
def run_assertions_tests():
    """Run the Assertions (I16) tests."""
    print_header("Running Assertions (I16) Tests")

    try:
        result = subprocess.run(
            [sys.executable, "test_assertions.py"],
            capture_output=True,
            text=True
        )

        if result.stdout:
            print("STDOUT:")
            print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        return result.returncode == 0
    except Exception as e:
        print(f"Error running Assertions (I16) tests: {e}")
        return False


def run_read_only_tests():
    """Run the Read-only and audit (I12) tests."""
    print_header("Running Read-Only And Audit (I12) Tests")

    try:
        result = subprocess.run(
            [sys.executable, "test_read_only.py"],
            capture_output=True,
            text=True
        )

        if result.stdout:
            print("STDOUT:")
            print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        return result.returncode == 0
    except Exception as e:
        print(f"Error running Read-only and audit (I12) tests: {e}")
        return False


def run_runbook_tests():
    """Run the runbook and analysis_diff (R6) tests."""
    print_header("Running Runbook and Diff Tests")

    try:
        result = subprocess.run(
            [sys.executable, "test_runbook.py"],
            capture_output=True,
            text=True
        )

        if result.stdout:
            print("STDOUT:")
            print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        return result.returncode == 0
    except Exception as e:
        print(f"Error running runbook tests: {e}")
        return False


def run_taint_tests():
    """Run the source-to-sink hypothesis (R5) tests."""
    print_header("Running Taint Hypothesis Tests")

    try:
        result = subprocess.run(
            [sys.executable, "test_taint.py"],
            capture_output=True,
            text=True
        )

        if result.stdout:
            print("STDOUT:")
            print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        return result.returncode == 0
    except Exception as e:
        print(f"Error running taint tests: {e}")
        return False


def run_mission_tests():
    """Run the mission mode (R8) tests."""
    print_header("Running Mission Mode Tests")

    try:
        result = subprocess.run(
            [sys.executable, "test_mission.py"],
            capture_output=True,
            text=True
        )

        if result.stdout:
            print("STDOUT:")
            print(result.stdout)

        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        return result.returncode == 0
    except Exception as e:
        print(f"Error running mission tests: {e}")
        return False


NO_GHIDRA_SUITES = (
    "--kuna", "--x64dbg", "--surface",
    "--capabilities", "--scripts", "--compatibility", "--runner", "--docs",
    "--capability-summary", "--tasks", "--errors", "--context-pack", "--tool-groups", "--telemetry",
    "--assertions", "--read-only", "--runbook", "--taint", "--mission",
)

SUITES = {
    "--http": run_http_api_tests,
    "--mcp": run_mcp_bridge_tests,
    "--data": run_data_tests,
    "--comments": run_comment_tests,
    "--port": run_port_tests,
    "--kuna": run_kuna_tests,
    "--x64dbg": run_x64dbg_tests,
    "--headless": run_headless_tests,
    "--evidence": run_evidence_tests,
    "--triage": run_triage_tests,
    "--rea": run_rea_parity_tests,
    "--surface": run_surface_parity_tests,
    "--capabilities": run_capabilities_tests,
    "--scripts": run_scripts_tests,
    "--compatibility": run_compatibility_tests,
    "--runner": run_runner_tests,
    "--docs": run_docs_tests,
    "--capability-summary": run_capability_summary_tests,
    "--tasks": run_tasks_tests,
    "--errors": run_errors_tests,
    "--context-pack": run_context_pack_tests,
    "--tool-groups": run_tool_groups_tests,
    "--telemetry": run_telemetry_tests,
    "--assertions": run_assertions_tests,
    "--read-only": run_read_only_tests,
    "--runbook": run_runbook_tests,
    "--taint": run_taint_tests,
    "--mission": run_mission_tests,
}

USAGE = (
    "Usage: python run_tests.py [--no-ghidra | --http | --mcp | --data | "
    "--comments | --port | --kuna | --x64dbg | --headless | --evidence | "
    "--triage | --rea | --surface | --capabilities | --scripts | "
    "--compatibility | --runner | --docs | --capability-summary | --tasks | --errors |"
    " --context-pack | --assertions | --read-only | --runbook | --taint | --require-live]"
    "  (suite flags may be combined)"
)

if __name__ == "__main__":
    # Check if we have the required dependencies
    try:
        import requests
    except ImportError:
        print("Error: The 'requests' package is required to run the tests.")
        print("Please install it with 'pip install requests'")
        sys.exit(1)

    # Any number of suite flags may be combined. --require-live is a guard,
    # not a suite: it refuses to run when the suites would only skip.
    args = sys.argv[1:]
    require_live = "--require-live" in args
    flags = [arg for arg in args if arg != "--require-live"]

    if require_live and not require_live_ghidra():
        print("REQUIRE_LIVE: no Ghidra instance is serving the API; "
              "refusing to run suites that would only skip.")
        sys.exit(1)

    expanded = []
    for flag in flags:
        if flag == "--no-ghidra":
            expanded.extend(NO_GHIDRA_SUITES)
        else:
            expanded.append(flag)
    flags = list(dict.fromkeys(expanded))  # order preserved, duplicates dropped

    unknown = [flag for flag in flags if flag not in SUITES]
    if unknown:
        print(f"Unknown argument: {unknown[0]}")
        print(USAGE)
        sys.exit(1)

    if flags:
        results = [(flag, SUITES[flag]()) for flag in flags]
        print_header("Selected Suites Summary")
        for flag, ok in results:
            print(f"{flag}: {'PASSED' if ok else 'FAILED'}")
        success = all(ok for _, ok in results)
    else:
        # No flags: run everything (the historical behaviour).
        success = run_all_tests()

    # Exit with the appropriate status code
    sys.exit(0 if success else 1)
