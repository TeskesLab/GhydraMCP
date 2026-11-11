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

# The suites live in tests/, next to the runner's entry point.
TESTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tests")


def suite_script(name):
    """The command that runs one suite, wherever the repository is."""
    return [sys.executable, os.path.join(TESTS_DIR, name)]


def print_header(text):
    """Print a header with the given text.

    Flushed on purpose: a redirected log is where a stuck run is diagnosed, and
    buffered output leaves it empty until the process ends — which is exactly when
    the answer is no longer needed.
    """
    print("\n" + "=" * 80, flush=True)
    print(f" {text} ".center(80, "="), flush=True)
    print("=" * 80 + "\n", flush=True)

def run_http_api_tests():
    """Run the HTTP API tests"""
    print_header("Running HTTP API Tests")
    # The suite lives in tests/; it is imported rather than spawned because it
    # builds a unittest suite in this process.
    if TESTS_DIR not in sys.path:
        sys.path.insert(0, TESTS_DIR)
    
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
            suite_script("test_mcp_client.py"),
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
            suite_script("test_data_operations.py"),
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
            suite_script("test_javalin_port.py"),
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
            suite_script("test_comments.py"),
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
            suite_script("test_kuna.py"),
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
            suite_script("test_x64dbg.py"),
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
            suite_script("test_headless.py"),
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
            suite_script("test_evidence.py"),
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
            suite_script("test_triage.py"),
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
            suite_script("test_rea_parity.py"),
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
            suite_script("test_surface_parity.py"),
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
            suite_script("test_capabilities.py"),
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
            suite_script("test_compatibility.py"),
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
            suite_script("test_scripts.py"),
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
            suite_script("test_runner.py"),
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
            suite_script("test_docs.py"),
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
            suite_script("test_capabilities_summary.py"),
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
            suite_script("test_tasks.py"),
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
            suite_script("test_errors.py"),
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
            suite_script("test_context_pack.py"),
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
            suite_script("test_tool_groups.py"),
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
            suite_script("test_telemetry.py"),
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
            suite_script("test_assertions.py"),
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
            suite_script("test_read_only.py"),
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
            suite_script("test_runbook.py"),
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
            suite_script("test_taint.py"),
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
            suite_script("test_mission.py"),
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


def run_cache_tests():
    """Run the decompile cache (I11) tests."""
    print_header("Running Decompile Cache Tests")

    try:
        result = subprocess.run(
            suite_script("test_cache.py"),
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
        print(f"Error running cache tests: {e}")
        return False


def run_fleet_tests():
    """Run the fleet query (R7) tests."""
    print_header("Running Fleet Query Tests")

    try:
        result = subprocess.run(
            suite_script("test_fleet.py"),
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
        print(f"Error running fleet tests: {e}")
        return False


def run_core_tests():
    """Run the single-core / generated-code (I1) tests."""
    print_header("Running Single Core Tests")

    try:
        result = subprocess.run(
            suite_script("test_core.py"),
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
        print(f"Error running core tests: {e}")
        return False


def run_twin_tests():
    """Run the digital-twin tests (R2) — no Ghidra, no network."""
    print_header("Running Digital Twin Tests")

    try:
        result = subprocess.run(
            suite_script("test_twin.py"),
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
        print(f"Error running twin tests: {e}")
        return False


def run_examples_tests():
    """Run the examples suite — no Ghidra, no network, no binary."""
    print_header("Running Examples Tests")

    try:
        result = subprocess.run(
            suite_script("test_examples.py"),
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
        print(f"Error running examples tests: {e}")
        return False


def run_contract_tests():
    """Run the unification-contract suite — no Ghidra, no debugger, no network."""
    print_header("Running Contract Tests")

    try:
        result = subprocess.run(
            suite_script("test_contract.py"),
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
        print(f"Error running contract tests: {e}")
        return False


def run_mcp_config_tests():
    """Run the combined MCP configuration suite — Phase 2, no services needed."""
    print_header("Running MCP Configuration Tests")

    try:
        result = subprocess.run(
            suite_script("test_mcp_config.py"),
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
        print(f"Error running MCP configuration tests: {e}")
        return False


def run_target_tests():
    """Run the cross-tool target workflow suite — fakes, no services.

    Two files, because they answer two questions: `test_target.py` asks whether
    the workflow computes the right thing, and `test_target_cli.py` asks whether
    the commands reach the user. The second one exists because a mistake in the
    command's own failure handling was invisible while only the helper was
    tested.
    """
    print_header("Running Target Workflow Tests")

    passed = True
    for script in ("test_target.py", "test_target_cli.py"):
        try:
            result = subprocess.run(
                suite_script(script),
                capture_output=True,
                text=True
            )

            if result.stdout:
                print("STDOUT:")
                print(result.stdout)

            if result.stderr:
                print("STDERR:")
                print(result.stderr)

            passed = passed and result.returncode == 0
        except Exception as e:
            print(f"Error running target workflow tests: {e}")
            passed = False
    return passed


def run_formatter_interface_tests():
    """Run the formatter interface suite - the base and its two children."""
    print_header("Running Formatter Interface Tests")

    try:
        result = subprocess.run(
            suite_script("test_formatter_interface.py"),
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
        print(f"Error running formatter interface tests: {e}")
        return False


def run_formatter_tests():
    """Run the formatter suite - every formatter, with its own tool's answer."""
    print_header("Running Formatter Tests")

    try:
        result = subprocess.run(
            suite_script("test_formatters.py"),
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
        print(f"Error running formatter tests: {e}")
        return False


def run_bridge_tool_tests():
    """Run the bridge tool suite - every tool, called with nothing serving."""
    print_header("Running Bridge Tool Tests")

    try:
        result = subprocess.run(
            suite_script("test_bridge_tools.py"),
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
        print(f"Error running bridge tool tests: {e}")
        return False


def run_cli_failure_tests():
    """Run the command-failure suite — no command may let an exception out."""
    print_header("Running CLI Failure Tests")

    try:
        result = subprocess.run(
            suite_script("test_cli_failures.py"),
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
        print(f"Error running CLI failure tests: {e}")
        return False


def run_progress_tests():
    """Run the progress reporter suite — what a long step is doing."""
    print_header("Running Progress Tests")

    try:
        result = subprocess.run(
            suite_script("test_progress.py"),
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
        print(f"Error running progress tests: {e}")
        return False


def run_launcher_tests():
    """Run the launcher suite — the JDK, the installation and the command."""
    print_header("Running Launcher Tests")

    try:
        result = subprocess.run(
            suite_script("test_launcher.py"),
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
        print(f"Error running launcher tests: {e}")
        return False


def run_doctor_tests():
    """Run the doctor suite — the command that says what is wrong here."""
    print_header("Running Doctor Tests")

    try:
        result = subprocess.run(
            suite_script("test_doctor.py"),
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
        print(f"Error running doctor tests: {e}")
        return False


def run_gateway_contract_tests():
    """Run the gateway contract suite - the vocabulary against the gateway."""
    print_header("Running Gateway Contract Tests")

    try:
        result = subprocess.run(
            suite_script("test_gateway_contract.py"),
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
        print(f"Error running gateway contract tests: {e}")
        return False


def run_gateway_tests():
    """Run the MCP gateway suite — fakes, no services, no protocol frames."""
    print_header("Running Gateway Tests")

    try:
        result = subprocess.run(
            suite_script("test_gateway.py"),
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
        print(f"Error running gateway tests: {e}")
        return False


NO_GHIDRA_SUITES = (
    "--kuna", "--x64dbg", "--surface",
    "--capabilities", "--scripts", "--compatibility", "--runner", "--docs",
    "--capability-summary", "--tasks", "--errors", "--context-pack", "--tool-groups", "--telemetry",
    "--assertions", "--read-only", "--runbook", "--taint", "--mission", "--cache", "--fleet", "--core", "--twin", "--examples",
    "--contract",
    "--mcp-config",
    "--target",
    "--gateway",
    "--gateway-contract",
    "--doctor",
    "--launcher",
    "--progress",
    "--cli-failures",
    "--bridge-tools",
    "--formatters",
    "--formatter-interface",
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
    "--cache": run_cache_tests,
    "--fleet": run_fleet_tests,
    "--core": run_core_tests,
    "--twin": run_twin_tests,
    "--examples": run_examples_tests,
    "--contract": run_contract_tests,
    "--mcp-config": run_mcp_config_tests,
    "--target": run_target_tests,
    "--doctor": run_doctor_tests,
    "--launcher": run_launcher_tests,
    "--progress": run_progress_tests,
    "--cli-failures": run_cli_failure_tests,
    "--bridge-tools": run_bridge_tool_tests,
    "--formatters": run_formatter_tests,
    "--formatter-interface": run_formatter_interface_tests,
    "--gateway": run_gateway_tests,
    "--gateway-contract": run_gateway_contract_tests,
}

def build_usage() -> str:
    """The usage, built from the suites that exist.

    The line used to be written out by hand, and it fell behind: twelve suites
    worked and were not in it. A user who typed one of them, saw the line that
    does not mention it, and had no way to learn the right name. Building the
    line from the dict makes that impossible.
    """
    flags = sorted(SUITES)
    return (
        "Usage: python run_tests.py [--no-ghidra | "
        + " | ".join(flags)
        + " | --require-live]"
        "  (suite flags may be combined)"
    )


USAGE = build_usage()

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
