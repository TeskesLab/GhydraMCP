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
    print(f"Overall: {'PASSED' if (http_api_success and mcp_bridge_success and data_tests_success and comment_tests_success and port_tests_success and kuna_success and x64dbg_success and headless_success and evidence_success and triage_success and rea_parity_success and surface_parity_success and capabilities_success and scripts_success and compatibility_success) else 'FAILED'}")

    return (http_api_success and mcp_bridge_success and data_tests_success
            and comment_tests_success and port_tests_success and kuna_success
            and x64dbg_success and headless_success and evidence_success
            and triage_success and rea_parity_success and surface_parity_success
            and capabilities_success and scripts_success and compatibility_success)

if __name__ == "__main__":
    # Check if we have the required dependencies
    try:
        import requests
    except ImportError:
        print("Error: The 'requests' package is required to run the tests.")
        print("Please install it with 'pip install requests'")
        sys.exit(1)
    
    # Parse command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "--http":
            # Run only the HTTP API tests
            success = run_http_api_tests()
        elif sys.argv[1] == "--mcp":
            # Run only the MCP bridge tests
            success = run_mcp_bridge_tests()
        elif sys.argv[1] == "--data":
            # Run only the data operations tests
            success = run_data_tests()
        elif sys.argv[1] == "--comments":
            # Run only the comment tests
            success = run_comment_tests()
        elif sys.argv[1] == "--port":
            # Run only the Javalin port edge-case tests
            success = run_port_tests()
        elif sys.argv[1] == "--kuna":
            # Run only the Kuna integration tests
            success = run_kuna_tests()
        elif sys.argv[1] == "--x64dbg":
            # Run only the x64dbg integration tests
            success = run_x64dbg_tests()
        elif sys.argv[1] == "--headless":
            # Run only the headless runner, report and annotation tests
            success = run_headless_tests()
        elif sys.argv[1] == "--evidence":
            # Run only the evidence ledger and session tests
            success = run_evidence_tests()
        elif sys.argv[1] == "--triage":
            # Run only the target triage tests
            success = run_triage_tests()
        elif sys.argv[1] == "--rea":
            # Run only the REA parity tests
            success = run_rea_parity_tests()
        elif sys.argv[1] == "--surface":
            # Run only the global tool/formatter contract tests
            success = run_surface_parity_tests()
        elif sys.argv[1] == "--capabilities":
            # Run only the capability negotiation contract tests
            success = run_capabilities_tests()
        elif sys.argv[1] == "--scripts":
            # Run only the ad-hoc script execution contract tests
            success = run_scripts_tests()
        elif sys.argv[1] == "--compatibility":
            # Run only the 11.x/12.2 compatibility contract tests
            success = run_compatibility_tests()
        elif sys.argv[1] == "--require-live":
            # Run all suites, but refuse a run with no live Ghidra behind them
            if not require_live_ghidra():
                print("REQUIRE_LIVE: no Ghidra instance is serving the API; "
                      "refusing to run suites that would only skip.")
                sys.exit(1)
            success = run_all_tests()
        else:
            print(f"Unknown argument: {sys.argv[1]}")
            print("Usage: python run_tests.py [--http|--mcp|--data|--comments|--port|--kuna|--x64dbg|--headless|--evidence|--triage|--rea|--surface|--capabilities|--scripts|--compatibility|--require-live]")
            sys.exit(1)
    else:
        # Run all tests
        success = run_all_tests()
    
    # Exit with the appropriate status code
    sys.exit(0 if success else 1)
