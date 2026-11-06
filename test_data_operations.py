#!/usr/bin/env python3
"""
Comprehensive test script for data operations in GhydraMCP.

This script tests all data-related operations including:
1. Creating data items with different types
2. Renaming data items
3. Updating data types
4. Deleting data items
5. Reading memory

Tests are performed using both direct HTTP API and MCP bridge interfaces.
"""
import json
import logging
import sys
import time
import requests
import anyio
from typing import Dict, Any
from urllib.parse import quote

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from ghydra.testing import free_data_addresses

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("data_test")

# Configure default test values
GHIDRA_PORT = 8192
DEFAULT_MEMORY_ADDRESS = "08000200"  # Fallback test address

def wait_for_program_loaded(port=GHIDRA_PORT, timeout=20):
    """Wait for a Ghidra program to be loaded."""
    for _ in range(timeout // 2):
        try:
            response = requests.get(f"http://localhost:{port}/program")
            if response.status_code == 200:
                data = json.loads(response.text)
                if data.get("success", False):
                    logger.info(f"Program loaded: {data['result']['name']}")
                    return True
        except Exception as e:
            logger.warning(f"Error checking program status: {e}")

        logger.info("Waiting for program to load...")
        time.sleep(2)

    logger.error("Timed out waiting for program to load")
    return False

def find_valid_addresses(port=GHIDRA_PORT) -> list:
    """Find addresses where a data item can be defined.

    The memory map alone is not enough: an address that already holds a
    data item, or that is inside a function, refuses to be defined again.
    So every candidate is asked about - the data items and the functions
    that cover it - before it is handed out.
    """
    base_url = f"http://localhost:{port}"
    free = free_data_addresses(base_url)
    if free:
        return free

    logger.error("No free address found for the data tests")
    return []

def test_http_data_create():
    """Test creating data items with different types using HTTP API."""
    if not wait_for_program_loaded():
        return False

    addresses = find_valid_addresses()
    if not addresses:
        logger.error("No valid addresses found for data creation test")
        return False

    types_to_try = ["uint", "int", "uint *", "int *", "byte", "word", "dword", "pointer"]
    success_count = 0

    for i, data_type in enumerate(types_to_try):
        address = addresses[i % len(addresses)]
        logger.info(f"Testing data type: {data_type} at address {address}")

        url = f"http://localhost:{GHIDRA_PORT}/data/{address}"
        payload = {
            "type": data_type,
            "newName": f"TEST_{data_type.upper()}"
        }

        # Add size for string types
        if data_type.lower() == "string":
            payload["size"] = 16

        try:
            response = requests.post(url, json=payload)
            logger.info(f"Status: {response.status_code}")
            logger.info(f"Response: {response.text}")
            if response.status_code in (200, 201) and json.loads(response.text).get("success", False):
                success_count += 1
                logger.info(f"Success with data type {data_type}")
        except Exception as e:
            logger.error(f"Error: {e}")

        time.sleep(0.5)

    return success_count > 0

def test_http_data_rename():
    """Test data rename operations using HTTP API."""
    addresses = find_valid_addresses()
    if not addresses:
        return False

    test_address = addresses[0]
    test_name = f"TEST_RENAME_{int(time.time())}"

    # First create a data item to rename
    create_url = f"http://localhost:{GHIDRA_PORT}/data/{test_address}"
    create_payload = {
        "type": "int",
        "newName": "TEST_BEFORE_RENAME"
    }

    try:
        create_response = requests.post(create_url, json=create_payload)
        if create_response.status_code not in (200, 201):
            logger.warning("Failed to create test data for rename test")
            return False

        # Rename the data
        rename_url = f"http://localhost:{GHIDRA_PORT}/data/{test_address}"
        rename_payload = {
            "newName": test_name
        }

        rename_response = requests.patch(rename_url, json=rename_payload)
        logger.info(f"Rename response: {rename_response.status_code}")
        logger.info(f"Rename response: {rename_response.text}")

        return rename_response.status_code in (200, 201) and json.loads(rename_response.text).get("success", False)
    except Exception as e:
        logger.error(f"Error in rename test: {e}")
        return False

def test_http_data_type_change():
    """Test changing data type using HTTP API."""
    addresses = find_valid_addresses()
    if not addresses:
        return False

    test_address = addresses[1]

    # First create a data item
    create_url = f"http://localhost:{GHIDRA_PORT}/data/{test_address}"
    create_payload = {
        "type": "uint",
        "newName": "TEST_TYPE_CHANGE"
    }

    try:
        create_response = requests.post(create_url, json=create_payload)
        if create_response.status_code not in (200, 201):
            logger.warning("Failed to create test data for type change test")
            return False

        # Change the type
        type_url = f"http://localhost:{GHIDRA_PORT}/data/{test_address}/type"
        type_payload = {
            "type": "byte"
        }

        type_response = requests.patch(type_url, json=type_payload)
        logger.info(f"Type change response: {type_response.status_code}")
        logger.info(f"Type change response: {type_response.text}")

        return type_response.status_code in (200, 201) and json.loads(type_response.text).get("success", False)
    except Exception as e:
        logger.error(f"Error in type change test: {e}")
        return False

def test_http_data_delete():
    """Test deleting data using HTTP API."""
    addresses = find_valid_addresses()
    if not addresses:
        return False

    test_address = addresses[2]

    # First create a data item to delete
    create_url = f"http://localhost:{GHIDRA_PORT}/data/{test_address}"
    create_payload = {
        "type": "int",
        "newName": "TEST_DELETE_ME"
    }

    try:
        create_response = requests.post(create_url, json=create_payload)
        if create_response.status_code not in (200, 201):
            logger.warning("Failed to create test data for delete test")
            return False

        # Delete the data
        delete_url = f"http://localhost:{GHIDRA_PORT}/data/{test_address}"

        delete_response = requests.delete(delete_url)
        logger.info(f"Delete response: {delete_response.status_code}")
        logger.info(f"Delete response: {delete_response.text}")

        return delete_response.status_code in (200, 201) and json.loads(delete_response.text).get("success", False)
    except Exception as e:
        logger.error(f"Error in delete test: {e}")
        return False

def test_http_combined_operations():
    """Test data operations that update both name and type together."""
    addresses = find_valid_addresses()
    if not addresses:
        return False

    test_address = addresses[3]

    # First create a data item
    create_url = f"http://localhost:{GHIDRA_PORT}/data/{test_address}"
    create_payload = {
        "type": "int",
        "newName": "TEST_COMBINED_ORIG"
    }

    try:
        create_response = requests.post(create_url, json=create_payload)
        if create_response.status_code not in (200, 201):
            logger.warning("Failed to create test data for combined update test")
            return False

        # Update both name and type in one operation
        update_url = f"http://localhost:{GHIDRA_PORT}/data/{test_address}"
        update_payload = {
            "newName": "TEST_COMBINED_NEW",
            "type": "uint"
        }

        update_response = requests.patch(update_url, json=update_payload)
        logger.info(f"Combined update response: {update_response.status_code}")
        logger.info(f"Combined update response: {update_response.text}")

        return update_response.status_code in (200, 201) and json.loads(update_response.text).get("success", False)
    except Exception as e:
        logger.error(f"Error in combined update test: {e}")
        return False

async def test_mcp_data_operations():
    """Test data operations using the MCP bridge."""
    server_parameters = StdioServerParameters(
        command=sys.executable,
        args=["bridge_mcp_hydra.py"],
    )

    logger.info("Connecting to MCP bridge...")
    async with stdio_client(server_parameters) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            logger.info("Initializing session...")
            await session.initialize()

            # First set the current instance
            logger.info("Setting current Ghidra instance...")
            await session.call_tool(
                "instances_use",
                arguments={"port": 8192}
            )

            # Get a valid address to work with
            addresses = find_valid_addresses()
            test_address = addresses[4] if addresses and len(addresses) > 4 else DEFAULT_MEMORY_ADDRESS

            logger.info(f"Using address {test_address} for MCP data operations test")

            # Test data_create
            try:
                logger.info("Testing data_create...")
                create_result = await session.call_tool(
                    "data_create",
                    arguments={"address": test_address, "data_type": "uint"}
                )
                create_data = create_result.content[0].text
                assert not create_data.startswith("Error"), \
                    f"data_create failed: {create_data}"
                logger.info("data_create passed")

                # Test data_rename
                logger.info("Testing data_rename...")
                test_name = f"MCP_TEST_{int(time.time())}"
                rename_result = await session.call_tool(
                    "data_rename",
                    arguments={"address": test_address, "name": test_name}
                )
                rename_data = rename_result.content[0].text
                assert not rename_data.startswith("Error"), \
                    f"data_rename failed: {rename_data}"
                logger.info("data_rename passed")

                # Test data_set_type
                logger.info("Testing data_set_type...")
                set_type_result = await session.call_tool(
                    "data_set_type",
                    arguments={"address": test_address, "data_type": "byte"}
                )
                set_type_data = set_type_result.content[0].text
                assert not set_type_data.startswith("Error"), \
                    f"data_set_type failed: {set_type_data}"
                logger.info("data_set_type passed")

                # Test memory_read on the data
                logger.info("Testing memory_read...")
                read_result = await session.call_tool(
                    "memory_read",
                    arguments={"address": test_address, "length": 4}
                )
                read_data = read_result.content[0].text
                assert not read_data.startswith("Error"), \
                    f"memory_read failed: {read_data}"
                assert "Memory at" in read_data, \
                    f"memory_read response is not a hex dump: {read_data}"
                logger.info("memory_read passed")

                # Test data_delete
                logger.info("Testing data_delete...")
                delete_result = await session.call_tool(
                    "data_delete",
                    arguments={"address": test_address}
                )
                delete_data = delete_result.content[0].text
                assert not delete_data.startswith("Error"), \
                    f"data_delete failed: {delete_data}"
                logger.info("data_delete passed")

                logger.info("All MCP data operations passed")
                return True

            except Exception as e:
                logger.error(f"Error in MCP data operations test: {e}")
                # Try to clean up
                try:
                    await session.call_tool("data_delete", arguments={"address": test_address})
                except:
                    pass
                return False

def main():
    """Main entry point for data operations tests."""
    all_passed = True

    try:
        # Run HTTP API tests
        logger.info("===== Testing HTTP API Data Operations =====")

        logger.info("----- Testing data creation -----")
        create_result = test_http_data_create()
        logger.info(f"Data creation test: {'PASSED' if create_result else 'FAILED'}")
        all_passed = all_passed and create_result

        logger.info("----- Testing data rename -----")
        rename_result = test_http_data_rename()
        logger.info(f"Data rename test: {'PASSED' if rename_result else 'FAILED'}")
        all_passed = all_passed and rename_result

        logger.info("----- Testing data type change -----")
        type_result = test_http_data_type_change()
        logger.info(f"Data type change test: {'PASSED' if type_result else 'FAILED'}")
        all_passed = all_passed and type_result

        logger.info("----- Testing data delete -----")
        delete_result = test_http_data_delete()
        logger.info(f"Data delete test: {'PASSED' if delete_result else 'FAILED'}")
        all_passed = all_passed and delete_result

        logger.info("----- Testing combined operations -----")
        combined_result = test_http_combined_operations()
        logger.info(f"Combined operations test: {'PASSED' if combined_result else 'FAILED'}")
        all_passed = all_passed and combined_result

        # Run MCP bridge tests
        logger.info("===== Testing MCP Bridge Data Operations =====")
        mcp_result = anyio.run(test_mcp_data_operations)
        logger.info(f"MCP data operations test: {'PASSED' if mcp_result else 'FAILED'}")
        all_passed = all_passed and mcp_result

        logger.info(f"Overall data operations test: {'PASSED' if all_passed else 'FAILED'}")
        if not all_passed:
            sys.exit(1)

    except Exception as e:
        logger.error(f"Unexpected error in data tests: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
