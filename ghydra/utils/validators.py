"""Input validation utilities."""

import re


def truthy(value) -> bool:
    """Interpret a boolean-ish value from an environment variable or config.

    Accepts real booleans, numbers and the usual truthy strings. Anything
    else is false, so a typo never silently enables a feature.

    Args:
        value: The value to interpret

    Returns:
        True when the value means "on"
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on", "enabled")
    return False


def validate_address(addr: str) -> str:
    """Validate and normalize hex address.

    Accepts formats: 0x401000, 401000, 401000h

    Args:
        addr: Address string to validate

    Returns:
        Normalized address string (bare hex, no prefix/suffix)

    Raises:
        ValueError: If address format is invalid
    """
    if not addr:
        raise ValueError("Address cannot be empty")

    normalized = addr.strip().lower()
    if normalized.startswith("0x"):
        normalized = normalized[2:]
    elif normalized.endswith("h"):
        normalized = normalized[:-1]

    if not re.match(r'^[0-9a-f]+$', normalized):
        raise ValueError(f"Invalid hex address format: {addr}")

    return normalized


def normalize_hex_address(addr: str) -> str:
    """Normalize hex address to standard format (with 0x prefix).

    Args:
        addr: Address string

    Returns:
        Normalized address with 0x prefix
    """
    validated = validate_address(addr)
    return f"0x{validated}"


def validate_port(port: int) -> int:
    """Validate port number.

    Args:
        port: Port number to validate

    Returns:
        Validated port number

    Raises:
        ValueError: If port is out of valid range
    """
    if not isinstance(port, int):
        raise ValueError(f"Port must be an integer, got {type(port)}")

    if port < 1 or port > 65535:
        raise ValueError(f"Port must be between 1 and 65535, got {port}")

    return port


def validate_hex_bytes(data: str) -> str:
    """Validate hex byte string.

    Args:
        data: Hex byte string to validate

    Returns:
        Validated hex string

    Raises:
        ValueError: If hex format is invalid
    """
    if not data:
        raise ValueError("Hex data cannot be empty")

    # Remove spaces and 0x prefixes
    normalized = data.replace(" ", "").replace("0x", "").lower()

    # Validate hex format
    if not re.match(r'^[0-9a-f]+$', normalized):
        raise ValueError(f"Invalid hex data format: {data}")

    # Ensure even number of characters (full bytes)
    if len(normalized) % 2 != 0:
        raise ValueError(f"Hex data must have even number of characters: {data}")

    return normalized
