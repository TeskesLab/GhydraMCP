"""What the test suites need to know about the instance they talk to.

A headless instance has no window, and therefore no cursor: the endpoints
that read the cursor answer 503, because there is no window to read it
from. The suites that exercise those endpoints have to know which kind of
instance they are talking to - otherwise they report a failure for a
limitation of the instance and not a defect of the code.

The same goes for the addresses of the data tests: an address that
already holds a data item refuses to be defined again, so the addresses
are asked about before they are used.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


def instance_snapshot(base_url: str, timeout: float = 5.0) -> Dict[str, Any]:
    """What the instance says about itself, as far as it says anything."""
    try:
        import requests
    except ImportError:
        return {}
    try:
        response = requests.get(f"{base_url.rstrip('/')}/program", timeout=timeout)
    except Exception:
        return {}
    if response.status_code != 200:
        return {}
    try:
        payload = response.json()
    except ValueError:
        return {}
    result = payload.get("result") if isinstance(payload, dict) else None
    return result if isinstance(result, dict) else {}


def instance_is_headless(base_url: str, timeout: float = 5.0) -> bool:
    """Whether the instance behind the URL runs without a window.

    An instance that does not say is assumed to have a window: the older
    versions of the plugin do not report the flag, and skipping a test
    because the instance is silent would be skipping it for no reason.
    """
    return bool(instance_snapshot(base_url, timeout).get("headless", False))


def skip_reason_headless(test: Any) -> Optional[str]:
    """The reason a cursor test cannot run, or None when it can."""
    return ("the cursor endpoints need a window; this instance is headless")


def free_data_addresses(base_url: str, count: int = 12,
                        timeout: float = 5.0) -> list:
    """Addresses where a data item can be defined.

    The memory map alone is not enough: an address that already holds a data
    item refuses to be defined again. The API answers 200 with
    "isDefined": false for an address that holds nothing, so that is the
    signal - not the status code, which is 200 either way.

    Only the blocks that can be written to are searched, and only their tail:
    that is where a variable fits without landing in the middle of a
    function. The size of a block is a number and its start is a hex string,
    so the size is read as a number - reading it as hexadecimal puts the
    address far outside the block.
    """
    try:
        import requests
    except ImportError:
        return []

    base = base_url.rstrip("/")
    try:
        response = requests.get(f"{base}/memory", timeout=timeout)
        blocks = response.json().get("result") or []
    except Exception:
        return []

    candidates = []
    for block in blocks:
        if not isinstance(block, dict) or not block.get("isWrite"):
            continue
        try:
            start = int(str(block.get("start")), 16)
        except (TypeError, ValueError):
            continue
        size = int(block.get("size") or 0)
        if size <= 0:
            continue
        for offset in range(size - 16, max(size - 0x400, 0), -4):
            candidates.append(start + offset)

    free = []
    for address in candidates:
        try:
            probe = requests.get(f"{base}/data/{address:08x}", timeout=timeout)
        except Exception:
            continue
        if probe.status_code == 404:
            free.append(f"{address:08x}")
            continue
        if probe.status_code != 200:
            continue
        try:
            payload = probe.json()
        except ValueError:
            continue
        result = payload.get("result") if isinstance(payload, dict) else None
        if isinstance(result, dict) and not result.get("isDefined", False):
            free.append(f"{address:08x}")
        if len(free) >= count:
            break

    return free
