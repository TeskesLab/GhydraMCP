"""The x64dbg MCP server, driven from the bridge and the CLI.

The x64dbg plugin *is* an MCP server: it lives inside the debugger and answers
JSON-RPC 2.0 requests POSTed to "/" with a bearer token. Every request stands
alone - there is no session and no handshake to keep alive - which makes it
easy to drive from here.

The plugin binds 127.0.0.1:9094 for a 64-bit debuggee and :9095 for a 32-bit
one, and it writes its settings - the bind address, the port and the bearer
token - to "mcp_config.json" next to its own DLL.

The two sides of the reverse engineering work disagree about addresses, and
that disagreement is the whole reason this module exists:

* Ghidra works on the image **as it sits in the file**, at the image base.
* x64dbg works on the **live process**, where the module was loaded wherever
  the loader put it.

The difference is a constant, and knowing it is what lets a breakpoint be set
on the function that static analysis just found.
"""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

import requests

# The plugin's defaults: 9094 for a 64-bit debuggee, 9095 for a 32-bit one.
DEFAULT_PORT = 9094
X32_PORT = 9095

# How many ports to try when looking for an instance. The plugin walks up to
# 32 ports when the configured one is taken, so the scan has to reach as far
# as the plugin can go.
PORT_SCAN = 32

# How many times a connection error is retried. The plugin hangs up after
# every response, and a local TCP connection is reset every now and then on
# Windows - measured at 7% of the connections on this machine, with curl and
# with plain sockets alike, so it is the network stack and not this client.
# One more attempt is enough to tell a reset apart from a server that is
# really not there.
CONNECT_ATTEMPTS = 3

# How long a connection may take to come up, and how long the server may
# take to answer. The two are separate because they mean different things: a
# closed local port does not refuse straight away on Windows - the SYN hangs
# and is only refused about two seconds later - so a probe must not wait for
# that, while a tool that blocks (WaitForEvent, run) must be allowed to take
# its time.
CONNECT_TIMEOUT = 2.0
READ_TIMEOUT = 30.0
PROBE_CONNECT_TIMEOUT = 0.35
PROBE_READ_TIMEOUT = 2.0

ENV_HOST = "GHYDRA_X64DBG_HOST"
ENV_PORT = "GHYDRA_X64DBG_PORT"
ENV_TOKEN = "GHYDRA_X64DBG_TOKEN"

CONFIG_SECTION = "x64dbg"

# The plugin's own settings file, next to its DLL.
PLUGIN_CONFIG_NAME = "mcp_config.json"

PROTOCOL_VERSION = "2024-11-05"

# The machine-readable reasons a call can fail. The bridge carries the same
# list, so an agent sees one taxonomy whichever side it drives.
ERROR_CODES = (
    "X64DBG_ERROR",         # the generic fallback
    "X64DBG_DISABLED",      # no token, so no way to talk to the server
    "X64DBG_MISSING",       # nothing answered on the port
    "X64DBG_TIMEOUT",       # the server did not answer in time
    "X64DBG_UNAUTHORIZED",  # the bearer token did not match
    "X64DBG_NO_SESSION",    # no debug session in x64dbg
    "X64DBG_NO_TOOL",       # the plugin has no tool with that name
    "X64DBG_BAD_ARGS",      # the tool rejected the arguments
    "X64DBG_NO_MATCH",      # the binary does not match any loaded module
)


class X64dbgError(Exception):
    """A failure from the x64dbg side, with a machine-readable code."""

    def __init__(self, message: str, code: str = "X64DBG_ERROR") -> None:
        super().__init__(message)
        self.code = code


def read_plugin_config(install: str) -> Dict[str, Any]:
    """The plugin's own settings, from the mcp_config.json next to its DLL.

    The file sits in the x64dbg root or in one of its plugin folders; which
    one depends on how x64dbg was unpacked.
    """
    root = os.path.abspath(os.path.expanduser(str(install or "")))
    candidates = [
        os.path.join(root, PLUGIN_CONFIG_NAME),
        os.path.join(root, "x64", "plugins", PLUGIN_CONFIG_NAME),
        os.path.join(root, "x32", "plugins", PLUGIN_CONFIG_NAME),
        os.path.join(root, "release", "x64", "plugins", PLUGIN_CONFIG_NAME),
        os.path.join(root, "release", "x32", "plugins", PLUGIN_CONFIG_NAME),
        os.path.join(root, "plugins", PLUGIN_CONFIG_NAME),
    ]
    for candidate in candidates:
        try:
            with open(candidate, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            return data
    return {}


def resolve_config(section: Optional[dict] = None) -> Dict[str, Any]:
    """Where the x64dbg MCP server is, and the token to talk to it.

    The configuration file wins over the environment, like everywhere else in
    this project. The token is the one thing that cannot be guessed: the
    plugin writes it to "mcp_config.json" next to its DLL, so pointing at an
    installed x64dbg with "path" is enough for the token to be found.
    """
    settings = dict(section or {})
    host = settings.get("host") or os.environ.get(ENV_HOST) or "127.0.0.1"
    port = settings.get("port") or os.environ.get(ENV_PORT) or DEFAULT_PORT
    token = settings.get("token") or os.environ.get(ENV_TOKEN) or ""
    install = settings.get("path") or ""

    plugin = read_plugin_config(install) if install else {}
    if not token:
        token = plugin.get("AuthToken") or ""
    if not settings.get("host") and plugin.get("IpAddress"):
        host = plugin["IpAddress"]
    if not settings.get("port") and plugin.get("Port"):
        port = plugin["Port"]

    try:
        port = int(port)
    except (TypeError, ValueError):
        port = DEFAULT_PORT

    return {
        "host": str(host),
        "port": port,
        "token": str(token),
        "path": str(install),
    }


def _classify(message: str) -> str:
    """The code that matches an error message from the plugin.

    The plugin answers with prose - "Error: No active debug session." - so
    the reason has to be read out of it.
    """
    text = str(message or "").lower()
    if "no active debug session" in text or "tool requires an active" in text:
        return "X64DBG_NO_SESSION"
    if "no such tool" in text or "unknown tool" in text or "not found" in text:
        return "X64DBG_NO_TOOL"
    if "required" in text or "invalid" in text or "missing" in text:
        return "X64DBG_BAD_ARGS"
    return "X64DBG_ERROR"


class Client:
    """A client for the x64dbg MCP server."""

    def __init__(self, host: str = "127.0.0.1", port: int = DEFAULT_PORT,
                 token: str = "", timeout: float = READ_TIMEOUT) -> None:
        self.host = str(host)
        self.port = int(port)
        self.token = str(token or "")
        self.timeout = float(timeout)
        self.base_url = f"http://{self.host}:{self.port}/"
        self._request_id = 0
        self._read_only: Dict[str, bool] = {}

    def _post(self, method: str, params: Optional[dict] = None,
              timeout: Optional[float] = None, connect_timeout: Optional[float] = None,
              idempotent: bool = False) -> Any:
        """One JSON-RPC request, and the result it carries.

        `idempotent` says the request may be sent again when the transport
        fails: a handshake, the catalogue, or a tool the plugin marks as
        read-only. A tool that changes the debuggee is never repeated, because
        the first attempt may already have reached it.
        """
        self._request_id += 1
        payload: Dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
        }
        if params is not None:
            payload["params"] = params

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        read_limit = timeout if timeout is not None else self.timeout
        connect_limit = connect_timeout if connect_timeout is not None else CONNECT_TIMEOUT
        last_error: Optional[Exception] = None
        connection_attempts = CONNECT_ATTEMPTS
        timeout_attempts = 2 if idempotent else 1

        while True:
            try:
                response = requests.post(
                    self.base_url, json=payload, headers=headers,
                    timeout=(connect_limit, read_limit),
                )
                break
            except requests.ConnectTimeout as exc:
                # The connection never came up: a closed port, or a SYN the
                # network stack dropped.
                last_error = exc
                connection_attempts -= 1
                if connection_attempts > 0:
                    continue
                raise X64dbgError(
                    f"could not reach the x64dbg MCP server at {self.base_url}: {exc}",
                    code="X64DBG_MISSING",
                ) from None
            except requests.ReadTimeout as exc:
                # The server did not answer in time. Only a request that is
                # safe to repeat may be tried again.
                last_error = exc
                timeout_attempts -= 1
                if timeout_attempts > 0:
                    continue
                raise X64dbgError(
                    f"the x64dbg MCP server did not answer within {read_limit}s",
                    code="X64DBG_TIMEOUT",
                ) from None
            except requests.ConnectionError as exc:
                # The connection died on the way: the plugin hangs up after
                # every response, and the local network stack resets a
                # connection every now and then.
                last_error = exc
                connection_attempts -= 1
                if connection_attempts > 0:
                    continue
                raise X64dbgError(
                    f"could not reach the x64dbg MCP server at {self.base_url}: {exc}",
                    code="X64DBG_MISSING",
                ) from None
            except requests.RequestException as exc:
                raise X64dbgError(
                    f"could not reach the x64dbg MCP server at {self.base_url}: {exc}",
                    code="X64DBG_MISSING",
                ) from None

        if response.status_code == 401:
            raise X64dbgError(
                "the x64dbg MCP server rejected the bearer token",
                code="X64DBG_UNAUTHORIZED",
            )
        if response.status_code >= 400:
            raise X64dbgError(
                f"the x64dbg MCP server answered {response.status_code}",
                code="X64DBG_ERROR",
            )

        body = (response.text or "").strip()
        if not body:
            raise X64dbgError("the x64dbg MCP server answered with an empty body",
                              code="X64DBG_ERROR")
        try:
            data = json.loads(body)
        except ValueError:
            raise X64dbgError(
                f"the x64dbg MCP server did not answer JSON: {body[:200]}",
                code="X64DBG_ERROR",
            ) from None

        if isinstance(data, dict) and data.get("error"):
            error = data["error"]
            message = error.get("message", "") if isinstance(error, dict) else str(error)
            raise X64dbgError(message or "the call failed", code=_classify(message))
        if isinstance(data, dict):
            return data.get("result")
        return data

    def initialize(self, timeout: Optional[float] = None,
                   connect_timeout: Optional[float] = None) -> Dict[str, Any]:
        """The handshake. The server keeps no state, so this is a courtesy."""
        result = self._post("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "ghydramcp", "version": "3.0.0"},
        }, timeout=timeout, connect_timeout=connect_timeout, idempotent=True)
        return result if isinstance(result, dict) else {}

    def list_tools(self) -> List[Dict[str, Any]]:
        """The plugin's tool catalogue, with the schema of each."""
        result = self._post("tools/list", idempotent=True)
        tools = result.get("tools") if isinstance(result, dict) else None
        return tools if tools is not None and isinstance(tools, list) else []

    def is_read_only(self, name: str) -> bool:
        """Whether the plugin marks a tool as read-only.

        The catalogue carries the hint, and it is fetched once and kept: the
        tool set does not change while the debugger runs.
        """
        if name not in self._read_only:
            try:
                for tool in self.list_tools():
                    annotations = tool.get("annotations") or {}
                    self._read_only[str(tool.get("name"))] = bool(
                        annotations.get("readOnlyHint"))
            except X64dbgError:
                return False
        return self._read_only.get(name, False)

    def call_tool(self, name: str, arguments: Optional[dict] = None) -> str:
        """Call one plugin tool and return its text.

        Every response carries a "[state]" line and whatever debugger events
        fired since the last call, so the text is returned whole.

        A read-only tool may be called again when the transport fails; a tool
        that changes the debuggee may not, because the first attempt may
        already have reached it.
        """
        result = self._post(
            "tools/call", {"name": name, "arguments": arguments or {}},
            idempotent=self.is_read_only(name),
        )
        if isinstance(result, dict):
            content = result.get("content")
            if isinstance(content, list):
                parts = [
                    str(item.get("text", ""))
                    for item in content
                    if isinstance(item, dict) and item.get("type") == "text"
                ]
                if parts:
                    return "\n".join(parts)
            if result.get("isError"):
                raise X64dbgError("the tool reported an error", code="X64DBG_ERROR")
            if "text" in result:
                return str(result["text"])
        return ""


def discover(section: Optional[dict] = None, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
    """Find an x64dbg MCP server.

    The plugin binds 9094 for a 64-bit debuggee and 9095 for a 32-bit one,
    and the ports around them are tried too. A server that answers 401 is
    still a server: it means the token is wrong, which is worth saying.

    The ports are probed concurrently and the probe timeout is short. A closed
    local port does not refuse straight away on Windows - the SYN hangs and is
    only refused about two seconds later - so probing the ports one at a time
    with a long timeout would cost a couple of seconds per port. A live
    instance answers in milliseconds, so a third of a second is plenty to tell
    it from a closed port.
    """
    settings = resolve_config(section)
    connect_limit = PROBE_CONNECT_TIMEOUT if timeout is None else timeout
    read_limit = PROBE_READ_TIMEOUT if timeout is None else timeout

    likely = list(dict.fromkeys([settings["port"], DEFAULT_PORT, X32_PORT]))
    others = [
        candidate + offset
        for offset in range(1, PORT_SCAN)
        for candidate in (DEFAULT_PORT, X32_PORT)
        if (candidate + offset) not in likely
    ]

    def _probe(port: int) -> Optional[str]:
        """The port that answered, or None."""
        client = Client(settings["host"], port, settings["token"], timeout=read_limit)
        try:
            client.initialize(timeout=read_limit, connect_timeout=connect_limit)
        except X64dbgError as exc:
            return "unauthorized" if exc.code == "X64DBG_UNAUTHORIZED" else None
        return str(port)

    unauthorized: Optional[Dict[str, Any]] = None
    for group in (likely, others):
        if not group:
            continue
        with ThreadPoolExecutor(max_workers=min(16, len(group))) as pool:
            answers = list(pool.map(_probe, group))
        for port, answer in zip(group, answers):
            if answer and answer != "unauthorized":
                return {
                    "host": settings["host"], "port": port,
                    "token": settings["token"], "path": settings["path"],
                    "unauthorized": False,
                }
        if any(answer == "unauthorized" for answer in answers):
            unauthorized = {
                "host": settings["host"], "port": likely[0],
                "token": settings["token"], "path": settings["path"],
                "unauthorized": True,
            }
            break
    return unauthorized


def parse_int(value: Any) -> Optional[int]:
    """An address, however it was written: "0x140001000", "140001000" or 0."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value or "").strip()
    if not text:
        return None
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        if all(char in "0123456789abcdefABCDEF" for char in text):
            return int(text, 16)
        return int(text, 10)
    except ValueError:
        return None


def normalize_path(path: str) -> str:
    """A path that the two sides can be compared on.

    The x64dbg side reports the module path with the Win32 extended-length
    prefix and in its own case; Ghidra reports the executable path as the
    file system gave it.
    """
    text = str(path or "").strip().strip('"')
    if text.startswith("\\\\?\\"):
        text = text[4:]
    if not text:
        return ""
    try:
        return os.path.normcase(os.path.abspath(text))
    except (OSError, ValueError):
        return os.path.normcase(text)


def parse_modules(text: str) -> List[Dict[str, Any]]:
    """The modules out of the ListModules text.

    The tool answers one module per line, "0xBASE | 0xSIZE | PATH".
    """
    modules: List[Dict[str, Any]] = []
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = [part.strip() for part in line.split("|")]
        if len(parts) < 3:
            continue
        try:
            base = int(parts[0], 16)
            size = int(parts[1], 16)
        except ValueError:
            continue
        path = "|".join(parts[2:]).strip()
        modules.append({"base": base, "size": size, "path": path})
    return modules


def find_module(modules: List[Dict[str, Any]], binary_path: str) -> Optional[Dict[str, Any]]:
    """The module that is the given binary.

    The paths are compared first as full paths and then by file name: the two
    sides can disagree about the directory - a copy, a symlink, a different
    drive letter - but not about the file.
    """
    wanted = normalize_path(binary_path)
    if not wanted:
        return None
    for module in modules:
        if normalize_path(module.get("path", "")) == wanted:
            return module
    wanted_name = os.path.basename(wanted).lower()
    for module in modules:
        candidate = normalize_path(module.get("path", ""))
        if candidate and os.path.basename(candidate).lower() == wanted_name:
            return module
    return None


def to_runtime(static_addr: int, image_base: int, module_base: int) -> int:
    """The runtime address of a static one.

    Ghidra's address is where the code sits in the file; x64dbg's is where
    the loader put it. The two differ by a constant, and that constant is
    what lets a breakpoint land on the function static analysis just found.
    """
    return int(static_addr) - int(image_base) + int(module_base)


def to_static(runtime_addr: int, image_base: int, module_base: int) -> int:
    """The static address of a runtime one."""
    return int(runtime_addr) - int(module_base) + int(image_base)
