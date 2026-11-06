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
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

import requests

# The plugin's defaults: 9094 for a 64-bit debuggee, 9095 for a 32-bit one.
# The released plugin binds exactly those and stops serving when the port is
# taken; the fixed build walks up instead.
DEFAULT_PORT = 9094
X32_PORT = 9095

# How many ports to try when looking for an instance. The fixed plugin walks
# up to 32 ports when the configured one is taken, so the scan has to reach
# as far as that build can go.
PORT_SCAN = 32

# How many times a connection error is retried. The plugin hangs up after
# every response, and a local TCP connection is reset every now and then on
# Windows - measured at 7% of the connections on this machine, with curl and
# with plain sockets alike, so it is the network stack and not this client.
# One more attempt is enough to tell a reset apart from a server that is
# really not there.
CONNECT_ATTEMPTS = 3

# How many times a request that is safe to repeat is sent in all. A reset is
# 7% of the connections, so two in a row - what a read-only request has to
# survive - happens about once in every two hundred calls. Three attempts,
# two re-sends, make that rare enough not to be a test flake.
DELIVERED_ATTEMPTS = 3

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
# The installation, where the plugin's own mcp_config.json - and with it the
# token - is found. The token is the one thing that cannot be guessed, so
# this is what makes the integration usable without editing a config file.
ENV_PATH = "GHYDRA_X64DBG_PATH"

CONFIG_SECTION = "x64dbg"

# The plugin's own settings file. The plugin asks the OS for the path of the
# *process*, so the file lands next to x64dbg.exe and not next to the DLL.
PLUGIN_CONFIG_NAME = "mcp_config.json"

PROTOCOL_VERSION = "2024-11-05"

# The machine-readable reasons a call can fail. The bridge carries the same
# list, so an agent sees one taxonomy whichever side it drives.
ERROR_CODES = (
    "X64DBG_ERROR",         # the generic fallback
    "X64DBG_DISABLED",      # no token, so no way to talk to the server
    "X64DBG_MISSING",       # nothing answered on the port
    "X64DBG_TIMEOUT",       # the server did not answer in time
    "X64DBG_UNCERTAIN",     # the request was sent but the answer was lost
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
    """The plugin's own settings, from the mcp_config.json next to x64dbg.exe.

    The file sits in the x64dbg root or in one of its plugin folders; which
    one depends on how x64dbg was unpacked.
    """
    root = os.path.abspath(os.path.expanduser(str(install or "")))
    candidates = [
        os.path.join(root, PLUGIN_CONFIG_NAME),
        os.path.join(root, "x64", PLUGIN_CONFIG_NAME),
        os.path.join(root, "x32", PLUGIN_CONFIG_NAME),
        os.path.join(root, "release", "x64", PLUGIN_CONFIG_NAME),
        os.path.join(root, "release", "x32", PLUGIN_CONFIG_NAME),
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
    plugin writes it to "mcp_config.json" next to x64dbg.exe, so pointing at
    an installed x64dbg with "path" is enough for the token to be found.
    """
    settings = dict(section or {})
    host = settings.get("host") or os.environ.get(ENV_HOST) or "127.0.0.1"
    port = settings.get("port") or os.environ.get(ENV_PORT) or DEFAULT_PORT
    token = settings.get("token") or os.environ.get(ENV_TOKEN) or ""
    install = settings.get("path") or os.environ.get(ENV_PATH) or ""

    plugin = read_plugin_config(install) if install else {}
    if not token:
        token = plugin.get("AuthToken") or ""
    # The plugin file fills the blanks and only the blanks: a host or a port
    # that came from the config file or from the environment is a decision
    # the user made, and the plugin file does not get to overrule it.
    if (not settings.get("host") and not os.environ.get(ENV_HOST)
            and plugin.get("IpAddress")):
        host = plugin["IpAddress"]
    if (not settings.get("port") and not os.environ.get(ENV_PORT)
            and plugin.get("Port")):
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


def _never_sent(exc: BaseException) -> bool:
    """Whether the request was never handed to the server.

    A connection that could not be established is one thing: the request
    never left, so trying again is safe. A connection that died while the
    answer was coming is another - there the server may already have acted
    on the request, and only a request that is safe to repeat may be tried
    again.

    urllib3 names the two cases "NewConnectionError" and "ProtocolError".
    The name is checked instead of the class, so this module does not have
    to depend on urllib3 directly: it comes with requests, but the bridge
    is a standalone script with its own dependency list.
    """
    cause: Optional[BaseException] = exc
    while cause is not None:
        if type(cause).__name__ == "NewConnectionError":
            return True
        cause = cause.__cause__ or cause.__context__
    return False


def _uncertain(reason: str) -> str:
    """The failure when a request was delivered and its answer was lost.

    The local network stack resets a loopback connection every now and then,
    so a request can reach the debugger and still lose its answer on the way
    back. The debugger may then have acted on it - and a request that changes
    the debuggee is never sent twice, because the second one would act on an
    unknown state. The caller has to be told that the state is unknown
    instead of being told that the server is gone.
    """
    return ("the x64dbg MCP server took the request but the answer was lost "
            f"({reason}). The request was not repeated, so the debugger may "
            "already have acted on it.")


def _repeatable(reason: str) -> str:
    """The failure when a request that may be sent again did not get through."""
    return f"{reason}. The request is safe to repeat."


def restore_types(schema: Optional[dict], arguments: Optional[dict]) -> dict:
    """Put back the types that arrived as text.

    A "--arg count=3" reaches the plugin as the string "3", and a plugin
    that cannot read a parameter ignores it and does something else: the
    call comes back with the default count instead of the one that was
    asked for. The plugin's own schema says what every parameter is, so
    the type is restored here, from the schema, rather than left to the
    plugin. A value the schema does not describe is left alone.
    """
    properties = schema.get("properties") if isinstance(schema, dict) else None
    if not isinstance(properties, dict) or not arguments:
        return arguments or {}
    restored = dict(arguments)
    for field, value in arguments.items():
        if not isinstance(value, str):
            continue
        declared = properties.get(field)
        if not isinstance(declared, dict):
            continue
        kind = declared.get("type")
        if kind == "integer":
            try:
                restored[field] = int(value, 0)
            except ValueError:
                pass
        elif kind == "number":
            try:
                restored[field] = float(value)
            except ValueError:
                pass
        elif kind == "boolean":
            if value.lower() in ("true", "false"):
                restored[field] = value.lower() == "true"
        elif kind in ("array", "object"):
            try:
                parsed = json.loads(value)
            except ValueError:
                continue
            if kind == "array" and isinstance(parsed, list):
                restored[field] = parsed
            elif kind == "object" and isinstance(parsed, dict):
                restored[field] = parsed
    return restored


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
        self._schemas: Dict[str, dict] = {}

    def _post(self, method: str, params: Optional[dict] = None,
              timeout: Optional[float] = None, connect_timeout: Optional[float] = None,
              idempotent: bool = False, connect_attempts: int = CONNECT_ATTEMPTS) -> Any:
        """One JSON-RPC request, and the result it carries.

        `idempotent` says the request may be sent again when the transport
        fails: a handshake, the catalogue, or a tool the plugin marks as
        read-only. A tool that changes the debuggee is never repeated that
        way, because the first attempt may already have reached it.

        `connect_attempts` is how many times to try when the connection never
        came up. The request was never sent in that case, so trying again is
        safe - but a closed port stays closed, so the port scan asks for one
        attempt only.
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
        connect_left = max(1, int(connect_attempts))
        delivered_left = DELIVERED_ATTEMPTS if idempotent else 1

        while True:
            try:
                response = requests.post(
                    self.base_url, json=payload, headers=headers,
                    timeout=(connect_limit, read_limit),
                )
                break
            except requests.ConnectTimeout as exc:
                # The connection never came up: the request was never sent.
                connect_left -= 1
                if connect_left > 0:
                    continue
                raise X64dbgError(
                    f"could not reach the x64dbg MCP server at {self.base_url}: {exc}",
                    code="X64DBG_MISSING",
                ) from None
            except requests.ReadTimeout as exc:
                # The request was delivered and the answer did not come back.
                # Only a request that is safe to repeat may be tried again.
                delivered_left -= 1
                if delivered_left > 0:
                    continue
                reason = f"the x64dbg MCP server did not answer within {read_limit}s"
                if idempotent:
                    raise X64dbgError(_repeatable(reason), code="X64DBG_TIMEOUT") from None
                raise X64dbgError(_uncertain(reason), code="X64DBG_UNCERTAIN") from None
            except requests.Timeout as exc:
                raise X64dbgError(
                    f"the x64dbg MCP server did not answer within {read_limit}s",
                    code="X64DBG_TIMEOUT",
                ) from None
            except requests.ConnectionError as exc:
                if _never_sent(exc):
                    # The connection was never established, so the request
                    # never left: trying again is safe for any request.
                    connect_left -= 1
                    if connect_left > 0:
                        continue
                    raise X64dbgError(
                        f"could not reach the x64dbg MCP server at {self.base_url}: {exc}",
                        code="X64DBG_MISSING",
                    ) from None
                # The connection died while the answer was coming. The plugin
                # hangs up after every response, and the local network stack
                # resets a connection every now and then, but the server may
                # already have acted on the request - so only a request that is
                # safe to repeat is tried again.
                delivered_left -= 1
                if delivered_left > 0:
                    continue
                reason = (f"the connection to {self.base_url} died while the answer "
                          f"was coming: {exc}")
                if idempotent:
                    raise X64dbgError(_repeatable(reason), code="X64DBG_MISSING") from None
                raise X64dbgError(_uncertain(reason), code="X64DBG_UNCERTAIN") from None
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
                   connect_timeout: Optional[float] = None,
                   connect_attempts: int = CONNECT_ATTEMPTS) -> Dict[str, Any]:
        """The handshake. The server keeps no state, so this is a courtesy."""
        result = self._post("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "ghydramcp", "version": "3.0.0"},
        }, timeout=timeout, connect_timeout=connect_timeout, idempotent=True,
            connect_attempts=connect_attempts)
        return result if isinstance(result, dict) else {}

    def list_tools(self) -> List[Dict[str, Any]]:
        """The plugin's tool catalogue, with the schema of each."""
        result = self._post("tools/list", idempotent=True)
        tools = result.get("tools") if isinstance(result, dict) else None
        return tools if tools is not None and isinstance(tools, list) else []

    def _load_catalogue(self) -> None:
        """Fetch the plugin's catalogue once.

        It carries the read-only hint and the input schema of every tool:
        the hint says whether a call may be repeated, and the schema says
        what type every parameter is.
        """
        if self._read_only or self._schemas:
            return
        try:
            tools = self.list_tools()
        except X64dbgError:
            return
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            annotations = tool.get("annotations") or {}
            name = str(tool.get("name"))
            self._read_only[name] = bool(annotations.get("readOnlyHint"))
            schema = tool.get("inputSchema")
            self._schemas[name] = schema if isinstance(schema, dict) else {}

    def is_read_only(self, name: str) -> bool:
        """Whether the plugin marks a tool as read-only.

        The catalogue carries the hint, and it is fetched once and kept: the
        tool set does not change while the debugger runs.
        """
        if name not in self._read_only:
            self._load_catalogue()
        return self._read_only.get(name, False)

    def call_tool(self, name: str, arguments: Optional[dict] = None) -> str:
        """Call one plugin tool and return its text.

        Every response carries a "[state]" line and whatever debugger events
        fired since the last call, so the text is returned whole.

        A read-only tool may be called again when the transport fails; a tool
        that changes the debuggee may not, because the first attempt may
        already have reached it.
        """
        self._load_catalogue()
        result = self._post(
            "tools/call",
            {"name": name,
             "arguments": restore_types(self._schemas.get(name), arguments or {})},
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


def candidate_ports(port: int) -> tuple:
    """The ports to try: the likely ones first, then the walk.

    The walk starts from the configured port as well as from the two
    defaults: the fixed plugin walks up from the port it was told to use, so
    a server on the configured port plus one has to be reachable.
    """
    likely = list(dict.fromkeys([port, DEFAULT_PORT, X32_PORT]))
    bases = tuple(dict.fromkeys((port, DEFAULT_PORT, X32_PORT)))
    others = [
        candidate + offset
        for offset in range(1, PORT_SCAN)
        for candidate in bases
        if (candidate + offset) not in likely
    ]
    return likely, others


def discover(section: Optional[dict] = None, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
    """Find an x64dbg MCP server.

    The plugin binds 9094 for a 64-bit debuggee and 9095 for a 32-bit one,
    and the ports around them are tried too. A server that answers 401 is
    still a server: it means the token is wrong, which is worth saying.

    Raises X64dbgError when there is no token at all: there is no way to
    talk to the server without one, and the scan would only report a
    missing server or a rejected token.

    The ports are probed concurrently and the probe timeout is short. A closed
    local port does not refuse straight away on Windows - the SYN hangs and is
    only refused about two seconds later - so probing the ports one at a time
    with a long timeout would cost a couple of seconds per port. A live
    instance answers in milliseconds, so a third of a second is plenty to tell
    it from a closed port.
    """
    settings = resolve_config(section)
    if not settings["token"]:
        # A token is the one thing that cannot be guessed. Without one there
        # is no way to talk to the server, and probing the ports would only
        # report a missing server or a rejected token - neither of which says
        # what is actually wrong.
        raise X64dbgError(
            "no bearer token for the x64dbg MCP server. Set "
            '"x64dbg": {"token": "..."} in ~/.ghydra/config.json, or point '
            '"x64dbg": {"path": "C:/tools/x64dbg"} - or GHYDRA_X64DBG_PATH - '
            "to read it from the plugin's own mcp_config.json.",
            code="X64DBG_DISABLED",
        )
    connect_limit = PROBE_CONNECT_TIMEOUT if timeout is None else timeout
    read_limit = PROBE_READ_TIMEOUT if timeout is None else timeout

    likely, others = candidate_ports(settings["port"])

    def _probe(port: int) -> Optional[str]:
        """The port that answered, or None."""
        client = Client(settings["host"], port, settings["token"], timeout=read_limit)
        try:
            # A closed port stays closed, so the scan asks for one attempt:
            # every extra one costs the whole connect timeout again.
            client.initialize(timeout=read_limit, connect_timeout=connect_limit,
                              connect_attempts=1)
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
        for port, answer in zip(group, answers):
            if answer == "unauthorized":
                unauthorized = {
                    "host": settings["host"], "port": port,
                    "token": settings["token"], "path": settings["path"],
                    "unauthorized": True,
                }
                break
        if unauthorized:
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


def collect_snapshot(client: Client, instruction_count: int = 16) -> Dict[str, Any]:
    """The state of the debugger, as it is right now.

    The plugin answers with prose, so the text is kept as it came and the
    parts that can be read are read: the modules, with their bases, are the
    ones the address model needs.

    A debugger without a session is not an error: the state says so, and the
    rest is simply not there.
    """
    snapshot: Dict[str, Any] = {"errors": []}

    def read(name: str, tool: str, arguments: Optional[dict] = None) -> str:
        try:
            return client.call_tool(tool, arguments or {})
        except X64dbgError as exc:
            snapshot["errors"].append(f"{name}: {exc}")
            return ""

    state = read("state", "GetDebugState")
    snapshot["state"] = state
    snapshot["modules_text"] = read("modules", "ListModules")
    snapshot["modules"] = parse_modules(snapshot["modules_text"])
    snapshot["registers"] = read("registers", "GetAllRegisters")
    snapshot["breakpoints"] = read("breakpoints", "ListBreakpoints")
    snapshot["disassembly"] = read(
        "disassembly", "Disassemble", {"count": int(instruction_count)})
    snapshot["memory_map"] = read("memory_map", "GetMemoryMap")
    snapshot["call_stack"] = read("call_stack", "GetCallStack")
    return snapshot


def render_snapshot(snapshot: Dict[str, Any], title: str = "x64dbg session") -> str:
    """The snapshot as a document a human reads.

    The plugin answers with prose, so the prose is what goes in. The modules
    are also tabulated, because their bases are what the address model is
    made of.
    """
    out: List[str] = [f"# {title}\n"]
    out.append(f"- Taken: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    state = (snapshot.get("state") or "").strip()
    out.append("## State\n")
    out.append("```\n" + (state or "_the debugger answered nothing_") + "\n```\n")

    modules = snapshot.get("modules") or []
    if modules:
        out.append("## Modules\n")
        out.append("| Base | Size | Path |")
        out.append("|---|---|---|")
        for module in modules:
            out.append(f"| {hex(module.get('base', 0))} | {hex(module.get('size', 0))} "
                       f"| {module.get('path', '')} |")
        out.append("")

    for title_text, key in (
        ("Registers", "registers"),
        ("Breakpoints", "breakpoints"),
        ("Disassembly", "disassembly"),
        ("Call stack", "call_stack"),
        ("Memory map", "memory_map"),
    ):
        text = (snapshot.get(key) or "").strip()
        if not text:
            continue
        out.append(f"## {title_text}\n")
        out.append("```\n" + text + "\n```\n")

    errors = snapshot.get("errors") or []
    if errors:
        out.append("## What could not be read\n")
        for error in errors:
            out.append(f"- {error}")
        out.append("")

    return "\n".join(out)


def load_annotations(path: str) -> Dict[str, Any]:
    """The annotations of a report, as they were written.

    The file is the one the report writes: the binary, the image base and the
    annotations themselves.
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except OSError as exc:
        raise X64dbgError(
            f"could not read the annotations: {exc}", code="X64DBG_NO_FILE") from None
    except ValueError as exc:
        raise X64dbgError(
            f"the annotations are not JSON: {exc}", code="X64DBG_BAD_ARGS") from None
    if not isinstance(data, dict) or not isinstance(data.get("annotations"), list):
        raise X64dbgError(
            "the file holds no annotations", code="X64DBG_BAD_ARGS")
    return data


def apply_annotations(client: Client, annotations: Dict[str, Any],
                      mode: str = "Comment", bookmarks: bool = False,
                      limit: int = 0, passes: int = 2) -> Dict[str, Any]:
    """Put the annotations into the debugger.

    The addresses in the file are the ones in the binary; the debugger works
    on the live process, where the module was loaded wherever the loader put
    it. The module that matches the binary gives the base, and the constant
    between the two follows from it.

    Every annotation becomes a comment (or a label) at the runtime address,
    and a bookmark when asked for.

    A failed annotation is tried again. Setting a comment and setting a
    bookmark are the same operation twice over, so repeating them is safe -
    and the local network stack resets a loopback connection every now and
    then, which is what makes a call fail without the debugger having done
    anything wrong.
    """
    binary = str(annotations.get("binary") or "")
    image_base = parse_int(annotations.get("image_base"))
    if image_base is None:
        raise X64dbgError(
            "the annotations carry no image base, so the addresses cannot be "
            "translated", code="X64DBG_BAD_ARGS")

    modules = parse_modules(client.call_tool("ListModules"))
    module = find_module(modules, binary) if binary else None
    if module is None:
        # No module matches the binary of the annotations. Falling back to
        # the first module would translate every address with the base of a
        # module that has nothing to do with the file - and the comments
        # would land at addresses that mean nothing. There is no way to
        # know the base without the module, so the annotations are refused.
        raise X64dbgError(
            f"no loaded module matches the binary of the annotations ({binary}). "
            "Load it in the debugger before applying them.",
            code="X64DBG_NO_MATCH")

    entries = annotations.get("annotations") or []
    if limit:
        entries = entries[:limit]

    applied: List[Dict[str, Any]] = []
    failed: List[Dict[str, Any]] = []

    # What is left to do, and what was already done: a failed annotation is
    # tried again, and the record of it is replaced rather than duplicated.
    pending: List[Dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        static = parse_int(entry.get("address"))
        if static is None:
            continue
        runtime = to_runtime(static, image_base, module["base"])
        pending.append({
            "static_address": hex(static),
            "runtime_address": hex(runtime),
            "name": entry.get("name") or "",
            "comment": str(entry.get("comment") or entry.get("name") or ""),
        })

    for _attempt in range(max(1, int(passes))):
        still_failing: List[Dict[str, Any]] = []
        for record in pending:
            try:
                if record["comment"]:
                    client.call_tool("CommentOrLabelAtAddress", {
                        "address": record["runtime_address"],
                        "value": record["comment"],
                        "mode": mode,
                    })
                if bookmarks:
                    # The plugin's own SetBookmark runs "bookmarkadd", which
                    # x64dbg does not know: the commands are "bookmarkset"
                    # (alias "bookmark"), "bookmarkdel" and "bookmarklist".
                    # The command is run directly, so the bookmark lands.
                    client.call_tool("ExecuteDebuggerCommand", {
                        "command": f"bookmarkset {record['runtime_address']}",
                    })
                record["ok"] = True
                record.pop("error", None)
                applied.append(record)
            except X64dbgError as exc:
                record["ok"] = False
                record["error"] = str(exc)
                still_failing.append(record)
        if not still_failing:
            break
        pending = still_failing
    failed = [record for record in pending if record.get("ok") is False]

    return {
        "binary": binary,
        "image_base": hex(image_base),
        "module_base": hex(module["base"]),
        "module_path": module.get("path", ""),
        "mode": mode,
        "bookmarks": bookmarks,
        "applied": applied,
        "failed": failed,
    }
