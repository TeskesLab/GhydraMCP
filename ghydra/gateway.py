"""The gateway: the five-step chain of the unification plan, as MCP tools.

Phase 3 of `docs/UNIFICATION-PLAN.md` asks for one MCP server in front of both
plugins, exposing cross-tool workflows that neither can express alone. The CLI
already has the workflow (`ghydra target …`); this module puts the same functions
behind MCP tools, so an agent can drive the chain without a shell:

    target_open        analyze_open: both sides, one TargetDescriptor
    target_locate      function_locate: the static address
    target_breakpoint  breakpoint_set: translate, set it, or refuse
    target_run_to      run_to: resume to it, report the registers
    target_decompile   decompile: the recovered C

Two design rules, both from the contract:

* **names follow `contract/vocabulary.json`** (`namespace_verb`, snake_case), so
  the gateway's tools live in the `target` namespace — the plan's workflow names
  (`analyze_open`, `function_locate`, …) are the workflow's name for the step, and
  `GATEWAY_STEPS` is where the two vocabularies are mapped;
* **a tool returns a code, it does not raise.** A failure is
  `{"success": false, "code": "TARGET_…", "reason": "…"}`, because the contract's
  rule 3 says an agent branches on a code rather than on prose, and an MCP tool that
  raises turns the code into an unstructured error.

The tools are thin: every one delegates to `ghydra.target`, so the refusal that
protects the address translation is the same one the CLI and the tests already pin.
"""

from __future__ import annotations

import os
from typing import Any, Callable, Dict, Optional, Tuple

from . import target as target_helper
from .client import GhidraHTTPClient
from .client.exceptions import GhidraError

#: The plan's step name for each tool, in the order the plan chains them.
GATEWAY_STEPS = (
    ("analyze_open", "target_open"),
    ("function_locate", "target_locate"),
    ("breakpoint_set", "target_breakpoint"),
    ("run_to", "target_run_to"),
    ("decompile", "target_decompile"),
)

INSTRUCTIONS = (
    "The GhydraMCP gateway: static analysis (Ghidra) and dynamic analysis (x64dbg) "
    "on one target. Start with target_open — it reports whether the two sides are "
    "looking at the same file, and every command that touches the debugger refuses "
    "with TARGET_NOT_SAME_BINARY otherwise. Then locate a function statically, set a "
    "breakpoint or run to it (both translate the address), and decompile it."
)


# --------------------------------------------------------------------- clients
def ghidra_client(host: Optional[str] = None,
                  port: Optional[int] = None) -> GhidraHTTPClient:
    """The static side: the argument, then the environment, then the configuration.

    The environment is the bridge's (`GHIDRA_HYDRA_HOST`, then `GHIDRA_HOST`),
    because `ghydra mcp-config --gateway` writes the host there — a generated
    configuration that names a variable the server ignores is a trap.
    """
    from .config import ConfigManager

    try:
        config = ConfigManager.load()
    except Exception:  # noqa: BLE001 - no config file is a normal state
        config = None
    environment_host = (os.environ.get("GHIDRA_HYDRA_HOST")
                        or os.environ.get("GHIDRA_HOST"))
    resolved_host = (host or environment_host
                     or getattr(config, "default_host", None) or "localhost")
    resolved_port = port or getattr(config, "default_port", None) or 8192
    return GhidraHTTPClient(str(resolved_host), int(resolved_port))


def debugger_client():
    """The dynamic side, from the same configuration the CLI uses."""
    from . import x64dbg as debugger
    from .config import ConfigManager

    try:
        config = ConfigManager.load()
    except Exception:  # noqa: BLE001
        config = None
    # The section, not an attribute called `x64dbg`: the object keeps the four
    # settings flat, and `getattr(config, "x64dbg", None)` silently ignored the
    # configuration file.
    section = config.x64dbg_section() if config is not None else None
    settings = debugger.resolve_config(section)
    if not settings["token"]:
        raise debugger.X64dbgError(
            "no bearer token for the x64dbg MCP server. Set "
            '"x64dbg": {"path": "C:/tools/x64dbg"} in ~/.ghydra/config.json, or '
            "GHYDRA_X64DBG_PATH, so the token is read from the plugin's own file.",
            code="X64DBG_DISABLED")
    return debugger.Client(settings["host"], settings["port"], settings["token"])


#: What a client factory returns: (ghidra client, debugger client factory).
Factory = Callable[[], Tuple[Any, Callable[[], Any]]]


def default_factory() -> Tuple[Any, Callable[[], Any]]:
    """The real clients: the static one now, the debugger one when it is needed."""
    return ghidra_client(), debugger_client


# ----------------------------------------------------------------- pure helpers
def _failure(exc: Exception) -> Dict[str, Any]:
    code = getattr(exc, "code", "") or "GATEWAY_ERROR"
    return {"success": False, "code": code, "reason": str(exc)}


def open_target(ghidra, debugger) -> Dict[str, Any]:
    """`analyze_open`: both sides, one descriptor, with the identity verdict."""
    try:
        descriptor = target_helper.describe(ghidra, debugger)
    except (target_helper.TargetError, GhidraError, Exception) as exc:  # noqa: BLE001
        return _failure(exc)
    document = descriptor.as_dict()
    document["success"] = True
    return document


def locate_function(ghidra, name: str) -> Dict[str, Any]:
    """`function_locate`: the static address of a function."""
    try:
        found = target_helper.locate(ghidra, name)
    except (target_helper.TargetError, GhidraError, Exception) as exc:  # noqa: BLE001
        return _failure(exc)
    found["success"] = True
    return found


def set_breakpoint(ghidra, debugger, name: str) -> Dict[str, Any]:
    """`breakpoint_set`: translate the static address and set it, or refuse."""
    try:
        result = target_helper.breakpoint(ghidra, debugger, name)
    except (target_helper.TargetError, GhidraError, Exception) as exc:  # noqa: BLE001
        return _failure(exc)
    result["success"] = True
    return result


def run_to(ghidra, debugger, name: str,
           timeout_ms: int = target_helper.RUN_TO_TIMEOUT_MS) -> Dict[str, Any]:
    """`run_to`: resume to the address and report the registers at the stop."""
    try:
        result = target_helper.run_to(ghidra, debugger, name, timeout_ms=timeout_ms)
    except (target_helper.TargetError, GhidraError, Exception) as exc:  # noqa: BLE001
        return _failure(exc)
    result["success"] = True
    return result


def decompile_function(ghidra, name: str, style: str = "normalize") -> Dict[str, Any]:
    """`decompile`: the recovered C of a function, addressed statically."""
    try:
        result = target_helper.decompile(ghidra, name, style=style)
    except (target_helper.TargetError, GhidraError, Exception) as exc:  # noqa: BLE001
        return _failure(exc)
    result["success"] = True
    return result


# ------------------------------------------------------------------- the server
def build_server(factory: Optional[Factory] = None):
    """The FastMCP server with the five tools.

    The client factory is a parameter so the suite can drive the server with fakes;
    the default builds the real clients, and the debugger's is deferred to the call
    that needs it (a gateway must start even when the debugger is not running).
    """
    from mcp.server.fastmcp import FastMCP

    factory = factory or default_factory
    server = FastMCP("GhydraMCP Gateway", instructions=INSTRUCTIONS)

    def clients(need_debugger: bool):
        """(ghidra, debugger, failure) — a client that cannot be built is a code."""
        try:
            ghidra, debugger_factory = factory()
            debugger = debugger_factory() if need_debugger else None
            return ghidra, debugger, None
        except Exception as exc:  # noqa: BLE001 - the reason is the answer
            return None, None, _failure(exc)

    @server.tool()
    def target_open() -> Dict[str, Any]:
        """Analyze the open target: image base, module base, and whether the two
        sides are looking at the same file (required before any address is used)."""
        ghidra, debugger, failure = clients(True)
        if failure:
            return failure
        return open_target(ghidra, debugger)

    @server.tool()
    def target_locate(name: str) -> Dict[str, Any]:
        """Find a function's static address by name or address.

        Args:
            name: The function name, or its static address in hex.
        """
        ghidra, _debugger, failure = clients(False)
        if failure:
            return failure
        return locate_function(ghidra, name)

    @server.tool()
    def target_breakpoint(name: str) -> Dict[str, Any]:
        """Set a breakpoint in the debugger on a function Ghidra knows.

        The static address is located and translated into the running process. If
        the two sides are not the same file the answer is
        TARGET_NOT_SAME_BINARY and nothing is written.

        Args:
            name: The function name, or its static address in hex.
        """
        ghidra, debugger, failure = clients(True)
        if failure:
            return failure
        return set_breakpoint(ghidra, debugger, name)

    @server.tool()
    def target_run_to(name: str,
                      timeout_ms: int = target_helper.RUN_TO_TIMEOUT_MS
                      ) -> Dict[str, Any]:
        """Run the debuggee to a function and report the registers at the stop.

        Args:
            name: The function name, or its static address in hex.
            timeout_ms: How long the debugger waits (default below the client read
                timeout on purpose).
        """
        ghidra, debugger, failure = clients(True)
        if failure:
            return failure
        return run_to(ghidra, debugger, name, timeout_ms=timeout_ms)

    @server.tool()
    def target_decompile(name: str, style: str = "normalize") -> Dict[str, Any]:
        """Decompile a function to C pseudocode, addressed statically.

        Args:
            name: The function name, or its static address in hex.
            style: The decompiler style (default: normalize).
        """
        ghidra, _debugger, failure = clients(False)
        if failure:
            return failure
        return decompile_function(ghidra, name, style=style)

    return server


def serve(host: Optional[str] = None, port: Optional[int] = None) -> None:
    """Run the gateway on stdio, which is what an MCP client launches."""
    server = build_server(lambda: (ghidra_client(host, port), debugger_client))
    server.run(transport="stdio")


def main(argv=None) -> int:
    """Run the gateway on stdio: what an MCP client launches.

    The host and the port name the static side; the debugger comes from the same
    configuration the CLI uses. Nothing is printed here — stdout belongs to the
    protocol.
    """
    import argparse
    import sys

    parser = argparse.ArgumentParser(prog="ghydra-gateway",
                                     description=__doc__)
    parser.add_argument("--host", default=None,
                        help="Ghidra host (default: the configuration)")
    parser.add_argument("--port", "-p", type=int, default=None,
                        help="Ghidra port (default: the configuration)")
    arguments = parser.parse_args(argv)
    # stderr is the only place a message may go: stdout carries the MCP frames.
    print("ghydra-gateway: serving the cross-tool chain on stdio", file=sys.stderr)
    serve(arguments.host, arguments.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
