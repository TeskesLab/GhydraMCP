"""x64dbg MCP server commands.

The x64dbg plugin (https://github.com/duty1g/x64dbg-mcp-server) is an MCP
server that lives inside the debugger: it answers JSON-RPC 2.0 POSTed to "/"
with a bearer token, and every request stands alone. These commands drive it
from the command line, next to the Ghidra ones, so the static side and the
dynamic side can be worked in the same session.

The plugin binds 127.0.0.1:9094 for a 64-bit debuggee and :9095 for a 32-bit
one, and it wants a bearer token. Point at it with "x64dbg": {"port": ...,
"token": ...} in ~/.ghydra/config.json, or with "path" pointing at the x64dbg
installation - the token is then read from the plugin's own mcp_config.json.
"""

import json
import sys

import click

from .. import x64dbg as x64dbg_helper
from ..utils import rich_echo

# How long a plugin call may take. The tools that block - run, WaitForEvent,
# WaitForPause - need more, and the "call" command takes a --timeout.
X64DBG_DEFAULT_TIMEOUT = 30.0


@click.group('x64dbg')
def x64dbg():
    """x64dbg debugger commands (through the plugin's MCP server).

    The x64dbg plugin is an MCP server inside the debugger. These commands
    drive it, and the ones that take an address take the *static* one - the
    address as Ghidra shows it - and translate it into the runtime address.

    \b
    Examples:
        ghydra x64dbg status
        ghydra x64dbg tools
        ghydra x64dbg call GetAllRegisters
        ghydra x64dbg target
        ghydra x64dbg breakpoint 0x140001234
    """
    pass


def _section(ctx):
    """The x64dbg config section, as the CLI resolved it."""
    config = ctx.obj['config']
    section = {}
    if config.x64dbg_host:
        section["host"] = config.x64dbg_host
    if config.x64dbg_port:
        section["port"] = config.x64dbg_port
    if config.x64dbg_token:
        section["token"] = config.x64dbg_token
    if config.x64dbg_path:
        section["path"] = config.x64dbg_path
    return section


def _emit(ctx, kind, data):
    """Print an x64dbg result through the active formatter."""
    text = ctx.obj['formatter'].format_x64dbg({"kind": kind, "data": data})
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        text.encode(encoding)
    except UnicodeEncodeError:
        text = text.encode(encoding, errors="replace").decode(encoding, errors="replace")
    click.echo(text)


def _fail(ctx, exc):
    """Report an x64dbg failure and stop with a non-zero exit code."""
    rich_echo(f"Error: {exc}", err=True)
    ctx.exit(1)


def _client(ctx, timeout: float = X64DBG_DEFAULT_TIMEOUT):
    """A client for the x64dbg MCP server, or None with the reason."""
    section = _section(ctx)
    settings = x64dbg_helper.resolve_config(section)
    if not settings["token"]:
        # A token is the one thing that cannot be guessed. The plugin writes
        # it to its own mcp_config.json, so pointing at the installation is
        # enough - but only if the path was given.
        if not settings["path"]:
            return None, (
                "no bearer token for the x64dbg MCP server. Set "
                '"x64dbg": {"token": "..."} in ~/.ghydra/config.json, or '
                '"x64dbg": {"path": "C:/tools/x64dbg"} to read it from the '
                "plugin's own mcp_config.json."
            )

    # The plugin binds 9094 for a 64-bit debuggee and 9095 for a 32-bit one,
    # so the port is looked for rather than assumed.
    instance = x64dbg_helper.discover(section)
    if instance is None:
        return None, (
            "no x64dbg MCP server answered on the ports around 9094; is "
            "x64dbg running with the plugin loaded?"
        )
    if instance.get("unauthorized"):
        return None, (
            "the x64dbg MCP server rejected the bearer token. Set "
            '"x64dbg": {"token": "..."} in ~/.ghydra/config.json, or '
            '"x64dbg": {"path": "C:/tools/x64dbg"} to read it from the '
            "plugin's own mcp_config.json."
        )
    return x64dbg_helper.Client(
        instance["host"], instance["port"], instance["token"],
        timeout=timeout,
    ), None


def _program_info(ctx):
    """The Ghidra program's image base and executable path."""
    response = ctx.obj['client'].get("/program")
    if not response.get("success", False):
        error = response.get("error") or {}
        raise x64dbg_helper.X64dbgError(
            error.get("message", "the Ghidra instance did not answer /program")
        )
    result = response.get("result") or {}
    return {
        "path": result.get("path") or "",
        "image_base": x64dbg_helper.parse_int(result.get("imageBase")),
    }


@x64dbg.command('status')
@click.pass_context
def status(ctx):
    """Show whether the x64dbg MCP server is reachable, and what it has.

    \b
    Examples:
        ghydra x64dbg status
    """
    client, problem = _client(ctx)
    if client is None:
        _fail(ctx, x64dbg_helper.X64dbgError(problem, code="X64DBG_DISABLED"))
        return
    try:
        tools = client.list_tools()
        text = client.call_tool("ListModules")
        modules = x64dbg_helper.parse_modules(text)
        debug_state = None
        try:
            debug_state = client.call_tool("GetDebugState").strip()
        except x64dbg_helper.X64dbgError:
            debug_state = None
    except x64dbg_helper.X64dbgError as exc:
        _fail(ctx, exc)
        return

    _emit(ctx, "status", {
        "reachable": True,
        "host": client.host,
        "port": client.port,
        "tools": len(tools),
        "modules": modules,
        "debug_state": debug_state,
    })


@x64dbg.command('tools')
@click.pass_context
def tools(ctx):
    """List the x64dbg plugin's tools, with the schema of each.

    \b
    Examples:
        ghydra x64dbg tools
    """
    client, problem = _client(ctx)
    if client is None:
        _fail(ctx, x64dbg_helper.X64dbgError(problem, code="X64DBG_DISABLED"))
        return
    try:
        catalogue = client.list_tools()
    except x64dbg_helper.X64dbgError as exc:
        _fail(ctx, exc)
        return

    _emit(ctx, "tools", {
        "count": len(catalogue),
        "tools": [
            {
                "name": tool.get("name"),
                "description": tool.get("description"),
                "input_schema": tool.get("inputSchema"),
            }
            for tool in catalogue if isinstance(tool, dict)
        ],
    })


@x64dbg.command('call')
@click.argument('tool')
@click.option('--arg', 'args', multiple=True, metavar='KEY=VALUE',
              help='An argument for the tool. Repeat it for more than one.')
@click.option('--json-args', 'json_args', default=None,
              help='The arguments as a JSON object.')
@click.option('--timeout', 'timeout', type=float, default=X64DBG_DEFAULT_TIMEOUT,
              help='How long to wait, in seconds. The tools that block need more.')
@click.pass_context
def call(ctx, tool, args, json_args, timeout):
    """Call one of the x64dbg plugin's tools by name.

    \b
    Examples:
        ghydra x64dbg call GetAllRegisters
        ghydra x64dbg call SetBreakpoint --arg target=0x7FF7A1234000
        ghydra x64dbg call ReadMemory --json-args '{"address": "0x7FF7A1234000", "size": 64}'
    """
    client, problem = _client(ctx, timeout=timeout)
    if client is None:
        _fail(ctx, x64dbg_helper.X64dbgError(problem, code="X64DBG_DISABLED"))
        return

    arguments = {}
    if json_args:
        try:
            parsed = json.loads(json_args)
        except ValueError as exc:
            _fail(ctx, x64dbg_helper.X64dbgError(
                f"--json-args is not JSON: {exc}", code="X64DBG_BAD_ARGS"))
            return
        if not isinstance(parsed, dict):
            _fail(ctx, x64dbg_helper.X64dbgError(
                "--json-args must be a JSON object", code="X64DBG_BAD_ARGS"))
            return
        arguments.update(parsed)
    for pair in args:
        if "=" not in pair:
            _fail(ctx, x64dbg_helper.X64dbgError(
                f"--arg {pair} is not KEY=VALUE", code="X64DBG_BAD_ARGS"))
            return
        key, _, value = pair.partition("=")
        arguments[key.strip()] = value.strip()

    try:
        text = client.call_tool(tool, arguments)
    except x64dbg_helper.X64dbgError as exc:
        _fail(ctx, exc)
        return
    _emit(ctx, "call", {"tool": tool, "text": text})


def _descriptor(ctx):
    """The correlation between the Ghidra program and the x64dbg session."""
    client, problem = _client(ctx)
    if client is None:
        raise x64dbg_helper.X64dbgError(problem, code="X64DBG_DISABLED")
    program = _program_info(ctx)
    text = client.call_tool("ListModules")
    modules = x64dbg_helper.parse_modules(text)
    module = x64dbg_helper.find_module(modules, program.get("path") or "")
    if module is None:
        raise x64dbg_helper.X64dbgError(
            "no loaded module matches the binary Ghidra has open "
            f"({program.get('path') or 'unknown'})",
            code="X64DBG_NO_MATCH",
        )
    if program.get("image_base") is None:
        raise x64dbg_helper.X64dbgError(
            "the Ghidra instance did not report an image base for this program")
    return client, program, module


@x64dbg.command('target')
@click.pass_context
def target(ctx):
    """Show how the Ghidra program and the x64dbg session line up.

    Ghidra works on the image as it sits in the file, at the image base.
    x64dbg works on the live process, where the loader put the module
    somewhere else. This works out the constant between them.

    \b
    Examples:
        ghydra x64dbg target
    """
    try:
        client, program, module = _descriptor(ctx)
    except x64dbg_helper.X64dbgError as exc:
        _fail(ctx, exc)
        return

    image_base = program["image_base"]
    module_base = module["base"]
    _emit(ctx, "target", {
        "binary": program.get("path") or "",
        "image_base": image_base,
        "module_base": module_base,
        "module_size": module.get("size"),
        "module_path": module.get("path"),
        "delta": module_base - image_base,
    })


@x64dbg.command('breakpoint')
@click.argument('address')
@click.pass_context
def breakpoint(ctx, address):
    """Set a breakpoint on a Ghidra address.

    The address is the static one - the one Ghidra shows - and it is
    translated into the runtime address before the breakpoint is set.

    \b
    Examples:
        ghydra x64dbg breakpoint 0x140001234
    """
    static_address = x64dbg_helper.parse_int(address)
    if static_address is None:
        _fail(ctx, x64dbg_helper.X64dbgError(
            f"'{address}' is not an address", code="X64DBG_BAD_ARGS"))
        return
    try:
        client, program, module = _descriptor(ctx)
    except x64dbg_helper.X64dbgError as exc:
        _fail(ctx, exc)
        return

    runtime = x64dbg_helper.to_runtime(
        static_address, program["image_base"], module["base"])
    try:
        text = client.call_tool("SetBreakpoint", {"target": hex(runtime)})
    except x64dbg_helper.X64dbgError as exc:
        _fail(ctx, exc)
        return

    _emit(ctx, "breakpoint_at", {
        "static_address": hex(static_address),
        "runtime_address": hex(runtime),
        "image_base": hex(program["image_base"]),
        "module_base": hex(module["base"]),
        "binary": program.get("path") or "",
        "text": text,
    })


@x64dbg.command('go-to')
@click.argument('address')
@click.pass_context
def go_to(ctx, address):
    """Move the instruction pointer to a Ghidra address.

    The address is translated from the static one into the runtime one, the
    same way "breakpoint" does it.

    \b
    Examples:
        ghydra x64dbg go-to 0x140001234
    """
    static_address = x64dbg_helper.parse_int(address)
    if static_address is None:
        _fail(ctx, x64dbg_helper.X64dbgError(
            f"'{address}' is not an address", code="X64DBG_BAD_ARGS"))
        return
    try:
        client, program, module = _descriptor(ctx)
    except x64dbg_helper.X64dbgError as exc:
        _fail(ctx, exc)
        return

    runtime = x64dbg_helper.to_runtime(
        static_address, program["image_base"], module["base"])
    try:
        text = client.call_tool("Disassemble", {"address": hex(runtime)})
    except x64dbg_helper.X64dbgError as exc:
        _fail(ctx, exc)
        return

    _emit(ctx, "go_to", {
        "static_address": hex(static_address),
        "runtime_address": hex(runtime),
        "binary": program.get("path") or "",
        "text": text,
    })
