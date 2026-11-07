"""x64dbg MCP server commands.

The x64dbg plugin (https://github.com/duty1g/x64dbg-mcp-server) is an MCP
server that lives inside the debugger: it answers JSON-RPC 2.0 POSTed to "/"
with a bearer token, and every request stands alone. These commands drive it
from the command line, next to the Ghidra ones, so the static side and the
dynamic side can be worked in the same session.

The plugin binds 127.0.0.1:9094 for a 64-bit debuggee and :9095 for a 32-bit
one, and it wants a bearer token. Point at it with "x64dbg": {"port": ...,
"token": ...} in ~/.ghydra/config.json, or with "path" - or
GHYDRA_X64DBG_PATH - pointing at the x64dbg installation: the token is then
read from the plugin's own mcp_config.json.
"""

import json
import os
import sys
import time

import click

from .. import x64dbg as x64dbg_helper
from ..client.exceptions import GhidraError
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
    """Report a failure and stop with a non-zero exit code.

    The code goes with it: the ten x64dbg codes are what an agent branches
    on, and the bridge reports them the same way.
    """
    code = getattr(exc, "code", "") or ""
    prefix = f"Error [{code}]" if code else "Error"
    rich_echo(f"{prefix}: {exc}", err=True)
    ctx.exit(1)


def _client(ctx, timeout: float = X64DBG_DEFAULT_TIMEOUT):
    """A client for the x64dbg MCP server.

    Raises X64dbgError when there is no way to talk to it.
    """
    section = _section(ctx)
    settings = x64dbg_helper.resolve_config(section)
    if not settings["token"]:
        # A token is the one thing that cannot be guessed. The plugin writes
        # it to its own mcp_config.json, so pointing at the installation is
        # usually enough - but when there is no token at all, there is
        # nothing to talk to the server with, and the scan would only report
        # a missing server or a rejected token.
        raise x64dbg_helper.X64dbgError(
            "no bearer token for the x64dbg MCP server. Set "
            '"x64dbg": {"token": "..."} in ~/.ghydra/config.json, or '
            '"x64dbg": {"path": "C:/tools/x64dbg"} - or '
            "GHYDRA_X64DBG_PATH - to read it from the "
            "plugin's own mcp_config.json.",
            code="X64DBG_DISABLED",
        )

    # The plugin binds 9094 for a 64-bit debuggee and 9095 for a 32-bit one,
    # so the port is looked for rather than assumed.
    instance = x64dbg_helper.discover(section)
    if instance is None:
        raise x64dbg_helper.X64dbgError(
            "no x64dbg MCP server answered on the ports around 9094; is "
            "x64dbg running with the plugin loaded?",
            code="X64DBG_MISSING",
        )
    if instance.get("unauthorized"):
        raise x64dbg_helper.X64dbgError(
            "the x64dbg MCP server rejected the bearer token. Set "
            '"x64dbg": {"token": "..."} in ~/.ghydra/config.json, or '
            '"x64dbg": {"path": "C:/tools/x64dbg"} - or '
            "GHYDRA_X64DBG_PATH - to read it from the "
            "plugin's own mcp_config.json.",
            code="X64DBG_UNAUTHORIZED",
        )
    return x64dbg_helper.Client(
        instance["host"], instance["port"], instance["token"],
        timeout=timeout,
    )


def _program_info(ctx):
    """The Ghidra program's image base and executable path.

    The Ghidra client raises GhidraError when the instance is not there, so
    the caller catches that as well.
    """
    response = ctx.obj['client'].get("/program")
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
    try:
        client = _client(ctx)
    except x64dbg_helper.X64dbgError as exc:
        _fail(ctx, exc)
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
    try:
        client = _client(ctx)
    except x64dbg_helper.X64dbgError as exc:
        _fail(ctx, exc)
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
              help='An argument for the tool, as a string. Repeat it for more '
                   'than one. A number needs --json-args.')
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
    try:
        client = _client(ctx, timeout=timeout)
    except x64dbg_helper.X64dbgError as exc:
        _fail(ctx, exc)
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
    client = _client(ctx)
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
    except GhidraError as exc:
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
    except GhidraError as exc:
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
    same way "breakpoint" does it. The debuggee has to be paused: a running
    target has no instruction pointer to move.

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
    except GhidraError as exc:
        _fail(ctx, exc)
        return

    runtime = x64dbg_helper.to_runtime(
        static_address, program["image_base"], module["base"])
    try:
        # "cip" is the x64dbg name for the instruction pointer, in a 64-bit
        # debuggee and in a 32-bit one alike; the plugin turns it into
        # "mov cip, <address>".
        text = client.call_tool(
            "SetRegister", {"register": "cip", "value": hex(runtime)})
    except x64dbg_helper.X64dbgError as exc:
        _fail(ctx, exc)
        return

    _emit(ctx, "go_to", {
        "static_address": hex(static_address),
        "runtime_address": hex(runtime),
        "binary": program.get("path") or "",
        "text": text,
    })


@x64dbg.command('report')
@click.option('--output', '-o', default=None,
              help="Where the files go (default: the current directory)")
@click.option('--name', default=None,
              help="Name of the files (default: x64dbg-report)")
@click.option('--instructions', type=int, default=16,
              help="How many instructions to disassemble (default: 16)")
@click.pass_context
def report(ctx, output, name, instructions):
    """Take a snapshot of the debugger and write it down.

    The snapshot holds the state, the registers, the modules, the
    breakpoints, the disassembly at the instruction pointer, the call stack
    and the memory map - as two files, one to read and one to read with a
    program.

    \b
    Examples:
        ghydra x64dbg report --output out
    """
    try:
        client = _client(ctx)
    except x64dbg_helper.X64dbgError as exc:
        _fail(ctx, exc)
        return

    try:
        snapshot = x64dbg_helper.collect_snapshot(client, instructions)
    except x64dbg_helper.X64dbgError as exc:
        _fail(ctx, exc)
        return

    directory = os.path.abspath(os.path.expanduser(output)) if output else os.getcwd()
    os.makedirs(directory, exist_ok=True)
    stem = name or "x64dbg-report"
    markdown_path = os.path.join(directory, f"{stem}.md")
    json_path = os.path.join(directory, f"{stem}.json")

    snapshot["taken_at"] = time.time()
    with open(markdown_path, "w", encoding="utf-8") as handle:
        handle.write(x64dbg_helper.render_snapshot(snapshot))
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(snapshot, handle, indent=2, ensure_ascii=False)

    payload = {
        "success": True,
        "result": {
            "message": f"The snapshot is in {directory}",
            "markdown": markdown_path,
            "json": json_path,
            "modules": len(snapshot.get("modules") or []),
            "errors": snapshot.get("errors") or [],
        },
    }
    click.echo(ctx.obj['formatter'].format_simple_result(payload))


@x64dbg.command('annotate')
@click.argument('annotations', type=click.Path(exists=True, dir_okay=False))
@click.option('--mode', type=click.Choice(['Comment', 'Label']), default='Comment',
              help="What to put at the address (default: Comment)")
@click.option('--bookmarks', is_flag=True,
              help="Also set a bookmark at every address")
@click.option('--limit', type=int, default=0,
              help="How many annotations to apply (default: all of them)")
@click.pass_context
def annotate(ctx, annotations, mode, bookmarks, limit):
    """Put the annotations of a report into the debugger.

    The file is the one the report writes. The addresses in it are the ones
    in the binary; they are translated into the addresses of the live
    process before they are set.

    \b
    Examples:
        ghydra x64dbg annotate cmd-x64dbg.json --bookmarks
    """
    try:
        client = _client(ctx)
    except x64dbg_helper.X64dbgError as exc:
        _fail(ctx, exc)
        return

    try:
        loaded = x64dbg_helper.load_annotations(annotations)
        result = x64dbg_helper.apply_annotations(
            client, loaded, mode=mode, bookmarks=bookmarks, limit=limit)
    except x64dbg_helper.X64dbgError as exc:
        _fail(ctx, exc)
        return

    payload = {
        "success": True,
        "result": {
            "message": (f"{len(result['applied'])} annotations applied, "
                        f"{len(result['failed'])} failed"),
            **result,
        },
    }
    click.echo(ctx.obj['formatter'].format_simple_result(payload))


@x64dbg.command('setup')
@click.option('--path', 'install', default=None,
              help="Where x64dbg is installed (default: the usual places)")
@click.option('--dry-run', is_flag=True,
              help="Show what would be written, and write nothing")
@click.pass_context
def setup(ctx, install, dry_run):
    """Find the x64dbg plugin's settings and write them down.

    The plugin writes its own settings - the address it binds to, the port
    and the bearer token - to an "mcp_config.json" next to x64dbg.exe. The
    token is the one thing that cannot be guessed, so this finds that file
    and puts what is in it into ~/.ghydra/config.json.

    \b
    Examples:
        ghydra x64dbg setup
        ghydra x64dbg setup --path C:\\tools\\x64dbg --dry-run
    """
    found = x64dbg_helper.find_plugin_config(install or "")
    settings = found.get("config") or {}
    if not settings:
        rich_echo(
            "Error: no mcp_config.json was found. Point at the x64dbg "
            "installation with --path, or start x64dbg once so that the "
            "plugin writes its settings.",
            err=True)
        ctx.exit(1)

    config = ctx.obj['config']
    section = {
        "host": str(settings.get("IpAddress") or config.x64dbg_host or ""),
        "port": int(settings.get("Port") or config.x64dbg_port or 0),
        "token": str(settings.get("AuthToken") or config.x64dbg_token or ""),
        "path": str(found.get("root") or ""),
    }

    payload = {
        "success": True,
        "result": {
            "message": "The x64dbg settings are in the configuration file",
            "found_at": found.get("path", ""),
            "config_path": str(_config_path()),
            "host": section["host"],
            "port": section["port"],
            "token_found": bool(section["token"]),
            "written": False,
        },
    }

    if not dry_run:
        config.x64dbg_host = section["host"]
        config.x64dbg_port = section["port"]
        config.x64dbg_token = section["token"]
        config.x64dbg_path = section["path"]
        from ..config.config_manager import ConfigManager
        ConfigManager.save(config)
        payload["result"]["written"] = True

    click.echo(ctx.obj['formatter'].format_simple_result(payload))


def _config_path():
    """Where the configuration file is."""
    try:
        from ..config.config_manager import ConfigManager
        return ConfigManager.CONFIG_FILE
    except Exception:
        import os
        return os.path.join(os.path.expanduser("~"), ".ghidra", "config.json")
