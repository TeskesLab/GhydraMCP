"""`ghydra mcp-config`: one client configuration for both servers.

Phase 2 of the unification plan. The command writes (or prints) a configuration in
the shape MCP clients already understand, with the two servers registered
separately so a client can enable or disable each — the plan's mitigation for
"165 tools in one context degrades tool selection".

The token of the debugger is a secret. It is written into the file when the caller
asks for a file, and **masked** in everything printed unless `--show-secrets` is
given: a bearer token echoed into a terminal ends up in a shell history file.
"""

import json

import click

from .. import mcpconfig
from ..utils import rich_echo


@click.command('mcp-config')
@click.option('--groups', default=None,
              help="The tool groups to load, comma-separated (default: all). "
                   "eg core,functions")
@click.option('--host', default=None,
              help="The Ghidra host the bridge should prefer (default: discovery)")
@click.option('--output', '-o', default=None,
              help="Write the configuration here instead of printing it")
@click.option('--no-x64dbg', is_flag=True, default=False,
              help="Leave the debugger out, even when its token is known")
@click.option('--show-secrets', is_flag=True, default=False,
              help="Print the debugger token instead of masking it")
@click.pass_context
def mcp_config(ctx, groups, host, output, no_x64dbg, show_secrets):
    """Build the combined MCP client configuration.

    One file that registers both servers: the Ghidra bridge over stdio, and the
    x64dbg MCP server over HTTP with its bearer token. They stay separately
    registered, so a client can enable one without the other.

    \b
    Examples:
        ghydra mcp-config                          # print it (token masked)
        ghydra mcp-config --groups core,functions  # a smaller tool list
        ghydra mcp-config -o claude_desktop.json   # write it for a client
    """
    formatter = ctx.obj['formatter']
    try:
        selected = mcpconfig.parse_groups(groups)
    except ValueError as exc:
        rich_echo(f"error: {exc}", err=True)
        ctx.exit(1)
        return

    try:
        document = mcpconfig.build(groups=selected, host=host,
                                   include_debugger=not no_x64dbg)
    except Exception as exc:  # noqa: BLE001 - the reason is the message
        rich_echo(f"error: {exc}", err=True)
        ctx.exit(1)
        return

    if output:
        written = mcpconfig.write(document, output)
        rich_echo(f"wrote {written}")
        if any("Authorization" in json.dumps(entry)
               for entry in (document.get("mcpServers") or {}).values()):
            rich_echo("the file carries the debugger token: keep it out of "
                      "version control", err=True)
        for line in mcpconfig.summary(document):
            rich_echo(line, err=True)
        return

    # Straight to stdout, not through Rich: Rich wraps a long line inside a
    # string, and a configuration wrapped in the middle of a Windows path is not
    # JSON any more - which makes `ghydra mcp-config | jq` fail for no visible
    # reason.
    shown = document if show_secrets else mcpconfig.mask(document)
    click.echo(json.dumps(shown, indent=2))
    for line in mcpconfig.summary(document, include_secrets=show_secrets):
        rich_echo(line, err=True)