"""`ghydra target` — the cross-tool workflow of the unification plan, Phase 3.

Three commands, the first three steps of the gateway chain:

    ghydra target describe      analyze_open: both sides, one descriptor
    ghydra target locate main   function_locate: the static address Ghidra knows
    ghydra target breakpoint main  breakpoint_set: translate, and set it

The output is JSON on stdout, unwrapped: this is a workflow a script or an agent
drives, not a table to read. The refusal is the valuable part — `breakpoint` exits
non-zero with `TARGET_NOT_SAME_BINARY` *before* touching the debugger when the two
sides are not the same file.
"""

import json

import click

from .. import target as target_helper
from ..client.exceptions import GhidraError
from ..utils import rich_echo
from .x64dbg import _client as debugger_client


@click.group('target')
def target_group():
    """Work on one target through both sides: static address, runtime address."""


def _settings(ctx):
    """The debugger's settings out of the CLI's configuration."""
    config = (getattr(ctx, "obj", None) or {}).get("config")
    for attribute in ("x64dbg", "debugger"):
        section = getattr(config, attribute, None) if config is not None else None
        if section:
            return section
    return None


def _debugger(ctx):
    """The client for the debugger's MCP server (it knows how to find the token)."""
    return debugger_client(ctx)


def _fail(ctx, exc):
    code = getattr(exc, "code", "") or ""
    prefix = f"Error [{code}]" if code else "Error"
    rich_echo(f"{prefix}: {exc}", err=True)
    ctx.exit(1)


def _emit(context, document):
    # Unwrapped, for the same reason as `mcp-config`: a rendered line break in the
    # middle of a path is not JSON any more.
    click.echo(json.dumps(document, indent=2))


@target_group.command('describe')
@click.pass_context
def describe(ctx):
    """Show the target as both sides see it, and whether they may be correlated.

    \b
    Example:
        ghydra target describe
    """
    ghidra = ctx.obj['client']
    try:
        debugger = _debugger(ctx)
        descriptor = target_helper.describe(ghidra, debugger)
    except (target_helper.TargetError, GhidraError) as exc:
        _fail(ctx, exc)
        return
    except Exception as exc:  # noqa: BLE001 - the debugger raises its own error
        _fail(ctx, exc)
        return
    document = descriptor.as_dict()
    _emit(ctx, document)
    verdict = ("correlatable" if document["correlatable"]
               else "NOT correlatable: " + str(document["identity"]["reason"]))
    rich_echo(f"{document['binary_name']}: {verdict}", err=True)


@target_group.command('locate')
@click.argument('name')
@click.pass_context
def locate(ctx, name):
    """Find a function's static address by name or by address.

    \b
    Example:
        ghydra target locate main
    """
    ghidra = ctx.obj['client']
    try:
        document = target_helper.locate(ghidra, name)
    except (target_helper.TargetError, GhidraError) as exc:
        _fail(ctx, exc)
        return
    _emit(ctx, document)
    rich_echo(f"{document['name']} at {document['static_address']}"
              f" (matched by {document['matched_by']})", err=True)


@target_group.command('breakpoint')
@click.argument('name')
@click.pass_context
def breakpoint(ctx, name):
    """Set a breakpoint in the debugger on a function Ghidra knows.

    The static address is located in Ghidra, translated into the running process,
    and set in the debugger. When the two sides are not looking at the same file
    the command refuses with TARGET_NOT_SAME_BINARY and touches nothing.

    \b
    Examples:
        ghydra target breakpoint main
        ghydra target breakpoint 0x140001234
    """
    ghidra = ctx.obj['client']
    try:
        debugger = _debugger(ctx)
        document = target_helper.breakpoint(ghidra, debugger, name)
    except (target_helper.TargetError, GhidraError) as exc:
        _fail(ctx, exc)
        return
    except Exception as exc:  # noqa: BLE001
        _fail(ctx, exc)
        return
    _emit(ctx, document)
    rich_echo(f"breakpoint {document['function']}: {document['static_address']}"
              f" (static) -> {document['runtime_address']} (runtime)", err=True)