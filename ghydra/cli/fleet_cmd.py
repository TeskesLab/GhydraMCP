"""`ghydra fleet` — one question, several instances (R7)."""

import json

import click

from ..client.exceptions import GhidraError
from ..client.http_client import GhidraHTTPClient
from ..fleet import KINDS, query, to_text


def _ports(text: str) -> list:
    ports = []
    for piece in str(text or "").replace(";", ",").split(","):
        piece = piece.strip()
        if not piece:
            continue
        try:
            ports.append(int(piece))
        except ValueError:
            raise click.BadParameter(f"not a port: {piece!r}")
    if not ports:
        raise click.BadParameter("give at least one port, e.g. --ports 8192,8193")
    return sorted(set(ports))


def _run(ctx, ports_text, kind, target):
    client = ctx.obj['client']
    config = ctx.obj['config']
    formatter = ctx.obj['formatter']
    try:
        members = {
            port: GhidraHTTPClient(host=client.host, port=port,
                                   timeout=config.timeout)
            for port in _ports(ports_text)
        }
    except click.BadParameter as exc:
        click.echo(f"Error: {exc}", err=True)
        ctx.exit(2)

    try:
        report = query(members, kind, target)
    except GhidraError as exc:
        click.echo(formatter.format_error(exc), err=True)
        ctx.exit(1)

    if not report.get("success", False):
        click.echo(f"Error: {report.get('error')}", err=True)
        ctx.exit(2)

    if ctx.obj.get('output_json'):
        click.echo(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        click.echo(to_text(report))

    # An unreachable member is a fact about the fleet, not a failure of the
    # command: the answer is complete for the members that did answer.
    ctx.exit(0)


@click.group('fleet')
def fleet():
    """Ask one question of several Ghidra instances."""


def _ports_option(function):
    return click.option(
        '--ports', '-p', required=True,
        help='The instances to ask, comma-separated (e.g. 8192,8193)')(function)


@fleet.command('overview')
@_ports_option
@click.pass_context
def overview_cmd(ctx, ports):
    """What each instance has open, merged by file.

    \b
    Example:
        ghydra fleet overview --ports 8192,8193
    """
    _run(ctx, ports, "overview", None)


@fleet.command('has-function')
@_ports_option
@click.argument('name')
@click.pass_context
def has_function_cmd(ctx, ports, name):
    """Which of the fleet's binaries contain this function.

    \b
    Example:
        ghydra fleet has-function main --ports 8192,8193
    """
    _run(ctx, ports, "has_function", name)


@fleet.command('has-import')
@_ports_option
@click.argument('name')
@click.pass_context
def has_import_cmd(ctx, ports, name):
    """Which of the fleet's binaries import this symbol.

    \b
    Example:
        ghydra fleet has-import CreateFileW --ports 8192,8193
    """
    _run(ctx, ports, "has_import", name)


@fleet.command('has-string')
@_ports_option
@click.argument('value')
@click.pass_context
def has_string_cmd(ctx, ports, value):
    """Which of the fleet's binaries contain this string.

    \b
    Example:
        ghydra fleet has-string /api/v1 --ports 8192,8193
    """
    _run(ctx, ports, "has_string", value)


@fleet.command('xrefs-to')
@_ports_option
@click.argument('name')
@click.pass_context
def xrefs_to_cmd(ctx, ports, name):
    """How many references to this name each binary has.

    \b
    Example:
        ghydra fleet xrefs-to strlen --ports 8192,8193
    """
    _run(ctx, ports, "xrefs_to", name)