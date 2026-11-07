"""The sessions.

A session is a named working context: the binary, the port that serves
it, and the state of the work. It outlives the shell that opened it, and
the tools keep working on it until it is closed.
"""

import click

from ..sessions import (
    SessionError,
    close_session,
    list_sessions,
    open_session,
)
from ..utils import rich_echo


@click.group('session')
def session():
    """Open a binary and keep it available.

    \b
    Examples:
        ghydra session open C:\\bin\\cmd.exe --name cmd
        ghydra session list
        ghydra session close s-3f9a21c4
    """
    pass


@session.command('open')
@click.argument('binary', type=click.Path(exists=False, dir_okay=False))
@click.option('--name', '-n', default="",
              help="What to call the session (default: the name of the binary)")
@click.option('--port', '-p', type=int, default=8192,
              help="The port to serve on (default: 8192)")
@click.option('--timeout', type=int, default=900,
              help="Seconds to wait for the analysis and the API (default: 900)")
@click.option('--ghidra-home', default=None,
              help="Path of the Ghidra installation (default: GHIDRA_HOME)")
@click.option('--java-home', default=None,
              help="Path of the JDK (default: the one Ghidra supports)")
@click.pass_context
def open_cmd(ctx, binary, name, port, timeout, ghidra_home, java_home):
    """Analyse BINARY and keep it available.

    The analysis of a big binary takes minutes, so the call waits for the
    API to come up.
    """
    formatter = ctx.obj['formatter']
    try:
        opened = open_session(
            binary=binary, name=name, port=port, timeout=timeout,
            ghidra_home=ghidra_home or "", java_home=java_home or "")
    except SessionError as exc:
        rich_echo(formatter.format_error(exc), err=True)
        ctx.exit(1)

    click.echo(formatter.format_simple_result({
        "success": True,
        "result": {
            "message": f"the session '{opened.name}' is open",
            "session": opened.to_dict(),
        },
    }))


@session.command('list')
@click.pass_context
def list_cmd(ctx):
    """The sessions, and what state they are in."""
    sessions = list_sessions()
    click.echo(ctx.obj['formatter'].format_simple_result({
        "success": True,
        "result": {
            "count": len(sessions),
            "sessions": [item.to_dict() for item in sessions],
        },
    }))


@session.command('close')
@click.argument('session_id')
@click.option('--timeout', type=int, default=20,
              help="Seconds to wait for the run to end (default: 20)")
@click.pass_context
def close_cmd(ctx, session_id, timeout):
    """Close a session, saving the analysis on its way out.

    The analysis stays in the project, and the program can be opened in
    Ghidra later.
    """
    formatter = ctx.obj['formatter']
    try:
        closed = close_session(session_id, timeout=timeout)
    except SessionError as exc:
        rich_echo(formatter.format_error(exc), err=True)
        ctx.exit(1)

    click.echo(formatter.format_simple_result({
        "success": True,
        "result": {
            "message": f"the session '{closed.name}' was closed",
            "session": closed.to_dict(),
        },
    }))
