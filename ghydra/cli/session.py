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
    reopen_session,
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
@click.argument('binary', required=False, default="", type=click.Path(exists=False, dir_okay=False))
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
@click.option('--repository-profile', default=None, help="Approved worker repository profile")
@click.option('--program', default=None, help="One literal repository program path")
@click.option('--connections-dir', default=None, help="Private worker profile directory (or GHYDRA_CONNECTIONS_DIR)")
@click.option('--writable', is_flag=True, help="Allow repository writes; requires --commit")
@click.option('--commit', default=None, help="Explicit repository check-in comment")
@click.pass_context
def open_cmd(ctx, binary, name, port, timeout, ghidra_home, java_home,
             repository_profile, program, connections_dir, writable, commit):
    """Analyse BINARY and keep it available.

    The analysis of a big binary takes minutes, so the call waits for the
    API to come up.
    """
    formatter = ctx.obj['formatter']
    try:
        opened = open_session(
            binary=binary, name=name, port=port, timeout=timeout,
            ghidra_home=ghidra_home or "", java_home=java_home or "",
            repository_profile=repository_profile, program=program,
            connections_dir=connections_dir, writable=writable, commit=commit)
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


@session.command('reopen')
@click.argument('session_id')
@click.option('--connections-dir', default=None, help="Private worker profile directory")
@click.option('--timeout', type=int, default=900)
@click.pass_context
def reopen_cmd(ctx, session_id, connections_dir, timeout):
    """Restart a stopped session using current approved worker credentials."""
    formatter = ctx.obj['formatter']
    try:
        opened = reopen_session(session_id, connections_dir=connections_dir, timeout=timeout)
    except SessionError as exc:
        rich_echo(formatter.format_error(exc), err=True)
        ctx.exit(1)
    click.echo(formatter.format_simple_result({"success": True, "result": opened.to_dict()}))
