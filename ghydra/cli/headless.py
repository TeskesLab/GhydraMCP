"""Headless GhydraMCP commands.

A headless run imports and analyses a binary and then serves the same REST
API that the CodeBrowser plugin serves - with no window and nobody watching.
"""

import click

from ..headless import (
    DEFAULT_PORT,
    DEFAULT_TIMEOUT,
    HeadlessError,
    HeadlessRunner,
    status,
)
from ..utils import rich_echo


@click.group('headless')
def headless():
    """Run the GhydraMCP API without a window.

    \b
    Examples:
        # Analyse a binary and serve the API on 8192
        ghydra headless start C:\\bin\\cmd.exe

        # What is running
        ghydra headless status

        # Stop it (the analysis is saved first)
        ghydra headless stop
    """
    pass


@headless.command('start')
@click.argument('binary', required=False, default="", type=click.Path(exists=False, dir_okay=False))
@click.option('--port', '-p', type=int, default=DEFAULT_PORT,
              help=f"Port to serve on (default: {DEFAULT_PORT})")
@click.option('--project-dir', default=None,
              help="Where the Ghidra project lives (default: ~/.ghydra/projects)")
@click.option('--project-name', default=None,
              help="Name of the Ghidra project (default: the name of the binary, with a mark of its path)")
@click.option('--ghidra-home', default=None,
              help="Path of the Ghidra installation (default: GHIDRA_HOME)")
@click.option('--java-home', default=None,
              help="Path of the JDK (default: JAVA_HOME)")
@click.option('--timeout', type=int, default=DEFAULT_TIMEOUT,
              help=f"Seconds to wait for the API (default: {DEFAULT_TIMEOUT})")
@click.option('--repository-profile', default=None, help="Approved worker repository profile")
@click.option('--program', default=None, help="One literal repository program path")
@click.option('--connections-dir', default=None, help="Private worker profile directory (or GHYDRA_CONNECTIONS_DIR)")
@click.option('--writable', is_flag=True, help="Explicitly allow repository writes; requires --commit")
@click.option('--commit', default=None, help="Explicit repository check-in comment")
@click.pass_context
def start(ctx, binary, port, project_dir, project_name, ghidra_home, java_home, timeout,
          repository_profile, program, connections_dir, writable, commit):
    """Analyse BINARY and serve the API from it.

    The run outlives this command: it keeps serving until it is stopped with
    "ghydra headless stop".

    \b
    Example:
        ghydra headless start C:\\bin\\cmd.exe --port 8192
    """
    formatter = ctx.obj['formatter']

    try:
        runner = HeadlessRunner(
            binary=binary,
            port=port,
            project_dir=project_dir,
            project_name=project_name,
            ghidra_home=ghidra_home,
            java_home=java_home,
            repository_profile=repository_profile, program=program,
            connections_dir=connections_dir, writable=writable, commit=commit,
        )
        instance = runner.start(timeout=timeout)
    except HeadlessError as exc:
        rich_echo(formatter.format_error(exc), err=True)
        ctx.exit(1)

    payload = {
        "success": True,
        "result": {
            "message": f"The API is serving on {instance.url}",
            "port": instance.port,
            "url": instance.url,
            "pid": instance.pid,
            "program": instance.program or instance.binary,
            "project": instance.repository_profile or f"{instance.project_dir}/{instance.project_name}",
            "repository_profile": instance.repository_profile,
            "read_only": bool(instance.repository_profile and not instance.writable),
            "log": instance.log,
        },
    }
    click.echo(formatter.format_simple_result(payload))


@headless.command('status')
@click.option('--port', '-p', type=int, default=DEFAULT_PORT,
              help=f"Port to look at (default: {DEFAULT_PORT})")
@click.pass_context
def status_cmd(ctx, port):
    """What is running on the port.

    \b
    Example:
        ghydra headless status
    """
    formatter = ctx.obj['formatter']
    payload = {"success": True, "result": status(port)}
    click.echo(formatter.format_simple_result(payload))


@headless.command('stop')
@click.option('--port', '-p', type=int, default=DEFAULT_PORT,
              help=f"Port to stop (default: {DEFAULT_PORT})")
@click.option('--timeout', type=int, default=20,
              help="Seconds to wait for the run to end (default: 20)")
@click.pass_context
def stop(ctx, port, timeout):
    """Stop the headless run on the port.

    The analysis is saved first, so the project holds it and the program can
    be opened in Ghidra later.

    \b
    Example:
        ghydra headless stop
    """
    formatter = ctx.obj['formatter']

    from ..headless import load_state

    instance = load_state(port)
    if instance is None:
        rich_echo(formatter.format_error(
            f"no headless run is known on port {port}"), err=True)
        ctx.exit(1)

    runner = HeadlessRunner.from_instance(instance)
    try:
        saved = runner.stop(timeout)
    except HeadlessError as exc:
        rich_echo(formatter.format_error(exc), err=True)
        ctx.exit(1)

    payload = {
        "success": True,
        "result": {
            "message": f"The run on port {port} was stopped",
            "port": port,
            "saved": instance.repository_saved if instance.repository_profile else saved,
            "checked_in": instance.checked_in if instance.repository_profile else None,
            "confirmation_unknown": bool(instance.repository_profile and
                                         (instance.repository_saved is None or instance.checked_in is None)),
        },
    }
    click.echo(formatter.format_simple_result(payload))
