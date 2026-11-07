"""The doctor command.

It looks at the machine before anything is started, and says what is
missing and what to do about it.
"""

import click

from ..doctor import render_text, run_checks
from ..utils import rich_echo


@click.command('doctor')
@click.option('--host', '-h', default="127.0.0.1",
              help="Host the API is served on (default: 127.0.0.1)")
@click.option('--port', '-p', type=int, default=8192,
              help="Port the API is served on (default: 8192)")
@click.option('--ghidra-home', default=None,
              help="Path of the Ghidra installation (default: the configuration)")
@click.option('--java-home', default=None,
              help="Path of the JDK (default: the configuration)")
@click.option('--project-dir', default=None,
              help="Where the Ghidra projects live (default: ~/ghidra_projects)")
@click.pass_context
def doctor(ctx, host, port, ghidra_home, java_home, project_dir):
    """Check that everything is in place, and say what is not.

    The installation, the JDK it needs, the extension, the port, the
    project directory, the API, Kuna and the x64dbg plugin. Every problem
    comes with the command that solves it.

    \b
    Examples:
        ghydra doctor
        ghydra doctor --port 8193
    """
    config = ctx.obj['config']
    report = run_checks(
        config,
        host=host,
        port=port,
        ghidra_home=ghidra_home or config.ghidra_home,
        java_home=java_home or config.java_home,
        project_dir=project_dir or "",
    )

    if ctx.obj.get('output_json'):
        click.echo(ctx.obj['formatter'].format_simple_result({
            "success": report.ok,
            "result": report.to_dict(),
        }))
    else:
        rich_echo(render_text(report))

    if not report.ok:
        ctx.exit(1)
