"""Main CLI entry point for ghydra command."""

import os
import sys

import click

from .. import __version__
from ..client import GhidraHTTPClient
from ..config import ConfigManager, GhidraConfig
from ..formatters import JSONFormatter, TableFormatter


class GhydraCLI(click.Group):
    """The root group, with --json accepted in any position.

    Click parses the root group's own options only *before* the subcommand
    name, so ``ghydra functions list --json`` used to be a usage error. The
    group lifts a ``--json`` found anywhere in the arguments into an
    environment variable the root option also reads, then parses what is
    left — so both positions work and no subcommand ever sees the flag.
    """

    def main(self, args=None, **extra):
        if args is None:
            args = sys.argv[1:]
        if "--json" in args:
            os.environ["GHYDRA_JSON"] = "1"
            args = [arg for arg in args if arg != "--json"]
        return super().main(args=args, **extra)


@click.group(cls=GhydraCLI)
@click.option('--host', '-h', envvar='GHYDRA_HOST', help='Ghidra host (default: from config or localhost)')
@click.option('--port', '-p', type=int, envvar='GHYDRA_PORT', help='Ghidra port (default: from config or 8192)')
@click.option('--json', 'output_json', is_flag=True, envvar='GHYDRA_JSON',
              help='Output raw JSON instead of formatted text (accepted in any position)')
@click.option('--no-color', is_flag=True, help='Disable colored output')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.version_option(version=__version__, prog_name='ghydra')
@click.pass_context
def cli(ctx, host, port, output_json, no_color, verbose):
    """Ghydra CLI - Interact with Ghidra reverse engineering tool.

    This CLI provides command-line access to all Ghidra functionality exposed
    by the GhydraMCP plugin via a HATEOAS REST API.

    \b
    Examples:
        # List all Ghidra instances
        ghydra instances list

        # Decompile a function
        ghydra functions decompile --name main

        # Read memory as hex dump
        ghydra memory read --address 0x401000 --length 64

        # List all strings
        ghydra data list-strings

    \b
    Configuration:
        Configuration file: ~/.ghydra/config.json
        Environment variables: GHYDRA_HOST, GHYDRA_PORT

    For more information, visit: https://github.com/TeskesLab/GhydraMCP
    """
    # Rich's tables use frame characters outside cp1252; on a Western Windows
    # pipe (sys.stdout.encoding == 'cp1252') click.echo used to raise
    # UnicodeEncodeError on every table. Reconfigure both streams once, here,
    # so every subcommand inherits UTF-8 with replacement instead of dying.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                # A stream that cannot be reconfigured (already-closed, or a
                # non-text wrapper) keeps its encoding; errors="replace" on
                # the echo side is the fallback.
                pass

    # Load configuration
    try:
        config = ConfigManager.load(verbose=verbose)
    except Exception as e:
        if verbose:
            click.echo(f"Warning: Failed to load config: {e}", err=True)
        config = GhidraConfig()

    # Override with CLI options
    if host:
        config.default_host = host
    if port:
        config.default_port = port
    if no_color:
        config.use_colors = False

    # Create HTTP client
    client = GhidraHTTPClient(
        host=config.default_host,
        port=config.default_port,
        timeout=config.timeout
    )

    # Create formatter
    if output_json:
        formatter = JSONFormatter(pretty=True)
    else:
        formatter = TableFormatter(use_colors=config.use_colors)

    # Store in context for subcommands
    ctx.ensure_object(dict)
    ctx.obj['config'] = config
    ctx.obj['verbose'] = verbose
    ctx.obj['client'] = client
    ctx.obj['formatter'] = formatter
    ctx.obj['output_json'] = output_json


# Import and register command groups
from . import (
    instances,
    functions,
    memory,
    data,
    structs,
    xrefs,
    scalars,
    scripts,
    analysis,
    ui,
    comments,
    project,
    classes,
    symbols,
    segments,
    namespaces,
    variables,
    datatypes,
    raw_image,
    kuna,
    x64dbg,
    headless,
    report,
    doctor,
    evidence,
    session,
    inspect,
    inspect_address,
)

from .stats import stats as stats_command

cli.add_command(instances.instances)
cli.add_command(functions.functions)
cli.add_command(memory.memory)
cli.add_command(data.data)
cli.add_command(structs.structs)
cli.add_command(xrefs.xrefs)
cli.add_command(scalars.scalars)
cli.add_command(scripts.scripts)
cli.add_command(analysis.analysis)
cli.add_command(ui.ui)
cli.add_command(comments.comments)
cli.add_command(project.project)
cli.add_command(classes.classes)
cli.add_command(symbols.symbols)
cli.add_command(segments.segments)
cli.add_command(namespaces.namespaces)
cli.add_command(variables.variables)
cli.add_command(datatypes.datatypes)
cli.add_command(raw_image.raw_image)
cli.add_command(kuna.kuna)
cli.add_command(x64dbg.x64dbg)
cli.add_command(headless.headless)
cli.add_command(report.report)
cli.add_command(doctor.doctor)
cli.add_command(evidence.evidence)
cli.add_command(session.session)
cli.add_command(inspect.inspect)
cli.add_command(stats_command)
cli.add_command(inspect_address.inspect_address)


@cli.command('version')
def version_cmd():
    """Show version information."""
    click.echo(f"ghydra version {__version__}")
    click.echo("Ghydra CLI for Ghidra reverse engineering tool")


if __name__ == '__main__':
    cli()
