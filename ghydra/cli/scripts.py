"""Ghidra script execution commands."""

import os

import click

from ..client.exceptions import GhidraError
from ..utils import should_page, page_output, rich_echo


@click.group('scripts')
def scripts():
    """Run Ghidra scripts (must be enabled on the server).

    Requires the Ghidra plugin started with -Dghydra.dev.allowScripts=true (or
    GHYDRA_ALLOW_SCRIPTS=1). Running a script is arbitrary code execution.
    """
    pass


@scripts.command('list')
@click.pass_context
def list_scripts(ctx):
    """List Ghidra scripts available to run."""
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        response = client.get('scripts')
        output = formatter.format_simple_result(response)
        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)
    except GhidraError as e:
        rich_echo(formatter.format_error(e), err=True)
        ctx.exit(1)


@scripts.command('run')
@click.option('--name', help='Name of an existing script (e.g. "MyScript.java" or "Probe.py")')
@click.option('--file', 'source_file', type=click.Path(exists=True, dir_okay=False),
              help='Path to a script source file to run ad-hoc (.java or .py)')
@click.option('--code', 'source_code', help='Inline script source (Java or Python 3)')
@click.option('--language', type=click.Choice(['java', 'python'], case_sensitive=False),
              default=None,
              help='Runtime for ad-hoc source. Defaults to the --file extension, then java.')
@click.option('--filename', default=None,
              help='Original filename to preserve, e.g. probe.py (a .py name selects Python 3)')
@click.option('--arg', 'args', multiple=True, help='Script argument (repeatable)')
@click.pass_context
def run_script(ctx, name, source_file, source_code, language, filename, args):
    """Run a Ghidra script by --name, or ad-hoc from --file / --code.

    Python 3 ad-hoc source needs Ghidra launched with pyghidraRun. A .py
    --file keeps its basename and selects PyGhidra explicitly; use --language
    python for inline --code. Installing the extension alone does not
    initialize the Python runtime.

    \b
    Examples:
        ghydra scripts run --name FixupNoReturnFunctionsScript.java
        ghydra scripts run --file ./MassRename.java --arg prefix_
        ghydra scripts run --file ./probe.py
        ghydra scripts run --code "print(currentProgram.getName())" --language python
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    if not name and not source_file and not source_code:
        rich_echo("[red]Error:[/red] one of --name, --file or --code is required", err=True)
        ctx.exit(1)

    payload = {}
    if name:
        payload['name'] = name
    if source_file:
        with open(source_file, 'r', encoding='utf-8') as handle:
            payload['source'] = handle.read()
        # Keep the extension: sending only the source text used to lose ".py"
        # and the server always wrote a .java file.
        if not filename:
            filename = os.path.basename(source_file)
    if source_code:
        payload['source'] = source_code

    if filename:
        payload['filename'] = filename
    lang = language
    if not lang and filename:
        lower = filename.lower()
        if lower.endswith('.py'):
            lang = 'python'
        elif lower.endswith('.java'):
            lang = 'java'
    if lang:
        payload['language'] = lang.lower()
    if args:
        payload['args'] = list(args)

    try:
        response = client.post('scripts/run', json_data=payload)
        if ctx.obj['output_json']:
            click.echo(formatter.format_simple_result(response))
            return
        result = response.get('result', {}) or {}
        output = (result.get('output') or '').rstrip()
        if output:
            click.echo(output)
        if result.get('success'):
            rich_echo(f"[green][{result.get('script', 'script')} OK][/green]", err=True)
        else:
            rich_echo(f"[red]Script failed:[/red] {result.get('error')}", err=True)
            ctx.exit(1)
    except GhidraError as e:
        rich_echo(formatter.format_error(e), err=True)
        ctx.exit(1)
