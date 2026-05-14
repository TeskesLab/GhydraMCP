"""Script execution commands."""

import click

from ..client.exceptions import GhidraError
from ..utils import should_page, page_output, rich_echo


@click.group('script')
def script():
    """Script execution commands.

    Commands for running Python 3 scripts inside Ghidra via PyGhidra.
    """
    pass


@script.command('execute')
@click.option('--code', '-c', required=True, help='Python 3 code to execute (multiline)')
@click.option('--language', type=click.Choice(['python3']), default='python3', help='Script language')
@click.option('--timeout', type=int, default=30, help='Execution timeout in seconds')
@click.pass_context
def execute(ctx, code, language, timeout):
    """Execute a Python 3 script inside Ghidra via PyGhidra.

    The script has access to currentProgram, currentAddress, monitor,
    state, and all Ghidra Java classes via JPype.

    Requires Ghidra to be launched via 'pyghidraRun' for Python 3 support.

    \b
    Examples:
        ghydra script execute --code "print(currentProgram.getName())"
        ghydra script execute -c "from ghidra.program.model.listing import Listing\\nlisting = currentProgram.getListing()\\nprint(listing.getNumInstructions())"
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        data = {
            'code': code,
            'language': language
        }

        params = {}
        if timeout != 30:
            params['timeout'] = timeout

        response = client.post('script/execute', json_data=data, params=params if params else None)
        output = formatter.format_simple_result(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@script.command('capabilities')
@click.pass_context
def capabilities(ctx):
    """Check which script languages/runtimes are available.

    \b
    Example:
        ghydra script capabilities
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        response = client.get('script/capabilities')
        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)
