"""Program analysis commands."""

import json
import click
from urllib.parse import quote

from ..client.exceptions import GhidraError
from ..utils import should_page, page_output, rich_echo, validate_address


@click.group('analysis')
def analysis():
    """Program analysis commands.

    Commands for running and retrieving analysis results.
    """
    pass


@analysis.command('run')
@click.option('--analysis-options', help='Analysis options as JSON dict')
@click.option('--background/--foreground', default=True,
              help='Run analysis in background (default) or block until complete')
@click.pass_context
def run_analysis(ctx, analysis_options, background):
    """Run analysis on the current program.

    \b
    Examples:
        ghydra analysis run
        ghydra analysis run --foreground
        ghydra analysis run --analysis-options '{"functionRecovery": true}'
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        payload = {}

        if analysis_options:
            try:
                opts = json.loads(analysis_options)
                if not isinstance(opts, dict):
                    raise click.BadParameter('--analysis-options must be a JSON object')
                payload.update(opts)
            except json.JSONDecodeError as e:
                click.echo(f"Error: Invalid JSON in --analysis-options: {e}", err=True)
                ctx.exit(1)

        payload.setdefault('background', str(background).lower())

        response = client.post('analysis/run', json_data=payload)
        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@analysis.command('get-callgraph')
@click.option('--name', help='Starting function name')
@click.option('--address', '-a', help='Starting function address (hex)')
@click.option('--max-depth', type=int, default=3, help='Max call depth (increase to 10-15 for complex functions)')
@click.pass_context
def get_callgraph(ctx, name, address, max_depth):
    """Get function call graph visualization data.

    One of --name or --address is required.

    \b
    Examples:
        ghydra analysis get-callgraph --name main
        ghydra analysis get-callgraph --address 0x401000 --max-depth 5
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    if not address and not name:
        rich_echo("Error: one of --name or --address is required", err=True)
        ctx.exit(1)

    try:
        # Current plugin reads max_depth; newer upstream servers read depth.
        params = {
            'depth': max_depth,
            'max_depth': max_depth
        }

        if address:
            params['address'] = validate_address(address)
        elif name:
            params['name'] = name

        response = client.get('analysis/callgraph', params=params)
        if hasattr(formatter, "format_callgraph"):
            output = formatter.format_callgraph(response)
        else:
            output = formatter.format_simple_result(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@analysis.command('trace-call-path')
@click.option('--from', 'from_function', required=True,
              help='Where the path starts — a function name or an address (hex)')
@click.option('--to', 'to_function', required=True,
              help='Where the path must end — a function name or an address (hex)')
@click.option('--max-depth', type=int, default=8,
              help='Maximum number of hops to look for (the server accepts at most 16)')
@click.pass_context
def trace_call_path(ctx, from_function, to_function, max_depth):
    """Trace how one function reaches another.

    The call graph says who calls whom; this says which chain of calls goes
    from one function to another. The path it returns is the shortest one
    Ghidra knows about.

    \b
    Examples:
        ghydra analysis trace-call-path --from main --to strcmp
        ghydra analysis trace-call-path --from 0x401000 --to 0x402000 --max-depth 12
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {
            'from': from_function,
            'to': to_function,
            'max_depth': max_depth
        }

        response = client.get('analysis/call-path', params=params)
        output = formatter.format_call_path(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@analysis.command('callers')
@click.argument('address')
@click.option('--offset', type=int, default=0, help='Pagination offset (default: 0)')
@click.option('--limit', type=int, default=100, help='Maximum items to return (default: 100)')
@click.pass_context
def callers(ctx, address, offset, limit):
    """Get the functions that call this function.

    \b
    Example:
        ghydra analysis callers 0x401000
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        response = client.get(f'analysis/callers/{quote(validate_address(address))}',
                              params={'offset': offset, 'limit': limit})
        output = formatter.format_callers(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@analysis.command('callees')
@click.argument('address')
@click.option('--offset', type=int, default=0, help='Pagination offset (default: 0)')
@click.option('--limit', type=int, default=100, help='Maximum items to return (default: 100)')
@click.pass_context
def callees(ctx, address, offset, limit):
    """Get the functions this function calls.

    \b
    Example:
        ghydra analysis callees 0x401000
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        response = client.get(f'analysis/callees/{quote(validate_address(address))}',
                              params={'offset': offset, 'limit': limit})
        output = formatter.format_callees(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@analysis.command('overview')
@click.option('--imports', 'import_limit', type=int, default=25,
              help='How many imports to list (default: 25)')
@click.pass_context
def overview(ctx, import_limit):
    """An overview of the loaded binary.

    What it is, how it is laid out, how much is in it, and what it pulls in
    - the summary a triage pass starts from.

    \b
    Example:
        ghydra analysis overview
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        response = client.get('program')
        segments = client.get('segments')
        imports = client.get('symbols/imports', params={'limit': import_limit})

        program = response.get('result') or {}
        statistics = program.get('statistics') or {}
        meta = imports.get('meta') or {}

        payload = {
            "success": True,
            "result": {
                "program": program,
                "segments": segments.get('result') or [],
                "imports": imports.get('result') or [],
                "statistics": {
                    "functions": statistics.get('functionCount'),
                    "symbols": statistics.get('symbolCount'),
                    "memoryBlocks": statistics.get('memoryBlockCount'),
                    "imports": meta.get('total'),
                }
            }
        }
        output = formatter.format_overview(payload)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@analysis.command('get-dataflow')
@click.option('--address', '-a', required=True, help='Starting address (hex)')
@click.option('--direction', type=click.Choice(['forward', 'backward']), default='forward', help='Analysis direction')
@click.option('--max-steps', type=int, default=50, help='Max analysis steps')
@click.pass_context
def get_dataflow(ctx, address, direction, max_steps):
    """Perform data flow analysis from an address.

    \b
    Examples:
        ghydra analysis get-dataflow --address 0x401000
        ghydra analysis get-dataflow --address 0x401000 --direction backward
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        # The server takes the address as a query param, not a path segment.
        params = {
            'address': validate_address(address),
            'direction': direction,
            'max_steps': max_steps
        }

        response = client.get('analysis/dataflow', params=params)
        if hasattr(formatter, "format_dataflow"):
            output = formatter.format_dataflow(response)
        else:
            output = formatter.format_simple_result(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@analysis.command('status')
@click.pass_context
def status(ctx):
    """Get analysis status for the current program.

    \b
    Example:
        ghydra analysis status
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        response = client.get('analysis/status')
        if hasattr(formatter, "format_analysis_status"):
            output = formatter.format_analysis_status(response)
        else:
            output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@analysis.command('capabilities-summary')
@click.option('--no-strings', is_flag=True,
              help='Skip the defined-strings evidence (imports only)')
@click.pass_context
def capabilities_summary(ctx, no_strings):
    """Rank ATT&CK/MBC-style capability leads for the loaded binary.

    Composes the program, imported symbols and defined strings into one ranked
    report, with the evidence behind each technique. This is a triage lead for
    an analyst, not a verdict.

    \b
    Example:
        ghydra analysis capabilities-summary
        ghydra analysis capabilities-summary --no-strings
    """
    from ..capabilities import build_capability_report

    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        program = client.get('program')
        imports = client.get('symbols/imports', params={'limit': 1000})
        strings = (None if no_strings
                   else client.get('strings', params={'limit': 2000}))
        report = build_capability_report(program, imports, strings,
                                         include_strings=not no_strings)
        output = formatter.format_capabilities_summary(report)
        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)
    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)
