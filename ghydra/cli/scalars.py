"""Scalar search commands."""

import click

from ..client.exceptions import GhidraError
from ..utils import should_page, page_output, rich_echo


@click.group('scalars')
def scalars():
    """Scalar (constant) value search commands.

    Commands for finding where constant values appear in instructions.
    """
    pass


@scalars.command('search')
@click.argument('value')
@click.option('--in-function', help='Filter by containing function name (case-insensitive substring)')
@click.option('--to-function', help='Filter by called function name (case-insensitive substring)')
@click.option('--offset', type=int, default=0, help='Pagination offset')
@click.option('--limit', type=int, default=100, help='Maximum results to return')
@click.pass_context
def search_scalars(ctx, value, in_function, to_function, offset, limit):
    """Search for occurrences of a scalar value in instructions.

    \b
    Examples:
        ghydra scalars search 0x1234
        ghydra scalars search 256
        ghydra scalars search 0 --to-function memset
        ghydra scalars search 0x80 --in-function main
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {
            'value': value,
            'offset': offset,
            'limit': limit
        }

        if in_function:
            params['in_function'] = in_function
        if to_function:
            params['to_function'] = to_function

        response = client.get('scalars', params=params)
        output = formatter.format_simple_result(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)
