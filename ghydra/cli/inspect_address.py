"""The address inspection.

An agent that lands on an address has to ask four questions: what is
called here, what function is it in, what does it hold, and who refers to
it. This answers all four at once - the symbol, the containing function,
the data, the instruction, the comments, and the references on both sides
of the address.
"""

from urllib.parse import quote

import click

from ..client.exceptions import GhidraError
from ..utils import rich_echo, validate_address


@click.command('inspect-address')
@click.argument('address')
@click.pass_context
def inspect_address(ctx, address):
    """Say what is at ADDRESS, in one call.

    An agent that lands on an address has to ask four questions: what is
    called here, what function is it in, what does it hold, and who refers
    to it. This answers all four at once - the symbol, the containing
    function, the data, the instruction, the comments, and the references on
    both sides of the address.

    \b
    Example:
        ghydra inspect-address 0x140001008
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        response = client.get(f'inspect/address/{quote(validate_address(address))}')
        click.echo(formatter.format_address_context(response))

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)
