"""Function analysis commands."""

import click
from urllib.parse import quote

from ..client.exceptions import GhidraError
from ..utils import (MAX_BATCH_TARGETS, should_page, page_output, parse_targets,
                     rich_echo, validate_address)

DEFAULT_DECOMPILATION_TIMEOUT = 1200


@click.group('functions')
def functions():
    """Function analysis and manipulation commands.

    Commands for listing, analyzing, and modifying functions in the binary.
    """
    pass


@functions.command('list')
@click.option('--offset', type=int, default=0, help='Pagination offset')
@click.option('--limit', type=int, default=100, help='Maximum results to return')
@click.option('--name-contains', help='Filter by function name substring (case-insensitive)')
@click.option('--name-matches', help='Filter by function name regex pattern')
@click.option('--containing-address', help='Find function containing this address (hex)')
@click.option('--addr-min', help='Only return functions at or above this address (hex)')
@click.option('--addr-max', help='Only return functions at or below this address (hex)')
@click.pass_context
def list_functions(ctx, offset, limit, name_contains, name_matches, containing_address,
                   addr_min, addr_max):
    """List all functions with optional filtering.

    \b
    Examples:
        ghydra functions list
        ghydra functions list --name-contains main
        ghydra functions list --name-matches "^sub_.*"
        ghydra functions list --containing-address 0x401234
        ghydra functions list --addr-min 0x401000 --addr-max 0x402000
        ghydra functions list --limit 50
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {
            'offset': offset,
            'limit': limit
        }

        if name_contains:
            params['name_contains'] = name_contains
        if name_matches:
            params['name_matches_regex'] = name_matches
        if containing_address:
            params['containing_addr'] = validate_address(containing_address)
        if addr_min:
            params['addr_min'] = validate_address(addr_min)
        if addr_max:
            params['addr_max'] = validate_address(addr_max)

        response = client.get('functions', params=params)
        output = formatter.format_functions_list(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('search')
@click.argument('name')
@click.option('--regex', '-r', is_flag=True, help='Treat NAME as a regex pattern')
@click.option('--offset', type=int, default=0, help='Pagination offset')
@click.option('--limit', type=int, default=100, help='Maximum results to return')
@click.pass_context
def search_functions(ctx, name, regex, offset, limit):
    """Search for functions by name.

    \b
    Examples:
        ghydra functions search ClassifyStar
        ghydra functions search main
        ghydra functions search --regex "^sub_.*"
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {'offset': offset, 'limit': limit}
        if regex:
            params['name_matches_regex'] = name
        else:
            params['name_contains'] = name

        response = client.get('functions', params=params)
        output = formatter.format_functions_list(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('get-containing')
@click.argument('address')
@click.pass_context
def get_containing(ctx, address):
    """Find the function containing the specified address.

    \b
    Example:
        ghydra functions get-containing 0x401234
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {'containing_addr': validate_address(address)}
        response = client.get('functions', params=params)
        output = formatter.format_functions_list(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('get-next')
@click.argument('address')
@click.pass_context
def get_next(ctx, address):
    """Get the next function after the given address (by memory order).

    \b
    Example:
        ghydra functions get-next 0x401000
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {'after': validate_address(address)}
        response = client.get('functions', params=params)
        output = formatter.format_functions_list(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('get-prev')
@click.argument('address')
@click.pass_context
def get_prev(ctx, address):
    """Get the previous function before the given address (by memory order).

    \b
    Example:
        ghydra functions get-prev 0x402000
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {'before': validate_address(address)}
        response = client.get('functions', params=params)
        output = formatter.format_functions_list(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('get')
@click.option('--name', '-n', help='Function fully-qualified name (e.g. "FOM::Read"); a bare name matches the global namespace only')
@click.option('--address', '-a', help='Function address (hex)')
@click.pass_context
def get_function(ctx, name, address):
    """Get detailed information about a function.

    Either --name or --address must be specified.

    \b
    Examples:
        ghydra functions get --name main
        ghydra functions get --address 0x401000
    """
    if not name and not address:
        rich_echo("[red]Error:[/red] Either --name or --address is required", err=True)
        ctx.exit(1)

    if name and address:
        rich_echo("[red]Error:[/red] Cannot specify both --name and --address", err=True)
        ctx.exit(1)

    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        # Build endpoint
        if address:
            endpoint = f'functions/{validate_address(address)}'
        else:
            endpoint = f'functions/by-name/{quote(name)}'

        # Make API request
        response = client.get(endpoint)

        output = formatter.format_function_info(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('decompile')
@click.option('--name', '-n', help='Function fully-qualified name (e.g. "FOM::Read"); a bare name matches the global namespace only')
@click.option('--address', '-a', help='Function address (hex)')
@click.option('--syntax-tree', is_flag=True, help='Include syntax tree in output')
@click.option('--style', default='normalize', help='Decompiler style (default: normalize)')
@click.option('--no-constants', is_flag=True, help='Hide constant values')
@click.option('--timeout', type=int, default=DEFAULT_DECOMPILATION_TIMEOUT,
              help=f'Decompilation timeout in seconds (default: {DEFAULT_DECOMPILATION_TIMEOUT})')
@click.option('--start-line', type=int, help='Start line (1-indexed)')
@click.option('--end-line', type=int, help='End line (inclusive)')
@click.option('--max-lines', type=int, help='Maximum lines to return')
@click.pass_context
def decompile(ctx, name, address, syntax_tree, style, no_constants, timeout, start_line, end_line, max_lines):
    """Decompile a function to C pseudocode.

    Either --name or --address must be specified.

    \b
    Examples:
        ghydra functions decompile --name main
        ghydra functions decompile --address 0x401000
        ghydra functions decompile --name main --start-line 10 --end-line 20
    """
    if not name and not address:
        rich_echo("[red]Error:[/red] Either --name or --address is required", err=True)
        ctx.exit(1)

    if name and address:
        rich_echo("[red]Error:[/red] Cannot specify both --name and --address", err=True)
        ctx.exit(1)

    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        # Build endpoint
        if address:
            endpoint = f'functions/{validate_address(address)}/decompile'
        else:
            endpoint = f'functions/by-name/{quote(name)}/decompile'

        # Build query parameters
        params = {
            'syntax_tree': str(syntax_tree).lower(),
            'style': style,
            'show_constants': str(not no_constants).lower(),
            'timeout': timeout
        }

        if start_line:
            params['start_line'] = start_line
        if end_line:
            params['end_line'] = end_line
        if max_lines:
            params['max_lines'] = max_lines

        # Keep HTTP timeout slightly above requested decompilation timeout
        # so client transport timeout does not fire first.
        original_timeout = client.timeout
        client.timeout = max(original_timeout, timeout + 30)
        try:
            response = client.get(endpoint, params=params)
        finally:
            client.timeout = original_timeout

        output = formatter.format_decompiled_code(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('decompile-batch')
@click.option('--targets', required=True,
              help='The functions to decompile: JSON text (e.g. \'["main","0x401000"]\'), a comma-separated list, or one name')
@click.option('--timeout', type=int, default=120,
              help='Decompilation timeout per function, in seconds (default: 120)')
@click.pass_context
def decompile_batch(ctx, targets, timeout):
    """Decompile a list of functions in one call.

    Each target is a function name or an address. A target that resolves to
    nothing comes back as a failed entry, so one wrong name does not cost
    the whole batch.

    \b
    Examples:
        ghydra functions decompile-batch --targets '["main","0x401000"]'
        ghydra functions decompile-batch --targets main,strcmp
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        wanted = parse_targets(targets)
    except ValueError as e:
        rich_echo(f"[red]Error:[/red] {e}", err=True)
        ctx.exit(1)

    if not wanted:
        rich_echo("[red]Error:[/red] No targets given", err=True)
        ctx.exit(1)

    try:
        # Keep the HTTP timeout above the whole batch: every target gets its
        # own decompilation timeout, and the server runs them one after the
        # other, so the transport must not fire before the last one is done.
        # The count is the one the server accepts - a longer batch is refused.
        original_timeout = client.timeout
        client.timeout = max(original_timeout,
                              timeout * min(len(wanted), MAX_BATCH_TARGETS) + 60)
        try:
            response = client.post('functions/decompile-batch',
                                   json_data={'targets': wanted, 'timeout': timeout})
        finally:
            client.timeout = original_timeout

        output = formatter.format_batch_decompile(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('analyze')
@click.option('--name', '-n', help='Function fully-qualified name (e.g. "FOM::Read"); a bare name matches the global namespace only')
@click.option('--address', '-a', help='Function address (hex)')
@click.option('--xref-limit', type=int, default=50, help='How many references to return (default: 50)')
@click.pass_context
def analyze(ctx, name, address, xref_limit):
    """Everything about one function, in one call.

    The decompilation, the callers, the callees and the references - the
    pieces an agent pays a round trip for when it has just found a
    function.

    \b
    Examples:
        ghydra functions analyze --name main
        ghydra functions analyze --address 0x401000
    """
    if not name and not address:
        rich_echo("[red]Error:[/red] Either --name or --address is required", err=True)
        ctx.exit(1)
    if name and address:
        rich_echo("[red]Error:[/red] Cannot specify both --name and --address", err=True)
        ctx.exit(1)

    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        if address:
            info = client.get(f'functions/{quote(validate_address(address))}')
        else:
            info = client.get(f'functions/by-name/{quote(name)}')

        function = info.get('result') or {}
        resolved = function.get('address') or address
        if not resolved:
            rich_echo(f"[red]Error:[/red] The function '{name or address}' has no address", err=True)
            ctx.exit(1)

        # A composed answer must not hide a failure, and it must not lose
        # what it already has: the function was found, and the decompilation
        # came with it. A part that failed is reported as empty, and only the
        # function - the thing the caller asked for - decides the success.
        def _part(call):
            """One part of the answer, and the reason it is not there."""
            try:
                return call(), None
            except GhidraError as exc:
                return None, str(exc)

        decompiled, decompile_error = _part(
            lambda: client.get(f'functions/{quote(resolved)}/decompile'))
        callers, _ = _part(
            lambda: client.get(f'analysis/callers/{quote(resolved)}'))
        callees, _ = _part(
            lambda: client.get(f'analysis/callees/{quote(resolved)}'))
        xrefs, _ = _part(
            lambda: client.get('xrefs', params={'to_addr': resolved, 'limit': xref_limit}))

        def _list_of(response):
            payload = (response or {}).get('result')
            return payload if isinstance(payload, list) else []

        code = (decompiled or {}).get('result') or {}
        payload = {
            "success": True,
            "result": {
                "function": function,
                "decompilation": code.get('decompilation'),
                "decompileError": code.get('errorMessage') or decompile_error,
                "callers": _list_of(callers),
                "callees": _list_of(callees),
                "xrefs": _list_of(xrefs),
            }
        }
        output = formatter.format_function_analysis(payload)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('disassemble')
@click.option('--name', '-n', help='Function fully-qualified name (e.g. "FOM::Read"); a bare name matches the global namespace only')
@click.option('--address', '-a', help='Function address (hex)')
@click.option('--offset', '-o', default=0, type=int, help='Number of instructions to skip')
@click.option('--limit', '-l', default=0, type=int, help='Max instructions to return (0 = all)')
@click.pass_context
def disassemble(ctx, name, address, offset, limit):
    """Get disassembly for a function.

    Either --name or --address must be specified.

    \b
    Examples:
        ghydra functions disassemble --name main
        ghydra functions disassemble --address 0x401000
        ghydra functions disassemble --name main --offset 50 --limit 100
    """
    if not name and not address:
        rich_echo("[red]Error:[/red] Either --name or --address is required", err=True)
        ctx.exit(1)

    if name and address:
        rich_echo("[red]Error:[/red] Cannot specify both --name and --address", err=True)
        ctx.exit(1)

    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        if address:
            endpoint = f'functions/{validate_address(address)}/disassembly'
        else:
            endpoint = f'functions/by-name/{quote(name)}/disassembly'

        params = {}
        if offset > 0:
            params['offset'] = offset
        if limit > 0:
            params['limit'] = limit

        response = client.get(endpoint, params=params)

        output = formatter.format_disassembly(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('create')
@click.option('--address', '-a', required=True, help='Address for new function (hex)')
@click.pass_context
def create_function(ctx, address):
    """Create a new function at specified address.

    \b
    Example:
        ghydra functions create --address 0x401500
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        response = client.post('functions', json_data={'address': validate_address(address)})

        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('rename')
@click.option('--old-name', help='Current fully-qualified function name; a bare name matches the global namespace only')
@click.option('--address', '-a', help='Function address (hex)')
@click.option('--new-name', required=True, help='New FQN; "A::B::foo" moves into namespace A::B (created if absent); leading "::" moves to global; bare keeps the current namespace')
@click.pass_context
def rename_function(ctx, old_name, address, new_name):
    """Rename a function.

    Either --old-name or --address must be specified.

    \b
    Examples:
        ghydra functions rename --old-name sub_401000 --new-name main
        ghydra functions rename --address 0x401000 --new-name main
    """
    if not old_name and not address:
        rich_echo("[red]Error:[/red] Either --old-name or --address is required", err=True)
        ctx.exit(1)

    if old_name and address:
        rich_echo("[red]Error:[/red] Cannot specify both --old-name and --address", err=True)
        ctx.exit(1)

    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        # Build endpoint
        if address:
            endpoint = f'functions/{validate_address(address)}'
        else:
            endpoint = f'functions/by-name/{quote(old_name)}'

        # Make API request
        data = {'name': new_name}
        response = client.patch(endpoint, data=data)

        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('set-signature')
@click.option('--name', '-n', help='Function fully-qualified name (e.g. "FOM::Read"); a bare name matches the global namespace only')
@click.option('--address', '-a', help='Function address (hex)')
@click.option('--signature', required=True, help='Function signature (e.g., "int func(char *data, int size)")')
@click.pass_context
def set_signature(ctx, name, address, signature):
    """Set function signature/prototype.

    Either --name or --address must be specified.

    \b
    Examples:
        ghydra functions set-signature --name main --signature "int main(int argc, char **argv)"
        ghydra functions set-signature --address 0x401000 --signature "void func(void)"
    """
    if not name and not address:
        rich_echo("[red]Error:[/red] Either --name or --address is required", err=True)
        ctx.exit(1)

    if name and address:
        rich_echo("[red]Error:[/red] Cannot specify both --name and --address", err=True)
        ctx.exit(1)

    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        # Build endpoint
        if address:
            endpoint = f'functions/{validate_address(address)}'
        else:
            endpoint = f'functions/by-name/{quote(name)}'

        # Make API request
        data = {'signature': signature}
        response = client.patch(endpoint, data=data)

        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('delete')
@click.option('--name', '-n', help='Function fully-qualified name (e.g. "FOM::Read"); a bare name matches the global namespace only')
@click.option('--address', '-a', help='Function address (hex)')
@click.pass_context
def delete_function(ctx, name, address):
    """Delete a function."""
    if not name and not address:
        rich_echo("[red]Error:[/red] Either --name or --address is required", err=True)
        ctx.exit(1)

    if name and address:
        rich_echo("[red]Error:[/red] Cannot specify both --name and --address", err=True)
        ctx.exit(1)

    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        if address:
            endpoint = f'functions/{validate_address(address)}'
        else:
            endpoint = f'functions/by-name/{quote(name)}'

        response = client.delete(endpoint)
        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('get-variables')
@click.option('--name', '-n', help='Function fully-qualified name (e.g. "FOM::Read"); a bare name matches the global namespace only')
@click.option('--address', '-a', help='Function address (hex)')
@click.pass_context
def get_variables(ctx, name, address):
    """Get variables for a function.

    Either --name or --address must be specified.

    \b
    Examples:
        ghydra functions get-variables --name main
        ghydra functions get-variables --address 0x401000
    """
    if not name and not address:
        rich_echo("[red]Error:[/red] Either --name or --address is required", err=True)
        ctx.exit(1)

    if name and address:
        rich_echo("[red]Error:[/red] Cannot specify both --name and --address", err=True)
        ctx.exit(1)

    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        # Build endpoint
        if address:
            endpoint = f'functions/{validate_address(address)}/variables'
        else:
            endpoint = f'functions/by-name/{quote(name)}/variables'

        # Make API request
        response = client.get(endpoint)

        output = formatter.format_function_info(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('set-comment')
@click.option('--address', '-a', required=True, help='Function address (hex)')
@click.option('--comment', required=True, help='Comment text (empty string removes comment)')
@click.pass_context
def set_comment(ctx, address, comment):
    """Set a decompiler-friendly comment at a function.

    Tries to set the function's plate comment first; falls back to a pre-comment
    at the entry address if the function PATCH is unavailable.

    \b
    Example:
        ghydra functions set-comment --address 0x401000 --comment "Main entry point"
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    addr = validate_address(address)

    try:
        response = client.patch(f'functions/{addr}', data={'comment': comment})
        output = formatter.format_simple_result(response)
        click.echo(output)
        return
    except GhidraError as primary_err:
        # Fall back to a pre-comment if the function endpoint can't set the comment.
        try:
            response = client.post(
                f'memory/{addr}/comments/pre',
                json_data={'comment': comment},
            )
            output = formatter.format_simple_result(response)
            click.echo(output)
        except GhidraError as fallback_err:
            rich_echo(formatter.format_error(primary_err), err=True)
            rich_echo(formatter.format_error(fallback_err), err=True)
            ctx.exit(1)


@functions.command('get-cfg')
@click.option('--name', '-n', help='Function name')
@click.option('--address', '-a', help='Function address (hex)')
@click.pass_context
def get_cfg(ctx, name, address):
    """Get control flow graph (basic blocks and edges)."""
    if not name and not address:
        rich_echo("[red]Error:[/red] Either --name or --address is required", err=True)
        ctx.exit(1)
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    try:
        if address:
            endpoint = f'functions/{address}/cfg'
        else:
            endpoint = f'functions/by-name/{quote(name)}/cfg'
        response = client.get(endpoint)
        output = formatter.format_simple_result(response)
        click.echo(output)
    except GhidraError as e:
        rich_echo(formatter.format_error(e), err=True)
        ctx.exit(1)


@functions.command('get-pcode')
@click.option('--name', '-n', help='Function name')
@click.option('--address', '-a', help='Function address (hex)')
@click.pass_context
def get_pcode(ctx, name, address):
    """Get pcode operations (low-level intermediate representation)."""
    if not name and not address:
        rich_echo("[red]Error:[/red] Either --name or --address is required", err=True)
        ctx.exit(1)
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    try:
        if address:
            endpoint = f'functions/{address}/pcode'
        else:
            endpoint = f'functions/by-name/{quote(name)}/pcode'
        response = client.get(endpoint)
        output = formatter.format_simple_result(response)
        click.echo(output)
    except GhidraError as e:
        rich_echo(formatter.format_error(e), err=True)
        ctx.exit(1)


@functions.command('set-variable')
@click.option('--name', '-n', help='Function name')
@click.option('--address', '-a', help='Function address (hex)')
@click.option('--variable', required=True, help='Current variable name')
@click.option('--new-name', help='New name for the variable')
@click.option('--data-type', help='New data type (e.g., int, char *, uint32_t)')
@click.pass_context
def set_variable(ctx, name, address, variable, new_name, data_type):
    """Rename or change the type of a function variable."""
    if not name and not address:
        rich_echo("[red]Error:[/red] Either --name or --address is required", err=True)
        ctx.exit(1)
    if not new_name and not data_type:
        rich_echo("[red]Error:[/red] At least one of --new-name or --data-type is required", err=True)
        ctx.exit(1)
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    try:
        if address:
            endpoint = f'functions/{address}/variables/{quote(variable)}'
        else:
            endpoint = f'functions/by-name/{quote(name)}/variables/{quote(variable)}'
        data = {}
        if new_name:
            data['name'] = new_name
        if data_type:
            data['data_type'] = data_type
        response = client.patch(endpoint, data=data)
        output = formatter.format_simple_result(response)
        click.echo(output)
    except GhidraError as e:
        rich_echo(formatter.format_error(e), err=True)
        ctx.exit(1)
