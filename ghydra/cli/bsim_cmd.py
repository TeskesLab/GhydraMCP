"""`ghydra bsim` — signature queries against local or worker-profile databases."""

import json

import click

from ..client.exceptions import GhidraError


def _select_profile(ctx, param, value):
    if value is not None:
        ctx.meta['bsim_profile'] = value
    return value


def _profile_params(ctx):
    profile = ctx.meta.get('bsim_profile')
    return {'profile': profile} if profile is not None else {}


_profile_option = click.option(
    '--profile', default=None, expose_value=False, callback=_select_profile,
    help='Worker-provisioned BSim profile ID (never a URL or credential)')


@click.group('bsim')
def bsim():
    """BSim: signature queries across a corpus of binaries."""


@bsim.command('status')
@_profile_option
@click.pass_context
def status_cmd(ctx: click.Context):
    """Is a BSim signature query possible, and against which database.

    Local H2 uses worker configuration. Remote PostgreSQL/Elasticsearch uses
    --profile or the worker's default BSim profile, provisioned out of band.

    \b
    Example:
        ghydra bsim status
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        response = client.get('bsim/status', params=_profile_params(ctx))
    except GhidraError as exc:
        click.echo(formatter.format_error(exc), err=True)
        ctx.exit(1)

    result = response.get('result') if isinstance(response, dict) else None
    if not isinstance(result, dict):
        click.echo(str(response), err=True)
        ctx.exit(1)

    if ctx.obj.get('output_json'):
        click.echo(json.dumps(result, ensure_ascii=False, indent=2))
        return

    click.echo(f"BSim: {'ready' if result.get('ready') else 'not ready'}")
    click.echo(f"  engine: {'present' if result.get('available') else 'absent'}")
    click.echo(f"  database: {result.get('database') or '(none configured)'}")
    if result.get("database"):
        exists = result.get('database_exists')
        click.echo("  database exists: " + (
            'not checked (remote)' if exists is None else 'yes' if exists else 'no'))
    if result.get("reason"):
        click.echo(f"  {result['reason']}")


@bsim.command('ingest')
@_profile_option
@click.option('--max-functions', type=int, default=0,
              help='How many functions to scan at most (0 = all)')
@click.option('--track-call-graph', is_flag=True, default=False,
              help='Record the call graph too (off by default to reduce corpus size)')
@click.pass_context
def ingest_cmd(ctx: click.Context, max_functions, track_call_graph):
    """Generate signatures for the open program and insert them (R1).

    Missing local H2 databases are created; remote databases must already exist.
    A previously ingested program is reported without duplicating signatures.

    
    Example:
        ghydra bsim ingest --max-functions 500
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    params = _profile_params(ctx)
    params['track_call_graph'] = 'true' if track_call_graph else 'false'
    if max_functions:
        params['max_functions'] = max_functions
    try:
        response = client.post('bsim/ingest', params=params)
    except GhidraError as exc:
        click.echo(formatter.format_error(exc), err=True)
        ctx.exit(1)

    result = response.get('result') if isinstance(response, dict) else None
    if not isinstance(result, dict):
        click.echo(str(response), err=True)
        ctx.exit(1)

    if ctx.obj.get('output_json'):
        click.echo(json.dumps(result, ensure_ascii=False, indent=2))
        return

    if result.get('already_present'):
        click.echo(f"BSim ingest: {result.get('program')} is already in the database")
        click.echo(f"  database: {result.get('database')}")
        click.echo("  inserted: 0 functions (nothing to do)")
        if result.get('reason'):
            click.echo(f"  {result['reason']}")
        return
    created = ' (created)' if result.get('created') else ''
    click.echo(f"BSim ingest: {result.get('program')}")
    click.echo(f"  database: {result.get('database')}{created}")
    click.echo(f"  discovered: {result.get('discovered_functions', 0)} functions")
    click.echo(f"  scanned: {result.get('scanned_functions', 0)}"
               f" ({result.get('skipped_functions', 0)} skipped)")
    click.echo(f"  described: {result.get('described_functions', 0)}")
    click.echo(f"  inserted: {result.get('inserted_functions', 0)} functions"
               f" into {result.get('inserted_executables', 0)} executable(s)")
    click.echo(f"  took: {result.get('seconds', 0)}s")
    if result.get('reason'):
        click.echo(f"  note: {result['reason']}")


@bsim.command('query')
@_profile_option
@click.option('--address', default=None, help='The function address to ask about')
@click.option('--name', default=None, help='The function name to ask about')
@click.option('--min-similarity', type=float, default=0.0,
              help='Similarity floor 0..1 (0 = BSim default 0.7)')
@click.option('--min-significance', type=float, default=0.0,
              help='Significance floor (0 = no floor)')
@click.option('--max-matches', type=int, default=0,
              help='How many matches to return (0 = default 10)')
@click.option('--executable', default=None, help='Exact native executable metadata value (AND)')
@click.option('--architecture', default=None, help='Exact native architecture metadata value (AND)')
@click.option('--compiler', default=None, help='Exact native compiler metadata value (AND)')
@click.option('--category', 'categories', multiple=True, metavar='NAME=VALUE',
              help='Exact native category predicate; repeat for AND (unique nonblank names)')
@click.pass_context
def query_cmd(ctx: click.Context, address, name, min_similarity, min_significance, max_matches,
              executable, architecture, compiler, categories):
    """Which stored functions look like this one (R1).

    A match is a lead, not an identification: it carries BSim's similarity and
    significance. The corpus is whatever was ingested into the configured
    database.
    Metadata filters use exact native values, combine with AND, and run before
    the match limit. Unknown or unsupported predicates fail rather than broaden.

    \b
    Example:
        ghydra bsim query --name main --min-similarity 0.8
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    if not address and not name:
        click.echo("give one of --address or --name", err=True)
        ctx.exit(2)
    params = _profile_params(ctx)
    for key, value in (('executable', executable), ('architecture', architecture),
                       ('compiler', compiler)):
        if value is not None:
            if not value.strip():
                raise click.BadParameter('must be a nonblank exact metadata value',
                                         param_hint=f'--{key}')
            params[key] = value
    category_values = {}
    for predicate in categories:
        category, separator, value = predicate.partition('=')
        if not separator or not category.strip() or not value.strip():
            raise click.BadParameter('expected nonblank NAME=VALUE', param_hint='--category')
        if category in category_values:
            raise click.BadParameter(f'duplicate category name: {category}', param_hint='--category')
        category_values[category] = value
    if category_values:
        params['categories'] = json.dumps(category_values, ensure_ascii=False)
    if address:
        params['address'] = address
    if name:
        params['name'] = name
    if min_similarity:
        params['min_similarity'] = min_similarity
    if min_significance:
        params['min_significance'] = min_significance
    if max_matches:
        params['max_matches'] = max_matches
    try:
        response = client.get('bsim/query', params=params)
    except GhidraError as exc:
        click.echo(formatter.format_error(exc), err=True)
        ctx.exit(1)

    result = response.get('result') if isinstance(response, dict) else None
    if not isinstance(result, dict):
        click.echo(str(response), err=True)
        ctx.exit(1)

    if ctx.obj.get('output_json'):
        click.echo(json.dumps(result, ensure_ascii=False, indent=2))
        return

    click.echo(f"BSim query: {result.get('function')} at {result.get('address')}")
    click.echo(f"  database: {result.get('database')}")
    if result.get('filters'):
        click.echo('  filters (AND, exact metadata): '
                   + json.dumps(result['filters'], ensure_ascii=False, sort_keys=True))
    if 'available_categories' in result:
        click.echo('  available categories: '
                   + json.dumps(result['available_categories'], ensure_ascii=False))
    click.echo(f"  threshold: similarity >= {result.get('min_similarity')}")
    click.echo(f"  matches: {result.get('returned', 0)}"
               f" (of {result.get('total_considered', 0)} considered)")
    for match in result.get('matches') or []:
        where = match.get('executable') or '?'
        path = match.get('path')
        click.echo(f"  {match.get('similarity')} similarity,"
                   f" significance {match.get('significance')}:"
                   f" {match.get('function')} @ {match.get('address')}"
                   f" in {where}" + (f" ({path})" if path else ""))
        click.echo(f"    match_id: {match.get('match_id')}"
                   + ("" if match.get('reference_available') else " (reference unavailable)"))
    if result.get('reason'):
        click.echo(f"  {result['reason']}")


@bsim.command('apply-names')
@_profile_option
@click.option('--address', default=None, help='The function address to name')
@click.option('--name', default=None, help='The function name to look up')
@click.option('--min-similarity', type=float, default=0.0,
              help='The floor for applying (0 = default 0.8)')
@click.option('--dry-run/--apply', default=True,
              help='Report the change without making it (default: dry run)')
@click.pass_context
def apply_names_cmd(ctx: click.Context, address, name, min_similarity, dry_run):
    """Name a function after the stored function it most resembles (R1).

    Dry run by default: the command reports what it would do. Pass --apply to
    rename. The match's similarity travels with the answer, because a signature
    match is a heuristic.

    \b
    Example:
        ghydra bsim apply-names --address 0x140001010 --apply
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    if not address and not name:
        click.echo("give one of --address or --name", err=True)
        ctx.exit(2)
    params = _profile_params(ctx)
    params['dry_run'] = 'true' if dry_run else 'false'
    if address:
        params['address'] = address
    if name:
        params['name'] = name
    if min_similarity:
        params['min_similarity'] = min_similarity
    try:
        response = client.post('bsim/apply-names', params=params)
    except GhidraError as exc:
        click.echo(formatter.format_error(exc), err=True)
        ctx.exit(1)

    result = response.get('result') if isinstance(response, dict) else None
    if not isinstance(result, dict):
        click.echo(str(response), err=True)
        ctx.exit(1)

    if ctx.obj.get('output_json'):
        click.echo(json.dumps(result, ensure_ascii=False, indent=2))
        return

    if result.get('already_named'):
        click.echo(f"BSim apply: {result.get('from')} already carries the "
                   f"matched name")
        click.echo(f"  database: {result.get('database')}")
        return
    match = result.get('match') or {}
    click.echo(f"BSim apply: {result.get('from')} -> {result.get('to')}")
    click.echo(f"  database: {result.get('database')}")
    click.echo(f"  from: {match.get('executable') or '?'}"
               f" {match.get('function')} @ {match.get('address')}")
    click.echo(f"  similarity: {match.get('similarity')}"
               f" (significance {match.get('significance')})")
    click.echo(f"  floor: {result.get('min_similarity')}")
    if result.get('applied'):
        click.echo("  applied: yes (undo in Ghidra if the match is wrong)")
    elif result.get('would_rename'):
        click.echo("  applied: no (dry run) — pass --apply to rename")
    if result.get('reason') and not result.get('applied'):
        click.echo(f"  {result['reason']}")


@bsim.command('diff')
@_profile_option
@click.argument('other_executable')
@click.option('--max-functions', type=int, default=0,
              help='How many functions to compare (0 = 25, cap 500)')
@click.option('--min-similarity', type=float, default=0.0,
              help='The floor for calling two functions a pair (0 = 0.8)')
@click.pass_context
def diff_cmd(ctx: click.Context, other_executable, max_functions, min_similarity):
    """What changed between two versions, paired by signature (R1).

    Both versions must have been ingested into the database. A function with no
    pair is listed, not dropped; a thunk that was never ingested shows as
    not_found, and a function without a body as no_signature.

    \b
    Example:
        ghydra bsim diff app-1.2.exe --max-functions 50
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    params = _profile_params(ctx)
    params['other_executable'] = other_executable
    if max_functions:
        params['max_functions'] = max_functions
    if min_similarity:
        params['min_similarity'] = min_similarity
    try:
        response = client.get('bsim/diff', params=params)
    except GhidraError as exc:
        click.echo(formatter.format_error(exc), err=True)
        ctx.exit(1)

    result = response.get('result') if isinstance(response, dict) else None
    if not isinstance(result, dict):
        click.echo(str(response), err=True)
        ctx.exit(1)

    if ctx.obj.get('output_json'):
        click.echo(json.dumps(result, ensure_ascii=False, indent=2))
        return

    click.echo(f"BSim diff: {result.get('program')} against"
               f" {result.get('other_executable')}")
    click.echo(f"  database has {result.get('discovered_functions', 0)} functions"
               f" in this program; compared {result.get('compared_functions', 0)}"
               f" ({result.get('not_compared', 0)} not compared)")
    click.echo(f"  same: {result.get('same', 0)}, moved: {result.get('moved', 0)},"
               f" not found: {result.get('not_found', 0)},"
               f" no signature: {result.get('no_signature', 0)}")
    click.echo(f"  threshold: similarity >= {result.get('min_similarity')}")
    for pair in result.get('pairs') or []:
        kind = pair.get('class')
        if kind in ('same', 'moved'):
            other = pair.get('other') or {}
            click.echo(f"  [{kind}] {pair.get('function')} @"
                       f" {pair.get('address')} ->"
                       f" {other.get('function')} @ {other.get('address')}"
                       f" ({other.get('similarity')} similar)")
        else:
            click.echo(f"  [{kind}] {pair.get('function')} @ {pair.get('address')}")
    for gap in result.get('query_failures') or []:
        click.echo(f"  [query failed] {gap.get('function')}: {gap.get('code')}"
                   f" — {gap.get('reason')}")


@bsim.command('compare-match')
@_profile_option
@click.argument('match_id')
@click.option('--reference-profile', required=True,
              help='Approved repository profile on the reference worker')
@click.option('--reference-port', required=True, type=click.IntRange(1, 65535),
              help='Reference worker HTTP port, on the configured host')
@click.option('--max-code-lines', default=1000, type=click.IntRange(1, 10000),
              help='Maximum lines per decompilation; truncation is explicit')
@click.pass_context
def compare_match_cmd(ctx: click.Context, match_id, reference_profile, reference_port, max_code_lines):
    """Compare one selected match without applying names, signatures or types.

    Args:
        match_id: Opaque match ID returned by bsim query on the target worker.
        reference_profile: Approved repository profile ID.
        reference_port: Reference worker port on the same configured host.
        max_code_lines: Maximum decompiled lines per function, 1..10000.

    Returns:
        A code/signature/type report and a non-mutating change preview.
    """
    from ..bsim import compare_selected_match

    formatter = ctx.obj['formatter']
    try:
        response = compare_selected_match(ctx.obj['client'], match_id,
            reference_profile, reference_port, max_code_lines=max_code_lines,
            profile=ctx.meta.get('bsim_profile'))
    except GhidraError as exc:
        click.echo(formatter.format_error(exc), err=True)
        ctx.exit(1)
    click.echo(formatter.format_bsim_comparison(response))


@bsim.command('prepare-apply')
@_profile_option
@click.argument('match_id')
@click.option('--reference-profile', required=True,
              help='Approved repository profile on the reference worker')
@click.option('--reference-port', required=True, type=click.IntRange(1, 65535),
              help='Reference worker HTTP port, on the configured host')
@click.pass_context
def prepare_apply_cmd(ctx: click.Context, match_id, reference_profile, reference_port):
    """Preview one selected match's native signature/types without applying them.

    Review the complete preview, then explicitly pass its token to apply-match.
    No comments, code, local variables, checkout or save are transferred.
    """
    from ..bsim import prepare_selected_match

    formatter = ctx.obj['formatter']
    try:
        response = prepare_selected_match(ctx.obj['client'], match_id,
            reference_profile, reference_port, profile=ctx.meta.get('bsim_profile'))
    except GhidraError as exc:
        click.echo(formatter.format_error(exc), err=True)
        ctx.exit(1)
    click.echo(formatter.format_bsim_prepare_apply(response))


@bsim.command('apply-match')
@_profile_option
@click.argument('match_id')
@click.option('--apply-token', required=True,
              help='Opaque token from a reviewed prepare-apply preview on this worker')
@click.pass_context
def apply_match_cmd(ctx: click.Context, match_id, apply_token):
    """Apply the exact prepared signature/types in one native transaction.

    A stale, unknown or replayed token fails; prepare and review a fresh preview.
    This command never queries for a new or best match.
    """
    from ..bsim import apply_selected_match

    formatter = ctx.obj['formatter']
    try:
        response = apply_selected_match(ctx.obj['client'], match_id, apply_token,
                                        profile=ctx.meta.get('bsim_profile'))
    except GhidraError as exc:
        click.echo(formatter.format_error(exc), err=True)
        ctx.exit(1)
    click.echo(formatter.format_bsim_apply_match(response))
