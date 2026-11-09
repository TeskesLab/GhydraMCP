"""`ghydra bsim` — is a signature query possible here (R1)."""

import json

import click

from ..client.exceptions import GhidraError


@click.group('bsim')
def bsim():
    """BSim: signature queries across a corpus of binaries."""


@bsim.command('status')
@click.pass_context
def status_cmd(ctx):
    """Is a BSim signature query possible, and against which database.

    BSim is a Ghidra feature, not a plugin API, so the plugin discovers it by
    loading the class; a build may ship without it. The database is
    configuration (-Dghydra.bsim.database or GHYDRA_BSIM_DATABASE).

    \b
    Example:
        ghydra bsim status
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        response = client.get('bsim/status')
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
        click.echo(f"  database exists: "
                   f"{'yes' if result.get('database_exists') else 'no'}")
    if result.get("reason"):
        click.echo(f"  {result['reason']}")


@bsim.command('ingest')
@click.option('--max-functions', type=int, default=0,
              help='How many functions to scan at most (0 = all)')
@click.option('--track-call-graph', is_flag=True, default=False,
              help='Record the call graph too (off: H2 rejects it on recursion)')
@click.pass_context
def ingest_cmd(ctx, max_functions, track_call_graph):
    """Generate signatures for the open program and insert them (R1).

    The database is created when it does not exist. Ingesting a program that is
    already there is not an error: the answer says so and inserts nothing.

    
    Example:
        ghydra bsim ingest --max-functions 500
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    params = {'track_call_graph': 'true' if track_call_graph else 'false'}
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
@click.option('--address', default=None, help='The function address to ask about')
@click.option('--name', default=None, help='The function name to ask about')
@click.option('--min-similarity', type=float, default=0.0,
              help='Similarity floor 0..1 (0 = BSim default 0.7)')
@click.option('--min-significance', type=float, default=0.0,
              help='Significance floor (0 = no floor)')
@click.option('--max-matches', type=int, default=0,
              help='How many matches to return (0 = default 10)')
@click.pass_context
def query_cmd(ctx, address, name, min_similarity, min_significance, max_matches):
    """Which stored functions look like this one (R1).

    A match is a lead, not an identification: it carries BSim's similarity and
    significance. The corpus is whatever was ingested into the configured
    database.

    \b
    Example:
        ghydra bsim query --name main --min-similarity 0.8
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    if not address and not name:
        click.echo("give one of --address or --name", err=True)
        ctx.exit(2)
    params = {}
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
    if result.get('reason'):
        click.echo(f"  {result['reason']}")


@bsim.command('apply-names')
@click.option('--address', default=None, help='The function address to name')
@click.option('--name', default=None, help='The function name to look up')
@click.option('--min-similarity', type=float, default=0.0,
              help='The floor for applying (0 = default 0.8)')
@click.option('--dry-run/--apply', default=True,
              help='Report the change without making it (default: dry run)')
@click.pass_context
def apply_names_cmd(ctx, address, name, min_similarity, dry_run):
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
    params = {'dry_run': 'true' if dry_run else 'false'}
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
@click.argument('other_executable')
@click.option('--max-functions', type=int, default=0,
              help='How many functions to compare (0 = 25, cap 500)')
@click.option('--min-similarity', type=float, default=0.0,
              help='The floor for calling two functions a pair (0 = 0.8)')
@click.pass_context
def diff_cmd(ctx, other_executable, max_functions, min_similarity):
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

    params = {'other_executable': other_executable}
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
