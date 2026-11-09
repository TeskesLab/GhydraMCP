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
