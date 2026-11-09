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
