"""`ghydra mission` — an objective, a budget, an auditable dossier (R8).

There is nobody to ask: a doubt becomes an `unknown` finding. The budget is a
hard stop, the evidence is re-read before a conclusion is kept, and a
checkpoint is written after every step so a mission can be resumed.
"""

import json
import os

import click

from ..client.exceptions import GhidraError
from ..mission import (ERROR_BAD_FILE, Budget, Mission, run, save_dossier,
                       to_markdown, verify)


def _emit(ctx, mission, verification, output):
    if output:
        path = save_dossier(mission, verification, output)
        click.echo(f"Dossier written to {path}")
    elif ctx.obj.get('output_json'):
        payload = mission.as_dict()
        payload["verification"] = verification
        click.echo(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        click.echo(to_markdown(mission, verification))

    unverified = (verification or {}).get("unverified") or []
    if unverified:
        click.echo(f"Unverified findings: {', '.join(unverified)}", err=True)
        ctx.exit(1)
    ctx.exit(0)


@click.group('mission')
def mission():
    """Run an objective against the binary and produce a dossier."""


@mission.command('start')
@click.option('--goal', '-g', required=True,
              help='The objective, in words (hints are read from it)')
@click.option('--max-calls', type=int, default=60, show_default=True,
              help='How many API calls the mission may spend')
@click.option('--max-tokens', type=int, default=200000, show_default=True,
              help='Approximate token budget for the answers')
@click.option('--max-seconds', type=int, default=900, show_default=True,
              help='Wall-clock budget')
@click.option('--output', '-o', default=None,
              help='Write the dossier to this path (default: ~/.ghydra/missions/<id>.md)')
@click.option('--no-verify', is_flag=True,
              help='Skip the adversarial re-read of the evidence')
@click.pass_context
def start_cmd(ctx, goal, max_calls, max_tokens, max_seconds, output, no_verify):
    """Run a mission from the beginning.

    \b
    Example:
        ghydra mission start -g "does data from recv reach system?"
        ghydra mission start -g "what does this binary do" --max-calls 20
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    budget = Budget(max_calls, max_tokens, max_seconds)
    current = Mission(goal, budget=budget)
    try:
        run(client, current)
        verification = None if no_verify else verify(client, current)
    except GhidraError as exc:
        click.echo(formatter.format_error(exc), err=True)
        ctx.exit(2)
    _emit(ctx, current, verification, output)


@mission.command('resume')
@click.argument('path')
@click.option('--output', '-o', default=None,
              help='Write the dossier to this path')
@click.option('--no-verify', is_flag=True,
              help='Skip the adversarial re-read of the evidence')
@click.option('--max-calls', type=int, default=None,
              help='Raise the checkpointed call budget (a resume may ask for more)')
@click.option('--max-tokens', type=int, default=None,
              help='Raise the checkpointed token budget')
@click.option('--max-seconds', type=int, default=None,
              help='Raise the checkpointed wall-clock budget')
@click.pass_context
def resume_cmd(ctx, path, output, no_verify, max_calls, max_tokens, max_seconds):
    """Continue a mission from its checkpoint.

    The budget spent so far is kept; a resume may raise the limits, because a
    mission that stopped on its budget is exactly the one worth continuing.

    \b
    Example:
        ghydra mission resume ~/.ghydra/missions/m1234.json
        ghydra mission resume ~/.ghydra/missions/m1234.json --max-calls 200
    """
    client = ctx.obj['client']
    try:
        current = Mission.load(path)
    except ValueError as exc:
        click.echo(f"Error [{ERROR_BAD_FILE}]: {exc}", err=True)
        ctx.exit(2)
    if max_calls is not None:
        current.budget.max_calls = max(1, int(max_calls))
    if max_tokens is not None:
        current.budget.max_tokens = max(1, int(max_tokens))
    if max_seconds is not None:
        current.budget.max_seconds = max(1, int(max_seconds))
    try:
        run(client, current, resume=True)
        verification = None if no_verify else verify(client, current)
    except GhidraError as exc:
        click.echo(str(exc), err=True)
        ctx.exit(2)
    _emit(ctx, current, verification, output)


@mission.command('show')
@click.argument('path')
@click.pass_context
def show_cmd(ctx, path):
    """Read a dossier from its checkpoint, without calling anything."""
    try:
        current = Mission.load(path)
    except ValueError as exc:
        click.echo(f"Error [{ERROR_BAD_FILE}]: {exc}", err=True)
        ctx.exit(2)
    if ctx.obj.get('output_json'):
        click.echo(json.dumps(current.as_dict(), ensure_ascii=False, indent=2))
    else:
        click.echo(to_markdown(current))