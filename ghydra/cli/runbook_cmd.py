"""`ghydra runbook` — record and replay a reproducible analysis (R6).

A runbook is a list of API calls with the digest of each answer. Recording it
turns a session into a file; replaying it against another binary, or another
version of the same one, says what changed.
"""

import json
import os

import click

from ..client.exceptions import GhidraError
from ..runbook import (RunbookError, load, load_steps, record, replay, save,
                       to_text)


def default_path(program: str | None = None) -> str:
    name = program or "runbook"
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in name)
    return os.path.join(os.getcwd(), f"{safe}.ghydrarb.jsonl")


@click.group('runbook')
def runbook():
    """Record and replay a reproducible sequence of API calls."""


@runbook.command('record')
@click.option('--steps', '-s', 'steps_file', required=True,
              help='JSON file with the steps to call')
@click.option('--output', '-o', default=None,
              help='Where to write the runbook (default: <program>.ghydrarb.jsonl)')
@click.pass_context
def record_cmd(ctx, steps_file, output):
    """Call each step once and write a replayable runbook.

    \b
    Example:
        ghydra runbook record -s steps.json -o sample.ghydrarb.jsonl
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    try:
        steps = load_steps(steps_file)
        document = record(client, steps)
        target = output or default_path((document.get("header") or {}).get("program", {}).get("name"))
        save(document, target)
    except RunbookError as exc:
        click.echo(f"Error [{exc.code}]: {exc}", err=True)
        ctx.exit(2)
    except GhidraError as exc:
        click.echo(formatter.format_error(exc), err=True)
        ctx.exit(2)

    entries = document.get("entries") or []
    failed = [entry for entry in entries if not entry.get("ok")]
    click.echo(f"Runbook written to {target} ({len(entries)} step(s), "
               f"{len(failed)} failed)")
    for entry in failed:
        click.echo(f"  step {entry['step']} {entry['request']['method']} "
                   f"{entry['request']['endpoint']}: {entry.get('code') or 'failed'}",
                   err=True)
    ctx.exit(1 if failed else 0)


@runbook.command('replay')
@click.argument('path', required=True)
@click.option('--fail-on-change', is_flag=True,
              help='Exit non-zero when any answer differs (CI gate)')
@click.pass_context
def replay_cmd(ctx, path, fail_on_change):
    """Re-run a runbook and report which answers moved.

    \b
    Example:
        ghydra runbook replay sample.ghydrarb.jsonl
        ghydra runbook replay sample.ghydrarb.jsonl --fail-on-change
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    try:
        document = load(path)
        report = replay(document, client)
    except RunbookError as exc:
        click.echo(f"Error [{exc.code}]: {exc}", err=True)
        ctx.exit(2)
    except GhidraError as exc:
        click.echo(formatter.format_error(exc), err=True)
        ctx.exit(2)

    if ctx.obj.get('output_json'):
        click.echo(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        click.echo(to_text(report))

    result = report.get("result", report)
    if fail_on_change and (result.get("changed") or result.get("failed")):
        ctx.exit(1)
    ctx.exit(0)


@runbook.command('show')
@click.argument('path', required=True)
@click.pass_context
def show_cmd(ctx, path):
    """Show what a runbook records, without running anything."""
    try:
        document = load(path)
    except RunbookError as exc:
        click.echo(f"Error [{exc.code}]: {exc}", err=True)
        ctx.exit(2)
    header = document.get("header") or {}
    click.echo(f"Runbook v{header.get('runbook')} — {len(document.get('entries') or [])} step(s)")
    program = header.get("program") or {}
    if program:
        click.echo(f"  program: {program.get('name') or '?'} "
                   f"{program.get('executable_path') or ''}".rstrip())
    for entry in document.get("entries") or []:
        request = entry.get("request") or {}
        click.echo(f"  step {entry.get('step')} {request.get('method')} "
                   f"{request.get('endpoint')}")