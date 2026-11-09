"""`ghydra twin` — the snapshot of a binary that answers without Ghidra (R2)."""

import json

import click

from .. import twin as twin_helper
from ..client.exceptions import GhidraError


def _built_at(document):
    """The build time, as a date a person reads (the file keeps the epoch)."""
    from datetime import datetime, timezone
    stamp = document.get('built_at')
    if not isinstance(stamp, (int, float)):
        return 'unknown'
    return datetime.fromtimestamp(stamp, timezone.utc).strftime('%Y-%m-%d %H:%M UTC')


@click.group('twin')
def twin():
    """A snapshot of a binary that answers questions with no Ghidra running."""


@twin.command('build')
@click.option('--name', default=None, help='The name to save it under')
@click.option('--output', default=None, help='Where to write it (default: state dir)')
@click.option('--max-strings', type=int, default=twin_helper.DEFAULT_MAX_STRINGS)
@click.option('--max-functions', type=int, default=twin_helper.DEFAULT_MAX_FUNCTIONS)
@click.pass_context
def build_cmd(ctx, name, output, max_strings, max_functions):
    """Take a snapshot of the instance's program.

    The snapshot holds what the API said — the program, its functions, imports,
    exports, strings and counts — with its provenance, so a stale twin can be
    recognised instead of trusted.

    \b
    Example:
        ghydra twin build --name app-1.2
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    try:
        document = twin_helper.build(client, name=name,
                                     max_strings=max_strings,
                                     max_functions=max_functions)
    except GhidraError as exc:
        click.echo(formatter.format_error(exc), err=True)
        ctx.exit(1)

    path = twin_helper.save(document, output)
    if ctx.obj.get('output_json'):
        click.echo(json.dumps({"path": path, **document}, ensure_ascii=False,
                              indent=2))
        return
    counts = document.get('counts') or {}
    click.echo(f"Twin: {document.get('name')} -> {path}")
    click.echo(f"  program: {document.get('program', {}).get('name')}"
               f" ({document.get('program', {}).get('md5') or 'no md5'})")
    click.echo(f"  functions: {counts.get('functions', 0)}"
               f" (of {counts.get('functions_total') or '?'} the API reports)")
    click.echo(f"  imports: {counts.get('imports', 0)},"
               f" exports: {counts.get('exports', 0)},"
               f" strings: {counts.get('strings', 0)}")
    capped = [kind for kind, stopped in (document.get('truncated') or {}).items()
              if stopped]
    if capped:
        click.echo(f"  note: {', '.join(capped)} were capped; the twin says so")


@twin.command('query')
@click.argument('path')
@click.option('--kind', default='overview',
              type=click.Choice(['overview', 'functions', 'function', 'imports',
                                 'exports', 'strings']),
              help='What to ask the snapshot')
@click.option('--match', default='', help='Text to look for (or an address)')
@click.option('--limit', type=int, default=50, help='How many items to return')
@click.pass_context
def query_cmd(ctx, path, kind, match, limit):
    """Answer a question from a snapshot, with no Ghidra running.

    \b
    Example:
        ghydra twin query app-1.2.json --kind functions --match str
    """
    formatter = ctx.obj['formatter']
    try:
        document = twin_helper.load(path)
        answer = twin_helper.query(document, kind, match, limit)
    except (OSError, ValueError) as exc:
        click.echo(f"Error: {exc}", err=True)
        ctx.exit(1)

    if ctx.obj.get('output_json'):
        click.echo(json.dumps(answer, ensure_ascii=False, indent=2))
        return

    if kind == 'overview':
        counts = answer.get('counts') or {}
        click.echo(f"Twin: {(answer.get('program') or {}).get('name')}"
                   f" (built {_built_at(document)} from {answer.get('source')})")
        click.echo(f"  functions: {counts.get('functions', 0)},"
                   f" imports: {counts.get('imports', 0)},"
                   f" exports: {counts.get('exports', 0)},"
                   f" strings: {counts.get('strings', 0)}")
        stopped = [kind for kind, capped in (answer.get('truncated') or {}).items()
                   if capped]
        if stopped:
            click.echo(f"  note: {', '.join(stopped)} were capped")
        return
    if kind == 'function':
        function = answer.get('function')
        if not function:
            click.echo(f"not found in the snapshot: {match}")
            ctx.exit(1)
        click.echo(f"{function.get('name')} @ {function.get('address')}"
                   f" -> {function.get('return_type') or '?'}")
        return
    click.echo(f"{kind}: {answer.get('returned', 0)} of"
               f" {answer.get('matched', 0)} matching")
    for item in answer.get('items') or []:
        if isinstance(item, dict):
            click.echo(f"  {item.get('name')} @ {item.get('address')}")
        else:
            click.echo(f"  {item}")


@twin.command('diff')
@click.argument('left')
@click.argument('right')
@click.pass_context
def diff_cmd(ctx, left, right):
    """What changed between two snapshots, with the shared comparison.

    The same report shape `ghydra analysis diff` produces, offline — which is
    the point: "what changed" has one definition.

    \b
    Example:
        ghydra twin diff app-1.1.json app-1.2.json
    """
    formatter = ctx.obj['formatter']
    try:
        first = twin_helper.load(left)
        second = twin_helper.load(right)
    except (OSError, ValueError) as exc:
        click.echo(f"Error: {exc}", err=True)
        ctx.exit(1)

    report = twin_helper.diff(first, second)
    if ctx.obj.get('output_json'):
        click.echo(json.dumps(report, ensure_ascii=False, indent=2))
        return

    summary = report.get('summary') or {}
    provenance = report.get('provenance') or {}
    click.echo(f"Twin diff: {provenance.get('a', {}).get('name')}"
               f" -> {provenance.get('b', {}).get('name')}")
    if report.get('same_binary'):
        click.echo("  the snapshots describe the same binary (same fingerprint)")
    click.echo(f"  changed: {'yes' if report.get('changed') else 'no'}")
    click.echo(f"  functions: +{summary.get('functions_added', 0)}"
               f" -{summary.get('functions_removed', 0)}"
               f" renamed {summary.get('functions_renamed', 0)}")
    click.echo(f"  imports: +{summary.get('imports_added', 0)}"
               f" -{summary.get('imports_removed', 0)}")
    click.echo(f"  strings: +{summary.get('strings_added', 0)}"
               f" -{summary.get('strings_removed', 0)}")
    for section, label in (("functions", "renamed"), ("imports", "added"),
                           ("strings", "added")):
        items = (report.get(section) or {}).get(label) or []
        for item in items[:5]:
            if isinstance(item, dict):
                click.echo(f"  {section} {label}: {item}")
            else:
                click.echo(f"  {section} {label}: {item}")