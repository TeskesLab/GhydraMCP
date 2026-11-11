"""`ghydra cache` — what the decompile cache holds (I11)."""

import click

from .. import cache as cache_helper


@click.group('cache')
def cache():
    """Inspect and clear the local decompile cache."""


@cache.command('stats')
@click.pass_context
def stats_cmd(ctx):
    """Show how many answers are cached and how much space they take.

    \b
    Example:
        ghydra cache stats
    """
    report = cache_helper.stats()
    if ctx.obj.get('output_json'):
        import json
        click.echo(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        click.echo(cache_helper.to_text(report))


@cache.command('path')
def path_cmd():
    """Print the directory the cache lives in."""
    click.echo(cache_helper.entries_dir())


@cache.command('clear')
@click.pass_context
def clear_cmd(ctx):
    """Remove every cached answer.

    Needed when a program is edited in a way the cache cannot see (a rename does
    not change the identity the server exposes).

    \b
    Example:
        ghydra cache clear
    """
    removed = cache_helper.clear()
    click.echo(f"Removed {removed} cached entr{'y' if removed == 1 else 'ies'}.")