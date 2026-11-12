"""Native Ghidra Server operations through worker-owned opaque profiles."""

import click

from ..client.exceptions import GhidraError
from ..utils import rich_echo


def _request(ctx, route, *, params=None, body=None):
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    try:
        response = (client.get(route, params=params) if body is None
                    else client.post(route, json_data=body))
        click.echo(formatter.format_repository(response))
    except GhidraError as exc:
        rich_echo(formatter.format_error(exc), err=True)
        ctx.exit(1)


@click.group('repositories')
def repositories():
    """Use a provisioned native Ghidra Server repository (not a plugin HTTP URL)."""


@repositories.command('status')
@click.option('--profile', required=True, help='Worker-owned Ghidra repository profile ID')
@click.pass_context
def status(ctx, profile):
    """Connect and report safe repository status and grants."""
    _request(ctx, 'repositories', params={'profile': profile})


@repositories.command('list-files')
@click.option('--profile', required=True, help='Worker-owned Ghidra repository profile ID')
@click.option('--path', default='/', show_default=True, help='Repository folder path')
@click.option('--limit', type=click.IntRange(1, 1000), default=100, show_default=True)
@click.option('--offset', type=click.IntRange(min=0), default=0, show_default=True)
@click.pass_context
def list_files(ctx, profile, path, limit, offset):
    """List one folder; response explicitly reports truncation."""
    _request(ctx, 'repositories/files', params={'profile': profile, 'path': path, 'offset': offset, 'limit': limit})


@repositories.command('open')
@click.option('--profile', required=True, help='Worker-owned Ghidra repository profile ID')
@click.option('--path', required=True, help='Absolute repository program path')
@click.option('--version', type=int, default=-1, show_default=True, help='-1 for latest or a positive version')
@click.pass_context
def open_program(ctx, profile, path, version):
    """Activate a native repository program without discarding unsaved changes."""
    if version != -1 and version < 1:
        raise click.BadParameter('must be -1 or a positive integer', param_hint='--version')
    _request(ctx, 'repositories/open', body={'profile': profile, 'path': path, 'version': version})


@repositories.command('checkout')
@click.option('--profile', required=True, help='Worker-owned Ghidra repository profile ID')
@click.option('--path', required=True, help='Absolute repository program path')
@click.option('--exclusive/--no-exclusive', default=False, help='Exclusive checkout is required for safe API check-in')
@click.pass_context
def checkout(ctx, profile, path, exclusive):
    """Create an explicit native local checkout; never force an existing checkout."""
    _request(ctx, 'repositories/checkout', body={'profile': profile, 'path': path, 'exclusive': exclusive})


@repositories.command('checkin')
@click.option('--profile', required=True, help='Worker-owned Ghidra repository profile ID')
@click.option('--path', required=True, help='Absolute repository program path')
@click.option('--comment', required=True, help='Explicit repository version comment (not a credential)')
@click.option('--keep-checked-out/--no-keep-checked-out', default=False,
              help='Keep checkout after publishing; required while the program remains open')
@click.pass_context
def checkin(ctx, profile, path, comment, keep_checked_out):
    """Publish saved changes from an exclusive checkout; save alone does not publish."""
    _request(ctx, 'repositories/checkin', body={'profile': profile, 'path': path,
             'comment': comment, 'keep_checked_out': keep_checked_out})
