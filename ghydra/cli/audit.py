"""`ghydra audit` — read the local mutation audit trail (I12).

The plugin records every state-changing request in a JSONL file next to the
other local state (``~/.ghydra/audit.jsonl``, or ``GHYDRA_AUDIT_LOG``). The
trail never leaves the machine and never carries the request body; this
command is how a human reads it back.
"""

import json
import os

import click


def default_path() -> str:
    configured = os.environ.get("GHYDRA_AUDIT_LOG")
    if configured:
        return os.path.expanduser(configured)
    return os.path.expanduser(os.path.join("~", ".ghydra", "audit.jsonl"))


def read_entries(path: str) -> list:
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return []
    entries = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict):
            entries.append(entry)
    return entries


@click.command('audit')
@click.option('--path', default=None,
              help='Audit file (default: $GHYDRA_AUDIT_LOG or ~/.ghydra/audit.jsonl)')
@click.option('--tail', type=int, default=20, show_default=True,
              help='Show the last N entries')
@click.option('--failures-only', is_flag=True,
              help='Only the requests that did not succeed')
@click.pass_context
def audit_cmd(ctx, path, tail, failures_only):
    """Show the mutations the plugin allowed, newest last.

    \b
    Example:
        ghydra audit
        ghydra audit --tail 100
        ghydra audit --failures-only
    """
    target = path or default_path()
    entries = read_entries(target)
    if not entries:
        click.echo(f"No audit trail at {target}.")
        return

    if failures_only:
        entries = [entry for entry in entries
                   if not 200 <= int(entry.get("status") or 0) < 300]
    entries = entries[-max(1, tail):]

    if ctx.obj.get('output_json'):
        click.echo(json.dumps(entries, ensure_ascii=False, indent=2))
        return

    click.echo(f"Audit trail: {target} ({len(entries)} entr(y/ies))")
    for entry in entries:
        click.echo(f"  {entry.get('method', '?'):<6} {entry.get('path', '?'):<44} "
                   f"{entry.get('status', '?'):>3}  "
                   f"{entry.get('ms', 0):>5}ms  "
                   f"port {entry.get('port', '?')}  "
                   f"{entry.get('request_id', '')}")
