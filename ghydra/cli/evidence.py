"""The evidence ledger.

Every finding gets an ID that never changes, so it can be referred to
later - in a report, in a note, in a conversation. The ledger can be
exported as a bundle: a document to read and one to read with a program.
"""

import click

from ..evidence import (
    EvidenceError,
    Ledger,
    export_bundle,
    list_ledgers,
)
from ..utils import rich_echo


@click.group('evidence')
def evidence():
    """Keep the findings, and give them an ID.

    \b
    Examples:
        # Record what was learned about a function
        ghydra evidence add --kind function --address 0x140001000 \\
            --name decrypt_blob --note "the key is derived from the serial"

        # What was found
        ghydra evidence list --tag crypto

        # Take it with you
        ghydra evidence export --output out
    """
    pass


@evidence.command('add')
@click.option('--kind', '-k', required=True,
              type=click.Choice(['function', 'string', 'xref', 'data', 'note',
                                 'vulnerability', 'custom']),
              help="What the finding is")
@click.option('--address', '-a', default="",
              help="Where it is, as the static address")
@click.option('--name', '-n', default="",
              help="The name of the thing")
@click.option('--note', default="",
              help="What was learned about it")
@click.option('--tags', '-t', default="",
              help="Tags, separated by commas")
@click.option('--source', default="",
              help="Where it was seen - a tool, an instance, a report")
@click.option('--code', default="",
              help="A snippet of code, when there is one")
@click.option('--confidence', default="medium",
              type=click.Choice(['high', 'medium', 'low']),
              help="How sure it is (default: medium)")
@click.option('--ledger', '-l', default="default",
              help="The ledger to write into (default: default)")
@click.pass_context
def add(ctx, kind, address, name, note, tags, source, code, confidence, ledger):
    """Record a finding, and give it an ID.

    The ID never changes and is never given out twice, so a finding can be
    referred to from anywhere, for as long as the ledger exists.
    """
    formatter = ctx.obj['formatter']
    try:
        book = Ledger.open(ledger)
        finding = book.add(
            kind=kind, address=address, name=name, note=note,
            tags=[tag.strip() for tag in tags.split(",") if tag.strip()],
            source=source, code=code, confidence=confidence)
        book.save()
    except EvidenceError as exc:
        rich_echo(formatter.format_error(exc), err=True)
        ctx.exit(1)

    click.echo(formatter.format_simple_result({
        "success": True,
        "result": {"message": f"{finding.id} was recorded", "finding": finding.to_dict()},
    }))


@evidence.command('list')
@click.option('--ledger', '-l', default="default",
              help="The ledger to read (default: default)")
@click.option('--kind', '-k', default="",
              help="Only the findings of this kind")
@click.option('--tag', '-t', default="",
              help="Only the findings with this tag")
@click.option('--address', '-a', default="",
              help="Only the findings at this address")
@click.option('--query', '-q', default="",
              help="Only the findings whose name, note or address holds this text")
@click.pass_context
def list_findings(ctx, ledger, kind, tag, address, query):
    """The findings of a ledger."""
    formatter = ctx.obj['formatter']
    try:
        book = Ledger.open(ledger)
        findings = book.list(kind=kind, tag=tag, address=address, query=query)
    except EvidenceError as exc:
        rich_echo(formatter.format_error(exc), err=True)
        ctx.exit(1)

    click.echo(formatter.format_simple_result({
        "success": True,
        "result": {
            "ledger": ledger,
            "count": len(findings),
            "findings": [finding.to_dict() for finding in findings],
        },
    }))


@evidence.command('ledgers')
@click.pass_context
def ledgers(ctx):
    """Every ledger that exists."""
    click.echo(ctx.obj['formatter'].format_simple_result({
        "success": True,
        "result": {"ledgers": list_ledgers()},
    }))


@evidence.command('export')
@click.option('--ledger', '-l', default="default",
              help="The ledger to export (default: default)")
@click.option('--output', '-o', default=None,
              help="The directory the files go to (default: the current one)")
@click.option('--binary', '-b', default="",
              help="The binary the findings are about, for the header")
@click.pass_context
def export(ctx, ledger, output, binary):
    """Export the ledger as a bundle.

    Two files: the Markdown one to read, and the JSON one to read with a
    program.
    """
    formatter = ctx.obj['formatter']
    try:
        book = Ledger.open(ledger)
        paths = export_bundle(book, output=output, binary=binary)
    except EvidenceError as exc:
        rich_echo(formatter.format_error(exc), err=True)
        ctx.exit(1)

    click.echo(formatter.format_simple_result({
        "success": True,
        "result": {"message": "the bundle was written", **paths},
    }))
