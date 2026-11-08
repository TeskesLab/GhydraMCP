"""`ghydra assert` — declarative assertions about a binary (I16).

Each assertion is one yes/no question the REST API can answer, so a CI job can
gate on it: "this build imports no CreateRemoteThread", "the string /api/v1
exists", "main reaches strcmp". The report is text, JUnit XML or SARIF 2.1.0.
"""

import sys

import click

from ..assertions import (AssertionError_, evaluate, load_assertions,
                          render)
from ..client.exceptions import GhidraError


@click.command('assert')
@click.option('--file', '-f', 'assertion_file', required=True,
              help='JSON file with the assertions (list or {"assertions": [...]})')
@click.option('--format', '-F', 'output_format',
              type=click.Choice(['text', 'junit', 'sarif']), default='text',
              show_default=True, help='Report format')
@click.option('--output', '-o', default=None,
              help='Write the report to this file instead of stdout')
@click.pass_context
def assert_cmd(ctx, assertion_file, output_format, output):
    """Assert facts about the binary and exit non-zero when one fails.

    \b
    Example:
        ghydra assert -f asserts.json
        ghydra assert -f asserts.json --format junit -o report.xml
        ghydra assert -f asserts.json --format sarif -o report.sarif
    """
    client = ctx.obj['client']

    try:
        assertions = load_assertions(assertion_file)
    except AssertionError_ as exc:
        click.echo(f"Error [{exc.code}]: {exc}", err=True)
        ctx.exit(2)

    try:
        report = evaluate(client, assertions)
    except GhidraError as exc:
        click.echo(f"Error: {exc}", err=True)
        ctx.exit(2)

    text = render(report, output_format)
    if output:
        with open(output, 'w', encoding='utf-8') as handle:
            handle.write(text + ("\n" if not text.endswith("\n") else ""))
        click.echo(f"Report written to {output}")
    else:
        click.echo(text)

    result = report.get("result", report)
    # A failure is the signal a CI job needs; an inconclusive verdict is
    # reported but does not fail the build (it means "not proven").
    ctx.exit(1 if result.get("failed") else 0)
