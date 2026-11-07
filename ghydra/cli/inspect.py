"""The target triage.

Before you can pick the right tool, you need to know what the target is.
A .NET assembly, an Android APK, an EVM contract, a WASM module, a
JavaScript application, a firmware image and a native PE all need
completely different treatment.

The address inspection lives here too: it is the same question asked of
the binary rather than of the file - what is at this address?
"""

import json
from urllib.parse import quote

import click

from ..client.exceptions import GhidraError
from ..triage import TriageError, format_of, hashes, overview
from ..utils import rich_echo, validate_address


@click.command('inspect')
@click.argument('target', type=click.Path(exists=False, dir_okay=True))
@click.option('--facts-only', is_flag=True,
              help="Only the format and the facts that identify it")
@click.pass_context
def inspect(ctx, target, facts_only):
    """Say what TARGET is, and what it needs.

    The format comes from the bytes and never from the name of the file.
    A PE, an ELF, a Mach-O, a DEX, an APK, a WASM module, an EVM contract, a
    firmware image, a JavaScript or Electron application, a core dump, a
    plist, a HAR capture - and what each of them needs to be looked at.

    It needs neither Ghidra nor the network.

    \b
    Example:
        ghydra inspect C:\\bin\\cmd.exe
    """
    formatter = ctx.obj['formatter']
    try:
        data = overview(target)
    except TriageError as exc:
        rich_echo(formatter.format_error(exc), err=True)
        ctx.exit(1)

    if ctx.obj.get('output_json'):
        click.echo(formatter.format_simple_result({
            "success": True,
            "result": data if facts_only else data,
        }))
        return

    lines = [f"{target}", f"  format: {data.get('format', 'unknown')}"]
    if data.get("size") is not None:
        lines.append(f"  size: {data.get('size')} bytes")
    if data.get("sha256"):
        lines.append(f"  sha256: {data.get('sha256')}")

    facts = data.get("facts") or {}
    if facts:
        lines.append("")
        lines.append("What says so:")
        for key, value in facts.items():
            if isinstance(value, (list, tuple)):
                value = ", ".join(str(item) for item in value[:8])
                if len(value) > 120:
                    value = value[:117] + "..."
            lines.append(f"  {key}: {value}")

    details = data.get("details") or {}
    if details and not facts_only:
        lines.append("")
        lines.append("What is in it:")
        lines.append(_render_details(details))

    recommendations = data.get("recommendations") or []
    if recommendations:
        lines.append("")
        lines.append("What it needs:")
        for item in recommendations:
            lines.append(f"  - {item}")

    rich_echo("\n".join(lines))


@click.command('inspect-address')
@click.argument('address')
@click.pass_context
def inspect_address(ctx, address):
    """Say what is at ADDRESS, in one call.

    An agent that lands on an address has to ask four questions: what is
    called here, what function is it in, what does it hold, and who refers
    to it. This answers all four at once - the symbol, the containing
    function, the data, the instruction, the comments, and the references on
    both sides of the address.

    \b
    Example:
        ghydra inspect-address 0x140001008
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        response = client.get(f'inspect/address/{quote(validate_address(address))}')
        click.echo(formatter.format_address_context(response))

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


def _render_details(details: dict, indent: str = "  ") -> str:
    """The details of a target, as readable lines."""
    lines = []
    for key, value in details.items():
        if isinstance(value, list):
            if not value:
                continue
            lines.append(f"{indent}{key}:")
            for item in value[:12]:
                if isinstance(item, dict):
                    summary = ", ".join(
                        f"{name}={part}" for name, part in list(item.items())[:4]
                        if not isinstance(part, (list, dict)))
                    lines.append(f"{indent}  {summary}")
                else:
                    lines.append(f"{indent}  {item}")
            if len(value) > 12:
                lines.append(f"{indent}  ... and {len(value) - 12} more")
        elif isinstance(value, dict):
            lines.append(f"{indent}{key}:")
            for name, part in list(value.items())[:12]:
                if isinstance(part, (list, dict)):
                    part = json.dumps(part, ensure_ascii=False)[:100]
                lines.append(f"{indent}  {name}: {part}")
        else:
            lines.append(f"{indent}{key}: {value}")
    return "\n".join(lines)
