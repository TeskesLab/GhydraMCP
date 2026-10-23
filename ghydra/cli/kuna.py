"""Kuna decompiler commands.

Kuna (https://github.com/Noelo-Lab/kuna) is a standalone decompiler CLI that
runs on the machine where the CLI runs, so these commands need no Ghidra
instance and work against any Ghidra version.

The integration is opt-in, because it lets the CLI run a program on the
host: enable it with the GHYDRA_KUNA=1 environment variable, or with
"kuna": {"enabled": true} in ~/.ghydra/config.json. The config file wins
when both are set.
"""

import subprocess
import sys

import click

from .. import kuna as kuna_helper
from ..utils import rich_echo


@click.group('kuna')
def kuna():
    """Kuna decompiler commands (local, no Ghidra instance needed).

    These commands drive the Kuna decompiler CLI on this machine. They are
    opt-in: set GHYDRA_KUNA=1, or add "kuna": {"enabled": true} to
    ~/.ghydra/config.json.

    \b
    Examples:
        ghydra kuna status
        ghydra kuna summary ./challenge.exe
        ghydra kuna strings ./challenge.exe '(?i)password|flag'
        ghydra kuna export ./challenge.exe -o ./challenge.kuna
    """
    pass


def _section(ctx):
    """The kuna config section, as the CLI resolved it."""
    config = ctx.obj['config']
    section = {}
    if config.kuna_enabled is not None:
        section["enabled"] = config.kuna_enabled
    if config.kuna_path:
        section["path"] = config.kuna_path
    return section


def _emit(ctx, kind, data):
    """Print a kuna result through the active formatter.

    The output is written with the replacement error handler: a binary can
    hold strings the terminal's encoding cannot represent, and a mangled
    character is better than a traceback.
    """
    text = ctx.obj['formatter'].format_kuna({"kind": kind, "data": data})
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        text.encode(encoding)
    except UnicodeEncodeError:
        text = text.encode(encoding, errors="replace").decode(encoding, errors="replace")
    click.echo(text)


def _fail(ctx, exc):
    """Report a Kuna failure and stop with a non-zero exit code."""
    rich_echo(f"Error: {exc}", err=True)
    ctx.exit(1)


@kuna.command('status')
@click.pass_context
def status(ctx):
    """Show whether the Kuna integration is enabled and ready to use.

    \b
    Examples:
        ghydra kuna status
    """
    config_section = _section(ctx)
    executable = kuna_helper.find_binary(config_section)
    version = None

    if executable:
        try:
            completed = subprocess.run(
                [executable, "--version"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
            if completed.returncode == 0:
                version = completed.stdout.strip() or None
        except (OSError, subprocess.TimeoutExpired):
            version = None

    source = (
        "the config file"
        if config_section.get("enabled") is not None
        else f"${kuna_helper.ENV_ENABLED}"
    )

    _emit(ctx, "status", {
        "enabled": kuna_helper.is_enabled(config_section),
        "source": source,
        "binary": executable,
        "version": version,
        "config_file": kuna_helper.CONFIG_FILE,
        "work_dir": kuna_helper.WORK_DIR,
    })


@kuna.command('summary')
@click.argument('binary')
@click.option('--mode', help='Kuna mode preset (auto, reliable, aggressive, fast)')
@click.pass_context
def summary(ctx, binary, mode):
    """Summarize a binary: function count, entry point, reachability, size.

    \b
    Examples:
        ghydra kuna summary ./challenge.exe
    """
    config_section = _section(ctx)
    args = ["functions", binary, "--summary", "--json"]
    if mode:
        args += ["--mode", mode]

    try:
        data = kuna_helper.run(args, config=config_section)
    except kuna_helper.KunaError as exc:
        _fail(ctx, exc)
        return

    _emit(ctx, "summary", data)


@kuna.command('functions')
@click.argument('binary')
@click.option('--name', 'name_filter', help='Case-insensitive substring filter on the name')
@click.option('--offset', type=int, default=0, help='Pagination offset')
@click.option('--limit', type=int, default=100, help='Maximum number of functions to show')
@click.pass_context
def functions(ctx, binary, name_filter, offset, limit):
    """List the functions Kuna recovered from a binary.

    \b
    Examples:
        ghydra kuna functions ./challenge.exe --limit 20
        ghydra kuna functions ./challenge.exe --name main
    """
    config_section = _section(ctx)
    try:
        data = kuna_helper.run(["functions", binary, "--json"], config=config_section)
    except kuna_helper.KunaError as exc:
        _fail(ctx, exc)
        return

    entries = data.get("functions", []) if isinstance(data, dict) else []
    if name_filter:
        needle = name_filter.lower()
        entries = [fn for fn in entries if needle in str(fn.get("name", "")).lower()]

    total = len(entries)
    window = entries[offset:offset + limit]
    _emit(ctx, "functions", {
        "binary": data.get("binary", binary),
        "total": total,
        "offset": offset,
        "limit": limit,
        "functions": window,
    })


@kuna.command('decompile')
@click.argument('binary')
@click.argument('function')
@click.option('--addr', is_flag=True, help='Treat the target as an address')
@click.option('--mode', help='Kuna mode preset (auto, reliable, aggressive, fast)')
@click.pass_context
def decompile(ctx, binary, function, addr, mode):
    """Decompile one function with Kuna.

    \b
    Examples:
        ghydra kuna decompile ./challenge.exe main
        ghydra kuna decompile ./challenge.exe 0x401000 --addr
    """
    config_section = _section(ctx)
    args = ["decompile", binary, function, "--json"]
    if addr:
        args.append("--addr")
    if mode:
        args += ["--mode", mode]

    try:
        data = kuna_helper.run(args, config=config_section)
    except kuna_helper.KunaError as exc:
        _fail(ctx, exc)
        return

    _emit(ctx, "decompile", data)


@kuna.command('disassemble')
@click.argument('binary')
@click.argument('target')
@click.option('--count', type=int, help='Maximum number of instructions')
@click.option('--bytes', type=int, help='Maximum number of bytes')
@click.option('--addr', is_flag=True, help='Treat the target as an address')
@click.option('--mode', help='Kuna mode preset (auto, reliable, aggressive, fast)')
@click.pass_context
def disassemble(ctx, binary, target, count, bytes, addr, mode):
    """Disassemble a function or an address range with Kuna.

    \b
    Examples:
        ghydra kuna disassemble ./challenge.exe main
        ghydra kuna disassemble ./challenge.exe 0x401000-0x401040
    """
    config_section = _section(ctx)
    args = ["disassemble", binary, target, "--json"]
    if count is not None:
        args += ["--count", str(count)]
    if bytes is not None:
        args += ["--bytes", str(bytes)]
    if addr:
        args.append("--addr")
    if mode:
        args += ["--mode", mode]

    try:
        data = kuna_helper.run(args, config=config_section)
    except kuna_helper.KunaError as exc:
        _fail(ctx, exc)
        return

    _emit(ctx, "disassemble", data)


@kuna.command('read')
@click.argument('binary')
@click.argument('target')
@click.option('--bytes', type=int, default=64, help='Number of bytes to read')
@click.option('--addr', is_flag=True, help='Treat the target as an address')
@click.pass_context
def read(ctx, binary, target, bytes, addr):
    """Read raw bytes with Kuna, as a hex dump.

    \b
    Examples:
        ghydra kuna read ./challenge.exe 0x401000 --bytes 32
    """
    config_section = _section(ctx)
    args = ["read", binary, target, "--bytes", str(bytes), "--json"]
    if addr:
        args.append("--addr")

    try:
        data = kuna_helper.run(args, config=config_section)
    except kuna_helper.KunaError as exc:
        _fail(ctx, exc)
        return

    _emit(ctx, "read", data)


@kuna.command('strings')
@click.argument('binary')
@click.argument('pattern')
@click.option('--limit', type=int, default=50, help='Maximum number of strings to show')
@click.option('--min-length', type=int, default=5, help='Minimum length of a string')
@click.option('--encoding', default='ascii', help='ascii, utf16 or all')
@click.option('--section', 'section_name', help='Restrict the scan to one section')
@click.pass_context
def strings(ctx, binary, pattern, limit, min_length, encoding, section_name):
    """Search the strings of a binary with Kuna.

    The pattern is a regular expression and is required: an unfiltered scan
    of a large binary returns hundreds of kilobytes of text.

    \b
    Examples:
        ghydra kuna strings ./challenge.exe '(?i)password|flag'
    """
    config_section = _section(ctx)
    args = ["strings", binary, "--filter", pattern, "--min-length", str(min_length),
            "--encoding", encoding, "--json"]
    if section_name:
        args += ["--section", section_name]

    try:
        data = kuna_helper.run(args, config=config_section)
    except kuna_helper.KunaError as exc:
        _fail(ctx, exc)
        return

    entries = data.get("strings", []) if isinstance(data, dict) else []
    total = data.get("count", len(entries))
    data = dict(data)
    data["count"] = total
    data["strings"] = entries[:limit]
    data["returned"] = len(data["strings"])
    _emit(ctx, "strings", data)


@kuna.command('crypto')
@click.argument('binary')
@click.option('--algorithm', help='Algorithm name filter (e.g. AES, SHA)')
@click.option('--section', 'section_name', help='Restrict the scan to one section')
@click.pass_context
def crypto(ctx, binary, algorithm, section_name):
    """Scan a binary for crypto constants with Kuna.

    \b
    Examples:
        ghydra kuna crypto ./challenge.exe
        ghydra kuna crypto ./challenge.exe --algorithm AES
    """
    config_section = _section(ctx)
    args = ["crypto", binary, "--json"]
    if algorithm:
        args += ["--algorithm", algorithm]
    if section_name:
        args += ["--section", section_name]

    try:
        data = kuna_helper.run(args, config=config_section)
    except kuna_helper.KunaError as exc:
        _fail(ctx, exc)
        return

    _emit(ctx, "crypto", data)


@kuna.command('xrefs')
@click.argument('binary')
@click.argument('target')
@click.option('--direction', type=click.Choice(['from', 'to']), default='from',
              help='"from" (who references it) or "to" (what it references)')
@click.option('--kind', help='Reference kind filter (call, jump, data, read, write)')
@click.pass_context
def xrefs(ctx, binary, target, direction, kind):
    """Find the cross-references of a symbol or address with Kuna.

    \b
    Examples:
        ghydra kuna xrefs ./challenge.exe main
        ghydra kuna xrefs ./challenge.exe main --direction to
    """
    config_section = _section(ctx)
    args = ["xrefs", binary, f"--{direction}", target, "--json"]
    if kind:
        args += ["--kind", kind]

    try:
        data = kuna_helper.run(args, config=config_section)
    except kuna_helper.KunaError as exc:
        _fail(ctx, exc)
        return

    _emit(ctx, "xrefs", data)


@kuna.command('unpack')
@click.argument('binary')
@click.option('--output', '-o', help='Path for the unpacked file')
@click.pass_context
def unpack(ctx, binary, output):
    """Unpack a UPX-packed executable with Kuna.

    \b
    Examples:
        ghydra kuna unpack ./packed.exe -o ./unpacked.exe
    """
    config_section = _section(ctx)
    args = ["unpack", binary, "--json"]
    if output:
        args += ["-o", output]

    try:
        data = kuna_helper.run(args, config=config_section)
    except kuna_helper.KunaError as exc:
        _fail(ctx, exc)
        return

    _emit(ctx, "unpack", data)


@kuna.command('export')
@click.argument('binary')
@click.option('--output', '-o', help='Directory to write the export to')
@click.option('--functions', help='Comma-separated function names to export')
@click.option('--jobs', default='auto', help='Worker count (default: auto)')
@click.pass_context
def export(ctx, binary, output, functions, jobs):
    """Export a binary to disk with Kuna.

    The image is loaded and analysed once, and the recovered C, the
    disassembly and an index.jsonl land in a directory. Every function is
    then read from those files, instead of paying the analysis cost again on
    each call.

    \b
    Examples:
        ghydra kuna export ./challenge.exe -o ./challenge.kuna
        ghydra kuna export-read ./challenge.kuna main
    """
    config_section = _section(ctx)
    try:
        data = kuna_helper.export(
            binary,
            output=output,
            functions=functions,
            jobs=jobs,
            config=config_section,
        )
    except kuna_helper.KunaError as exc:
        _fail(ctx, exc)
        return

    _emit(ctx, "export", data)


@kuna.command('export-read')
@click.argument('directory')
@click.argument('function', required=False)
@click.option('--artifact', type=click.Choice(['c', 'asm', 'index', 'readme']),
              default='c', help='What to read from the export')
@click.option('--max-bytes', type=int, default=40000, help='Maximum bytes of text to show')
@click.pass_context
def export_read(ctx, directory, function, artifact, max_bytes):
    """Read a function out of a Kuna export.

    \b
    Examples:
        ghydra kuna export-read ./challenge.kuna main
        ghydra kuna export-read ./challenge.kuna main --artifact asm
        ghydra kuna export-read ./challenge.kuna --artifact index
    """
    config_section = _section(ctx)
    try:
        kuna_helper.require_binary(config_section)
        data = kuna_helper.read_export(
            directory,
            function=function,
            artifact=artifact,
            max_bytes=max_bytes,
        )
    except kuna_helper.KunaError as exc:
        _fail(ctx, exc)
        return

    _emit(ctx, "export-read", data)
