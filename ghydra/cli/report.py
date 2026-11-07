"""Report commands.

One command builds the whole report: Ghidra and Kuna on the same binary, in
one Markdown document and one JSON file, plus the annotations for x64dbg.
"""

import os

import click

from ..progress import Progress
from ..report import ReportError, ReportRequest, build_report, write_report
from ..utils import rich_echo


@click.group('report')
def report():
    """Build a report on a binary.

    \b
    Examples:
        # The whole report: Ghidra, Kuna and the annotations for x64dbg
        ghydra report build C:\\bin\\cmd.exe --output out

        # Without the debugger annotations
        ghydra report build C:\\bin\\cmd.exe --no-annotations

        # The report, and then put the annotations into the debugger
        ghydra report build C:\\bin\\cmd.exe --annotate
    """
    pass


def target_endpoint(ctx, host=None, port=None):
    """Where the report goes: the options of the command, or the CLI's own.

    The instance the CLI talks to is the one the root command chose: the host
    and the port come from the configuration, from the environment or from
    --host/--port. A report that went somewhere else would say one thing and
    show another.
    """
    client = (getattr(ctx, "obj", None) or {}).get('client')
    target_host = host or (client.host if client is not None else "127.0.0.1")
    # A port of 0 is a port that is not a port, and the runner says so -
    # so the test is whether the option was given, not whether it is true.
    target_port = int(port) if port is not None else int(client.port if client is not None else 8192)
    return target_host, target_port


@report.command('build')
@click.argument('binary', type=click.Path(exists=False, dir_okay=False))
@click.option('--output', '-o', default=None,
              help="Where the files go (default: the current directory)")
@click.option('--host', default=None,
              help="Host of the Ghidra instance (default: the one the CLI uses)")
@click.option('--port', '-p', type=int, default=None,
              help="Port of the Ghidra instance (default: the one the CLI uses)")
@click.option('--ghidra-home', default=None,
              help="Path of the Ghidra installation (default: GHIDRA_HOME)")
@click.option('--java-home', default=None,
              help="Path of the JDK (default: JAVA_HOME)")
@click.option('--timeout', type=int, default=900,
              help="Seconds to wait for the analysis and the API (default: 900)")
@click.option('--no-kuna', is_flag=True,
              help="Do not run Kuna; the report carries Ghidra alone")
@click.option('--no-headless', is_flag=True,
              help="Do not start a headless run; use the instance that is already there")
@click.option('--keep', is_flag=True,
              help="Leave the headless run running when the report is done")
@click.option('--max-functions', type=int, default=400,
              help="How many functions to read (default: 400)")
@click.option('--max-strings', type=int, default=300,
              help="How many strings to read (default: 300)")
@click.option('--max-decompile', type=int, default=12,
              help="How many functions to decompile (default: 12)")
@click.option('--max-annotations', type=int, default=60,
              help="How many annotations to prepare (default: 60)")
@click.option('--annotate', is_flag=True,
              help="Put the annotations into the debugger when the report is done")
@click.option('--bookmarks', is_flag=True,
              help="Also set a bookmark at every address (with --annotate)")
@click.option('--mode', type=click.Choice(['Comment', 'Label']), default='Comment',
              help="What to put at the address (default: Comment)")
@click.pass_context
def build(ctx, binary, output, host, port, ghidra_home, java_home, timeout,
          no_kuna, no_headless, keep, max_functions, max_strings,
          max_decompile, max_annotations, annotate, bookmarks, mode):
    """Build the report on BINARY.

    The report is written as three files: the Markdown one to read, the JSON
    one to read with a program, and the annotations for the debugger. It
    says what Ghidra found, what Kuna found, and what one of them saw and
    the other did not.

    \b
    Example:
        ghydra report build C:\\bin\\cmd.exe --output out
    """
    formatter = ctx.obj['formatter']

    target_host, target_port = target_endpoint(ctx, host, port)

    request = ReportRequest(
        binary=binary,
        output=output,
        host=target_host,
        port=target_port,
        ghidra_home=ghidra_home,
        java_home=java_home,
        timeout=timeout,
        with_kuna=not no_kuna,
        with_headless=not no_headless,
        keep=keep,
        max_functions=max_functions,
        max_strings=max_strings,
        max_decompile=max_decompile,
        max_annotations=max_annotations,
    )

    progress = Progress(enabled=not ctx.obj.get('output_json', False))
    try:
        data = build_report(request, progress=progress)
        with progress.step("writing the report"):
            paths = write_report(data, output)
    except ReportError as exc:
        rich_echo(formatter.format_error(exc), err=True)
        ctx.exit(1)

    applied = None
    if annotate:
        applied = _annotate(ctx, paths["annotations"], mode, bookmarks)

    payload = {
        "success": True,
        "result": {
            "message": f"The report is in {os.path.dirname(paths['markdown'])}",
            "markdown": paths["markdown"],
            "json": paths["json"],
            "annotations": paths["annotations"],
            "functions": len(data.get("functions") or []),
            "decompiled": len(data.get("decompiled") or []),
            "kuna_code": len(data.get("kuna_code") or []),
            "comparison": data.get("comparison") or {},
        },
    }
    if applied is not None:
        payload["result"]["annotated"] = applied
    click.echo(formatter.format_simple_result(payload))


def _annotate(ctx, path, mode, bookmarks):
    """Put the annotations of the report into the debugger."""
    from .. import x64dbg as x64dbg_helper

    config = ctx.obj['config']
    section = {
        "host": config.x64dbg_host,
        "port": config.x64dbg_port,
        "token": config.x64dbg_token,
        "path": config.x64dbg_path,
    }
    try:
        client = x64dbg_helper.Client(
            **{k: v for k, v in x64dbg_helper.resolve_config(section).items()
               if k in ("host", "port", "token")}
        )
        loaded = x64dbg_helper.load_annotations(path)
        result = x64dbg_helper.apply_annotations(
            client, loaded, mode=mode, bookmarks=bookmarks)
    except x64dbg_helper.X64dbgError as exc:
        rich_echo(f"Error [{exc.code}]: {exc}", err=True)
        return None
    return {
        "applied": len(result.get("applied") or []),
        "failed": len(result.get("failed") or []),
    }
