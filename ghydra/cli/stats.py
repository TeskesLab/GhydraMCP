"""`ghydra stats` — the local usage summary (I14).

Reads ~/.ghydra/telemetry.jsonl (written by the bridge, never sent anywhere)
and prints what the session actually did: calls, failures, latency and
estimated token volume per tool, the error codes seen, and the composed tool
to use when the log shows a pattern one of them replaces.
"""

import time

import click

from ..telemetry import read_entries, summarize


def _format(report: dict, as_json: bool) -> str:
    import json
    if as_json:
        return json.dumps(report, ensure_ascii=False, indent=2)
    if not report.get("calls"):
        return f"No telemetry in the last {report.get('days')} day(s)."
    lines = [
        f"Local telemetry — {report['calls']} calls in the last "
        f"{report['days']} day(s)  ({report['path']})",
        f"  {'tool':<32} {'calls':>5} {'fail':>4} {'avg ms':>7} {'tokens':>8}",
    ]
    for row in report.get("tools") or []:
        lines.append(f"  {row['tool']:<32} {row['calls']:>5} "
                     f"{row['failed']:>4} {row.get('ms_avg', 0):>7} "
                     f"{row['tokens']:>8}")
    codes = report.get("error_codes") or {}
    if codes:
        lines.append("Error codes: " + ", ".join(
            f"{code}={count}" for code, count in sorted(codes.items())))
    found = report.get("recommendations") or []
    if found:
        lines.append("Recommendations:")
        lines.extend(f"  - {item}" for item in found)
    return "\n".join(lines)


@click.command('stats')
@click.option('--days', type=int, default=7, show_default=True,
              help='Only count calls from the last N days')
@click.option('--reset', is_flag=True,
              help='Delete the local telemetry log before reporting')
@click.pass_context
def stats(ctx, days, reset):
    """Summarize what this bridge has actually done, from the local log.

    \b
    Example:
        ghydra stats
        ghydra stats --days 30
    """
    import os
    from ..telemetry import telemetry_path

    if reset:
        try:
            os.remove(telemetry_path())
        except OSError:
            pass

    cutoff = time.time() - max(1, days) * 86400
    entries = [entry for entry in read_entries()
               if float(entry.get("ts") or 0) >= cutoff]
    report = summarize(entries, days)
    click.echo(_format(report, ctx.obj.get('output_json', False)))
