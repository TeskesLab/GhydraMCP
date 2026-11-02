#!/usr/bin/env python3
"""Measure what the Kuna integration costs, and print the table for the docs.

The numbers quoted in GHYDRA_KUNA.md are only as good as the version they
were measured with, and Kuna keeps moving. This script measures the three
commands the integration actually runs, on the binaries the docs quote, and
prints a Markdown table ready to paste.

What it measures is the cost of *one* invocation, because that is the cost
the agent pays: Kuna loads and analyses the whole image every time, and
keeps no state between calls. The export flow is the way out of that, and
--with-export measures the two halves of it - the analysis, and the re-read
of an export that already exists.

Two things this script is careful about:

* It measures the **real** Kuna binary, not the Scoop shim. The shim is a
  small launcher that execs the real executable: the timing is honest, but
  the size and the function count would be the shim's.
* It measures the export **in process**, through the integration itself.
  The export goes into a directory of its own and is removed afterwards, so
  the cache of the user is left alone, and the numbers are the cost of the
  work rather than the cost of starting Python.

Usage:
    python scripts/bench_kuna.py
    python scripts/bench_kuna.py --repeat 5
    python scripts/bench_kuna.py --with-export
    python scripts/bench_kuna.py --binary C:\\path\\to\\binary.exe
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def resolve_install(path: str) -> str:
    """The real executable behind a Scoop shim.

    The shim in "scoop\\shims" is a tiny launcher that execs the real
    executable. Running it is honest, but the size and the function count
    of a binary found there are the shim's, and the docs quote both.
    """
    absolute = os.path.abspath(path)
    if os.path.basename(os.path.dirname(absolute)).lower() != "shims":
        return absolute
    apps = os.path.join(os.path.dirname(os.path.dirname(absolute)), "apps")
    name = os.path.basename(absolute)
    # The application usually carries the name of the executable.
    direct = os.path.join(apps, os.path.splitext(name)[0].lower(), "current", name)
    if os.path.isfile(direct):
        return direct
    if os.path.isdir(apps):
        for app in sorted(os.listdir(apps), reverse=True):
            candidate = os.path.join(apps, app, "current", name)
            if os.path.isfile(candidate):
                return candidate
    return absolute


def find_kuna() -> Optional[str]:
    """The kuna executable, or None when it is not installed."""
    override = os.environ.get("GHYDRA_KUNA_BINARY")
    if override and os.path.isfile(override):
        return resolve_install(override)
    found = shutil.which("kuna")
    if found:
        return resolve_install(found)
    if os.name == "nt":
        home = os.path.expanduser("~")
        current = os.path.join(home, "scoop", "apps", "kuna", "current", "kuna.exe")
        if os.path.isfile(current):
            return current
    return None


def kuna_version(executable: str) -> str:
    """The version string, for the table's caption."""
    try:
        completed = subprocess.run(
            [executable, "--version"], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    return (completed.stdout or "").strip() or "unknown"


def run(executable: str, args: Sequence[str], timeout: int = 1800) -> Tuple[float, str]:
    """Run kuna and return how long it took, in milliseconds, and its output.

    Kuna writes UTF-8. Decoding with the locale instead would break on a
    non-UTF-8 locale, which is what the CLI learned the hard way.
    """
    started = time.perf_counter()
    completed = subprocess.run(
        [executable, *args], capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=timeout,
    )
    elapsed = (time.perf_counter() - started) * 1000.0
    if completed.returncode != 0:
        raise RuntimeError(
            f"kuna {' '.join(args[:2])} failed ({completed.returncode}): "
            f"{(completed.stderr or '').strip()[:200]}"
        )
    return elapsed, completed.stdout or ""


def median(values: List[float]) -> float:
    """The middle sample. One run can be unlucky; the middle is the number."""
    return float(statistics.median(values))


def first_function(summary: str) -> Optional[str]:
    """A function to decompile: the entry point, when the summary names one."""
    try:
        data: Dict[str, Any] = json.loads(summary)
    except ValueError:
        return None
    entry = ((data.get("summary") or {}).get("entry") or {})
    name = entry.get("name")
    return str(name) if name else None


def count_functions(summary: str) -> Optional[int]:
    """How many functions the summary found."""
    try:
        data: Dict[str, Any] = json.loads(summary)
    except ValueError:
        return None
    for key in ("count", "total"):
        value = data.get(key)
        if isinstance(value, int):
            return value
    return None


def measure(executable: str, binary: str, repeat: int) -> Dict[str, Any]:
    """Measure the three commands on one binary."""
    results: Dict[str, Any] = {"binary": binary}

    samples: List[float] = []
    summary = ""
    for _ in range(repeat):
        elapsed, summary = run(executable, ["functions", binary, "--summary", "--json"])
        samples.append(elapsed)
    results["summary"] = median(samples)
    results["functions"] = count_functions(summary)

    target = first_function(summary)
    if not target:
        raise RuntimeError(f"the summary of {binary} named no entry point to decompile")

    samples = []
    for _ in range(repeat):
        elapsed, _ = run(executable, ["crypto", binary, "--json"])
        samples.append(elapsed)
    results["crypto"] = median(samples)

    samples = []
    for _ in range(repeat):
        elapsed, _ = run(executable, ["decompile", binary, target, "--json"])
        samples.append(elapsed)
    results["decompile"] = median(samples)
    results["target"] = target
    return results


def measure_export(binary: str, repeat: int) -> Dict[str, Any]:
    """Measure the export flow: the analysis, and the re-read of the export.

    The export goes through the integration itself, so what is measured is
    the path the agent takes - including the reuse that the digest makes
    possible. It lands in a directory of its own, which is removed
    afterwards, so the cache of the user is left exactly as it was.
    """
    os.environ.setdefault("GHYDRA_KUNA", "1")
    from ghydra import kuna as kuna_helper

    with tempfile.TemporaryDirectory(prefix="ghydra-bench-kuna-") as directory:
        started = time.perf_counter()
        first = kuna_helper.export(binary, output=directory)
        analysis = (time.perf_counter() - started) * 1000.0
        if first.get("reused"):
            raise RuntimeError(
                f"the export of {binary} was already complete before the measurement"
            )

        samples: List[float] = []
        for _ in range(repeat):
            started = time.perf_counter()
            again = kuna_helper.export(binary, output=directory)
            samples.append((time.perf_counter() - started) * 1000.0)
            if not again.get("reused"):
                raise RuntimeError(f"the export of {binary} was not reused")

    return {"analysis": analysis, "reread": median(samples)}


def human_size(path: str) -> str:
    """A size a human reads: 332 KB, 44 MB."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return "?"
    if size >= 1024 * 1024:
        return f"{size / (1024 * 1024):.0f} MB"
    if size >= 1024:
        return f"{size / 1024:.0f} KB"
    return f"{size} B"


def default_binaries(executable: str) -> List[str]:
    """The binaries the docs quote: a small one and a large one."""
    found: List[str] = []
    system = os.environ.get("SystemRoot", r"C:\Windows")
    cmd = os.path.join(system, "System32", "cmd.exe")
    if os.path.isfile(cmd):
        found.append(cmd)
    if os.path.isfile(executable):
        found.append(executable)
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--binary", action="append", default=[],
                        help="a binary to measure; repeatable (default: cmd.exe and kuna itself)")
    parser.add_argument("--repeat", type=int, default=3,
                        help="how many times to run each command (default: 3)")
    parser.add_argument("--with-export", action="store_true",
                        help="also measure the export flow: the analysis and the re-read")
    args = parser.parse_args()

    executable = find_kuna()
    if not executable:
        print("kuna is not on PATH; install it or set GHYDRA_KUNA_BINARY", file=sys.stderr)
        return 1

    binaries = args.binary or default_binaries(executable)
    if not binaries:
        print("no binary to measure", file=sys.stderr)
        return 1

    version = kuna_version(executable)
    print(f"kuna {version} - median of {args.repeat} runs", file=sys.stderr)
    print(f"binary: {executable}", file=sys.stderr)

    rows: List[Dict[str, Any]] = []
    for binary in binaries:
        print(f"measuring {binary} ...", file=sys.stderr)
        row = measure(executable, binary, max(1, args.repeat))
        row["size"] = human_size(binary)
        if args.with_export:
            print(f"exporting {binary} ...", file=sys.stderr)
            row.update(measure_export(binary, max(1, args.repeat)))
        rows.append(row)

    print()
    print("| Binary | Size | `summary` | `crypto` | `decompile` |")
    print("| --- | --- | --- | --- | --- |")
    for row in rows:
        label = os.path.basename(row["binary"])
        functions = row.get("functions")
        size = f"{row['size']}" + (f", {functions:,} functions" if functions else "")
        print(f"| `{label}` | {size} | {row['summary']:.0f} ms | "
              f"{row['crypto']:.0f} ms | {row['decompile']:.0f} ms |")

    if args.with_export:
        print()
        print("| Binary | Export (the analysis) | Re-read of that export |")
        print("| --- | --- | --- |")
        for row in rows:
            print(f"| `{os.path.basename(row['binary'])}` | {row['analysis']:.0f} ms | "
                  f"{row['reread']:.0f} ms |")

    return 0


if __name__ == "__main__":
    sys.exit(main())
