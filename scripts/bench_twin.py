"""Measure the twin against the live API — the experiment R2 stands or falls on.

The criterion, written down before the code: *if a snapshot does not answer
faster than the live API on two real binaries, R2 dies.* A snapshot is only worth
its provenance if reading the facts costs less than fetching them again.

    python scripts/bench_twin.py --port 8192 --binary C:\\Windows\\System32\\where.exe

It builds a twin of the running instance, then measures the same questions three
ways: over HTTP to the instance, from the snapshot in memory, and from the
snapshot file on disk. The numbers are printed as medians, because a mean hides
the tail that a caller feels.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from ghydra import twin as twin_helper  # noqa: E402
from ghydra.client import GhidraHTTPClient  # noqa: E402


def timed(action, rounds: int) -> list:
    samples = []
    for _ in range(rounds):
        started = time.perf_counter()
        action()
        samples.append((time.perf_counter() - started) * 1000.0)
    return samples


def report(label: str, samples: list) -> float:
    median = statistics.median(samples)
    print(f"{label:38} median {median:8.2f} ms"
          f"  p95 {sorted(samples)[max(0, int(len(samples) * 0.95) - 1)]:8.2f} ms")
    return median


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8192)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--rounds", type=int, default=20)
    parser.add_argument("--binary", default="", help="only for the report header")
    arguments = parser.parse_args(argv)

    client = GhidraHTTPClient(host=arguments.host, port=arguments.port)
    print(f"instance: {arguments.host}:{arguments.port}")
    if arguments.binary:
        print(f"binary:   {arguments.binary}")

    started = time.perf_counter()
    document = twin_helper.build(client)
    build_ms = (time.perf_counter() - started) * 1000.0
    print(f"\nbuild: {build_ms:.1f} ms for"
          f" {document['counts']['functions']} functions,"
          f" {document['counts']['imports']} imports,"
          f" {document['counts']['strings']} strings")

    directory = tempfile.mkdtemp(prefix="ghydra-twin-bench-")
    path = os.path.join(directory, "twin.json")
    twin_helper.save(document, path)
    size_kb = os.path.getsize(path) / 1024.0

    first = {}
    for function in document.get("functions") or []:
        first = function
        break
    address = first.get("address") or "0x0"

    live_program = timed(lambda: client.get("program"), arguments.rounds)
    live_functions = timed(
        lambda: client.get("functions", params={"limit": 100, "offset": 0}),
        arguments.rounds)
    live_function = timed(
        lambda: client.get("functions", params={"limit": 1}), arguments.rounds)

    in_memory = timed(lambda: twin_helper.query(document, "functions", "FUN"), 200)
    by_address = timed(lambda: twin_helper.query(document, "function", address), 200)
    disk = timed(lambda: twin_helper.query(twin_helper.load(path), "overview"), 20)

    print(f"\nsnapshot: {size_kb:.1f} KB on disk\n")
    print("live API")
    program_ms = report("  GET /program", live_program)
    functions_ms = report("  GET /functions?limit=100", live_functions)
    single_ms = report("  GET /functions?limit=1", live_function)
    print("\nsnapshot")
    memory_ms = report("  functions matching a name (in memory)", in_memory)
    address_ms = report("  one function by address (in memory)", by_address)
    disk_ms = report("  overview (read the file each time)", disk)

    print("\nverdict")
    print(f"  name search:  snapshot is {functions_ms / memory_ms:6.1f}x faster"
          " than paging the live listing")
    print(f"  by address:   snapshot is {single_ms / address_ms:6.1f}x faster"
          " than asking the API")
    print(f"  file on disk: {disk_ms:.2f} ms against {program_ms:.2f} ms —"
          f" {'faster' if disk_ms < program_ms else 'slower'}")
    print("\nA snapshot answers facts that were already fetched. It cannot"
          " decompile,")
    print("read memory, or see a change made after it was taken — the"
          " provenance is why.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())