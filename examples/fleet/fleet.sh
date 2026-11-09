#!/usr/bin/env bash
# One question, several binaries: a fleet query across two instances.
#
# What to watch for in the output:
#   * the rows are *files*, not ports: two instances serving one binary are one
#     row, and a disagreement between them is reported instead of averaged;
#   * an instance that did not answer is reported as unreachable — "did not ask"
#     is never printed as "does not have it".
#
# Needs a Ghidra installation and two binaries.
set -euo pipefail

FIRST="${1:-}"
SECOND="${2:-}"
if [ -z "$FIRST" ] || [ -z "$SECOND" ]; then
    echo "usage: $0 <binary-a> <binary-b>" >&2
    echo "   eg: $0 C:\\Windows\\System32\\where.exe C:\\Windows\\System32\\whoami.exe" >&2
    exit 2
fi

PORT_A="${GHYDRA_EXAMPLE_PORT_A:-8194}"
PORT_B="${GHYDRA_EXAMPLE_PORT_B:-8195}"

echo "== start two headless runs =="
ghydra headless start "$FIRST" --port "$PORT_A"
ghydra headless start "$SECOND" --port "$PORT_B"

cleanup() {
    echo "== stop both =="
    ghydra headless stop --port "$PORT_A" || true
    ghydra headless stop --port "$PORT_B" || true
}
trap cleanup EXIT

echo
echo "== what each instance has open, merged by file =="
ghydra fleet overview --ports "$PORT_A,$PORT_B"

echo
echo "== does any of them import CreateFileW? =="
ghydra fleet has-import CreateFileW --ports "$PORT_A,$PORT_B"

echo
echo "== the references to strlen, file by file =="
ghydra fleet xrefs-to strlen --ports "$PORT_A,$PORT_B"

echo
echo "== and what happens when one member cannot be reached =="
echo "   (the row says unreachable; it does not say 'no')"
ghydra fleet overview --ports "$PORT_A,9999" || true