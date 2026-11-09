#!/usr/bin/env bash
# A mission from start to finish: a goal in prose, a hard budget, a dossier.
#
# What to watch for in the output:
#   * the findings carry a status (verified / unverified / unknown);
#   * the "not determined" section is filled in when the budget stops the work;
#   * the verification section says how many evidence items were re-read — and
#     the command exits 1 when a conclusion could not be kept.
#
# Needs a Ghidra installation (`ghydra doctor` says whether you have one) and a
# binary. Nothing else.
set -euo pipefail

BINARY="${1:-}"
GOAL="${2:-does data from recv reach system?}"

if [ -z "$BINARY" ]; then
    echo "usage: $0 <binary> [goal]" >&2
    echo "   eg: $0 C:\\Windows\\System32\\where.exe" >&2
    exit 2
fi

PORT="${GHYDRA_EXAMPLE_PORT:-8193}"

echo "== start a headless run on port $PORT =="
ghydra headless start "$BINARY" --port "$PORT"

# The run is stopped even when the mission fails, so a broken mission cannot
# leave an analyzer holding the project.
cleanup() {
    echo "== stop the headless run =="
    ghydra headless stop --port "$PORT" || true
}
trap cleanup EXIT

echo
echo "== the mission: \"$GOAL\" =="
echo "   (a budget is a hard stop: when it is spent, the dossier says what it"
echo "    did not determine instead of doing less quietly)"
set +e
ghydra --port "$PORT" mission start -g "$GOAL" --max-calls 40 --max-tokens 60000 \
    --output "$(dirname "$0")/dossier.md"
STATUS=$?
set -e

echo
echo "== the dossier was written to examples/mission/dossier.md =="
echo "   exit status: $STATUS"
case "$STATUS" in
    0) echo "   every conclusion held when its evidence was re-read" ;;
    1) echo "   at least one conclusion could not be kept (see 'unverified')" ;;
    *) echo "   the mission could not run: look at the reason above" ;;
esac
exit "$STATUS"