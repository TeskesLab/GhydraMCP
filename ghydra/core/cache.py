"""Which program an answer belongs to, and the key that says so.

The decompile cache is only safe because its key names the program: a different
binary must never read another one's answer, and a program that changed must not
read its own old one. Two things define that, and both were written twice (once
for the CLI, once for the bridge, which ships as one file):

* **the identity** — the fields of ``/program`` that name the program, plus the
  statistics that move when the program is edited;
* **the key** — a digest over the version, the kind of answer, the identity and
  the request.

What the identity *cannot* see is a rename inside the program: the server exposes
no modification counter, which is exactly why the cache is opt-in and has an age
limit. Keeping the definition in one place means both surfaces agree on what
"the same program" means — a disagreement there would serve a wrong answer
instead of a stale one.
"""

from __future__ import annotations

from typing import Any, Dict

from .digest import digest

#: Bumping this invalidates every entry on disk at once.
CACHE_VERSION = 1

#: The fields of /program that name the program an answer belongs to.
IDENTITY_FIELDS = ("programId", "path", "executablePath", "language",
                   "languageId", "imageBase", "creationDate")

#: The counters that move when the program is edited.
STATISTIC_FIELDS = ("functionCount", "symbolCount", "memoryBlockCount")


def identity_from_program(program: Any) -> Dict[str, Any]:
    """The identity of a program, from the payload of ``/program``.

    Args:
        program: The ``result`` of ``/program`` (any shape; a non-dict is "no
            identity", which the caller reports rather than keys on).

    Returns:
        dict: The identifying fields that were present, plus the statistics.
              Empty when the program cannot be identified.
    """
    if not isinstance(program, dict):
        return {}
    identity = {key: program[key] for key in IDENTITY_FIELDS
                if program.get(key) is not None}
    statistics = program.get("statistics")
    if isinstance(statistics, dict):
        identity["statistics"] = {key: statistics[key]
                                  for key in STATISTIC_FIELDS
                                  if statistics.get(key) is not None}
    return identity


def cache_key(identity: Dict[str, Any], kind: str, request: Dict[str, Any]) -> str:
    """The key of one answer: the version, the kind, the program and the question.

    Every part is load-bearing: the version lets a change to the format retire
    the old entries, the kind keeps two sorts of answer apart, the program keeps
    two binaries apart, and the request keeps two questions apart.
    """
    return digest({"version": CACHE_VERSION, "kind": kind,
                   "program": identity, "request": request})