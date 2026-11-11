"""A disk cache for the answers that cost the most (I11).

Decompilation is the expensive call in this API: it runs the decompiler once per
function, and a session that revisits the same function pays again. This cache
stores those answers under ``~/.ghydra/cache`` and serves them when the program
has not changed.

Three rules keep it from lying:

* **The key includes the program's identity.** ``programId``, ``executable_path``,
  ``language``, ``imageBase``, ``creationDate`` and the statistics the server
  reports name the program the answer belongs to. A different binary never reads
  another one's cached decompilation.
* **The server exposes no modification counter**, so those facts cannot prove a
  program is unedited. The cache is therefore **opt-in**, has a **max age**
  (24 hours by default) and is **bounded** — and ``ghydra cache clear`` exists
  because a name-only edit would not change the identity we can see.
* **A cache failure is never a failed call.** Every disk error is swallowed: a
  full disk costs a re-decompile, not an answer.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any, Dict, Optional, Tuple

from .core import cache as core_identity

CACHE_VERSION = 1
DEFAULT_MAX_BYTES = 50_000_000
DEFAULT_MAX_AGE_SECONDS = 24 * 60 * 60

#: Defined once, in the core (I1).
IDENTITY_FIELDS = core_identity.IDENTITY_FIELDS
STATISTIC_FIELDS = core_identity.STATISTIC_FIELDS


def cache_root() -> str:
    """Where the cache lives ($GHYDRA_STATE_DIR wins, then ~/.ghydra)."""
    base = os.environ.get("GHYDRA_STATE_DIR")
    root = base if base else os.path.join(os.path.expanduser("~"), ".ghydra")
    return os.path.join(root, "cache")


def entries_dir() -> str:
    return os.path.join(cache_root(), f"v{CACHE_VERSION}")


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def program_identity(client) -> Dict[str, Any]:
    """The facts that say which program an answer belongs to.

    Reads ``/program`` once; an unreachable instance yields an empty identity,
    which makes the caller skip the cache rather than key on nothing.
    """
    try:
        response = client.get("program")
    except Exception:
        return {}
    payload = response.get("result") if isinstance(response, dict) else None
    # The fields that define the identity live in the core (I1).
    return core_identity.identity_from_program(payload)


def cache_key(identity: Dict[str, Any], kind: str,
              request: Dict[str, Any]) -> str:
    """A key that changes when the program or the question changes.

    Delegates to the core (I1): the bridge computes the same key, so an entry
    written by one surface is read by the other.
    """
    return core_identity.cache_key(identity, kind, request)


def entry_path(key: str) -> str:
    return os.path.join(entries_dir(), key[:2], f"{key}.json")


def get(key: str, max_age: int = DEFAULT_MAX_AGE_SECONDS) -> Optional[Dict[str, Any]]:
    """The cached entry, or None when it is missing, stale or unreadable."""
    try:
        with open(entry_path(key), encoding="utf-8") as handle:
            entry = json.load(handle)
    except (OSError, ValueError):
        return None
    if not isinstance(entry, dict):
        return None
    created = entry.get("created")
    if not isinstance(created, (int, float)):
        return None
    if max_age > 0 and time.time() - created > max_age:
        return None
    if not isinstance(entry.get("response"), dict):
        return None
    return entry


def put(key: str, identity: Dict[str, Any], kind: str,
        request: Dict[str, Any], response: Dict[str, Any],
        max_bytes: int = DEFAULT_MAX_BYTES) -> bool:
    """Store an answer. Returns False when it could not be written."""
    if not isinstance(response, dict):
        return False
    path = entry_path(key)
    entry = {"key": key, "created": time.time(), "kind": kind,
             "program": identity, "request": request, "response": response}
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        temporary = path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            handle.write(canonical(entry))
        os.replace(temporary, path)
    except OSError:
        return False
    evict(max_bytes)
    return True


def iter_entries() -> list:
    """Every entry on disk, as (path, entry, size) triples."""
    found = []
    root = entries_dir()
    if not os.path.isdir(root):
        return found
    for bucket in sorted(os.listdir(root)):
        bucket_path = os.path.join(root, bucket)
        if not os.path.isdir(bucket_path):
            continue
        for name in sorted(os.listdir(bucket_path)):
            if not name.endswith(".json"):
                continue
            path = os.path.join(bucket_path, name)
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            entry = {}
            try:
                with open(path, encoding="utf-8") as handle:
                    entry = json.load(handle)
            except (OSError, ValueError):
                entry = {}
            found.append((path, entry if isinstance(entry, dict) else {}, size))
    return found


def stats() -> Dict[str, Any]:
    """What the cache holds: entries, bytes, age and the bound."""
    entries = iter_entries()
    sizes = [size for _path, _entry, size in entries]
    created = [entry["created"] for _path, entry, _size in entries
               if isinstance(entry.get("created"), (int, float))]
    return {
        "path": entries_dir(),
        "entries": len(entries),
        "bytes": sum(sizes),
        "max_bytes": DEFAULT_MAX_BYTES,
        "oldest": min(created) if created else None,
        "newest": max(created) if created else None,
        "programs": len({canonical(entry.get("program"))
                         for _path, entry, _size in entries}),
        "kinds": sorted({str(entry.get("kind")) for _path, entry, _size in entries
                         if entry.get("kind")}),
    }


def clear() -> int:
    """Remove every entry; returns how many were removed."""
    removed = 0
    for path, _entry, _size in iter_entries():
        try:
            os.unlink(path)
            removed += 1
        except OSError:
            continue
    return removed


def evict(max_bytes: int = DEFAULT_MAX_BYTES) -> int:
    """Drop the oldest entries until the cache is under the bound."""
    entries = iter_entries()
    total = sum(size for _path, _entry, size in entries)
    if total <= max_bytes:
        return 0
    removed = 0
    # Oldest first: created when known, file mtime otherwise.
    def age(item):
        path, entry, _size = item
        created = entry.get("created")
        if isinstance(created, (int, float)):
            return created
        try:
            return os.path.getmtime(path)
        except OSError:
            return 0.0

    for path, _entry, size in sorted(entries, key=age):
        if total <= max_bytes:
            break
        try:
            os.unlink(path)
            total -= size
            removed += 1
        except OSError:
            continue
    return removed


def get_or_compute(client, kind: str, request: Dict[str, Any], compute,
                   identity: Optional[Dict[str, Any]] = None,
                   max_age: int = DEFAULT_MAX_AGE_SECONDS,
                   max_bytes: int = DEFAULT_MAX_BYTES) -> Tuple[Dict[str, Any], bool]:
    """Serve an answer from the cache, or compute it and store it.

    Returns ``(response, cached)``. A cache that cannot be read or written is
    not an error: the answer is computed and the caller gets it either way.
    """
    identity = identity if identity is not None else program_identity(client)
    if not identity:
        return compute(), False
    key = cache_key(identity, kind, request)
    if max_age == 0:
        # A zero age asks for a fresh answer: compute it, refresh the entry,
        # and say it was not served from the cache.
        response = compute()
        if isinstance(response, dict) and response.get("success", False):
            put(key, identity, kind, request, response, max_bytes=max_bytes)
        return response, False
    entry = get(key, max_age=max_age)
    if entry is not None:
        return entry["response"], True
    response = compute()
    if isinstance(response, dict) and response.get("success", False):
        put(key, identity, kind, request, response, max_bytes=max_bytes)
    return response, False


def to_text(report: Dict[str, Any]) -> str:
    """A text rendering shared by the CLI and the bridge."""
    if not isinstance(report, dict):
        return str(report)
    oldest = report.get("oldest")
    newest = report.get("newest")
    def when(value):
        if not isinstance(value, (int, float)):
            return "?"
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(value))
    return "\n".join([
        f"Decompile cache: {report.get('path', '?')}",
        f"  entries: {report.get('entries', 0)}  "
        f"bytes: {report.get('bytes', 0)} of {report.get('max_bytes', 0)}",
        f"  programs: {report.get('programs', 0)}  "
        f"kinds: {', '.join(report.get('kinds') or []) or '-'}",
        f"  oldest: {when(oldest)}  newest: {when(newest)}",
    ])