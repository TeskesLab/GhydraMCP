# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "mcp==1.6.0",
#     "requests==2.32.3",
#     # Same ceiling as pyproject.toml: mcp 1.6.0 imports
#     # pydantic._internal._typing_extra.eval_type_backport, which pydantic
#     # 2.14 removed. Without it a fresh resolve picks pydantic >= 2.14 and
#     # `import mcp.server.fastmcp` dies with an ImportError - measured with
#     # uv 0.10.10, which resolved 2.14.1 and failed to import.
#     "pydantic<2.14",
# ]
# ///
# GhydraMCP Bridge for Ghidra HATEOAS API - Optimized for MCP integration
# Provides namespaced tools for interacting with Ghidra's reverse engineering capabilities
import base64
import functools
import hashlib
import math
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from typing import Annotated, Dict, List, Optional, Union, Any
from urllib.parse import quote, unquote, urlencode, urlparse

import requests
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.resources import FunctionResource
from pydantic import AnyUrl, BeforeValidator

# ================= Core Infrastructure =================

ALLOWED_ORIGINS = os.environ.get(
    "GHIDRA_ALLOWED_ORIGINS", "http://localhost").split(",")

active_instances: Dict[int, dict] = {}
instances_lock = Lock()
_scan_lock = Lock()
_last_quick_scan = 0.0
DEFAULT_GHIDRA_PORT = 8192
DEFAULT_GHIDRA_HOST = "localhost"
# The plugin walks up to MAX_PORT_ATTEMPTS ports from DEFAULT_PORT (8192-8447).
# The full sweep has to reach every port the plugin can bind: an instance above
# 8211 used to need manual registration. The probes run concurrently (16
# workers), so the wider range costs batches, not one round trip per port.
MAX_PORT_ATTEMPTS = 256
QUICK_DISCOVERY_RANGE = range(DEFAULT_GHIDRA_PORT, DEFAULT_GHIDRA_PORT+10)
FULL_DISCOVERY_RANGE = range(DEFAULT_GHIDRA_PORT,
                            DEFAULT_GHIDRA_PORT + MAX_PORT_ATTEMPTS)

# A live Ghidra plugin on the local host answers /plugin-version in
# milliseconds. The timeout only bounds what a closed port costs, and on a host
# whose firewall drops the packets instead of refusing them that is the whole
# cost of the scan.
DISCOVERY_PROBE_TIMEOUT = 0.2

# How long a quick scan stays valid: a burst of instances_list calls shares
# one scan instead of paying the probe timeout each time.
QUICK_SCAN_TTL = 1.0

BRIDGE_VERSION = "v3.37.1"
REQUIRED_API_VERSION = 3000

DEFAULT_TIMEOUT = int(os.environ.get("GHIDRA_TIMEOUT", "900"))
DEFAULT_DECOMPILATION_TIMEOUT = int(
    os.environ.get("GHIDRA_DECOMP_TIMEOUT", str(max(DEFAULT_TIMEOUT, 1200)))
)

# How many functions one batch may ask for. The server refuses a longer one,
# so the deadline of a batch is sized for the batch it will actually accept.
MAX_BATCH_TARGETS = 200

current_instance_port = DEFAULT_GHIDRA_PORT

# The tools answer in text, because a human - or an LLM - reads a table
# better than a JSON envelope. A machine wants the envelope itself, so
# GHYDRA_MCP_OUTPUT=json hands it the raw response as one JSON document.
# The default stays text: that is the contract the agents are written against.
RAW_OUTPUT = os.environ.get("GHYDRA_MCP_OUTPUT", "").strip().lower() in ("json", "raw")

# ================= HTTP session =================

_http_local = threading.local()


def _http_session() -> requests.Session:
    """Return the calling thread's HTTP session.

    A session pools the connection to the Ghidra instance, so a run of tool
    calls reuses one connection instead of opening a new one per request.
    Measured against a local instance: median 3.1 ms -> 1.6 ms per request,
    and the p95 tail 12.3 ms -> 1.9 ms.

    The session is per thread because requests.Session is not thread-safe and
    the bridge runs a discovery thread next to the request path.
    """
    session = getattr(_http_local, "session", None)
    if session is None:
        session = requests.Session()
        _http_local.session = session
    return session


# ================= Kuna integration =================
# Kuna (https://github.com/Noelo-Lab/kuna) is a standalone decompiler CLI.
# The bridge shells out to it, so the kuna_* tools need no Ghidra instance
# and work against any Ghidra version - nothing here touches the REST API.
#
# Shelling out is an elevation of privilege for the bridge (it normally only
# speaks HTTP to Ghidra), so the integration is opt-in:
#
#   * the GHYDRA_KUNA environment variable (1/true/yes/on), or
#   * "kuna": {"enabled": true} in ~/.ghydra/config.json
#
# The config file wins when both are present. The config file also carries
# "kuna": {"path": ...} to point at a specific binary.

KUNA_ENV_ENABLED = "GHYDRA_KUNA"
KUNA_ENV_PATH = "GHYDRA_KUNA_PATH"
KUNA_CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".ghydra")
KUNA_CONFIG_FILE = os.path.join(KUNA_CONFIG_DIR, "config.json")
KUNA_WORK_DIR = os.path.join(KUNA_CONFIG_DIR, "kuna")

# Kuna loads and analyses the whole image on every invocation, so a large
# binary costs seconds per call. The default timeout matches the bridge's own
# read timeout; GHYDRA_KUNA_TIMEOUT lowers it for callers that would rather
# fail fast than wait.
KUNA_DEFAULT_TIMEOUT = int(os.environ.get("GHYDRA_KUNA_TIMEOUT", str(DEFAULT_TIMEOUT)))

# Refuse to pull an unbounded answer into the agent's context. 8 MiB is well
# above a full function listing and well below the payload that stalls an
# MCP client.
KUNA_MAX_OUTPUT = 8 * 1024 * 1024

# The machine-readable reasons a Kuna call can fail. The CLI carries the same
# list, so an agent sees one taxonomy whichever side it drives.
KUNA_ERROR_CODES = (
    "KUNA_ERROR",         # the generic fallback
    "KUNA_DISABLED",      # the opt-in did not reach this process
    "KUNA_MISSING",       # the kuna binary is not installed
    "KUNA_TIMEOUT",       # kuna ran past its timeout
    "KUNA_LAUNCH",        # kuna could not be started at all
    "KUNA_FAILED",        # kuna ran and failed
    "KUNA_NO_JSON",       # kuna printed something that is not JSON
    "KUNA_TOO_LARGE",     # the answer is above the output cap
    "KUNA_NO_FILE",       # a file the call named does not exist
    "KUNA_IO",            # reading or writing a file failed
    "KUNA_NO_DIR",        # the export directory does not exist
    "KUNA_NO_INDEX",      # the export has no index yet
    "KUNA_BAD_ARTIFACT",  # the artifact name is not one of the four
    "KUNA_NO_FUNCTION",   # the function is not in the export index
)

# Export jobs started by kuna_export_start, keyed by job id. The registry
# lives in the bridge process: a job started by one bridge is invisible to
# another.
_kuna_jobs: Dict[str, dict] = {}
_kuna_jobs_lock = Lock()


# Long-running bridge tasks (I7), keyed by task id. The same shape the Kuna
# job registry has, generalized to any blocking call the agent should not
# have to sit through: functions_batch_decompile and headless_start today.
#
# The registry survives in this bridge process only — a task handle from a
# previous bridge is not addressable, exactly like the Kuna jobs. Cancelling
# marks the task and frees the caller: the batch request already sent is not
# interrupted server-side, and a headless run keeps running on purpose (it
# outlives the call that started it). What cancel stops is the waiting.
_bg_tasks: Dict[str, dict] = {}
_bg_tasks_lock = Lock()
_bg_task_counter = 0


def _task_new(kind: str, label: str) -> dict:
    """Register a working task and return its record."""
    global _bg_task_counter
    with _bg_tasks_lock:
        _bg_task_counter += 1
        task_id = f"T-{_bg_task_counter:04d}"
        record = {
            "id": task_id,
            "kind": kind,
            "label": label,
            "status": "working",
            "cancel_requested": False,
            "created": time.time(),
            "started": time.time(),
            "finished": None,
            "result": None,
            "error": None,
        }
        _bg_tasks[task_id] = record
        return record


def _task_view(record: dict) -> dict:
    """The task as the agent sees it: the bookkeeping, never the lock."""
    elapsed = (record["finished"] or time.time()) - record["started"]
    view = {
        "id": record["id"],
        "kind": record["kind"],
        "label": record["label"],
        "status": record["status"],
        "elapsed_seconds": round(elapsed, 1),
    }
    if record["status"] in ("completed", "failed"):
        view["result"] = record["result"]
        view["error"] = record["error"]
    if record["cancel_requested"] and record["status"] == "working":
        view["note"] = "cancel requested; the task will discard its result"
    return view


def _task_finish(record: dict, status: str, result=None, error=None) -> None:
    with _bg_tasks_lock:
        record["status"] = status
        record["finished"] = time.time()
        record["result"] = result
        record["error"] = error


def _task_run(record: dict, body, result_of) -> None:
    """Run a blocking body in this thread and file the outcome.

    The body is a zero-argument callable; result_of turns whatever it returns
    into the task result. A cancel requested while the body runs discards the
    outcome — the caller asked to stop waiting, so the answer would land on
    nobody.
    """
    try:
        outcome = body()
        with _bg_tasks_lock:
            cancelled = record["cancel_requested"]
        if cancelled:
            _task_finish(record, "cancelled")
            return
        result = result_of(outcome)
        if isinstance(result, dict) and result.get("success") is False:
            _task_finish(record, "failed", result=result,
                         error=(result.get("error") or {}).get("code"))
        else:
            _task_finish(record, "completed", result=result)
    except Exception as exc:  # the worker thread must never raise
        with _bg_tasks_lock:
            cancelled = record["cancel_requested"]
        if cancelled:
            _task_finish(record, "cancelled")
        else:
            _task_finish(record, "failed",
                         error=f"{type(exc).__name__}: {exc}")


def _task_spawn(kind: str, label: str, body, result_of) -> dict:
    """Register a task, start its worker thread, and return the handle view."""
    record = _task_new(kind, label)
    thread = threading.Thread(
        target=_task_run, args=(record, body, result_of), daemon=True)
    thread.start()
    return {
        "success": True,
        "result": {
            "task": _task_view(record),
            "note": "running in the background; poll tasks_get(task_id) "
                    "until status is completed/failed/cancelled. Cancelling "
                    "stops the waiting, not the server-side work.",
        },
    }


def _kuna_config() -> dict:
    """Read the "kuna" section of ~/.ghydra/config.json.

    Never raises: a missing or malformed config simply means "not configured".
    """
    try:
        with open(KUNA_CONFIG_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    section = data.get("kuna")
    return section if isinstance(section, dict) else {}


def _kuna_truthy(value: Any) -> bool:
    """Interpret an opt-in value coming from the environment or the config."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on", "enabled")
    return False


def _kuna_enabled() -> bool:
    """Is the Kuna integration enabled? The config file wins over the env var.

    A config file that carries no "enabled" value (or a null one) leaves the
    decision to GHYDRA_KUNA; an explicit true or false in the file wins.
    """
    config = _kuna_config()
    if config.get("enabled") is not None:
        return _kuna_truthy(config["enabled"])
    return _kuna_truthy(os.environ.get(KUNA_ENV_ENABLED))


def _kuna_candidates() -> List[str]:
    """Where the kuna binary may live, most specific first.

    A configured path wins, then whatever is on PATH, and finally the
    Scoop install locations - those only exist on Windows, so they are
    skipped elsewhere.
    """
    candidates: List[str] = []
    configured = _kuna_config().get("path") or os.environ.get(KUNA_ENV_PATH)
    if configured:
        candidates.append(os.path.expanduser(str(configured)))
    found = shutil.which("kuna")
    if found:
        candidates.append(found)
    if os.name == "nt":
        home = os.path.expanduser("~")
        candidates.append(os.path.join(home, "scoop", "shims", "kuna.exe"))
        candidates.append(os.path.join(home, "scoop", "apps", "kuna", "current", "kuna.exe"))
    return candidates


def _kuna_binary() -> Optional[str]:
    """Resolve the kuna executable, or None when it is not installed."""
    for candidate in _kuna_candidates():
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


def _kuna_error(message: str, code: str = "KUNA_ERROR") -> dict:
    """Build the bridge's error envelope for a Kuna failure."""
    return {"success": False, "error": {"code": code, "message": message}}


def _kuna_guard() -> Optional[dict]:
    """Return an error envelope when the integration is off, else None."""
    if _kuna_enabled():
        return None
    return _kuna_error(
        "the Kuna integration is disabled. Enable it with the GHYDRA_KUNA=1 "
        "environment variable, or by adding 'kuna': {'enabled': true} to "
        f"{KUNA_CONFIG_FILE}",
        code="KUNA_DISABLED",
    )


def _kuna_target(binary_path: str) -> Union[str, dict]:
    """Validate a binary path.

    Returns the absolute path, or an error envelope when the path is empty
    or names no file.
    """
    if not binary_path:
        return _kuna_error("binary_path is required", code="KUNA_NO_FILE")
    path = os.path.abspath(os.path.expanduser(binary_path))
    if not os.path.isfile(path):
        return _kuna_error(f"no such file: {binary_path}", code="KUNA_NO_FILE")
    return path


def _kuna_run(args: List[str], timeout: Optional[int] = None) -> dict:
    """Run the kuna binary with args.

    Returns {"code": int, "stdout": str, "stderr": str}. A missing binary is
    reported as 127 and a timeout as 124, the conventional shell codes, and
    "error_code" carries the matching machine-readable reason.
    """
    executable = _kuna_binary()
    if not executable:
        return {"code": 127, "stdout": "", "stderr": "the kuna binary was not found",
                "error_code": "KUNA_MISSING"}
    limit = timeout if timeout is not None else KUNA_DEFAULT_TIMEOUT
    try:
        completed = subprocess.run(
            [executable, *args],
            capture_output=True,
            text=True,
            # Kuna writes UTF-8. Decoding with the locale instead would mangle
            # the output on a system with no UTF-8 locale set (LANG=C, and a
            # NixOS box with the locale left unset).
            encoding="utf-8",
            errors="replace",
            timeout=limit,
        )
    except subprocess.TimeoutExpired:
        return {"code": 124, "stdout": "", "stderr": f"kuna timed out after {limit}s",
                "error_code": "KUNA_TIMEOUT"}
    except OSError as exc:
        return {"code": 126, "stdout": "", "stderr": f"could not launch kuna: {exc}",
                "error_code": "KUNA_LAUNCH"}
    return {
        "code": completed.returncode,
        "stdout": completed.stdout or "",
        "stderr": completed.stderr or "",
    }


def _kuna_json(args: List[str], timeout: Optional[int] = None) -> dict:
    """Run kuna and parse its JSON output.

    Returns the bridge envelope: {"success": True, "result": <parsed>} or
    {"success": False, "error": {...}}. The error carries one of the
    KUNA_ERROR_CODES, so an agent can branch on the reason.
    """
    command = " ".join(args[:1])
    outcome = _kuna_run(args, timeout=timeout)
    stdout = outcome["stdout"].strip()
    parsed: Any = None
    if stdout:
        try:
            parsed = json.loads(stdout)
        except ValueError:
            parsed = None

    if outcome["code"] != 0:
        detail = outcome["stderr"].strip() or stdout or "no output"
        if isinstance(parsed, dict) and parsed.get("error"):
            detail = str(parsed["error"])
        return _kuna_error(
            f"kuna {command} failed (exit {outcome['code']}): {detail}",
            code=outcome.get("error_code", "KUNA_FAILED"),
        )

    if parsed is None:
        return _kuna_error(f"kuna {command} did not return JSON", code="KUNA_NO_JSON")

    if len(stdout) > KUNA_MAX_OUTPUT:
        return _kuna_error(
            f"kuna {command} returned {len(stdout)} bytes of JSON, above the "
            f"{KUNA_MAX_OUTPUT} byte cap; narrow the request",
            code="KUNA_TOO_LARGE",
        )

    if isinstance(parsed, dict) and parsed.get("error"):
        return _kuna_error(f"kuna {command}: {parsed['error']}", code="KUNA_FAILED")

    return {"success": True, "result": parsed}


def _kuna_work_dir(binary: str) -> str:
    """Where the export of a binary lives.

    Keyed by path and mtime, so a rebuilt binary gets a fresh directory while
    a re-analysis of the same file reuses it.
    """
    try:
        mtime = os.path.getmtime(binary)
    except OSError:
        mtime = 0.0
    digest = hashlib.sha256(f"{binary}|{mtime}".encode("utf-8")).hexdigest()[:12]
    return os.path.join(KUNA_WORK_DIR, digest)


def _kuna_job_view(job: dict) -> dict:
    """The public view of an export job, with live progress when present."""
    view = {
        "id": job["id"],
        "binary": job["binary"],
        "dir": job["dir"],
        "status": job["status"],
        "started_at": job["started_at"],
        "finished_at": job.get("finished_at"),
        "returncode": job.get("returncode"),
        "error": job.get("error"),
        "reused": bool(job.get("reused")),
    }
    if job.get("functions") is not None:
        view["functions"] = job["functions"]
        view["failed"] = job.get("failed", 0)
    streaming = os.path.join(job["dir"], ".streaming")
    if os.path.isfile(streaming):
        try:
            with open(streaming, "r", encoding="utf-8") as handle:
                view["streaming"] = json.load(handle)
        except (OSError, ValueError):
            view["streaming"] = None
    return view


def _kuna_index_records(work_dir: str) -> List[dict]:
    """Read index.jsonl from an export directory.

    Only newline-terminated records are read: an unfinished last record is
    deferred until the next read, because a streamed export appends a record
    only after that function's C block is complete.
    """
    path = os.path.join(work_dir, "index.jsonl")
    if not os.path.isfile(path):
        return []
    records: List[dict] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if not line.endswith("\n"):
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if isinstance(record, dict):
                    records.append(record)
    except OSError:
        return []
    return records


def _kuna_export_file(work_dir: str, suffix: str) -> Optional[str]:
    """Find the single export artifact with the given suffix."""
    try:
        entries = sorted(os.listdir(work_dir))
    except OSError:
        return None
    for entry in entries:
        if entry.endswith(suffix) and os.path.isfile(os.path.join(work_dir, entry)):
            return os.path.join(work_dir, entry)
    return None


def _kuna_find_record(records: List[dict], function: str) -> Optional[dict]:
    """The index record of a function, by name.

    The exact name wins; a case-insensitive match is the fallback, because a
    decompiler's names differ in case between runs more often than one would
    like.
    """
    for candidate in records:
        if candidate.get("name") == function:
            return candidate
    lowered = str(function).lower()
    for candidate in records:
        if str(candidate.get("name", "")).lower() == lowered:
            return candidate
    return None


def _kuna_extract_c(work_dir: str, record: dict, max_bytes: int) -> Optional[str]:
    """Slice one function's C block out of the exported .c file."""
    path = _kuna_export_file(work_dir, ".c")
    if not path:
        return None
    offset = record.get("c_offset")
    length = record.get("c_len")
    if not isinstance(offset, int) or not isinstance(length, int):
        return None
    try:
        with open(path, "rb") as handle:
            handle.seek(offset)
            blob = handle.read(length)
    except OSError:
        return None
    text = blob.decode("utf-8", errors="replace")
    if max_bytes and len(text) > max_bytes:
        text = text[:max_bytes] + f"\n... truncated at {max_bytes} bytes"
    return text


def _kuna_extract_asm(work_dir: str, name: str, max_bytes: int) -> Optional[str]:
    """Slice one function's disassembly out of the exported .asm file.

    The file is streamed: a function block runs from its label line to the
    next label, and labels sit at column zero while instructions are
    indented.
    """
    path = _kuna_export_file(work_dir, ".asm")
    if not path:
        return None
    label = f"{name}:"
    block: List[str] = []
    inside = False
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if not inside:
                    if line.startswith(label):
                        inside = True
                        block.append(line)
                    continue
                if line and not line[0].isspace() and not line.startswith(";"):
                    break
                block.append(line)
    except OSError:
        return None
    if not inside:
        return None
    text = "".join(block)
    if max_bytes and len(text) > max_bytes:
        text = text[:max_bytes] + f"\n... truncated at {max_bytes} bytes"
    return text


# The sidecar the bridge and the CLI write next to an export. The digest is a
# hash, not a reversible pointer, so without it an export cannot say which
# binary it came from - and the listing of exports needs that.
KUNA_EXPORT_META = ".ghydra.json"

# An export directory is named after a 12 hex character digest.
KUNA_DIGEST_RE = re.compile(r"^[0-9a-f]{12}$")


def _kuna_export_meta_path(directory: str) -> str:
    """Where the sidecar of an export lives."""
    return os.path.join(directory, KUNA_EXPORT_META)


def _kuna_write_export_meta(directory: str, binary: str, **extra: Any) -> None:
    """Record which binary an export came from.

    Best effort: the export is already on disk and perfectly usable without
    the sidecar, so a failure here must not fail the export.
    """
    payload: Dict[str, Any] = {
        "binary": os.path.abspath(binary),
        "created": time.time(),
    }
    # The mtime is the other half of the provenance: the digest is keyed by
    # the path and the mtime, so a binary rebuilt at the same path is a
    # different binary and an export of the old one must not be reused.
    try:
        payload["mtime"] = os.path.getmtime(os.path.abspath(binary))
    except OSError:
        pass
    payload.update(extra)
    try:
        with open(_kuna_export_meta_path(directory), "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
    except OSError:
        pass


def _kuna_read_export_meta(directory: str) -> Dict[str, Any]:
    """The sidecar of an export, or an empty dict when there is none."""
    try:
        with open(_kuna_export_meta_path(directory), "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _kuna_readme_binary(directory: str) -> Optional[str]:
    """The binary an export came from, read from Kuna's own report.

    The sidecar is the primary source, but an export made before the
    sidecar existed still names its binary in the report Kuna writes.
    """
    path = os.path.join(directory, "README.md")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                match = re.match(r"\|\s*Path\s*\|\s*`(.+?)`\s*\|", line)
                if match:
                    raw = match.group(1).strip()
                    # Kuna writes the Win32 extended-length prefix.
                    if raw.startswith("\\\\?\\"):
                        raw = raw[4:]
                    return raw
    except OSError:
        return None
    return None


def _kuna_export_binary(directory: str) -> Optional[str]:
    """Which binary an export came from, by sidecar or by report."""
    meta_binary = _kuna_read_export_meta(directory).get("binary")
    if meta_binary:
        return meta_binary
    return _kuna_readme_binary(directory)


def _kuna_export_state(directory: str) -> Optional[dict]:
    """The state of an export directory, or None when it holds no export.

    An export is complete when it has an index and is not still streaming: a
    streamed export appends a record only after that function's C block is
    done, so an index without the streaming marker is a finished one.
    """
    if not os.path.isdir(directory):
        return None
    if os.path.isfile(os.path.join(directory, ".streaming")):
        return None
    records = _kuna_index_records(directory)
    if not records:
        return None
    meta = _kuna_read_export_meta(directory)
    return {
        "dir": directory,
        "functions": len(records),
        "failed": len([record for record in records if record.get("error")]),
        "binary": meta.get("binary") or _kuna_readme_binary(directory),
        "created": meta.get("created"),
        # Whether the export was made with a filter: a subset export holds
        # only the functions it was asked for, so it is not a full export of
        # the binary.
        "filtered": bool(meta.get("functions")),
        "names": {record.get("name") for record in records},
    }


def _kuna_export_covers(state: dict, functions: Optional[str]) -> bool:
    """Does this export already hold everything the caller asked for?

    A full export covers every request. A subset export covers a request for
    one of its own functions, and nothing else - and an unfiltered request
    needs an export that was itself unfiltered, or the whole binary is
    analysed again.
    """
    wanted = {name.strip() for name in (functions or "").split(",") if name.strip()}
    if not wanted:
        return not state.get("filtered")
    return wanted.issubset(state.get("names") or set())


def _kuna_list_exports() -> List[dict]:
    """Every export on this machine, newest first.

    The listing is read from disk, so it survives a restart and is the same
    list the MCP resources expose.
    """
    exports: List[dict] = []
    try:
        entries = sorted(os.listdir(KUNA_WORK_DIR))
    except OSError:
        return []
    for entry in entries:
        directory = os.path.join(KUNA_WORK_DIR, entry)
        if not os.path.isdir(directory):
            continue
        records = _kuna_index_records(directory)
        meta = _kuna_read_export_meta(directory)
        exports.append({
            "digest": entry,
            "dir": directory,
            "binary": meta.get("binary") or _kuna_readme_binary(directory),
            "functions": len(records),
            "failed": len([record for record in records if record.get("error")]),
            "created": meta.get("created"),
            "streaming": os.path.isfile(os.path.join(directory, ".streaming")),
        })
    exports.sort(key=lambda item: item.get("created") or 0, reverse=True)
    return exports


def _kuna_resolve_export_dir(reference: str) -> str:
    """Turn an export reference into a directory.

    A bare digest - the 12 hex characters an export is named after - resolves
    inside the work directory; anything else is a path.
    """
    candidate = str(reference or "").strip()
    if not candidate:
        raise ValueError("an export directory or digest is required")
    if KUNA_DIGEST_RE.match(candidate):
        return os.path.join(KUNA_WORK_DIR, candidate)
    return os.path.abspath(os.path.expanduser(candidate))


instructions = """
GhydraMCP allows interacting with multiple Ghidra SRE instances. Ghidra SRE is a tool for reverse engineering and analyzing binaries, e.g. malware.

First, run `instances_list()` to see all available Ghidra instances (automatically discovers instances on the default host).
Then use `instances_use(port)` to set your working instance.

Note: Use `instances_discover(host)` only if you need to scan a different host.

The API is organized into namespaces for different types of operations:
- instances_* : For managing Ghidra instances
- functions_* : For working with functions
- data_* : For working with data items
- structs_* : For creating and managing struct data types
- scalars_* : For searching scalar (constant) values in instructions
- memory_* : For memory access
- xrefs_* : For cross-references
- analysis_* : For program analysis
- classes_* : For listing classes and namespaces
- symbols_* : For symbols, imports, and exports
- segments_* : For memory segments/blocks
- namespaces_* : For namespace hierarchy
- variables_* : For global and local variables
- datatypes_* : For data type management
"""

mcp = FastMCP("GhydraMCP", instructions=instructions)

# Backward-compatible host env resolution:
# - GHIDRA_HYDRA_HOST: current preferred variable
# - GHIDRA_HOST: legacy/common variable used in older setups
ghidra_host = (
    os.environ.get("GHIDRA_HYDRA_HOST")
    or os.environ.get("GHIDRA_HOST")
    or DEFAULT_GHIDRA_HOST
)

# Helper function to get the current instance or validate a specific port
def _get_instance_port(port: int | None = None) -> int:
    """Internal helper to get the current instance port or validate a specific port"""
    port = port or current_instance_port
    # Validate that the instance exists and is active
    if port not in active_instances:
        # Try to register it if not found
        register_instance(port)
        if port not in active_instances:
            raise ValueError(f"No active Ghidra instance on port {port}")
    return port

# The rest of the utility functions (HTTP helpers, etc.) remain the same...
def get_instance_url(port: int) -> str:
    """Get URL for a Ghidra instance by port"""
    with instances_lock:
        if port in active_instances:
            return active_instances[port]["url"]

        if 8192 <= port <= 65535:
            register_instance(port)
            if port in active_instances:
                return active_instances[port]["url"]

        return f"http://{ghidra_host}:{port}"

def validate_origin(headers: dict) -> bool:
    """Validate request origin against allowed origins"""
    origin = headers.get("Origin")
    if not origin:
        # No origin header - allow (browser same-origin policy applies)
        return True

    # Parse origin to get scheme+hostname
    try:
        parsed = urlparse(origin)
        origin_base = f"{parsed.scheme}://{parsed.hostname}"
        if parsed.port:
            origin_base += f":{parsed.port}"
    except (ValueError, AttributeError):
        return False

    return origin_base in ALLOWED_ORIGINS


def _extract_requested_decompile_timeout(params: dict | None = None) -> int:
    """Get requested decompile timeout from params with safe defaults."""
    requested_timeout = None
    if isinstance(params, dict):
        requested_timeout = params.get("timeout")
    try:
        return int(requested_timeout) if requested_timeout is not None else DEFAULT_DECOMPILATION_TIMEOUT
    except (TypeError, ValueError):
        return DEFAULT_DECOMPILATION_TIMEOUT


def _extract_batch_transport_timeout(json_data: dict | None = None) -> int:
    """The transport deadline a batch of decompilations needs.

    A batch is processed one target after the other, and each target may take
    the whole timeout, so the deadline has to cover the batch and not one
    function. The timeout of a batch travels in the body and not in the query,
    so the query alone cannot say how long the server may take - reading the
    body is what makes the deadline right.
    """
    if not isinstance(json_data, dict):
        return 0
    targets = json_data.get("targets")
    if not isinstance(targets, (list, tuple)) or not targets:
        return 0
    try:
        per_target = int(json_data.get("timeout", DEFAULT_DECOMPILATION_TIMEOUT))
    except (TypeError, ValueError):
        per_target = DEFAULT_DECOMPILATION_TIMEOUT
    # The server refuses a batch longer than this, so the deadline is sized
    # for the batch it will actually accept.
    return per_target * min(len(targets), MAX_BATCH_TARGETS) + 30

def _connection_never_established(exc: BaseException) -> bool:
    """Was the connection refused before any request byte was sent?

    "Failed to establish a new connection" is the one transport failure that is
    always safe to repeat: the request never reached the server, so repeating it
    cannot make a state-changing call happen twice. A reset *mid-flight* is not
    this: there the request may already have been acted on.
    """
    seen = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        text = f"{type(current).__name__}: {current}"
        lowered = text.lower()
        if "newconnectionerror" in lowered:
            return True
        if "failed to establish a new connection" in lowered:
            return True
        if "connection refused" in lowered or "actively refused" in lowered:
            return True
        current = current.__cause__ or current.__context__
    return False


def _request_with_connection_retry(method: str, url: str, attempts: int = 3,
                                   **kwargs):
    """Do the request, retrying only when nothing was ever sent.

    This machine resets or refuses a loopback connection every now and then
    (measured at ~7% of them). A refusal before the connection exists leaves the
    server untouched, so the retry is safe for every method - including POST,
    which is not otherwise retried.
    """
    last: BaseException | None = None
    for attempt in range(attempts):
        try:
            return _http_session().request(method, url, **kwargs)
        except requests.exceptions.ConnectionError as exc:
            if not _connection_never_established(exc) or attempt == attempts - 1:
                raise
            last = exc
            time.sleep(0.05 * (2 ** attempt))
    if last is not None:
        raise last
    raise RuntimeError("unreachable")


def _make_request(method: str, port: int, endpoint: str, params: dict | None = None, 
                 json_data: dict | None = None, data: str | None = None, 
                 headers: dict | None = None) -> dict:
    """Internal helper to make HTTP requests and handle common errors."""
    url = f"{get_instance_url(port)}/{endpoint}"
    
    # Set up headers according to HATEOAS API expected format
    request_headers = {
        'Accept': 'application/json',
        'X-Request-ID': f"mcp-bridge-{int(time.time() * 1000)}"
    }
    
    if headers:
        request_headers.update(headers)

    request_timeout = DEFAULT_TIMEOUT
    if "decompile" in endpoint:
        requested_timeout = _extract_requested_decompile_timeout(params)
        # Keep transport timeout above decompiler timeout to avoid premature client-side cutoffs.
        request_timeout = max(DEFAULT_TIMEOUT, requested_timeout + 30)
        # A batch runs its targets one after the other, so the deadline has to
        # cover the whole batch: otherwise the bridge answers REQUEST_TIMEOUT
        # while the server is still decompiling the targets that are left.
        request_timeout = max(request_timeout, _extract_batch_transport_timeout(json_data))

    is_state_changing = method.upper() in ["POST", "PUT", "PATCH", "DELETE"]
    if is_state_changing:
        check_headers = json_data.get("headers", {}) if isinstance(
            json_data, dict) else (headers or {})
        if not validate_origin(check_headers):
            return {
                "success": False,
                "error": {
                    "code": "ORIGIN_NOT_ALLOWED",
                    "message": "Origin not allowed for state-changing request"
                },
                "status_code": 403,
                "timestamp": int(time.time() * 1000)
            }
        if json_data is not None:
            request_headers['Content-Type'] = 'application/json'
        elif data is not None:
            request_headers['Content-Type'] = 'text/plain'

    try:
        response = _request_with_connection_retry(
            method,
            url,
            params=params,
            json=json_data,
            data=data,
            headers=request_headers,
            timeout=request_timeout
        )

        # Successful empty-body responses (204 No Content from DELETE) are real
        # successes, not "non-JSON response" errors. Test the raw bytes: decoding
        # the body to str here would decode it a second time before .json().
        if response.ok and (not response.content or not response.content.strip()):
            return {
                "success": True,
                "status_code": response.status_code,
                "timestamp": int(time.time() * 1000)
            }

        try:
            parsed_json = response.json()

            # Add timestamp if not present
            if isinstance(parsed_json, dict) and "timestamp" not in parsed_json:
                parsed_json["timestamp"] = int(time.time() * 1000)
                
            # Check for HATEOAS compliant error response format and reformat if needed
            if not response.ok and isinstance(parsed_json, dict) and "success" in parsed_json and not parsed_json["success"]:
                # Check if error is in the expected HATEOAS format
                if "error" in parsed_json and not isinstance(parsed_json["error"], dict):
                    # Convert string error to the proper format
                    error_message = parsed_json["error"]
                    parsed_json["error"] = {
                        "code": f"HTTP_{response.status_code}",
                        "message": error_message
                    }
            
            return parsed_json
            
        except ValueError:
            if response.ok:
                return {
                    "success": False,
                    "error": {
                        "code": "NON_JSON_RESPONSE",
                        "message": "Received non-JSON success response from Ghidra plugin"
                    },
                    "status_code": response.status_code,
                    "response_text": response.text[:500],
                    "timestamp": int(time.time() * 1000)
                }
            else:
                return {
                    "success": False,
                    "error": {
                        "code": f"HTTP_{response.status_code}",
                        "message": f"Non-JSON error response: {response.text[:100]}..."
                    },
                    "status_code": response.status_code,
                    "response_text": response.text[:500],
                    "timestamp": int(time.time() * 1000)
                }

    except requests.exceptions.Timeout:
        timeout_message = f"Request to {endpoint} timed out after {request_timeout}s."
        if "decompile" in endpoint:
            requested_timeout = _extract_requested_decompile_timeout(params)
            suggested_timeout = max(requested_timeout * 2, DEFAULT_DECOMPILATION_TIMEOUT)
            timeout_message += (
                f" Decompilation can take longer for large functions; retry with a higher timeout "
                f"(for example timeout={suggested_timeout}) and/or increase GHIDRA_TIMEOUT."
            )
        return {
            "success": False,
            "error": {
                "code": "REQUEST_TIMEOUT",
                "message": timeout_message
            },
            "status_code": 408,
            "timestamp": int(time.time() * 1000)
        }
    except requests.exceptions.ConnectionError:
        return {
            "success": False,
            "error": {
                "code": "CONNECTION_ERROR",
                "message": f"Failed to connect to Ghidra instance at {url}"
            },
            "status_code": 503,
            "timestamp": int(time.time() * 1000)
        }
    except Exception as e:
        return {
            "success": False,
            "error": {
                "code": "UNEXPECTED_ERROR",
                "message": f"An unexpected error occurred: {str(e)}"
            },
            "exception": e.__class__.__name__,
            "timestamp": int(time.time() * 1000)
        }

# >>> generated from ghydra/core/digest.py (945a74f28ae18371) — edit the core, then run scripts/gen_core.py
_CORE_VOLATILE_KEYS = ('id', 'timestamp', 'instance', '_links', 'api_links')

def _core_canonical(value):
    """The text a digest is taken over: sorted keys, no separator noise."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), default=str)

def _core_digest(value):
    """The SHA-256 of the canonical form of a value."""
    return hashlib.sha256(_core_canonical(value).encode('utf-8')).hexdigest()

def _core_stable_result(value, volatile=_CORE_VOLATILE_KEYS):
    """The part of an answer that two identical calls share.

    A dict loses the volatile keys; anything else is returned as it is. The
    list of volatile keys is a parameter so a caller can widen it, never so it
    can silently narrow it in one place and not the other.
    """
    if isinstance(value, dict):
        payload = value.get('result', value)
        if isinstance(payload, dict):
            dropped = set(volatile)
            return {key: item for key, item in payload.items() if key not in dropped}
        return payload
    return value
# <<< end generated from ghydra/core/digest.py


# >>> generated from ghydra/core/runbook.py (33df1f2b71fa9252) — edit the core, then run scripts/gen_core.py
_CORE_RUNBOOK_METHODS = ('GET', 'POST', 'PATCH', 'PUT', 'DELETE')

class _CoreBadSteps(ValueError):
    """The document is not a usable list of steps."""

class _CoreBadEntry(ValueError):
    """One step is not something the runbook could call."""

def _core_validate_steps(data):
    """The steps of a parsed document, validated and normalised.

    Args:
        data: The parsed JSON — a list of steps or ``{"steps": [...]}``.

    Returns:
        list[dict]: One dict per step, with endpoint, method, params, payload.

    Raises:
        BadSteps: when the document holds no usable list.
        BadEntry: when a step is not an object, has no endpoint or a bad method.
    """
    items = data.get('steps') if isinstance(data, dict) else data
    if not isinstance(items, list) or not items:
        raise _CoreBadSteps("expected a non-empty list of steps or {'steps': [...]}")
    steps: List[Dict[str, Any]] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise _CoreBadEntry(f'step #{index + 1} is not an object')
        endpoint = item.get('endpoint')
        if not isinstance(endpoint, str) or not endpoint.strip():
            raise _CoreBadEntry(f"step #{index + 1}: 'endpoint' is required")
        method = str(item.get('method') or 'GET').upper()
        if method not in _CORE_RUNBOOK_METHODS:
            raise _CoreBadEntry(f'step #{index + 1}: unknown method {method!r}')
        steps.append({'endpoint': endpoint.strip(), 'method': method, 'params': item.get('params') or None, 'payload': item.get('payload') or None})
    return steps
# <<< end generated from ghydra/core/runbook.py


# >>> generated from ghydra/core/hints.py (f86a5a58967f95b1) — edit the core, then run scripts/gen_core.py
_CORE_HINT_PATTERNS = {'source': '\\b(?:de|from|entrada|enters?|input)\\s+[`\\"\']?([A-Za-z_][\\w.]*)', 'sink': '\\b(?:para|to|ate|até|into|sink|reach(?:es)?|alcanc[ae]|alcança|chega(?:r)?)\\s+[`\\"\']?([A-Za-z_][\\w.]*)', 'address': '\\b(0x[0-9A-Fa-f]+)\\b', 'function': '\\b(?:funcao|função|function)\\s+[`\\"\']?([A-Za-z_]\\w*)'}

def _core_parse_goal(goal):
    """The hints a goal carries, keyed by kind.

    Args:
        goal: The objective, as the user wrote it (any language in the patterns).

    Returns:
        dict: The hints that matched; empty when the goal names none of them.
    """
    text = str(goal or '')
    hints: Dict[str, str] = {}
    for key, pattern in _CORE_HINT_PATTERNS.items():
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            hints[key] = match.group(1)
    return hints
# <<< end generated from ghydra/core/hints.py


# >>> generated from ghydra/core/cache.py (9e480acbded364a4) — edit the core, then run scripts/gen_core.py
_CORE_CACHE_VERSION = 1

_CORE_CACHE_IDENTITY_FIELDS = ('programId', 'path', 'executablePath', 'language', 'languageId', 'imageBase', 'creationDate')

_CORE_CACHE_STATISTIC_FIELDS = ('functionCount', 'symbolCount', 'memoryBlockCount')

_CORE_CACHE_FINGERPRINT_FIELDS = (('name', ('name',)), ('executable_path', ('path', 'executablePath')), ('image_base', ('imageBase',)), ('language', ('language', 'languageId')), ('compiler', ('compiler', 'compilerSpecId')))

def _core_cache_fingerprint(program):
    """The facts that tell one program from another, out of a `/program` payload.

    Args:
        program: The ``result`` of ``/program`` (any shape; a non-dict is "no
            fingerprint", which the caller reports rather than guesses).

    Returns:
        dict: The fingerprint, with the names the callers read: ``name``,
              ``executable_path``, ``image_base``, ``language`` and
              ``compiler``. A fact the payload does not carry is absent.
    """
    if not isinstance(program, dict):
        return {}
    fingerprint: Dict[str, Any] = {}
    for name, sources in _CORE_CACHE_FINGERPRINT_FIELDS:
        for source in sources:
            value = program.get(source)
            if value is not None:
                fingerprint[name] = value
                break
    return fingerprint

def _core_cache_identity(program):
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
    identity = {key: program[key] for key in _CORE_CACHE_IDENTITY_FIELDS if program.get(key) is not None}
    statistics = program.get('statistics')
    if isinstance(statistics, dict):
        identity['statistics'] = {key: statistics[key] for key in _CORE_CACHE_STATISTIC_FIELDS if statistics.get(key) is not None}
    return identity

def _core_cache_key(identity, kind, request):
    """The key of one answer: the version, the kind, the program and the question.

    Every part is load-bearing: the version lets a change to the format retire
    the old entries, the kind keeps two sorts of answer apart, the program keeps
    two binaries apart, and the request keeps two questions apart.
    """
    return _core_digest({'version': _CORE_CACHE_VERSION, 'kind': kind, 'program': identity, 'request': request})
# <<< end generated from ghydra/core/cache.py


# >>> generated from ghydra/core/diff.py (ef204fc8a80da5eb) — edit the core, then run scripts/gen_core.py
_CORE_DIFF_PROGRAM_FIELDS = tuple((name for name, _ in _CORE_CACHE_FINGERPRINT_FIELDS))

def _core_diff_name_set(values):
    """The non-empty names of a listing, as a set (order and repeats are noise)."""
    return {value for value in values if value}

def _core_diff_names(before, after):
    """The names added and removed between two sets.

    Args:
        before: The names of the first snapshot.
        after: The names of the second one.

    Returns:
        dict: ``added`` and ``removed`` (sorted, so the answer is stable) plus
              both counts.
    """
    return {'added': sorted(after - before), 'removed': sorted(before - after), 'count_a': len(before), 'count_b': len(after)}

def _section_diff(before, after, before_complete, after_complete):
    """The names added and removed between two listings, and how sure we are.

    A removal is a claim about the *second* listing: "this name is not in B". If
    B was never read to its end, the name may simply not have been read — so the
    removal is reported as "not seen in B", and the section says it is
    incomplete. The same reasoning applies to an addition against A.

    Args:
        before: The names of the first listing.
        after: The names of the second one.
        before_complete: Whether the first listing was read to its end.
        after_complete: Whether the second listing was read to its end.

    Returns:
        dict: ``added``, ``removed`` (each with a ``seen`` variant), the counts
              and ``complete``.
    """
    added = sorted(after - before)
    removed = sorted(before - after)
    added_certain = added if before_complete else []
    removed_certain = removed if after_complete else []
    return {'added': added_certain, 'removed': removed_certain, 'added_not_seen': [] if before_complete else added, 'removed_not_seen': [] if after_complete else removed, 'count_a': len(before), 'count_b': len(after), 'complete': before_complete and after_complete}

def _core_diff_snapshots(a, b):
    """What changed between two snapshots, section by section.

    Args:
        a: The first snapshot: ``program``, ``functions``, ``imports``,
           ``strings`` and the ``*_complete`` flags.
        b: The second one, in the same shape.

    Returns:
        dict: ``functions`` (added/removed/renamed, with counts and whether both
              listings were complete), ``imports``, ``strings``,
              ``program_changed``, ``changed`` and a ``summary`` of counts.
    """
    by_addr_a = {fn['address']: fn for fn in a.get('functions') or [] if fn.get('address')}
    by_addr_b = {fn['address']: fn for fn in b.get('functions') or [] if fn.get('address')}
    added: List[Dict[str, Any]] = []
    removed: List[Dict[str, Any]] = []
    renamed: List[Dict[str, Any]] = []
    for address, fn in sorted(by_addr_b.items()):
        if address not in by_addr_a:
            added.append({'address': address, 'name': fn.get('name')})
        elif fn.get('name') != by_addr_a[address].get('name'):
            renamed.append({'address': address, 'from': by_addr_a[address].get('name'), 'to': fn.get('name')})
    for address, fn in sorted(by_addr_a.items()):
        if address not in by_addr_b:
            removed.append({'address': address, 'name': fn.get('name')})
    imports = _section_diff(_core_diff_name_set(a.get('imports') or []), _core_diff_name_set(b.get('imports') or []), bool(a.get('imports_complete', True)), bool(b.get('imports_complete', True)))
    strings = _section_diff(_core_diff_name_set(a.get('strings') or []), _core_diff_name_set(b.get('strings') or []), bool(a.get('strings_complete', True)), bool(b.get('strings_complete', True)))
    result: Dict[str, Any] = {'program': {'a': a.get('program') or {}, 'b': b.get('program') or {}}, 'program_changed': (a.get('program') or {}) != (b.get('program') or {}), 'functions': {'added': added, 'removed': removed, 'renamed': renamed, 'count_a': len(by_addr_a), 'count_b': len(by_addr_b), 'complete': bool(a.get('functions_complete', True)) and bool(b.get('functions_complete', True))}, 'imports': imports, 'strings': strings}
    result['changed'] = bool(added or removed or renamed or imports['added'] or imports['removed'] or strings['added'] or strings['removed'] or result['program_changed'])
    result['complete'] = bool(result['functions']['complete'] and imports['complete'] and strings['complete'])
    result['incomplete_sections'] = [name for name, section in (('functions', result['functions']), ('imports', imports), ('strings', strings)) if not section.get('complete', True)]
    result['summary'] = {'functions_added': len(added), 'functions_removed': len(removed), 'functions_renamed': len(renamed), 'imports_added': len(imports['added']), 'imports_removed': len(imports['removed']), 'strings_added': len(strings['added']), 'strings_removed': len(strings['removed']), 'program_changed': result['program_changed']}
    return result
# <<< end generated from ghydra/core/diff.py


# >>> generated from ghydra/core/fleet.py (c80eb884de60cc6d) — edit the core, then run scripts/gen_core.py
_CORE_FLEET_KINDS = ('overview', 'has_function', 'has_import', 'has_string', 'xrefs_to')

_CORE_FLEET_IDENTITY_FIELDS = ('programId', 'path', 'executablePath', 'imageBase')

def _core_fleet_identity_of(program):
    """The key two instances serving the same file share.

    ``programId`` is project + pathname, and is what the plugin already uses to
    name a program. The path is the fallback. A program with none of them has no
    identity (``""``), which the caller reports rather than merging every
    stranger together.

    Args:
        program: The ``result`` of ``/program`` (any shape).

    Returns:
        str: The identity, or the empty string when the program has none.
    """
    if not isinstance(program, dict):
        return ''
    for key in _CORE_FLEET_IDENTITY_FIELDS:
        value = program.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ''

def _core_fleet_merge(seen, kind, target, unreachable=None):
    """Merge what every reachable instance answered into one report.

    Args:
        seen: One entry per instance that answered: ``port``, ``identity``,
              ``name``, ``program`` and ``answer`` (itself a dict with
              ``ok``/``present``/``detail``/``complete``).
        kind: The question, echoed in the report.
        target: What the question was about (``None`` for an overview).
        unreachable: The ports that did not answer, with their reason.

    Returns:
        dict: The envelope — one row per *binary*, the counts, the members that
              could not answer, the rows that were partial or truncated.
    """
    members: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    for entry in seen:
        identity = entry.get('identity')
        if not identity:
            continue
        answer = entry.get('answer') or {}
        existing = members.get(identity)
        if existing is None:
            members[identity] = {'identity': identity, 'name': entry.get('name'), 'ports': [entry.get('port')], 'program': entry.get('program'), 'answer': answer}
            order.append(identity)
        else:
            existing['ports'].append(entry.get('port'))
            if existing['answer'].get('present') != answer.get('present'):
                existing.setdefault('disagreements', []).append({'port': entry.get('port'), 'answer': answer})
    rows = []
    for identity in order:
        member = members[identity]
        answer = member.get('answer') or {}
        row = {'identity': identity, 'name': member.get('name'), 'ports': member['ports'], 'present': bool(answer.get('present')), 'ok': bool(answer.get('ok')), 'detail': answer.get('detail') or {}}
        if answer.get('complete') is False:
            row['complete'] = False
        if member.get('disagreements'):
            row['disagreements'] = member['disagreements']
        rows.append(row)
    partial = [row['identity'] for row in rows if not row['ok']]
    truncated = [row['identity'] for row in rows if row.get('complete') is False]
    missing = list(unreachable or [])
    return {'success': True, 'result': {'kind': kind, 'target': target, 'binaries': rows, 'count': len(rows), 'with_it': sum((1 for row in rows if row['present'])), 'without_it': sum((1 for row in rows if row['ok'] and (not row['present']))), 'unreachable': missing, 'partial': partial, 'truncated': truncated, 'ok': not partial and (not missing)}}
# <<< end generated from ghydra/core/fleet.py


# >>> generated from ghydra/core/capabilities.py (07aad7e52b759946) — edit the core, then run scripts/gen_core.py
_CORE_CAPABILITY_RULES = ({'id': 'T1055', 'name': 'Process Injection', 'tactic': 'Defense Evasion / Privilege Escalation', 'imports': ('VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'NtCreateThreadEx', 'QueueUserAPC', 'SetThreadContext', 'NtMapViewOfSection'), 'strings': ()}, {'id': 'T1057', 'name': 'Process Discovery', 'tactic': 'Discovery', 'imports': ('CreateToolhelp32Snapshot', 'Process32First', 'Process32Next', 'EnumProcesses', 'NtQuerySystemInformation'), 'strings': ()}, {'id': 'T1082', 'name': 'System Information Discovery', 'tactic': 'Discovery', 'imports': ('GetSystemInfo', 'GetVersionEx', 'GetComputerName', 'GetUserName', 'GetDiskFreeSpace', 'RegQueryValueEx'), 'strings': ()}, {'id': 'T1105', 'name': 'Ingress Tool Transfer', 'tactic': 'Command and Control', 'imports': ('URLDownloadToFile', 'WinHttpOpen', 'InternetOpenUrl', 'HttpSendRequest', 'curl_easy_perform', 'recv', 'WSARecv'), 'strings': ('http://', 'https://', 'Mozilla/', 'User-Agent', 'download')}, {'id': 'T1071', 'name': 'Application Layer Protocol', 'tactic': 'Command and Control', 'imports': ('WSAConnect', 'InternetConnect', 'HttpOpenRequest', 'WSAStartup', 'connect', 'send'), 'strings': ()}, {'id': 'T1486', 'name': 'Data Encrypted for Impact', 'tactic': 'Impact', 'imports': ('CryptEncrypt', 'CryptGenKey', 'BCryptEncrypt', 'CryptDeriveKey'), 'strings': ('YOUR FILES', 'ransom', 'decrypt', '.locked', 'bitcoin', 'restore your', 'encrypted')}, {'id': 'T1497', 'name': 'Virtualization / Sandbox Evasion', 'tactic': 'Defense Evasion / Discovery', 'imports': ('IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'GetTickCount', 'Sleep', 'NtQueryInformationProcess'), 'strings': ('VMware', 'VirtualBox', 'QEMU', 'Sandbox', 'VBox', 'ollydbg')}, {'id': 'T1113', 'name': 'Screen Capture', 'tactic': 'Collection', 'imports': ('BitBlt', 'GetDC', 'CreateCompatibleBitmap', 'PrintWindow', 'GetWindowDC'), 'strings': ()}, {'id': 'T1547', 'name': 'Boot or Logon Autostart Execution', 'tactic': 'Persistence', 'imports': ('CreateService', 'OpenSCManager', 'RegSetValueEx', 'ShellExecute'), 'strings': ('\\CurrentVersion\\Run', '\\RunOnce', 'schtasks', 'startup')}, {'id': 'T1027', 'name': 'Obfuscated Files or Information', 'tactic': 'Defense Evasion', 'imports': ('VirtualProtect', 'GetProcAddress', 'LoadLibraryA', 'LoadLibraryW', 'LdrLoadDll'), 'strings': ('base64', 'obfuscat')})

_CORE_CAP_IMPORT_KEYS = ('name', 'label', 'symbol', 'value')

_CORE_CAP_STRING_KEYS = ('value', 'name', 'string', 'text')

_CORE_CAP_ADDRESS_KEYS = ('address', 'addr', 'offset')

def _core_cap_items(response):
    if not isinstance(response, dict) or not response.get('success', False):
        return []
    payload = response.get('result')
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict)]

def _core_cap_text(item, keys):
    for key in keys:
        value = item.get(key)
        if isinstance(value, str) and value:
            return value
    return ''

def _core_cap_address(item):
    for key in _CORE_CAP_ADDRESS_KEYS:
        value = item.get(key)
        if isinstance(value, (str, int)) and value != '':
            return str(value)
    return ''

def _core_cap_evidence(items, keys, patterns, kind):
    found: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for item in items:
        text = _core_cap_text(item, keys)
        if not text:
            continue
        lowered = text.lower()
        for pattern in patterns:
            if pattern.lower() in lowered:
                marker = (kind, text)
                if marker not in seen:
                    seen.add(marker)
                    found.append({'kind': kind, 'name': text[:120], 'address': _core_cap_address(item), 'matched': pattern})
                break
    return found

def _core_build_capability_report(program, imports, strings, include_strings=True):
    """Compose the three envelopes into a ranked capability triage report."""
    import_items = _core_cap_items(imports)
    string_items = _core_cap_items(strings) if include_strings else []
    failures = []
    for label, response in (('imports', imports), ('strings', strings)):
        if label == 'strings' and (not include_strings):
            continue
        if isinstance(response, dict) and response.get('success') is False:
            failures.append(label)
    findings = []
    for rule in _CORE_CAPABILITY_RULES:
        import_hits = _core_cap_evidence(import_items, _CORE_CAP_IMPORT_KEYS, rule['imports'], 'import')
        string_hits = _core_cap_evidence(string_items, _CORE_CAP_STRING_KEYS, rule['strings'], 'string')
        score = 2 * len(import_hits) + len(string_hits)
        if score < 2:
            continue
        confidence = 'high' if score >= 6 else 'medium' if score >= 3 else 'low'
        findings.append({'id': rule['id'], 'name': rule['name'], 'tactic': rule['tactic'], 'confidence': confidence, 'score': score, 'import_matches': len(import_hits), 'string_matches': len(string_hits), 'evidence': (import_hits + string_hits)[:6]})
    findings.sort(key=lambda finding: (-finding['score'], finding['id']))
    name = ''
    if isinstance(program, dict) and isinstance(program.get('result'), dict):
        name = program['result'].get('name') or ''
    return {'success': True, 'result': {'program': name, 'summary': {'imports_scanned': len(import_items), 'strings_scanned': len(string_items), 'rules': len(_CORE_CAPABILITY_RULES), 'techniques_matched': len(findings)}, 'failures': failures, 'findings': findings, 'method': 'Heuristic import/string matching; a lead for an analyst, not a verdict.'}}
# <<< end generated from ghydra/core/capabilities.py


# >>> generated from ghydra/core/contextpack.py (52886803566460de) — edit the core, then run scripts/gen_core.py
_CORE_CONTEXT_TEMPLATES = {'what_it_does': re.compile('o que (esse|esse|esta|essa|este|a função|the function|it) |what .*(does|do)|o que faz|descompil|decompil', re.IGNORECASE), 'data_origin': re.compile('de onde|quem (escreve|lê|le|leu|escreveu)|where .*(from|written|read)|who (writes|reads)|xref|referên|referen', re.IGNORECASE), 'what_changed': re.compile('o que mudou|what changed|mudou|diff|desde a última|since last', re.IGNORECASE)}

_CORE_CONTEXT_CHAR_PER_TOKEN = 4

def _core_context_classify(question):
    """Map a free-form question to one of the three MVP templates."""
    for template, pattern in _CORE_CONTEXT_TEMPLATES.items():
        if pattern.search(question or ''):
            return template
    return 'overview'

def _core_context_tokens(text):
    return max(1, len(text) // _CORE_CONTEXT_CHAR_PER_TOKEN)

def _core_build_context_pack(question, template, program, sections, budget_tokens=4000):
    """Assemble the fetched sections into one budgeted dossier.

    sections: ordered dicts {title, body, citations} in DESCENDING priority —
    the first section is the answer the caller asked for and is never dropped,
    only truncated. Everything after it is dropped whole, oldest first, until
    the pack fits; each drop is recorded with its reason.
    """
    budget_tokens = max(200, int(budget_tokens))
    included = []
    omitted = []
    citations = []
    seen_citations = set()
    used = 0
    header = _core_context_tokens(f'Context pack: {question}')
    for index, section in enumerate(sections):
        title = str(section.get('title', 'section'))
        body = str(section.get('body', ''))
        section_citations = [str(c) for c in section.get('citations') or []]
        if index == 0:
            room = budget_tokens - header - used - _core_context_tokens(title)
            if _core_context_tokens(body) > room > 0:
                keep_chars = room * _CORE_CONTEXT_CHAR_PER_TOKEN
                body = body[:keep_chars].rsplit('\n', 1)[0]
                omitted.append({'section': title, 'reason': f'truncated to fit {budget_tokens} tokens'})
        elif used + _core_context_tokens(title) + _core_context_tokens(body) + header > budget_tokens:
            omitted.append({'section': title, 'reason': 'dropped: over the token budget'})
            continue
        used += _core_context_tokens(title) + _core_context_tokens(body)
        included.append({'title': title, 'body': body, 'citations': section_citations})
        for citation in section_citations:
            if citation not in seen_citations:
                seen_citations.add(citation)
                citations.append(citation)
    return {'success': True, 'result': {'question': question, 'template': template, 'program': program, 'sections': included, 'citations': citations, 'omitted': omitted, 'budget_tokens': budget_tokens, 'used_tokens': header + used, 'method': 'Composed from already-fetched endpoints; ranked by relevance to the question, truncated by budget. Every address is citable.'}}
# <<< end generated from ghydra/core/contextpack.py


# >>> generated from ghydra/core/telemetry.py (58f503bc88f0d56d) — edit the core, then run scripts/gen_core.py
_CORE_TELEMETRY_MAX_BYTES = 1000000

_CORE_TELEMETRY_KEEP_LINES = 2000

_CORE_TELEMETRY_INSPECTION_TOOLS = ('functions_get', 'functions_decompile', 'analysis_callers', 'analysis_callees', 'xrefs_list', 'inspect_address')

_CORE_TELEMETRY_LISTING_TOOLS = ('functions_list', 'data_list', 'symbols_list', 'variables_list')

def _core_telemetry_recent(entries, days, now=None):
    """The entries inside the last ``days`` days.

    Args:
        entries: The rows of the log (as :func:`read_entries` returns them).
        days: The size of the window, at least one day.
        now: The current epoch time; passed in so the answer is reproducible.

    Returns:
        list: The entries whose timestamp is inside the window.
    """
    import time as _time
    moment = _time.time() if now is None else now
    cutoff = moment - max(1, int(days)) * 86400
    return [entry for entry in entries if float(entry.get('ts') or 0) >= cutoff]

def _core_telemetry_recommendations(entries):
    """Name the composed tool when the log shows the pattern it replaces."""
    found: List[str] = []
    counts: Dict[str, int] = {}
    slow: Dict[str, float] = {}
    for entry in entries:
        tool = str(entry.get('tool'))
        counts[tool] = counts.get(tool, 0) + 1
        if entry.get('ok'):
            slow[tool] = max(slow.get(tool, 0.0), float(entry.get('ms') or 0))
    inspection = sum((counts.get(name, 0) for name in _CORE_TELEMETRY_INSPECTION_TOOLS))
    if inspection >= 4:
        found.append(f'{inspection} inspection calls in the window: analysis_context_pack(question, address) answers that pattern in one call, with a token budget and citable addresses.')
    listing = sum((counts.get(name, 0) for name in _CORE_TELEMETRY_LISTING_TOOLS))
    if listing >= 4:
        found.append(f'{listing} listing calls: programs_overview composes the counts and imports in one call, and a page takes limit/offset.')
    batch = counts.get('functions_decompile', 0)
    if batch >= 4:
        found.append(f'{batch} single decompiles: functions_batch_decompile takes a list (async_mode=True for a long batch).')
    for tool, worst in sorted(slow.items(), key=lambda item: -item[1])[:3]:
        if worst >= 500:
            found.append(f'{tool} took up to {worst:.0f} ms: consider async_mode=True or a narrower request.')
    return found[:5]

def _core_telemetry_summarize(entries, days=7, path=''):
    """Aggregate the log rows into the report the CLI and the tool share.

    Args:
        entries: The rows inside the window (see :func:`filter_recent`).
        days: The window, echoed in the report.
        path: Where the log lives, echoed so the reader can open it.

    Returns:
        dict: call and failure totals per tool (the 25 busiest), the error codes
              seen, the advice, and the path of the log. An empty window says so
              instead of answering with an empty table.
    """
    totals: Dict[str, Dict[str, Any]] = {}
    codes: Dict[str, int] = {}
    for entry in entries:
        tool = str(entry.get('tool'))
        row = totals.setdefault(tool, {'tool': tool, 'calls': 0, 'failed': 0, 'ms_total': 0.0, 'ms_max': 0.0, 'tokens': 0})
        row['calls'] += 1
        if not entry.get('ok'):
            row['failed'] += 1
        row['ms_total'] += float(entry.get('ms') or 0)
        row['ms_max'] = max(row['ms_max'], float(entry.get('ms') or 0))
        row['tokens'] += int(entry.get('tokens') or 0)
        code = entry.get('code')
        if code:
            codes[str(code)] = codes.get(str(code), 0) + 1
    rows = []
    for row in sorted(totals.values(), key=lambda item: -item['calls']):
        rows.append({**row, 'ms_avg': round(row['ms_total'] / row['calls'], 1), 'ms_max': round(row['ms_max'], 1)})
    report: Dict[str, Any] = {'days': days, 'calls': len(entries), 'tools': rows[:25], 'error_codes': codes, 'recommendations': _core_telemetry_recommendations(entries), 'path': path}
    if not entries:
        report['message'] = 'no telemetry recorded in this window'
    return report
# <<< end generated from ghydra/core/telemetry.py


# >>> generated from ghydra/core/taint.py (46f670da8b2fa636) — edit the core, then run scripts/gen_core.py
_CORE_TAINT_PAGE_LIMIT = 1000

_CORE_TAINT_MAX_PAGES = 5

_CORE_TAINT_CALL_OPCODES = {7, 8}

_CORE_TAINT_CONFIDENCE_DIRECT = 'direct'

_CORE_TAINT_CONFIDENCE_REACHABLE = 'reachable'

_CORE_TAINT_DISCLAIMER = "These are hypotheses from pcode and the call graph, not proof of exploitability. Branches are not modelled; a 'direct' finding means the sink call appears after the source call in the same function."

def _core_taint_looks_like_address(text):
    """Whether a string is an address rather than a name.

    Ghidra writes an address as unprefixed hexadecimal (`00401000`, `140001234`),
    and every hex digit is also a legal character in a symbol name - so this is a
    heuristic, used only to decide whether a value that arrived in the `function`
    field can be read as an address. A name that is all hex digits is rare enough
    that the alternative (a wasted containing-function lookup) is worse.
    """
    value = str(text or '').strip()
    if not value:
        return False
    if value.lower().startswith('0x'):
        value = value[2:]
    return bool(value) and all((char in '0123456789abcdefABCDEF' for char in value))

def _core_taint_result_of(envelope):
    """The payload of a successful envelope, or ``None``.

    A failed answer is not an empty result: it is no result, which the callers
    report as a gap rather than as an absence of evidence.
    """
    if isinstance(envelope, dict) and envelope.get('success', False):
        return envelope.get('result')
    return None

def _core_taint_site_for(calls, wanted, wanted_name):
    """The call site whose target is the wanted address or name.

    Args:
        calls: The calls of a function, each with ``target`` and ``at``.
        wanted: The address (or symbol) the sink resolved to.
        wanted_name: The name of the function the sink resolved to.

    Returns:
        str | None: The address of the first matching call, or ``None``.
    """
    wanted_lower = (wanted or '').lower()
    for call in calls:
        target = (call.get('target') or '').lower()
        if not target:
            continue
        if target == wanted_lower or (wanted_name or '').lower() in target:
            return call['at']
    return None

def _core_taint_address_key(address):
    """Sort key for an address: numeric order, unparseable values last.

    Returned as a tuple so ``sorted`` never compares an int with a string — a
    single odd address would otherwise raise and lose the whole report.
    """
    try:
        return (0, int(str(address), 16))
    except (TypeError, ValueError):
        return (1, 0)

def _core_taint_summarize(report):
    """The counts a report carries, shared by both surfaces.

    ``found`` is true only for a ``direct`` or ``reachable`` hypothesis: a pile
    of ``weak`` ones is not a finding.
    """
    hypotheses = report.get('hypotheses') or []
    by_confidence: Dict[str, int] = {}
    for item in hypotheses:
        key = item.get('confidence') or 'unknown'
        by_confidence[key] = by_confidence.get(key, 0) + 1
    return {'total': len(hypotheses), 'direct': by_confidence.get(_CORE_TAINT_CONFIDENCE_DIRECT, 0), 'reachable': by_confidence.get(_CORE_TAINT_CONFIDENCE_REACHABLE, 0), 'weak': by_confidence.get('weak', 0), 'found': bool(by_confidence.get(_CORE_TAINT_CONFIDENCE_DIRECT) or by_confidence.get(_CORE_TAINT_CONFIDENCE_REACHABLE))}
# <<< end generated from ghydra/core/taint.py


# >>> generated from ghydra/core/mission.py (05a2838bbe643615) — edit the core, then run scripts/gen_core.py
_CORE_MISSION_VERSION = 1

_CORE_MISSION_DEFAULT_CALLS = 60

_CORE_MISSION_DEFAULT_TOKENS = 200000

_CORE_MISSION_DEFAULT_SECONDS = 900

_CORE_MISSION_ERROR_NO_PROGRAM = 'MISSION_NO_PROGRAM'

_CORE_MISSION_ERROR_BUDGET = 'MISSION_BUDGET'

_CORE_MISSION_ERROR_BAD_FILE = 'MISSION_BAD_FILE'

_CORE_MISSION_STATUS_OPEN = 'open'

_CORE_MISSION_STATUS_VERIFIED = 'verified'

_CORE_MISSION_STATUS_UNVERIFIED = 'unverified'

_CORE_MISSION_STATUS_UNKNOWN = 'unknown'

def _core_mission_tokens_of(payload):
    """The token estimate of one answer: about four characters per token.

    Never zero: a call that answered nothing still cost a call, and a budget
    that counts it as free would let an empty loop run forever.
    """
    text = json.dumps(payload, default=str) if payload is not None else ''
    return max(1, len(text) // 4)

def _core_mission_budget_exhausted(calls, max_calls, tokens, max_tokens, elapsed, max_seconds=None):
    """Which budget is spent, in the order that matters, or ``None``.

    Args:
        calls: Calls already spent.
        max_calls: The call limit.
        tokens: Tokens already spent.
        max_tokens: The token limit.
        elapsed: Seconds since the mission started.
        max_seconds: The wall-clock limit, when the surface enforces one.

    Returns:
        str | None: The reason the mission must stop, in the words the report
                    uses, or ``None`` when there is room left.
    """
    if calls >= max_calls:
        return f'the call budget ({max_calls}) is spent'
    if tokens >= max_tokens:
        return f'the token budget ({max_tokens}) is spent'
    if max_seconds is not None and elapsed >= max_seconds:
        return f'the time budget ({max_seconds}s) is spent'
    return None

def _core_mission_budget_row(calls, max_calls, tokens, max_tokens, seconds, max_seconds=None):
    """The budget as the report shows it.

    ``max_seconds`` is included only when the caller enforces one, so a surface
    that has no wall clock does not advertise a limit it never checks.
    """
    row: Dict[str, Any] = {'calls': calls, 'max_calls': max_calls, 'tokens': tokens, 'max_tokens': max_tokens, 'seconds': round(float(seconds), 1)}
    if max_seconds is not None:
        row['max_seconds'] = max_seconds
    return row

def _core_mission_dossier(goal, mission_id, program, hints, budget, failed, skipped, findings, verification=None):
    """The dossier a human reads, and the artifact a CI job keeps.

    Args:
        goal: The objective, in the words the user gave.
        mission_id: The id the mission is stored under.
        program: The program fingerprint (``name``, ``executable_path``).
        hints: The hints read from the goal.
        budget: The row from :func:`budget_row`.
        failed: Why the mission stopped early, when it did.
        skipped: The steps that were not run, with the reason in their name.
        findings: The findings, each with id/title/kind/confidence/status and
                  the evidence digests behind it.
        verification: The re-read result, when the mission verified itself.

    Returns:
        str: The Markdown document.
    """
    lines = [f'# Mission: {goal}', '', f'- id: `{mission_id}`', f"- program: `{program.get('name') or '?'}` ({program.get('executable_path') or 'no path'})", f'- hints: {json.dumps(hints, ensure_ascii=False)}', f"- budget: {budget['calls']}/{budget['max_calls']} calls, ~{budget['tokens']} tokens, {budget['seconds']}s", '']
    if failed:
        lines.extend([f'**The mission stopped: {failed}**', ''])
    if skipped:
        lines.extend([f"Skipped steps: {', '.join(skipped)}", ''])
    lines.extend(['## Findings', ''])
    if not findings:
        lines.append('_No finding was recorded._')
    for finding in findings:
        lines.append(f"### {finding['id']} — {finding['title']}")
        lines.append('')
        lines.append(f"- kind: `{finding.get('kind')}`  confidence: `{finding.get('confidence')}`  status: `{finding.get('status')}`")
        if finding.get('detail'):
            detail = str(finding['detail'])
            cut = len(detail) > 2000
            lines.extend(['', '```', detail[:2000], '```'])
            if cut:
                lines.append(f'_(detail truncated to 2000 of {len(detail)} characters)_')
        for item in finding.get('evidence') or []:
            lines.append(f"- evidence: `{item.get('endpoint')}` (digest `{(item.get('digest') or '')[:16]}`)")
        lines.append('')
    if verification is not None:
        lines.extend(['## Verification', '', f"- evidence items re-read: {verification['checked']}", f"- findings verified: {verification['verified']}"])
        if verification.get('unverified'):
            lines.append(f"- **unverified: {', '.join(verification['unverified'])}** (their evidence moved or could not be re-read)")
        elif not verification.get('checked'):
            lines.append('- no evidence item was re-read, so no conclusion was verified')
        else:
            lines.append('- every conclusion still holds against its evidence')
        lines.append('')
    unknowns = [item for item in findings if item.get('status') == _CORE_MISSION_STATUS_UNKNOWN]
    lines.extend(['## Not determined', ''])
    if not unknowns and failed:
        lines.append(f'_The mission stopped before it could answer: {failed}_')
    elif not unknowns and (not findings):
        lines.append('_No question was answered, so nothing is undetermined yet._')
    elif not unknowns:
        lines.append('_Nothing was left undetermined._')
    for item in unknowns:
        lines.append(f"- {item['id']}: {item['title']} — {item.get('detail') or ''}".rstrip())
    lines.append('')
    return '\n'.join(lines)
# <<< end generated from ghydra/core/mission.py


def safe_get(port: int, endpoint: str, params: dict | None = None) -> dict:
    """Make GET request to Ghidra instance"""
    return _make_request("GET", port, endpoint, params=params)

def safe_put(port: int, endpoint: str, data: dict,
             params: dict | None = None) -> dict:
    """Make PUT request to Ghidra instance with JSON payload"""
    headers = data.pop("headers", None) if isinstance(data, dict) else None
    return _make_request("PUT", port, endpoint, params=params,
                         json_data=data, headers=headers)

def safe_post(port: int, endpoint: str, data: Union[dict, str],
              params: dict | None = None) -> dict:
    """Perform a POST request to a specific Ghidra instance with JSON or text payload"""
    headers = None
    json_payload = None
    text_payload = None

    if isinstance(data, dict):
        headers = data.pop("headers", None)
        json_payload = data
    else:
        text_payload = data

    return _make_request("POST", port, endpoint, params=params,
                         json_data=json_payload, data=text_payload, headers=headers)

def safe_patch(port: int, endpoint: str, data: dict,
               params: dict | None = None) -> dict:
    """Perform a PATCH request to a specific Ghidra instance with JSON payload"""
    headers = data.pop("headers", None) if isinstance(data, dict) else None
    return _make_request("PATCH", port, endpoint, params=params,
                         json_data=data, headers=headers)

def safe_delete(port: int, endpoint: str, params: dict | None = None) -> dict:
    """Perform a DELETE request to a specific Ghidra instance"""
    return _make_request("DELETE", port, endpoint, params=params)


# ================= Text Formatters =================
# Format API responses as plain text for efficient LLM consumption

def format_error(response: dict) -> str:
    """Format an error response as plain text.

    A machine-readable code, when the error carries one, is kept in the text:
    the Kuna failures have a code an agent can branch on, and dropping it
    here would leave only the prose. The envelope's request id is kept too,
    so an agent that wants the server's log line for this exact failure has
    the handle to ask with.
    """
    if isinstance(response, dict) and "error" in response:
        err = response["error"]
        if isinstance(err, dict):
            message = err.get("message", "Unknown error")
            code = err.get("code")
            if code:
                text = f"Error [{code}]: {message}"
            else:
                text = f"Error: {message}"
        else:
            text = f"Error: {err}"
        request_id = response.get("id")
        if request_id:
            text += f" (request id: {request_id})"
        return text
    return "Error: Unknown error"


def _list_total(response: dict, items: list) -> int:
    """Total item count: the Javalin server nests it at meta.total; older builds
    used top-level size. Fall back to the page length."""
    meta = response.get("meta")
    if isinstance(meta, dict):
        if "total" in meta:
            return meta["total"]
        if "total_estimate" in meta:
            return meta["total_estimate"]
    return response.get("size", response.get("total_estimate", len(items)))


def format_functions_list(response: dict, offset: int = 0, limit: int = 100, **kwargs) -> str:
    """Format function list as plain text table"""
    if not response.get("success", False):
        return format_error(response)

    items = response.get("result", [])
    total = _list_total(response, items)

    lines = [f"Functions ({offset+1}-{offset+len(items)} of {total}):", ""]

    for fn in items:
        name = fn.get("name", "???")
        addr = fn.get("address", "???")
        sig = fn.get("signature", "")
        if len(sig) > 60:
            sig = sig[:57] + "..."
        lines.append(f"  {addr}  {name:<30}  {sig}")

    if offset + len(items) < total:
        lines.append(f"\n  ... {total - offset - len(items)} more (use offset={offset+limit})")

    return "\n".join(lines)


def format_function_info(response: dict, **kwargs) -> str:
    """Format single function info as plain text"""
    if not response.get("success", False):
        return format_error(response)

    fn = response.get("result", {})
    lines = [
        f"Function: {fn.get('name', '???')}",
        f"Address:  {fn.get('address', '???')}",
        f"Signature: {fn.get('signature', 'unknown')}",
    ]

    if fn.get("entryPoint"):
        lines.append(f"Entry:    {fn.get('entryPoint')}")
    if fn.get("returnType"):
        lines.append(f"Returns:  {fn.get('returnType')}")

    params = fn.get("parameters", [])
    if params:
        lines.append(f"Parameters ({len(params)}):")
        for p in params:
            lines.append(f"  {p.get('dataType', '?')} {p.get('name', '?')}")

    local_vars = fn.get("localVariables", [])
    if local_vars:
        lines.append(f"Local variables ({len(local_vars)}):")
        for v in local_vars[:10]:
            lines.append(f"  {v.get('dataType', '?')} {v.get('name', '?')}")
        if len(local_vars) > 10:
            lines.append(f"  ... and {len(local_vars) - 10} more")

    return "\n".join(lines)


def format_decompile(response: dict, **kwargs) -> str:
    """Format decompiled code - just return the code"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    # Javalin server sends "decompilation"; older builds used "ccode"/"decompiled".
    code = result.get("decompilation") or result.get("ccode") or result.get("decompiled") or ""
    # The DTO carries its own success flag for decompiler-level failures.
    if not code and result.get("success") is False:
        return f"Decompilation failed: {result.get('errorMessage', 'unknown error')}"
    message = result.get("message")
    suggested_timeout = result.get("suggested_timeout_seconds")
    retry_recommended = bool(result.get("retry_recommended"))
    decompile_error = result.get("decompile_error") or result.get("errorMessage")

    # Line filtering happens client-side (the server returns the full function).
    start_line = kwargs.get("start_line")
    end_line = kwargs.get("end_line")
    max_lines = kwargs.get("max_lines")
    if code and (start_line or end_line or max_lines):
        all_lines = code.splitlines()
        total = len(all_lines)
        s = max(1, start_line or 1)
        e = min(end_line or total, total)
        if max_lines:
            e = min(e, s + max_lines - 1)
        selected = all_lines[s - 1:e]
        code = "\n".join([f"// lines {s}-{e} of {total}"] + selected)

    advisory_lines = []
    if retry_recommended:
        if message:
            advisory_lines.append(f"// {message}")
        if suggested_timeout:
            advisory_lines.append(f"// Suggested timeout: {suggested_timeout}s")
        if decompile_error:
            advisory_lines.append(f"// Decompiler error: {decompile_error}")

    if advisory_lines:
        advisory_text = "\n".join(advisory_lines)
        if not code:
            return advisory_text
        # Case-insensitive containment without copying the decompilation:
        # code.lower() allocated a lowercased copy of the whole function
        # just to answer "is the advisory already in there?".
        if not re.search(re.escape(advisory_text), code, re.IGNORECASE):
            return f"{code.rstrip()}\n\n{advisory_text}"

    if not code:
        return "Error: No decompiled code returned"

    return code


def format_disassembly(response: dict, **kwargs) -> str:
    """Format disassembly as plain text"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    # The javalin-port API returns the instruction list directly as `result`;
    # the legacy API nests it under result["instructions"]. Handle both.
    if isinstance(result, list):
        instructions = result
        result = {}
    else:
        instructions = result.get("instructions", [])

    # simplify_response converts instructions list to disassembly_text
    if not instructions and "disassembly_text" in result:
        disasm_text = result["disassembly_text"].rstrip()
        if not disasm_text:
            if "message" in result:
                return result["message"]
            if "warning" in result:
                return f"Warning: {result['warning']}"
            return "No disassembly available"
        return disasm_text

    if not instructions:
        if "message" in result:
            return result["message"]
        if "warning" in result:
            return f"Warning: {result['warning']}"
        return "No disassembly available"

    lines = []
    for instr in instructions:
        addr = instr.get("address", "")
        bytes_hex = instr.get("bytes", "")
        mnemonic = instr.get("mnemonic", "")
        operands = instr.get("operands", "")
        lines.append(f"  {addr}  {bytes_hex:<12} {mnemonic:<8} {operands}")

    # Surface truncation: the server caps a page (default 100 instructions) and the
    # raw list carries no hint that more follow, so a long function silently looks
    # complete. meta.total is the full instruction count for the function.
    meta = response.get("meta") or {}
    total = _list_total(response, instructions)
    offset = meta.get("offset") or 0
    shown = len(instructions)
    if offset + shown < total:
        more = total - offset - shown
        lines.append(f"\n  ... {more} more instruction(s) of {total} total (use offset={offset + shown})")

    return "\n".join(lines)


def format_xrefs(response: dict, to_addr: str | None = None, from_addr: str | None = None, **kwargs) -> str:
    """Format cross-references as plain text"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    # Handle both dict (with references key) and list format
    if isinstance(result, dict):
        items = result.get("references", [])
    else:
        items = result if isinstance(result, list) else []

    total = _list_total(response, items)
    target = to_addr or from_addr

    header = f"References"
    if target:
        header += f" {'to' if to_addr else 'from'} {target}"
    header += f" ({len(items)}"
    if total > len(items):
        header += f" of {total}"
    header += "):"

    lines = [header]
    for xref in items:
        # Server XrefDto uses fromAddress/toAddress/fromFunction; accept legacy names too.
        from_a = xref.get("fromAddress") or xref.get("from_addr", "???")
        to_a = xref.get("toAddress") or xref.get("to_addr", "")
        ref_type = xref.get("refType", "???")
        from_func_obj = xref.get("fromFunction") or xref.get("from_function") or ""
        to_func_obj = xref.get("toFunction") or ""

        # Extract function name if it is a dict
        if isinstance(from_func_obj, dict):
            from_func = from_func_obj.get("name", "")
        else:
            from_func = from_func_obj or ""
        to_func = to_func_obj.get("name", "") if isinstance(to_func_obj, dict) else (to_func_obj or "")

        line = f"  {from_a}"
        if from_addr and to_a:
            # listing refs FROM an address: the target is the interesting part
            line += f" -> {to_a}"
        line += f"  {ref_type:<10}"
        if from_func:
            line += f"  from {from_func}"
        if to_func and from_addr:
            line += f"  to {to_func}"
        lines.append(line)

    return "\n".join(lines)


def format_strings(response: dict, offset: int = 0, **kwargs) -> str:
    """Format strings list as plain text"""
    if not response.get("success", False):
        return format_error(response)

    items = response.get("result", [])
    total = _list_total(response, items)

    lines = [f"Strings ({offset+1}-{offset+len(items)} of {total}):", ""]

    for s in items:
        addr = s.get("address", "???")
        value = s.get("value", "")
        value = repr(value)[1:-1]
        if len(value) > 60:
            value = value[:57] + "..."
        lines.append(f"  {addr}  \"{value}\"")

    return "\n".join(lines)


def format_data_list(response: dict, offset: int = 0, limit: int = 100, **kwargs) -> str:
    """Format data items list as plain text"""
    if not response.get("success", False):
        return format_error(response)

    items = response.get("result", [])
    total = _list_total(response, items)

    lines = [f"Data items ({offset+1}-{offset+len(items)} of {total}):", ""]

    for d in items:
        addr = d.get("address", "???")
        label = d.get("label") or d.get("name", "")  # DataDto field is 'label'
        dtype = d.get("dataType", "???")  # Java returns 'dataType' not 'type'
        value = d.get("value", "")

        line = f"  {addr}  {dtype:<16}"
        if label and label != "(unnamed)":
            line += f"  {label}"
        if value:
            val_str = str(value)
            if len(val_str) > 30:
                val_str = val_str[:27] + "..."
            line += f"  = {val_str}"
        lines.append(line)

    return "\n".join(lines)


def format_instances(response: dict, **kwargs) -> str:
    """Format instances list as plain text"""
    # Handle both dict with 'instances' key and direct list
    if isinstance(response, dict):
        instances = response.get("instances", [])
    else:
        instances = response if isinstance(response, list) else []

    if not instances:
        return "No Ghidra instances found."

    lines = [f"Ghidra instances ({len(instances)}):", ""]

    for inst in instances:
        port = inst.get("port", "???")
        project = inst.get("project", "")
        file = inst.get("file", "")

        line = f"  :{port}"
        if project:
            line += f"  {project}"
        if file:
            line += f" / {file}"
        lines.append(line)

    return "\n".join(lines)


def format_instance_info(response: dict, **kwargs) -> str:
    """Format single instance info as plain text"""
    if "error" in response:
        return format_error(response)

    port = response.get("port", "???")
    program = response.get("program_name", "unknown")
    project = response.get("project", "")
    lang = response.get("language", "")
    base = response.get("base_address", "")
    lines = [f"Instance :{port}"]
    if project:
        lines.append(f"Project:  {project}")
    lines.append(f"Program:  {program}")
    if lang:
        lines.append(f"Language: {lang}")
    if base:
        lines.append(f"Base:     {base}")
    if response.get("function_count") is not None:
        lines.append(f"Functions: {response['function_count']}")
    if response.get("symbol_count") is not None:
        lines.append(f"Symbols:  {response['symbol_count']}")
    # /program does not report analysis state; only show it when actually present.
    if "analysis_complete" in response:
        lines.append(f"Analysis: {'complete' if response['analysis_complete'] else 'incomplete'}")

    return "\n".join(lines)


def format_memory(response: dict, **kwargs) -> str:
    """Format memory read as hex dump"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", response)
    addr = result.get("address", "???")
    hex_bytes = result.get("hex") or result.get("hexBytes") or ""
    if not hex_bytes and isinstance(result.get("bytes"), list):
        hex_bytes = "".join(f"{b:02x}" for b in result["bytes"])
    length = result.get("length", result.get("bytesRead", 0))

    lines = [f"Memory at {addr} ({length} bytes):"]

    if hex_bytes:
        hex_bytes = hex_bytes.replace(" ", "")  # Strip any spaces for safety
        byte_pairs = [hex_bytes[i:i+2] for i in range(0, len(hex_bytes), 2)]

        for i in range(0, len(byte_pairs), 16):
            chunk = byte_pairs[i:i+16]
            hex_part = " ".join(chunk)

            ascii_part = ""
            for bp in chunk:
                try:
                    b = int(bp, 16)
                    ascii_part += chr(b) if 32 <= b < 127 else "."
                except ValueError:
                    ascii_part += "?"

            lines.append(f"  {hex_part:<48}  {ascii_part}")

    return "\n".join(lines)


def format_variables(response: dict, **kwargs) -> str:
    """Format function variables as plain text"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})

    # Javalin server shape: {function: {name, address}, variables: [{name, type,
    # isParameter, storage, source}]}. Older builds: functionName/parameters/localVariables.
    fn = result.get("function")
    if isinstance(fn, dict):
        fn_name = fn.get("name", "???")
        variables = result.get("variables", [])
        params = [v for v in variables if v.get("isParameter")]
        locals_list = [v for v in variables if not v.get("isParameter")]
        type_key = "type"
    else:
        fn_name = result.get("functionName", "???")
        params = result.get("parameters", [])
        locals_list = result.get("localVariables", [])
        type_key = "dataType"

    lines = [f"Variables for {fn_name}:"]

    if params:
        lines.append(f"\nParameters ({len(params)}):")
        for p in params:
            storage = p.get('storage', '')
            lines.append(f"  {p.get(type_key, '?'):<20} {p.get('name', '?'):<20} {storage}")

    if locals_list:
        lines.append(f"\nLocal variables ({len(locals_list)}):")
        for v in locals_list:
            storage = v.get('storage', '')
            source = v.get('source', '')
            suffix = f"  [{source}]" if source == "decompiler" else ""
            lines.append(f"  {v.get(type_key, '?'):<20} {v.get('name', '?'):<20} {storage}{suffix}")

    if not params and not locals_list:
        lines.append("  (no variables)")

    return "\n".join(lines)


def format_callgraph(response: dict, **kwargs) -> str:
    """Format call graph as plain text"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})

    # Server shape: {root: {name, address, ...}, depth, direction,
    #                callers: [{function: {...}, callers: [...]}],
    #                callees: [{function: {...}, callees: [...]}]}
    root = result.get("root")
    if not isinstance(root, dict):
        return "No call graph data returned."

    root_name = root.get("name", "???")
    root_addr = root.get("address", "")
    depth = result.get("depth", "?")

    def render_tree(nodes, child_key, indent=1, budget=None):
        if budget is None:
            budget = [200]  # total line budget across the whole tree
        out = []
        if not isinstance(nodes, list):
            return out
        for node in nodes:
            if budget[0] <= 0:
                out.append(f"{'  ' * indent}...")
                break
            if not isinstance(node, dict):
                continue
            fn = node.get("function", {})
            name = fn.get("name", "???")
            addr = fn.get("address", "")
            out.append(f"{'  ' * indent}{name}  {addr}")
            budget[0] -= 1
            out.extend(render_tree(node.get(child_key), child_key, indent + 1, budget))
        return out

    lines = [f"Call graph for {root_name} ({root_addr}), depth {depth}:"]

    callers = result.get("callers")
    if callers is not None:
        lines.append("")
        lines.append(f"Callers ({len(callers)}):")
        lines.extend(render_tree(callers, "callers") or ["  (none)"])

    callees = result.get("callees")
    if callees is not None:
        lines.append("")
        lines.append(f"Callees ({len(callees)}):")
        lines.extend(render_tree(callees, "callees") or ["  (none)"])

    return "\n".join(lines)


def format_dataflow(response: dict, **kwargs) -> str:
    """Format data flow analysis as plain text"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    steps = result.get("steps", [])

    if not steps:
        return "No data flow steps found."

    lines = [f"Data Flow ({len(steps)} steps):", ""]

    for i, step in enumerate(steps, 1):
        addr = step.get("address", step.get("to", step.get("from", "???")))
        # Server steps carry instruction text + containing function + reference list.
        instr = step.get("instruction", step.get("description", step.get("label", "")))
        fn = step.get("function", "")
        fn_part = f"  [{fn}]" if fn else ""
        lines.append(f"  {i:>2}. {addr}  {instr}{fn_part}")
        for ref in step.get("references", [])[:8]:
            lines.append(f"        {ref.get('type', '?'):<14} {ref.get('from', '?')} -> {ref.get('to', '?')}")

    return "\n".join(lines)


def _xref_line(xref: dict) -> str:
    """One cross-reference, as a line of text."""
    from_addr = xref.get("fromAddress") or xref.get("from_addr", "???")
    to_addr = xref.get("toAddress") or xref.get("to_addr", "")
    ref_type = xref.get("refType", "???")
    from_func = xref.get("fromFunction") or ""
    if isinstance(from_func, dict):
        from_func = from_func.get("name", "")

    line = f"{from_addr}"
    if to_addr:
        line += f" -> {to_addr}"
    line += f"  {ref_type:<18}"
    if from_func:
        line += f"  from {from_func}"
    return line


def format_batch_decompile(response: dict, **kwargs) -> str:
    """Format a batch decompilation as plain text"""
    if not response.get("success", False):
        return format_error(response)

    items = response.get("result", [])
    if not isinstance(items, list):
        return "No decompilation results returned."

    done = [i for i in items if isinstance(i, dict) and i.get("success")]
    failed = [i for i in items if isinstance(i, dict) and not i.get("success")]

    lines = [f"Batch decompile ({len(done)} of {len(items)} succeeded):", ""]

    for item in done:
        name = item.get("functionName") or item.get("function_name") or "???"
        address = item.get("functionAddress") or item.get("function_address") or ""
        code = item.get("decompilation") or ""
        lines.append(f"=== {name}  {address}  ({len(code.splitlines())} lines) ===")
        lines.append(code.rstrip())
        lines.append("")

    if failed:
        lines.append("Failed:")
        for item in failed:
            name = item.get("functionName") or item.get("function_name") or "???"
            reason = item.get("errorMessage") or item.get("error_message") or "unknown error"
            lines.append(f"  {name}: {reason}")

    return "\n".join(lines)


def format_xrefs_by_name(response: dict, name: str | None = None, **kwargs) -> str:
    """Format the references to a name as plain text"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    if not isinstance(result, dict):
        return "No references found."

    symbols = result.get("symbols") or []
    references = result.get("references") or []
    total = result.get("total", len(references))
    label = result.get("name") or name or "?"

    lines = [f"References to '{label}' ({len(references)} of {total}):", ""]

    for symbol in symbols:
        if not isinstance(symbol, dict):
            continue
        lines.append(f"  symbol: {symbol.get('name', '???')}  {symbol.get('address', '')}"
                     f"  {symbol.get('type', '')}")

    if not references:
        lines.append("  (no references)")

    for xref in references:
        if isinstance(xref, dict):
            lines.append("  " + _xref_line(xref))

    return "\n".join(lines)


def format_address_context(response: dict, **kwargs) -> str:
    """Format what an address is, as plain text"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    if not isinstance(result, dict):
        return "No address context returned."

    address = result.get("address", "???")
    symbol = result.get("symbol") or {}
    function = result.get("function") or {}
    data = result.get("data") or {}
    instruction = result.get("instruction") or {}

    lines = [f"Address {address} ({result.get('addressSpace', '?')}):"]

    if symbol:
        lines.append(f"  symbol:   {symbol.get('name', '???')}  ({symbol.get('type', '')})")

    if function:
        lines.append(f"  function: {function.get('name', '???')}  {function.get('address', '')}")
        signature = function.get("signature")
        if signature:
            lines.append(f"            {signature}")

    if instruction:
        lines.append(f"  code:     {instruction.get('address', '')}  "
                     f"{instruction.get('bytes', '')}  "
                     f"{instruction.get('mnemonic', '')} {instruction.get('operands', '')}")

    if data:
        label = data.get("label") or ""
        lines.append(f"  data:     {data.get('dataType', '???')}  "
                     f"len={data.get('length', '?')}  {label}")

    comment = result.get("comment")
    if comment:
        lines.append(f"  comment:  {comment}")

    eol_comment = result.get("eolComment")
    if eol_comment:
        lines.append(f"  eol:      {eol_comment}")

    xrefs_to = result.get("xrefsTo") or []
    xrefs_from = result.get("xrefsFrom") or []

    lines.append(f"  referenced by ({len(xrefs_to)}):")
    for xref in xrefs_to:
        if isinstance(xref, dict):
            lines.append("    " + _xref_line(xref))

    lines.append(f"  references ({len(xrefs_from)}):")
    for xref in xrefs_from:
        if isinstance(xref, dict):
            lines.append("    " + _xref_line(xref))

    return "\n".join(lines)


def format_call_path(response: dict, **kwargs) -> str:
    """Format a call path as plain text"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    if not isinstance(result, dict):
        return "No call path returned."

    source = result.get("from") or {}
    target = result.get("to") or {}
    source_name = source.get("name", "???")
    target_name = target.get("name", "???")

    if not result.get("found"):
        reason = result.get("reason") or "no path found"
        return f"No call path from {source_name} to {target_name}: {reason}"

    path = result.get("path") or []
    lines = [f"Call path from {source_name} to {target_name} "
             f"({result.get('depth', '?')} hop(s), "
             f"{result.get('visited', '?')} function(s) explored):", ""]

    for index, fn in enumerate(path):
        if not isinstance(fn, dict):
            continue
        arrow = "  " if index == 0 else "-> "
        lines.append(f"  {arrow}{fn.get('name', '???')}  {fn.get('address', '')}")

    return "\n".join(lines)


def _page_note(response: dict, items: list) -> str:
    """The note that says the list is one page of a longer one.

    A page that is not the whole list has to say so: "Callers (100)" reads
    as "there are 100" when there are two hundred and fifty.
    """
    meta = response.get("meta")
    if not isinstance(meta, dict):
        return ""
    total = meta.get("total")
    if not isinstance(total, int) or total <= len(items):
        return ""
    return (f"There are {total} in total - this page holds {len(items)}. "
            f"Ask for the rest with offset and limit.")


def format_callers(response: dict, **kwargs) -> str:
    """Format the callers of a function as plain text"""
    if not response.get("success", False):
        return format_error(response)

    items = response.get("result", [])
    if not isinstance(items, list):
        return "No callers found."

    if not items:
        return "Nobody calls it."

    lines = [f"Callers ({len(items)}):", ""]
    note = _page_note(response, items)
    if note:
        lines.insert(1, note)
    for item in items:
        if not isinstance(item, dict):
            continue
        lines.append(f"  {item.get('name', '???')}  {item.get('address', '')}")
        signature = item.get("signature")
        if signature:
            lines.append(f"    {signature}")

    return "\n".join(lines)


def format_callees(response: dict, **kwargs) -> str:
    """Format the callees of a function as plain text"""
    if not response.get("success", False):
        return format_error(response)

    items = response.get("result", [])
    if not isinstance(items, list):
        return "No callees found."

    if not items:
        return "It calls nothing."

    lines = [f"Callees ({len(items)}):", ""]
    note = _page_note(response, items)
    if note:
        lines.insert(1, note)
    for item in items:
        if not isinstance(item, dict):
            continue
        lines.append(f"  {item.get('name', '???')}  {item.get('address', '')}")
        signature = item.get("signature")
        if signature:
            lines.append(f"    {signature}")

    return "\n".join(lines)


def format_function_analysis(response: dict, **kwargs) -> str:
    """Format everything about one function as plain text"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    if not isinstance(result, dict):
        return "Nothing to analyse."

    function = result.get("function") or {}
    lines = [f"{function.get('name', '???')}  {function.get('address', '')}"]

    signature = function.get("signature")
    if signature:
        lines.append(f"  {signature}")

    code = result.get("decompilation")
    if code:
        lines.append("")
        lines.append(code.rstrip())
    else:
        reason = result.get("decompileError")
        lines.append("")
        lines.append(f"(no decompilation{f': {reason}' if reason else ''})")

    for label, key in (("Callers", "callers"), ("Callees", "callees"), ("References", "xrefs")):
        items = result.get(key) or []
        lines.append("")
        lines.append(f"{label} ({len(items)}):")
        for item in items:
            if not isinstance(item, dict):
                continue
            if key == "xrefs":
                lines.append("  " + _xref_line(item))
            else:
                lines.append(f"  {item.get('name', '???')}  {item.get('address', '')}")

    return "\n".join(lines)


def format_overview(response: dict, **kwargs) -> str:
    """Format the overview of the loaded binary as plain text"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    if not isinstance(result, dict):
        return "No overview available."

    program = result.get("program") or {}
    statistics = result.get("statistics") or {}

    lines = [f"{program.get('name', '?')}"]
    if program.get("path"):
        lines.append(f"  path:     {program['path']}")
    lines.append(f"  language: {program.get('language', '?')}")
    lines.append(f"  base:     {program.get('imageBase', '?')}")

    counts = []
    if statistics.get("functions") is not None:
        counts.append(f"{statistics['functions']} functions")
    if statistics.get("symbols") is not None:
        counts.append(f"{statistics['symbols']} symbols")
    if statistics.get("imports") is not None:
        counts.append(f"{statistics['imports']} imports")
    if statistics.get("memoryBlocks") is not None:
        counts.append(f"{statistics['memoryBlocks']} blocks")
    if counts:
        lines.append(f"  holds:    {', '.join(counts)}")

    segments = result.get("segments") or []
    if segments:
        lines.append("")
        lines.append(f"Segments ({len(segments)}):")
        for segment in segments:
            if not isinstance(segment, dict):
                continue
            lines.append(f"  {segment.get('name', '?'):<10} {segment.get('start', '?')}"
                         f" - {segment.get('end', '?')}  {segment.get('size', '?')} bytes")

    imports = result.get("imports") or []
    if imports:
        lines.append("")
        lines.append(f"Imports ({len(imports)}):")
        for item in imports:
            if isinstance(item, dict):
                lines.append(f"  {item.get('name', '?')}")

    return "\n".join(lines)


def format_structs_list(response: dict, offset: int = 0, **kwargs) -> str:
    """Format struct list as plain text"""
    if not response.get("success", False):
        return format_error(response)

    items = response.get("result", [])
    total = _list_total(response, items)

    lines = [f"Structs ({offset+1}-{offset+len(items)} of {total}):", ""]

    for s in items:
        name = s.get("name", "???")
        size = s.get("size", 0)
        fields = s.get("fieldCount", s.get("numFields", "?"))
        lines.append(f"  {name:<40} {size:>6} bytes  {fields} fields")

    return "\n".join(lines)


def format_struct_info(response: dict, **kwargs) -> str:
    """Format struct details as plain text"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    if isinstance(result, list):
        result = result[0] if result else {}

    name = result.get("name", "???")
    size = result.get("size", 0)
    fields = result.get("fields", [])

    lines = [f"Struct: {name} ({size} bytes)", ""]

    if fields:
        lines.append(f"Fields ({len(fields)}):")
        for f in fields:
            foffset = f.get("offset", 0)
            fname = f.get("name", "???")
            ftype = f.get("type", "???")
            fsize = f.get("length", f.get("size", "?"))  # StructFieldDto field is 'length'
            lines.append(f"  +{foffset:<4} {ftype:<20} {fname:<20} ({fsize} bytes)")
    else:
        lines.append("  (no fields)")

    return "\n".join(lines)


def format_project_info(response: dict, **kwargs) -> str:
    """Format project info as plain text"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    name = result.get("name", "???")
    location = result.get("location", "???")
    file_count = result.get("fileCount", "?")

    return f"Project: {name}\nLocation: {location}\nFiles: {file_count}"


def format_project_files(response: dict, **kwargs) -> str:
    """Format project files as plain text"""
    if not response.get("success", False):
        return format_error(response)

    items = response.get("result", [])
    lines = [f"Project files ({len(items)}):", ""]

    for f in items:
        path = f.get("path", f.get("name", "???"))
        ftype = "DIR" if f.get("isFolder") else "   "
        lines.append(f"  {ftype}  {path}")

    return "\n".join(lines)


def format_simple_result(response: dict, success_msg: str = "Done", **kwargs) -> str:
    """Format a simple success/error response"""
    if not response.get("success", False):
        return format_error(response)
    return success_msg


def format_generic_dict(response: dict, **kwargs) -> str:
    """Format a dictionary result as key-value pairs"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", response)
    if not isinstance(result, dict):
        return str(result)

    lines = []
    for k, v in result.items():
        if k == "_links" or k == "success" or k == "timestamp":
            continue
        lines.append(f"{k}: {v}")
    return "\n".join(lines)


def format_generic_list(response: dict, **kwargs) -> str:
    """Format a list result as plain text lines"""
    if not response.get("success", False):
        return format_error(response)

    items = response.get("result", [])
    if not isinstance(items, list):
        return str(items)

    if not items:
        return "No items found."

    lines = []
    for item in items:
        if isinstance(item, dict):
            # Try to find a name or description field
            label = item.get("name") or item.get("path") or item.get("id") or str(item)
            lines.append(f"  {label}")
        else:
            lines.append(f"  {item}")
    return "\n".join(lines)


def format_classes_list(response: dict, offset: int = 0, limit: int = 100, **kwargs) -> str:
    """Format classes list as text"""
    items = response.get("result", [])
    total = _list_total(response, items)

    lines = [f"Classes ({offset+1}-{offset+len(items)} of {total}):", ""]

    for c in items:
        name = c.get("name", "???")
        namespace = c.get("namespace", "")
        simple = c.get("simpleName", name)
        if namespace and namespace != "default":
            lines.append(f"  {simple}  ({namespace})")
        else:
            lines.append(f"  {simple}")

    return "\n".join(lines)


def format_symbols_list(response: dict, offset: int = 0, limit: int = 100, **kwargs) -> str:
    """Format symbols list as text"""
    items = response.get("result", [])
    total = _list_total(response, items)

    lines = [f"Symbols ({offset+1}-{offset+len(items)} of {total}):", ""]

    for s in items:
        addr = s.get("address", "???")
        name = s.get("name", "???")
        stype = s.get("type", "")
        primary = " *" if s.get("isPrimary") else ""
        lines.append(f"  {addr}  {stype:<12}  {name}{primary}")

    return "\n".join(lines)


def format_imports_exports(response: dict, offset: int = 0, limit: int = 100, **kwargs) -> str:
    """Format imports/exports list as text"""
    items = response.get("result", [])
    total = _list_total(response, items)

    lines = [f"Entries ({offset+1}-{offset+len(items)} of {total}):", ""]

    for item in items:
        addr = item.get("address", "???")
        name = item.get("name", "???")
        lines.append(f"  {addr}  {name}")

    return "\n".join(lines)


def format_segments_list(response: dict, offset: int = 0, limit: int = 100, **kwargs) -> str:
    """Format segments list as text"""
    items = response.get("result", [])
    total = _list_total(response, items)

    lines = [f"Segments ({offset+1}-{offset+len(items)} of {total}):", ""]

    for seg in items:
        name = seg.get("name", "???")
        start = seg.get("start", "???")
        end = seg.get("end", "???")
        size = seg.get("size", 0)
        # MemoryBlockDto serializes isRead/isWrite/isExecute/isInitialized.
        perms = ""
        perms += "R" if seg.get("isRead", seg.get("readable")) else "-"
        perms += "W" if seg.get("isWrite", seg.get("writable")) else "-"
        perms += "X" if seg.get("isExecute", seg.get("executable")) else "-"
        init = "init" if seg.get("isInitialized", seg.get("initialized")) else "uninit"
        lines.append(f"  {name:<16}  {start}-{end}  {size:>8} bytes  {perms}  {init}")

    return "\n".join(lines)


def format_namespaces_list(response: dict, offset: int = 0, limit: int = 100, **kwargs) -> str:
    """Format namespaces list as text"""
    items = response.get("result", [])
    total = _list_total(response, items)

    lines = [f"Namespaces ({offset+1}-{offset+len(items)} of {total}):", ""]

    for ns in items:
        if isinstance(ns, str):
            lines.append(f"  {ns}")
        else:
            lines.append(f"  {ns.get('name', '???')}")

    return "\n".join(lines)


def format_variables_list(response: dict, offset: int = 0, limit: int = 100, **kwargs) -> str:
    """Format variables list as text"""
    items = response.get("result", [])
    total = _list_total(response, items)

    lines = [f"Variables ({offset+1}-{offset+len(items)} of ~{total}):", ""]

    for v in items:
        addr = v.get("address", "???")
        name = v.get("name", "???")
        vtype = v.get("type", "")
        dtype = v.get("dataType", "")
        func = v.get("function", "")
        loc = f"  [{func}]" if func else ""
        lines.append(f"  {addr}  {vtype:<10}  {dtype:<16}  {name}{loc}")

    return "\n".join(lines)


def format_datatypes_list(response: dict, offset: int = 0, limit: int = 100, **kwargs) -> str:
    """Format datatypes list as text"""
    items = response.get("result", [])
    total = _list_total(response, items)

    lines = [f"Data Types ({offset+1}-{offset+len(items)} of {total}):", ""]

    for dt in items:
        name = dt.get("name", "???")
        kind = dt.get("kind", "")
        category = dt.get("category", "/")
        length = dt.get("length", 0)
        extra = ""
        if kind in ("struct", "union"):
            extra = f"  ({dt.get('numComponents', 0)} fields)"
        elif kind == "enum":
            extra = f"  ({dt.get('numValues', 0)} values)"
        lines.append(f"  {kind:<8}  {name:<24}  {length:>4}B  {category}{extra}")

    return "\n".join(lines)


# ================= Formatter Registry & Decorator =================

def format_scalars(response: dict, **kwargs) -> str:
    """Format scalar search results as plain text"""
    if not response.get("success", False):
        return format_error(response)

    items = response.get("result", [])
    meta = response.get("meta") or {}
    offset = meta.get("offset", 0)

    if not items:
        if meta.get("scanTruncated"):
            return "No scalars found (scan truncated before completing; narrow with in_function or a more specific value)"
        return "No scalars found"

    lines = [f"Scalars ({offset + 1}-{offset + len(items)}):", ""]
    for s in items:
        addr = s.get("address", "")
        hexv = s.get("hexValue", "")
        op = s.get("operandIndex", "?")
        instr = s.get("instruction", "")
        in_fn = s.get("inFunction") or "-"
        line = f"  {addr}  {hexv:<12} op{op}  {instr}  [in {in_fn}]"
        to_fn = s.get("toFunction")
        if to_fn:
            line += f"  -> calls {to_fn}"
        lines.append(line)

    if meta.get("scanTruncated"):
        lines.append("")
        lines.append("  (scan stopped early to keep the UI responsive; results may be incomplete "
                     "- narrow with in_function or a more specific value)")
    elif (response.get("_links") or {}).get("next"):
        lines.append(f"\n  ... more available (use offset={offset + len(items)})")

    return "\n".join(lines)


def format_cfg(response: dict, **kwargs) -> str:
    """Format control flow graph as plain text"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    fn_name = result.get("function", "???")
    blocks = result.get("blocks", [])
    edges = result.get("edges", [])

    lines = [
        f"CFG for {fn_name} ({result.get('address', '???')})",
        f"  {result.get('blockCount', 0)} blocks, {result.get('edgeCount', 0)} edges",
        ""
    ]

    for b in blocks:
        start = b.get("start", "")
        lines.append(f"  Block {start} - {b.get('end', '')} (size: {b.get('size', 0)})")

    if edges:
        lines.append("")
        lines.append("  Edges:")
        for e in edges:
            lines.append(f"    {e.get('from', '')} -> {e.get('to', '')}  [{e.get('type', '?')}]")

    return "\n".join(lines)


def format_pcode(response: dict, **kwargs) -> str:
    """Format pcode operations as plain text"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    fn_name = result.get("function", "???")
    ops = result.get("operations", [])

    lines = [
        f"Pcode for {fn_name} ({result.get('address', '???')})",
        f"  {result.get('opCount', 0)} operations",
        ""
    ]

    for op in ops:
        addr = op.get("address", "?")
        opcode = op.get("opcode", "?")
        output = op.get("output", "")
        inputs = ", ".join(op.get("inputs", []))

        if output:
            lines.append(f"  {addr}: {output} = {opcode} {inputs}")
        else:
            lines.append(f"  {addr}: {opcode} {inputs}")

    return "\n".join(lines)


# ================= Kuna formatters =================

def format_kuna_status(response: dict, **kwargs) -> str:
    """Format the Kuna integration status"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    state = "enabled" if result.get("enabled") else "disabled"
    binary = result.get("binary") or "not found"
    version = result.get("version")
    lines = [
        f"Kuna integration: {state} (opt-in via {result.get('source', 'unknown')})",
        f"  Binary: {binary}" + (f"  [{version}]" if version else ""),
        f"  Config: {result.get('config_file', '')}",
        f"  Work:   {result.get('work_dir', '')}",
    ]

    jobs = result.get("jobs") or []
    lines.append("")
    if jobs:
        lines.append(f"Export jobs ({len(jobs)}):")
        for job in jobs:
            reused = "  (reused)" if job.get("reused") else ""
            lines.append(f"  {job.get('id')}  {job.get('status')}  {job.get('binary')}{reused}")
    else:
        lines.append("Export jobs: none")

    exports = result.get("exports") or []
    if exports:
        lines.append("")
        lines.append(f"Exports on disk ({len(exports)}):")
        for export in exports:
            name = export.get("binary") or "unknown binary"
            streaming = "  (streaming)" if export.get("streaming") else ""
            lines.append(
                f"  {export.get('digest')}  {export.get('functions', 0)} functions  {name}{streaming}"
            )
            lines.append(f"    kuna://export/{export.get('digest')}/index.jsonl")

    return "\n".join(lines)


def format_kuna_summary(response: dict, **kwargs) -> str:
    """Format the kuna binary summary"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    summary = result.get("summary") or {}
    entry = summary.get("entry") or {}
    main = summary.get("main") or {}

    lines = [
        f"Summary for {result.get('binary', '?')}",
        f"  Functions:  {result.get('count', '?')} (total {result.get('total', '?')})",
    ]
    if entry:
        lines.append(f"  Entry:      {entry.get('name')} @ {entry.get('address_hex')}")
    if main:
        lines.append(f"  Main:       {main.get('name')} @ {main.get('address_hex')}")
    lines.append(f"  Reachable:  {summary.get('reachable_from_entry', '?')} from entry")
    lines.append(f"  No callers: {summary.get('no_callers', '?')}")
    lines.append(f"  Code bytes: {summary.get('code_bytes', '?')}")

    runtime = summary.get("runtime")
    if runtime:
        lines.append(f"  Runtime:    {runtime}")

    buckets = summary.get("size_buckets") or []
    if buckets:
        lines.append("")
        lines.append("  Size buckets:")
        for bucket in buckets:
            lines.append(f"    {bucket.get('bucket', '?'):>10}  {bucket.get('count', 0)}")

    largest = summary.get("largest") or []
    if largest:
        lines.append("")
        lines.append("  Largest functions:")
        for fn in largest[:10]:
            lines.append(
                f"    {fn.get('name', '?'):<28} {fn.get('size', 0):>7} bytes  @ {fn.get('address_hex', '?')}"
            )

    warnings = result.get("warnings") or []
    if warnings:
        lines.append("")
        lines.append("  Warnings:")
        for warning in warnings:
            lines.append(f"    {warning}")

    return "\n".join(lines)


def format_kuna_functions(response: dict, offset: int = 0, limit: int = 100, **kwargs) -> str:
    """Format the kuna function list"""
    if not response.get("success", False):
        return format_error(response)

    items = response.get("result", [])
    total = _list_total(response, items)

    lines = [f"Functions ({offset + 1}-{offset + len(items)} of {total}):", ""]
    for fn in items:
        lines.append(
            f"  {fn.get('address_hex', '???'):<18} {fn.get('name', '???'):<32} {fn.get('size', 0):>7}B"
        )

    if offset + len(items) < total:
        lines.append(f"\n  ... {total - offset - len(items)} more (use offset={offset + limit})")

    return "\n".join(lines)


def format_kuna_decompile(response: dict, **kwargs) -> str:
    """Format a kuna decompilation"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    functions = result.get("functions") or []
    if not functions:
        return f"Kuna returned no function (count={result.get('count', 0)})"

    fn = functions[0]
    lines = [
        f"{fn.get('name', '?')} @ {fn.get('address_hex', '?')} ({fn.get('size', 0)} bytes)",
        "",
    ]

    code = fn.get("code") or ""
    max_lines = kwargs.get("max_lines")
    if code and max_lines:
        code = "\n".join(code.splitlines()[:max_lines])

    if fn.get("error"):
        lines.append(f"// kuna error: {fn['error']}")
    lines.append(code or "// no output")

    return "\n".join(lines)


def format_kuna_disassemble(response: dict, **kwargs) -> str:
    """Format a kuna disassembly"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    target = result.get("target") or {}
    lines = [
        f"Disassembly of {target.get('name', '?')} "
        f"({result.get('start_hex', '?')}-{result.get('end_hex', '?')}), "
        f"{result.get('count', 0)} instructions, {result.get('bytes', 0)} bytes",
        "",
    ]

    for instruction in result.get("instructions", []):
        lines.append(
            f"  {instruction.get('address_hex', '?'):<18} "
            f"{instruction.get('bytes', ''):<30} {instruction.get('text', '')}"
        )

    if result.get("truncated"):
        lines.append("  (output truncated)")

    return "\n".join(lines)


def format_kuna_read(response: dict, **kwargs) -> str:
    """Format a kuna byte read as a hex dump"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    lines = [
        f"Bytes at {result.get('start_hex', '?')} ({result.get('bytes', 0)} bytes):",
        "",
    ]

    for row in result.get("rows", []):
        lines.append(
            f"  {row.get('address_hex', '?'):<18} {row.get('bytes', ''):<34} {row.get('ascii', '')}"
        )

    return "\n".join(lines)


def format_kuna_strings(response: dict, **kwargs) -> str:
    """Format a kuna string search"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    strings = result.get("strings", [])
    total = result.get("count", len(strings))

    lines = [f"Strings matching /{result.get('filter', '')}/ ({len(strings)} of {total}):", ""]
    for entry in strings:
        text = str(entry.get("text", "")).replace("\n", "\\n")
        lines.append(
            f"  {entry.get('address_hex', '?'):<18} {text!r}  "
            f"[{entry.get('section', '?')}]  xrefs: {entry.get('xrefs_count', 0)}"
        )
        functions = entry.get("functions") or []
        if functions:
            names = ", ".join(fn.get("name", "?") for fn in functions[:3])
            if len(functions) > 3:
                names += f" (+{len(functions) - 3} more)"
            lines.append(f"      -> {names}")

    return "\n".join(lines)


def format_kuna_crypto(response: dict, **kwargs) -> str:
    """Format a kuna crypto constant scan"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    constants = result.get("constants", [])

    lines = [f"Crypto constants in {result.get('binary', '?')} ({len(constants)}):", ""]
    for entry in constants:
        detail = " ".join(str(part) for part in (entry.get("kind"), entry.get("layout")) if part)
        lines.append(
            f"  {entry.get('algorithm', '?'):<10} {entry.get('name', '')}"
            f"  @ {entry.get('address_hex', '?')}  [{entry.get('section', '?')}]"
        )
        if detail:
            lines.append(f"      {detail}  xrefs: {entry.get('xrefs_count', 0)}")
        for fn in (entry.get("functions") or [])[:5]:
            lines.append(f"      -> {fn.get('name', '?')} @ {fn.get('address_hex', '?')}")

    return "\n".join(lines)


def format_kuna_xrefs(response: dict, **kwargs) -> str:
    """Format kuna cross-references"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    target = result.get("target") or {}
    xrefs = result.get("xrefs", [])

    lines = [
        f"Cross-references {result.get('direction', '?')} {target.get('name', '?')} ({len(xrefs)}):",
        "",
    ]
    for xref in xrefs:
        lines.append(
            f"  {xref.get('address_hex', '?'):<18} {xref.get('kind', '?'):<6} {xref.get('instruction', '')}"
        )

    return "\n".join(lines)


def format_kuna_unpack(response: dict, **kwargs) -> str:
    """Format a kuna unpack result"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    output = result.get("output", result.get("unpacked", result.get("path", "?")))
    return f"Unpacked {result.get('binary', '?')}\n  Output: {output}"


def format_kuna_export_start(response: dict, **kwargs) -> str:
    """Format the start of a kuna export job"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    job_id = result.get("id", "?")
    if result.get("reused"):
        return "\n".join([
            f"Export reused (job {job_id})",
            f"  Binary: {result.get('binary')}",
            f"  Dir:    {result.get('dir')}",
            f"  Status: {result.get('status')}",
            f"  Functions: {result.get('functions', 0)} ({result.get('failed', 0)} failed)",
            "",
            "The export was already there, so the binary was not analysed again.",
            f"Read it with kuna_export_read(job_id='{job_id}', function='<name>'),",
            "or as the resources kuna://export/{digest}/index.jsonl and",
            "kuna://export/{digest}/{function}.c.",
        ])
    return "\n".join([
        f"Export job {job_id} started",
        f"  Binary: {result.get('binary')}",
        f"  Dir:    {result.get('dir')}",
        f"  Status: {result.get('status')}",
        "",
        f"Poll it with kuna_export_status(job_id='{job_id}').",
    ])


def format_kuna_export_status(response: dict, **kwargs) -> str:
    """Format the status of a kuna export job"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    lines = [
        f"Export job {result.get('id', '?')}",
        f"  Binary: {result.get('binary')}",
        f"  Dir:    {result.get('dir')}",
        f"  Status: {result.get('status')}",
    ]
    if result.get("finished_at"):
        lines.append(f"  Ended:  {result.get('finished_at')}")
    if result.get("returncode") is not None:
        lines.append(f"  Exit:   {result.get('returncode')}")
    if result.get("error"):
        lines.append(f"  Error:  {result.get('error')}")

    streaming = result.get("streaming")
    if streaming:
        lines.append(f"  Phase:  {streaming.get('phase', '?')}")
        if streaming.get("counts"):
            lines.append(f"  Counts: {streaming.get('counts')}")
        if streaming.get("error"):
            lines.append(f"  Failed: {streaming.get('error')}")

    return "\n".join(lines)


def format_kuna_export_read(response: dict, **kwargs) -> str:
    """Format a read from a kuna export"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    artifact = result.get("artifact", "?")

    functions = result.get("functions")
    if functions is not None:
        lines = [
            f"Exported functions ({result.get('total', len(functions))}):",
            "",
        ]
        for record in functions:
            error = f"  ERROR: {record.get('error')}" if record.get("error") else ""
            lines.append(
                f"  {record.get('addr', '?'):<18} {record.get('name', '?'):<32} "
                f"{record.get('size', 0):>7}B{error}"
            )
        return "\n".join(lines)

    header = f"{artifact} for {result.get('function') or result.get('binary', '?')}"
    return f"{header}\n\n{result.get('text', '')}"


# ================= x64dbg formatters =================

def format_x64dbg_status(response: dict, **kwargs) -> str:
    """Format the state of the x64dbg MCP server"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    lines = [
        f"x64dbg MCP server: reachable at {result.get('host')}:{result.get('port')}",
        f"  Tools: {result.get('tools', 0)}",
    ]
    modules = result.get("modules") or []
    if modules:
        lines.append(f"  Modules ({len(modules)}):")
        for module in modules:
            lines.append(
                f"    {hex(module.get('base', 0))}  {hex(module.get('size', 0))}  "
                f"{module.get('path')}"
            )
    else:
        lines.append("  Modules: none loaded (no debug session?)")
    if result.get("debug_state"):
        lines.append(f"  State: {result['debug_state']}")
    return "\n".join(lines)


def format_x64dbg_tools(response: dict, **kwargs) -> str:
    """Format the x64dbg tool catalogue"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    tools = result.get("tools") or []
    lines = [f"x64dbg tools ({result.get('count', len(tools))}):", ""]
    for tool in tools:
        description = str(tool.get("description") or "").split("\n")[0]
        if len(description) > 110:
            description = description[:107] + "..."
        lines.append(f"  {tool.get('name')}")
        if description:
            lines.append(f"    {description}")
    lines.append("")
    lines.append("Call one with x64dbg_call(tool='<name>', tool_arguments='{\"param\": \"value\"}').")
    lines.append("The arguments go as one piece of JSON text: a client that flattens a nested")
    lines.append("object turns every value into a string.")
    return "\n".join(lines)


def format_x64dbg_call(response: dict, **kwargs) -> str:
    """Format the result of a call to an x64dbg tool"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    return f"{result.get('tool')}\n\n{result.get('text', '')}"


def format_x64dbg_target(response: dict, **kwargs) -> str:
    """Format the correlation between the Ghidra program and the x64dbg session"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    return "\n".join([
        "Ghidra and x64dbg agree on this binary:",
        f"  Binary:     {result.get('binary')}",
        f"  Image base: {result.get('image_base') and hex(result['image_base'])}  (Ghidra, in the file)",
        f"  Module base:{result.get('module_base') and hex(result['module_base'])}  (x64dbg, in the process)",
        f"  Delta:      {result.get('delta') and hex(result['delta'])}",
        "",
        "A static address becomes a runtime one with:",
        "  runtime = static - image_base + module_base",
    ])


def format_x64dbg_breakpoint_at(response: dict, **kwargs) -> str:
    """Format the result of setting a breakpoint on a static address"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    return "\n".join([
        f"Breakpoint set at {result.get('runtime_address')} "
        f"(static {result.get('static_address')})",
        f"  Binary:     {result.get('binary')}",
        f"  Image base: {result.get('image_base')}",
        f"  Module base:{result.get('module_base')}",
        "",
        result.get("text", ""),
    ])


def format_x64dbg_go_to(response: dict, **kwargs) -> str:
    """Format the result of moving the instruction pointer to a static address"""
    if not response.get("success", False):
        return format_error(response)

    result = response.get("result", {})
    return "\n".join([
        f"Runtime address {result.get('runtime_address')} "
        f"(static {result.get('static_address')})",
        f"  Binary: {result.get('binary')}",
        "",
        result.get("text", ""),
    ])


def format_headless(response: dict, **kwargs) -> str:
    """A headless run: where it serves, and what it analyses."""
    result = response.get("result") if isinstance(response, dict) else None
    if not isinstance(result, dict):
        return format_error(response)
    lines = [f"The API is serving on port {result.get('port', '?')}"]
    if result.get("binary"):
        lines.append(f"  Binary: {result.get('binary')}")
    if result.get("project"):
        lines.append(f"  Project: {result.get('project')}")
    if result.get("pid"):
        lines.append(f"  Process: {result.get('pid')}")
    if result.get("log"):
        lines.append(f"  Log: {result.get('log')}")
    return "\n".join(lines)


def format_doctor(response: dict, **kwargs) -> str:
    """The checks of the doctor, one per line."""
    result = response.get("result") if isinstance(response, dict) else None
    if not isinstance(result, dict):
        return format_error(response)
    marks = {"ok": "ok", "warn": "warn", "fail": "FAIL"}
    lines = []
    for check in result.get("checks") or []:
        status = check.get("status", "")
        lines.append(f"[{marks.get(status, '?'):>4}] {check.get('name')}: {check.get('detail')}")
        if check.get("hint") and status != "ok":
            lines.append(f"         -> {check.get('hint')}")
    return "\n".join(lines)


def format_evidence(response: dict, **kwargs) -> str:
    """The findings of a ledger."""
    result = response.get("result") if isinstance(response, dict) else None
    if not isinstance(result, dict):
        return format_error(response)
    findings = result.get("findings") or []
    if not findings:
        return "No findings."
    lines = []
    for finding in findings:
        lines.append(f"{finding.get('id', '')}  {str(finding.get('kind', '')):<14} "
                     f"{str(finding.get('address', '')):<14} {finding.get('name', '')}")
        if finding.get("note"):
            lines.append(f"      {finding.get('note')}")
    return "\n".join(lines)


def format_sessions(response: dict, **kwargs) -> str:
    """The sessions, and what state they are in."""
    result = response.get("result") if isinstance(response, dict) else None
    if not isinstance(result, dict):
        return format_error(response)
    sessions = result.get("sessions") or []
    if not sessions:
        return "No sessions."
    lines = []
    for session in sessions:
        lines.append(f"{session.get('id', '')}  {str(session.get('state', '')):<8} "
                     f"port {session.get('port', '?')}  {session.get('name', '')}")
        if session.get("binary"):
            lines.append(f"      {session.get('binary')}")
    return "\n".join(lines)


def format_tool_groups(response: dict, **kwargs) -> str:
    """The tool groups: size, loaded state, namespaces."""
    if not response.get("success", False):
        return format_error(response)
    result = response.get("result", response)
    if not isinstance(result, dict):
        return str(result)
    if "groups" not in result:
        return str(result)
    groups = result["groups"]
    if groups and isinstance(groups[0], str):
        return "Groups loaded: " + ", ".join(groups)
    lines = [f"Tool groups ({result.get('visible_tools', '?')} of "
             f"{result.get('total_tools', '?')} tools visible)"]
    for group in groups:
        state = "loaded" if group.get("loaded") else "      "
        lines.append(f"  [{state}] {group.get('group', '?'):<10} "
                     f"{group.get('tools', 0):>3} tools  "
                     f"{', '.join(group.get('namespaces') or [])}")
    return "\n".join(lines)


def format_tool_matches(response: dict, **kwargs) -> str:
    """Search results: the tool, its group and whether it is loaded."""
    if not response.get("success", False):
        return format_error(response)
    result = response.get("result", response)
    if not isinstance(result, dict):
        return str(result)
    matches = result.get("matches") or []
    if not matches:
        return f"No tool matches '{result.get('query', '')}'."
    lines = [f"Tools matching '{result.get('query', '')}' "
             f"({len(matches)}):"]
    for match in matches:
        state = "loaded" if match.get("loaded") else "hidden"
        lines.append(f"  [{state}] {match.get('name')}  "
                     f"({match.get('group')})  {match.get('summary', '')}")
    return "\n".join(lines)


def format_task_view(response: dict, **kwargs) -> str:
    """One background task: its status, elapsed time and outcome."""
    if not response.get("success", False):
        return format_error(response)
    result = response.get("result", response)
    if not isinstance(result, dict):
        return str(result)
    lines = [
        f"Task {result.get('id', '?')}  [{result.get('status', '?')}]",
        f"  kind: {result.get('kind', '?')}  {result.get('label', '')}",
        f"  elapsed: {result.get('elapsed_seconds', '?')}s",
    ]
    if result.get("note"):
        lines.append(f"  note: {result['note']}")
    if result.get("error"):
        lines.append(f"  error: {result['error']}")
    outcome = result.get("result")
    if isinstance(outcome, dict):
        summary = outcome.get("result")
        if isinstance(summary, list):
            lines.append(f"  outcome: {len(summary)} item(s)")
        else:
            lines.append(f"  outcome: {str(summary)[:200]}")
    return "\n".join(lines)


def format_tasks_list(response: dict, **kwargs) -> str:
    """The background tasks, one line each."""
    result = response.get("result") if isinstance(response, dict) else None
    if not isinstance(result, dict):
        return format_error(response)
    tasks = result.get("tasks") or []
    if not tasks:
        return "No background tasks."
    lines = []
    for task in tasks:
        lines.append(f"{task.get('id', '?')}  [{task.get('status', '?'):<9}] "
                     f"{task.get('kind', '?'):<16} {task.get('elapsed_seconds', '?')}s  "
                     f"{task.get('label', '')}")
    return "\n".join(lines)


def format_triage(response: dict, **kwargs) -> str:
    """What a target is, and what it needs."""
    result = response.get("result") if isinstance(response, dict) else None
    if not isinstance(result, dict):
        return format_error(response)
    lines = [f"{result.get('path', '')}", f"  format: {result.get('format', 'unknown')}"]
    if result.get("size"):
        lines.append(f"  size: {result.get('size')} bytes")
    facts = result.get("facts") or {}
    for key, value in facts.items():
        if isinstance(value, (list, tuple)):
            value = ", ".join(str(item) for item in value[:8])
        lines.append(f"  {key}: {value}")
    recommendations = result.get("recommendations") or []
    if recommendations:
        lines.append("")
        for item in recommendations:
            lines.append(f"  - {item}")
    return "\n".join(lines)


def format_capabilities(response: dict, **kwargs) -> str:
    """Show what an instance can do: versions, flags and limits, not a bare dict."""
    if not response.get("success", False):
        return format_error(response)
    result = response.get("result", response)
    if not isinstance(result, dict):
        return str(result)

    lines = [
        f"GhydraMCP {result.get('plugin_version', '?')} "
        f"(API {result.get('api_version', '?')})",
        f"  Ghidra: {result.get('ghidra_version', 'unknown')}  "
        f"Java: {result.get('java_version', 'unknown')}",
        f"  port: {result.get('port', '?')}  "
        f"headless: {result.get('headless', False)}",
    ]
    features = result.get("features") or {}
    if features:
        on = sorted(name for name, enabled in features.items() if enabled)
        off = sorted(name for name, enabled in features.items() if not enabled)
        lines.append("  features on: " + (", ".join(on) or "none"))
        if off:
            lines.append("  features off: " + ", ".join(off))
    limits = result.get("limits") or {}
    if limits:
        lines.append("  limits: " + ", ".join(
            f"{name}={value}" for name, value in sorted(limits.items())))
    compatibility = result.get("compatibility") or {}
    if compatibility:
        state = "ok" if compatibility.get("compatible") else "MISMATCH"
        lines.append(
            f"  compatibility: {state} (compiled against "
            f"{compatibility.get('compiled_against', '?')}, "
            f"setFieldName returns {compatibility.get('set_field_name_return', '?')})")
        if not compatibility.get("compatible"):
            lines.append("  remedy: " + str(compatibility.get("remedy", "")))
    return "\n".join(lines)


def format_context_pack(response: dict, **kwargs) -> str:
    """The budgeted dossier: sections, citations, omissions."""
    if not response.get("success", False):
        return format_error(response)
    result = response.get("result", response)
    if not isinstance(result, dict):
        return str(result)
    lines = [
        f"Context pack [{result.get('template', '?')}] — "
        f"{result.get('question', '')}",
        f"  program: {result.get('program') or '?'}  "
        f"budget: {result.get('budget_tokens', '?')} tokens, "
        f"used {result.get('used_tokens', '?')}",
    ]
    for section in result.get("sections") or []:
        lines.append("")
        lines.append(f"## {section.get('title')}")
        lines.append(str(section.get("body", "")))
        if section.get("citations"):
            lines.append("  (addresses: " + ", ".join(section["citations"]) + ")")
    citations = result.get("citations") or []
    if citations:
        lines.append("")
        lines.append("Citations: " + ", ".join(citations))
    omitted = result.get("omitted") or []
    if omitted:
        lines.append("Omitted:")
        for item in omitted:
            lines.append(f"  - {item.get('section')}: {item.get('reason')}")
    return "\n".join(lines)


def format_capabilities_summary(response: dict, **kwargs) -> str:
    """Show a ranked capability triage, with the evidence behind each lead."""
    if not response.get("success", False):
        return format_error(response)
    result = response.get("result", response)
    if not isinstance(result, dict):
        return str(result)
    summary = result.get("summary") or {}
    findings = result.get("findings") or []
    lines = [
        f"Capability triage for {result.get('program') or 'the program'}: "
        f"{len(findings)} technique(s) matched",
        f"  scanned {summary.get('imports_scanned', 0)} imports, "
        f"{summary.get('strings_scanned', 0)} strings against "
        f"{summary.get('rules', 0)} rules",
        "  " + str(result.get("method", "")),
    ]
    if result.get("failures"):
        lines.append("  unavailable: " + ", ".join(result["failures"]))
    for finding in findings:
        lines.append(
            f"  [{finding.get('confidence', '?'):>6}] {finding.get('id')} "
            f"{finding.get('name')}  score={finding.get('score')}")
        lines.append(f"           {finding.get('tactic', '')}")
        for evidence in (finding.get("evidence") or [])[:3]:
            lines.append(
                f"           - {evidence.get('kind')} {evidence.get('name')} "
                f"@ {evidence.get('address') or '?'}")
    if not findings:
        lines.append("  No known technique patterns matched.")
    return "\n".join(lines)


def format_telemetry_summary(response: dict, **kwargs) -> str:
    """The local usage summary: totals, the busiest tools, the advice."""
    if not response.get("success", False):
        return format_error(response)
    result = response.get("result", response)
    if not isinstance(result, dict):
        return str(result)
    if not result.get("calls"):
        return f"No telemetry in the last {result.get('days', '?')} day(s)."
    lines = [
        f"Local telemetry — {result.get('calls')} calls in the last "
        f"{result.get('days')} day(s)  ({result.get('path', '')})",
        f"  {'tool':<32} {'calls':>5} {'fail':>4} {'avg ms':>7} {'tokens':>8}",
    ]
    for row in result.get("tools") or []:
        lines.append(f"  {row['tool']:<32} {row['calls']:>5} "
                     f"{row['failed']:>4} {row.get('ms_avg', 0):>7} "
                     f"{row['tokens']:>8}")
    codes = result.get("error_codes") or {}
    if codes:
        lines.append("Error codes: " + ", ".join(
            f"{code}={count}" for code, count in sorted(codes.items())))
    recommendations = result.get("recommendations") or []
    if recommendations:
        lines.append("Recommendations:")
        for item in recommendations:
            lines.append(f"  - {item}")
    return "\n".join(lines)


def format_runbook_record(response: dict, **kwargs) -> str:
    """A recorded runbook: where it went and which steps failed."""
    if not response.get("success", False):
        return format_error(response)
    result = response.get("result", response)
    if not isinstance(result, dict):
        return str(result)
    lines = [f"Runbook recorded: {result.get('path', '?')} "
             f"({result.get('steps', 0)} step(s))"]
    for entry in result.get("failed") or []:
        lines.append(f"  failed step {entry.get('step')}: "
                     f"{entry.get('endpoint')} ({entry.get('code') or 'failed'})")
    return "\n".join(lines)


def format_runbook_replay(response: dict, **kwargs) -> str:
    """A replayed runbook: what is identical, what moved, what failed."""
    if not response.get("success", False):
        return format_error(response)
    result = response.get("result", response)
    if not isinstance(result, dict):
        return str(result)
    lines = [f"Replay: {result.get('total', 0)} step(s) - "
             f"{result.get('identical', 0)} identical, "
             f"{result.get('changed', 0)} changed, "
             f"{result.get('failed', 0)} failed"]
    if result.get("program_changed"):
        lines.append("  note: the program fingerprint changed since the recording")
    for item in result.get("steps") or []:
        marker = {"identical": "SAME", "changed": "DIFF", "failed": "FAIL"}.get(
            item.get("status"), "????")
        line = f"  [{marker}] step {item.get('step')} {item.get('endpoint')}"
        if item.get("code"):
            line += f" ({item['code']})"
        if item.get("reason"):
            line += f" - {item['reason']}"
        lines.append(line)
    return "\n".join(lines)


def format_analysis_diff(response: dict, **kwargs) -> str:
    """Two snapshots compared: functions, imports and strings."""
    if not response.get("success", False):
        return format_error(response)
    result = response.get("result", response)
    if not isinstance(result, dict):
        return str(result)
    summary = result.get("summary") or {}
    functions = result.get("functions") or {}
    lines = ["Diff" + (" - the program fingerprint changed"
                       if result.get("program_changed")
                       else " - same program fingerprint")]
    if not functions.get("complete", True):
        lines.append("  note: a function listing was truncated; the counts are a floor")
    # A section that was not read to its end supports no removal claim, and the
    # reader has to know which ones those were.
    for section_name in ("imports", "strings"):
        if not (result.get(section_name) or {}).get("complete", True):
            lines.append(f"  note: the {section_name} listing was truncated; no "
                         f"removal is claimed from it")
    lines.append(f"  functions: +{summary.get('functions_added', 0)} "
                 f"-{summary.get('functions_removed', 0)} "
                 f"~{summary.get('functions_renamed', 0)} renamed "
                 f"({functions.get('count_a', 0)} -> {functions.get('count_b', 0)})")
    lines.append(f"  imports:   +{summary.get('imports_added', 0)} "
                 f"-{summary.get('imports_removed', 0)}")
    lines.append(f"  strings:   +{summary.get('strings_added', 0)} "
                 f"-{summary.get('strings_removed', 0)}")

    def section(title, rows, render):
        if not rows:
            return
        lines.append("")
        lines.append(f"{title}:")
        for row in rows[:40]:
            lines.append("  " + render(row))
        if len(rows) > 40:
            lines.append(f"  ... {len(rows) - 40} more")

    section("functions added", functions.get("added") or [],
            lambda row: f"+ {row.get('address')} {row.get('name') or '?'}")
    section("functions removed", functions.get("removed") or [],
            lambda row: f"- {row.get('address')} {row.get('name') or '?'}")
    section("functions renamed", functions.get("renamed") or [],
            lambda row: f"~ {row.get('address')} {row.get('from')} -> {row.get('to')}")
    section("imports added", (result.get("imports") or {}).get("added") or [],
            lambda row: f"+ {row}")
    section("imports removed", (result.get("imports") or {}).get("removed") or [],
            lambda row: f"- {row}")
    section("strings added", (result.get("strings") or {}).get("added") or [],
            lambda row: f"+ {str(row)[:100]}")
    section("strings removed", (result.get("strings") or {}).get("removed") or [],
            lambda row: f"- {str(row)[:100]}")
    # What was not seen, kept apart from what is known to be gone.
    for section_name in ("imports", "strings"):
        rows = (result.get(section_name) or {}).get("removed_not_seen") or []
        if rows:
            lines.append("")
            lines.append(f"{section_name} not seen in the second listing "
                         "(the listing was not read to its end):")
            for row in rows[:40]:
                lines.append(f"  ? {str(row)[:100]}")
    return "\n".join(lines)


def format_analysis_taint(response: dict, **kwargs) -> str:
    """Source-to-sink hypotheses: confidence, evidence and the disclaimer."""
    if not response.get("success", False):
        return format_error(response)
    result = response.get("result", response)
    if not isinstance(result, dict):
        return str(result)
    source = result.get("source") or {}
    sink = result.get("sink") or {}
    counts = _taint_summarize(result)
    lines = [f"Taint hypotheses: {source.get('name', '?')} -> {sink.get('name', '?')}",
             f"  source sites: {source.get('sites', 0)}  "
             f"sink sites: {sink.get('sites', 0)}  "
             f"functions examined: {result.get('functions_examined', 0)}"]
    if not counts["found"]:
        lines.append("  no source-to-sink path was found - this is not proof of "
                     "safety (the search is linear and bounded)")
    for item in (result.get("hypotheses") or [])[:20]:
        lines.append(f"  [{item.get('confidence')}] {item.get('reason')}")
        if item.get("source_call"):
            lines.append(f"      source call at {item['source_call']}")
        if item.get("sink_call"):
            lines.append(f"      sink call at {item['sink_call']}")
        hops = item.get("hops") or []
        if hops:
            lines.append("      hops: " + " -> ".join(str(hop) for hop in hops))
    if result.get("disclaimer"):
        lines.append("")
        lines.append(result["disclaimer"])
    return "\n".join(lines)


def format_mission_start(response: dict, **kwargs) -> str:
    """A mission dossier: findings, verification and what was not determined."""
    if not response.get("success", False):
        return format_error(response)
    result = response.get("result", response)
    if not isinstance(result, dict):
        return str(result)
    return str(result.get("dossier") or "")


def format_cache_stats(response: dict, **kwargs) -> str:
    """The cache: entries, bytes, programs, age."""
    if not response.get("success", False):
        return format_error(response)
    result = response.get("result", response)
    if not isinstance(result, dict):
        return str(result)

    def when(value):
        if not isinstance(value, (int, float)):
            return "?"
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(value))

    return "\n".join([
        f"Decompile cache: {result.get('path', '?')}",
        f"  entries: {result.get('entries', 0)}  "
        f"bytes: {result.get('bytes', 0)} of {result.get('max_bytes', 0)}",
        f"  programs: {result.get('programs', 0)}  "
        f"kinds: {', '.join(result.get('kinds') or []) or '-'}",
        f"  oldest: {when(result.get('oldest'))}  "
        f"newest: {when(result.get('newest'))}",
    ])


def format_fleet_query(response: dict, **kwargs) -> str:
    """The fleet answer: one row per binary, and what could not be asked."""
    if not response.get("success", False):
        return format_error(response)
    result = response.get("result", response)
    if not isinstance(result, dict):
        return str(result)
    kind = result.get("kind")
    target = result.get("target")
    lines = ["Fleet: " + str(kind) + (f" {target}" if target else ""),
             f"  binaries: {result.get('count', 0)}  "
             f"with it: {result.get('with_it', 0)}  "
             f"without it: {result.get('without_it', 0)}"]
    for row in result.get("binaries") or []:
        marker = "YES" if row.get("present") else ("no " if row.get("ok") else "???")
        line = (f"  [{marker}] {row.get('name') or row.get('identity')}"
                f"  ports {','.join(str(port) for port in row.get('ports') or [])}")
        detail = row.get("detail") or {}
        if detail.get("address"):
            line += f"  at {detail['address']}"
        if detail.get("count") is not None:
            line += f"  refs {detail['count']}"
        if detail.get("matched"):
            line += f"  matched {', '.join(str(m) for m in detail['matched'][:2])}"
        if row.get("complete") is False:
            line += "  (listing truncated)"
        lines.append(line)
        if row.get("disagreements"):
            lines.append(f"       the ports disagree: {row['disagreements']}")
    for item in result.get("unreachable") or []:
        lines.append(f"  [---] port {item.get('port')} did not answer "
                     f"({item.get('reason')})")
    if result.get("partial"):
        lines.append(f"  note: the question could not be answered for "
                     f"{len(result['partial'])} member(s)")
    return "\n".join(lines)


def format_bsim_status(response: dict, **kwargs) -> str:
    """Whether a signature query is possible, and what is missing if not."""
    if not response.get("success", False):
        return format_error(response)
    result = response.get("result", response)
    if not isinstance(result, dict):
        return str(result)
    state = "ready" if result.get("ready") else "not ready"
    lines = [f"BSim: {state}",
             f"  engine: {'present' if result.get('available') else 'absent'}",
             f"  database: {result.get('database') or '(none configured)'}"]
    if result.get("database"):
        lines.append(f"  database exists: "
                     f"{'yes' if result.get('database_exists') else 'no'}")
    if result.get("reason"):
        lines.append(f"  {result['reason']}")
    return "\n".join(lines)


def format_bsim_ingest(response: dict, **kwargs) -> str:
    """What the ingest did: how much was scanned, how much BSim inserted."""
    if not response.get("success", False):
        return format_error(response)
    result = response.get("result", response)
    if not isinstance(result, dict):
        return str(result)
    if result.get("already_present"):
        lines = [f"BSim ingest: {result.get('program')} is already in the database",
                 f"  database: {result.get('database')}",
                 f"  inserted: 0 functions (nothing to do)"]
        if result.get("reason"):
            lines.append(f"  {result['reason']}")
        return "\n".join(lines)
    lines = [f"BSim ingest: {result.get('program')}",
             f"  database: {result.get('database')}"
             + (" (created)" if result.get("created") else ""),
             f"  discovered: {result.get('discovered_functions', 0)} functions",
             f"  scanned: {result.get('scanned_functions', 0)}"
             f" ({result.get('skipped_functions', 0)} skipped)",
             f"  described: {result.get('described_functions', 0)}",
             f"  inserted: {result.get('inserted_functions', 0)} functions"
             f" into {result.get('inserted_executables', 0)} executable(s)",
             f"  took: {result.get('seconds', 0)}s"]
    if result.get("track_call_graph") is False:
        lines.append("  call graph: not recorded (track_call_graph=false)")
    if result.get("reason"):
        lines.append(f"  note: {result['reason']}")
    return "\n".join(lines)


def format_bsim_query(response: dict, **kwargs) -> str:
    """Which stored functions look like this one, with BSim's numbers."""
    if not response.get("success", False):
        return format_error(response)
    result = response.get("result", response)
    if not isinstance(result, dict):
        return str(result)
    lines = [f"BSim query: {result.get('function')} at {result.get('address')}",
             f"  database: {result.get('database')}",
             f"  threshold: similarity >= {result.get('min_similarity')}",
             f"  matches: {result.get('returned', 0)}"
             f" (of {result.get('total_considered', 0)} considered)"]
    for match in result.get("matches") or []:
        where = match.get("executable") or "?"
        path = match.get("path")
        lines.append(f"  {match.get('similarity')} similarity,"
                     f" significance {match.get('significance')}:"
                     f" {match.get('function')} @ {match.get('address')}"
                     f" in {where}" + (f" ({path})" if path else ""))
    if result.get("reason"):
        lines.append(f"  {result['reason']}")
    return "\n".join(lines)


def format_bsim_apply_names(response: dict, **kwargs) -> str:
    """What apply-names did, or would do, with the match that justified it."""
    if not response.get("success", False):
        return format_error(response)
    result = response.get("result", response)
    if not isinstance(result, dict):
        return str(result)
    if result.get("already_named"):
        return "\n".join([
            f"BSim apply: {result.get('from')} already carries the matched name",
            f"  database: {result.get('database')}"])
    match = result.get("match") or {}
    lines = [f"BSim apply: {result.get('from')} -> {result.get('to')}",
             f"  database: {result.get('database')}",
             f"  from: {match.get('executable') or '?'}"
             f" {match.get('function')} @ {match.get('address')}",
             f"  similarity: {match.get('similarity')}"
             f" (significance {match.get('significance')})",
             f"  floor: {result.get('min_similarity')}"]
    if result.get("applied"):
        lines.append("  applied: yes (undo in Ghidra if the match is wrong)")
    elif result.get("would_rename"):
        lines.append("  applied: no (dry run) — pass dry_run=False to rename")
    if result.get("reason") and not result.get("applied"):
        lines.append(f"  {result['reason']}")
    return "\n".join(lines)


def format_bsim_diff(response: dict, **kwargs) -> str:
    """What changed between two versions, paired by signature."""
    if not response.get("success", False):
        return format_error(response)
    result = response.get("result", response)
    if not isinstance(result, dict):
        return str(result)
    lines = [f"BSim diff: {result.get('program')} against"
             f" {result.get('other_executable')}",
             f"  database has {result.get('discovered_functions', 0)} functions"
             f" in this program; compared {result.get('compared_functions', 0)}"
             f" ({result.get('not_compared', 0)} not compared)",
             f"  same: {result.get('same', 0)}, moved: {result.get('moved', 0)},"
             f" not found: {result.get('not_found', 0)},"
             f" no signature: {result.get('no_signature', 0)}",
             f"  threshold: similarity >= {result.get('min_similarity')}"]
    for pair in result.get("pairs") or []:
        kind = pair.get("class")
        if kind in ("same", "moved"):
            other = pair.get("other") or {}
            lines.append(f"  [{kind}] {pair.get('function')} @"
                         f" {pair.get('address')} ->"
                         f" {other.get('function')} @ {other.get('address')}"
                         f" ({other.get('similarity')} similar)")
        else:
            lines.append(f"  [{kind}] {pair.get('function')} @"
                         f" {pair.get('address')}")
    for gap in result.get("query_failures") or []:
        lines.append(f"  [query failed] {gap.get('function')}:"
                     f" {gap.get('code')} — {gap.get('reason')}")
    if not result.get("pairs"):
        lines.append("  no function was compared")
    return "\n".join(lines)


FORMATTERS = {
    "functions_list": format_functions_list,
    "functions_get": format_function_info,
    "functions_get_containing": format_functions_list,
    "functions_get_next": format_functions_list,
    "functions_get_prev": format_functions_list,
    "functions_decompile": format_decompile,
    "functions_batch_decompile": format_batch_decompile,
    "functions_analyze": format_function_analysis,
    "functions_disassemble": format_disassembly,
    "functions_get_variables": format_variables,
    "xrefs_list": format_xrefs,
    "xrefs_find_by_name": format_xrefs_by_name,
    "scalars_search": format_scalars,
    "data_list": format_data_list,
    "data_list_strings": format_strings,
    "memory_read": format_memory,
    "memory_disassemble": format_disassembly,
    "instances_list": format_instances,
    "instances_discover": format_instances,
    "instances_current": format_instance_info,
    "instances_capabilities": format_capabilities,
    "analysis_capabilities_summary": format_capabilities_summary,
    "analysis_context_pack": format_context_pack,
    "tasks_list": format_tasks_list,
    "tasks_get": format_task_view,
    "tasks_cancel": format_task_view,
    "tools_groups": format_tool_groups,
    "tools_search": format_tool_matches,
    "tools_load_group": format_tool_groups,
    "tools_unload_group": format_tool_groups,
    "telemetry_summary": format_telemetry_summary,
    "structs_list": format_structs_list,
    "structs_get": format_struct_info,
    "analysis_get_callgraph": format_callgraph,
    "analysis_get_dataflow": format_dataflow,
    "analysis_trace_call_path": format_call_path,
    "analysis_callers": format_callers,
    "analysis_callees": format_callees,
    "analysis_status": format_generic_dict,
    "ui_get_current_address": format_generic_dict,
    "ui_get_current_function": format_function_info,
    "comments_get": format_generic_dict,
    "projects_list": format_generic_list,
    "projects_get": format_generic_dict,
    "programs_list": format_generic_list,
    "programs_get": format_generic_dict,
    "programs_overview": format_overview,
    "project_info": format_project_info,
    "project_list_files": format_project_files,
    "classes_list": format_classes_list,
    "symbols_list": format_symbols_list,
    "symbols_imports": format_imports_exports,
    "symbols_exports": format_imports_exports,
    "segments_list": format_segments_list,
    "namespaces_list": format_namespaces_list,
    "variables_list": format_variables_list,
    "datatypes_list": format_datatypes_list,
    "datatypes_search": format_datatypes_list,
    "functions_get_cfg": format_cfg,
    "functions_get_pcode": format_pcode,
    "raw_image_define": format_generic_dict,
    "raw_image_cleanup": format_generic_dict,
    "kuna_status": format_kuna_status,
    "kuna_summary": format_kuna_summary,
    "kuna_functions": format_kuna_functions,
    "kuna_decompile": format_kuna_decompile,
    "kuna_disassemble": format_kuna_disassemble,
    "kuna_read": format_kuna_read,
    "kuna_strings": format_kuna_strings,
    "kuna_crypto": format_kuna_crypto,
    "kuna_xrefs": format_kuna_xrefs,
    "kuna_unpack": format_kuna_unpack,
    "kuna_export_start": format_kuna_export_start,
    "kuna_export_status": format_kuna_export_status,
    "kuna_export_read": format_kuna_export_read,
    "x64dbg_status": format_x64dbg_status,
    "x64dbg_tools": format_x64dbg_tools,
    "x64dbg_call": format_x64dbg_call,
    "x64dbg_target": format_x64dbg_target,
    "x64dbg_breakpoint_at": format_x64dbg_breakpoint_at,
    "x64dbg_go_to": format_x64dbg_go_to,
    "inspect_address": format_address_context,
    "inspect_target": format_triage,
    "headless_start": format_headless,
    "headless_stop": format_generic_dict,
    "headless_status": format_generic_dict,
    "doctor_check": format_doctor,
    "evidence_add": format_generic_dict,
    "evidence_list": format_evidence,
    "evidence_export": format_generic_dict,
    "session_open": format_generic_dict,
    "session_list": format_sessions,
    "session_close": format_generic_dict,
    # These 28 used to have no FORMATTERS entry and silently degraded to
    # format_simple_result(response, "Done"), which threw away the result the
    # server returned (notably the script catalogue and the captured output of
    # scripts_run). Every tool now has a formatter; test_surface_parity.py
    # asserts the invariant over the whole registered catalogue.
    "analysis_run": format_generic_dict,
    "comments_set": format_generic_dict,
    "data_create": format_generic_dict,
    "data_delete": format_generic_dict,
    "data_rename": format_generic_dict,
    "data_set_type": format_generic_dict,
    "datatypes_create_enum": format_generic_dict,
    "datatypes_create_struct": format_generic_dict,
    "datatypes_create_union": format_generic_dict,
    "functions_create": format_generic_dict,
    "functions_delete": format_generic_dict,
    "functions_rename": format_generic_dict,
    "functions_set_comment": format_generic_dict,
    "functions_set_signature": format_generic_dict,
    "functions_update_variable": format_generic_dict,
    "instances_register": format_generic_dict,
    "instances_unregister": format_generic_dict,
    "instances_use": format_generic_dict,
    "memory_write": format_generic_dict,
    "programs_delete": format_generic_dict,
    "programs_save": format_generic_dict,
    "project_open_file": format_generic_dict,
    "scripts_list": format_generic_list,
    "scripts_run": format_generic_dict,
    "structs_add_field": format_generic_dict,
    "structs_create": format_generic_dict,
    "structs_delete": format_generic_dict,
    "structs_update_field": format_generic_dict,
    "runbook_record": format_runbook_record,
    "runbook_replay": format_runbook_replay,
    "analysis_diff": format_analysis_diff,
    "analysis_taint": format_analysis_taint,
    "mission_start": format_mission_start,
    "cache_stats": format_cache_stats,
    "cache_clear": format_cache_stats,
    "fleet_query": format_fleet_query,
    "bsim_status": format_bsim_status,
    "bsim_ingest": format_bsim_ingest,
    "bsim_query": format_bsim_query,
    "bsim_apply_names": format_bsim_apply_names,
    "bsim_diff_versions": format_bsim_diff,
}


def text_output(func):
    """Decorator that converts dict responses to plain text using registered formatters"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        started = time.perf_counter()
        response = func(*args, **kwargs)
        text = _render_tool_output(response, func.__name__, kwargs)
        _telemetry_safely(func.__name__, started, response, text)
        return text

    wrapper.__annotations__['return'] = str
    return wrapper


def _render_tool_output(response, name: str, kwargs: dict):
    """The body text_output used to have, with the Next: line (I8)."""
    # If already a string, pass through
    if isinstance(response, str):
        return response

    # GHYDRA_MCP_OUTPUT=json: the raw envelope, for a machine that
    # parses it. The error envelope goes out the same way.
    if RAW_OUTPUT:
        try:
            return json.dumps(response, default=str)
        except (TypeError, ValueError):
            return str(response)

    # Check for error first
    if isinstance(response, dict) and not response.get("success", True):
        return format_error(response)

    # Look up formatter by function name
    formatter = FORMATTERS.get(name)
    if formatter:
        text = formatter(response, **kwargs)
    else:
        # Fallback: format_simple_result for mutation operations
        text = format_simple_result(response, "Done")

    # Actionable HATEOAS (I8): the envelope's links, translated into the
    # bridge calls that follow them. The hrefs carry real values, so the
    # suggestion is a call the agent can make as it reads. A link that
    # does not map to a registered tool is left out — a wrong suggestion
    # is worse than none.
    suggestions = _suggested_calls(response)
    if suggestions:
        text += "\nNext: " + " | ".join(suggestions)
    return text


_ADDRESSISH = re.compile(r"^(0x[0-9a-fA-F]+|[0-9a-fA-F]{4,})$")


def _suggested_calls(response: dict, limit: int = 4) -> list[str]:
    """Translate the envelope's _links into registered bridge calls.

    Two shapes reach here: the raw envelope (``_links`` = rel -> {href,
    method}) and the one ``simplify_response`` returns for the ordinary HTTP
    tools (``_links`` is dropped and the hrefs are kept flat under
    ``api_links``). Both are read, so the suggestion is emitted either way.
    """
    if not isinstance(response, dict):
        return []
    links = response.get("_links")
    if not isinstance(links, dict):
        flat = response.get("api_links")
        if isinstance(flat, dict):
            links = {rel: {"href": href} for rel, href in flat.items()}
    if not isinstance(links, dict):
        return []
    registered = set(getattr(mcp._tool_manager, "_tools", {}))
    suggestions = []
    for rel, link in links.items():
        if rel == "self" or not isinstance(link, dict):
            continue  # self is the call that just happened
        href = link.get("href")
        if not isinstance(href, str) or not href.startswith("/"):
            continue
        path, _, query = href.partition("?")
        segments = [seg for seg in path.strip("/").split("/") if seg]
        if len(segments) >= 2:
            candidates = (f"{segments[0]}_{segments[-1]}",
                          f"{segments[0]}_get_{segments[-1]}")
            tool = next((name for name in candidates if name in registered), None)
            values = segments[1:-1]
        elif len(segments) == 1:
            tool = f"{segments[0]}_list" if f"{segments[0]}_list" in registered else None
            values = []
        else:
            continue
        if tool is None:
            continue
        args = []
        if values:
            arg_name = "address" if _ADDRESSISH.match(values[-1]) else "name"
            args.append(f'{arg_name}="{values[-1]}"')
        for pair in query.split("&"):
            key, sep, value = pair.partition("=")
            if sep and key in ("offset", "limit"):
                args.append(f"{key}={value}")
        suggestions.append(f"{tool}({', '.join(args)})" if args else f"{tool}()")
        if len(suggestions) >= limit:
            break
    return suggestions


def simplify_response(response: dict) -> dict:
    """
    Simplify HATEOAS response data for easier AI agent consumption
    - Removes _links from result entries
    - Flattens nested structures when appropriate
    - Preserves important metadata
    - Converts structured data like disassembly to text for easier consumption
    """
    if not isinstance(response, dict):
        return response

    # Make a copy to avoid modifying the original
    result = response.copy()
    
    # Store API response metadata
    api_metadata = {}
    for key in ["id", "instance", "timestamp", "size", "offset", "limit"]:
        if key in result:
            api_metadata[key] = result.get(key)
    
    # Simplify the main result data if present
    if "result" in result:
        # Handle array results
        if isinstance(result["result"], list):
            simplified_items = []
            for item in result["result"]:
                if isinstance(item, dict):
                    # Store but remove HATEOAS links from individual items
                    item_copy = item.copy()
                    links = item_copy.pop("_links", None)
                    
                    # Optionally store direct href links as more accessible properties
                    # This helps AI agents navigate the API without understanding HATEOAS
                    if isinstance(links, dict):
                        for link_name, link_data in links.items():
                            if isinstance(link_data, dict) and "href" in link_data:
                                item_copy[f"{link_name}_url"] = link_data["href"]
                    
                    simplified_items.append(item_copy)
                else:
                    simplified_items.append(item)
            result["result"] = simplified_items
        
        # Handle object results
        elif isinstance(result["result"], dict):
            result_copy = result["result"].copy()
            
            # Store but remove links from result object
            links = result_copy.pop("_links", None)
            
            # Add direct href links for easier navigation
            if isinstance(links, dict):
                for link_name, link_data in links.items():
                    if isinstance(link_data, dict) and "href" in link_data:
                        result_copy[f"{link_name}_url"] = link_data["href"]
            
            # Special case for disassembly - convert to text for easier consumption
            if "instructions" in result_copy and isinstance(result_copy["instructions"], list):
                disasm_text = ""
                for instr in result_copy["instructions"]:
                    if isinstance(instr, dict):
                        addr = instr.get("address", "")
                        mnemonic = instr.get("mnemonic", "")
                        operands = instr.get("operands", "")
                        bytes_str = instr.get("bytes", "")
                        
                        # Format: address: bytes  mnemonic operands
                        disasm_text += f"{addr}: {bytes_str.ljust(10)}  {mnemonic} {operands}\n"
                
                # Add the text representation
                result_copy["disassembly_text"] = disasm_text
                # Remove the original structured instructions to simplify the response
                result_copy.pop("instructions", None)
            
            # Special case for decompiled code - make sure it's directly accessible
            if "decompilation" in result_copy:
                result_copy["decompiled_text"] = result_copy["decompilation"]
            elif "ccode" in result_copy:
                result_copy["decompiled_text"] = result_copy["ccode"]
            elif "decompiled" in result_copy:
                result_copy["decompiled_text"] = result_copy["decompiled"]
            
            result["result"] = result_copy
    
    # Store but remove HATEOAS links from the top level
    links = result.pop("_links", None)
    
    # Add direct href links in a more accessible format
    if isinstance(links, dict):
        api_links = {}
        for link_name, link_data in links.items():
            if isinstance(link_data, dict) and "href" in link_data:
                api_links[link_name] = link_data["href"]
        
        # Add simplified links
        if api_links:
            result["api_links"] = api_links
    
    # Restore API metadata
    for key, value in api_metadata.items():
        if key not in result:
            result[key] = value
    
    return result

def negotiate_capabilities(result: dict, url: str = "") -> tuple[dict | None, str | None]:
    """Normalise a /capabilities (or /plugin-version) result and check compatibility.

    The old check compared API_VERSION by exact equality and let a mismatch
    surface much later as "No active Ghidra instance". This returns the
    normalised capability info plus an error that names both versions, the
    runtime and what to do about it. A plugin that only has /plugin-version
    still works: the missing keys get honest defaults.

    Args:
        result: The ``result`` object of the plugin's HATEOAS envelope.
        url: Instance URL, used in the mismatch message.

    Returns:
        tuple: ``(info, None)`` when compatible, ``(None, error_message)`` when not.
    """
    info = {
        "plugin_version": result.get("plugin_version", ""),
        "api_version": result.get("api_version", 0),
        "ghidra_version": result.get("ghidra_version", "unknown"),
        "java_version": result.get("java_version", "unknown"),
        "headless": bool(result.get("headless", False)),
        "features": result.get("features") or {},
        "limits": result.get("limits") or {},
        "compatibility": result.get("compatibility") or {},
    }
    if info["api_version"] != REQUIRED_API_VERSION:
        return None, (
            f"API version mismatch at {url or 'the instance'}: plugin reports API "
            f"{info['api_version']}, but bridge {BRIDGE_VERSION} requires "
            f"{REQUIRED_API_VERSION} (plugin {info['plugin_version'] or 'unknown'}, "
            f"Ghidra {info['ghidra_version']}, Java {info['java_version']}). "
            "Install a GhydraMCP extension built for this bridge, or rebuild the "
            "bridge against this API version. Optional features are discovered "
            "through GET /capabilities; an older plugin simply lacks them."
        )
    return info, None


def register_instance(port: int, url: str | None = None) -> str:
    """Register a new Ghidra instance
    
    Args:
        port: Port number of the Ghidra instance
        url: Optional URL if different from default http://host:port
    
    Returns:
        str: Confirmation message or error
    """
    if url is None:
        url = f"http://{ghidra_host}:{port}"

    try:
        # Prefer /capabilities for negotiation. An older plugin answers 404
        # there, so fall back to /plugin-version: the endpoint is additive and
        # API_VERSION does not move.
        response = _http_session().get(f"{url}/capabilities", timeout=2)
        if response.status_code == 404:
            response = _http_session().get(f"{url}/plugin-version", timeout=2)
        
        if not response.ok:
            return f"Error: Instance at {url} is not responding properly to HATEOAS API"

        project_info = {"url": url}

        try:
            # Check plugin version to ensure compatibility
            try:
                version_data = response.json()
                if "result" in version_data:
                    result = version_data["result"]
                    if isinstance(result, dict):
                        plugin_version = result.get("plugin_version", "")
                        api_version = result.get("api_version", 0)
                        
                        project_info["plugin_version"] = plugin_version
                        project_info["api_version"] = api_version
                        
                        # Verify API version compatibility, with the versions and
                        # runtime in the message instead of a generic failure later.
                        negotiated, error_msg = negotiate_capabilities(result, url)
                        if error_msg:
                            print(error_msg, file=sys.stderr)
                            return error_msg
                        project_info["capabilities"] = negotiated
                        compat = negotiated.get("compatibility") or {}
                        if compat and not compat.get("compatible", True):
                            print("WARNING: incompatible Ghidra build: "
                                  + str(compat.get("remedy", "")), file=sys.stderr)

                        print(f"Connected to Ghidra plugin version {plugin_version} with API version {api_version}")
            except Exception as e:
                print(f"Error parsing plugin version: {e}", file=sys.stderr)
            
            # Get program info from HATEOAS API
            info_url = f"{url}/program"
            
            try:
                info_response = _http_session().get(info_url, timeout=2)
                if info_response.ok:
                    try:
                        info_data = info_response.json()
                        if "result" in info_data:
                            result = info_data["result"]
                            if isinstance(result, dict):
                                # Extract project and file from programId (format: "project:/file")
                                program_id = result.get("programId", "")
                                if ":" in program_id:
                                    project_name, file_path = program_id.split(":", 1)
                                    project_info["project"] = project_name
                                    # Remove leading slash from file path if present
                                    if file_path.startswith("/"):
                                        file_path = file_path[1:]
                                    project_info["path"] = file_path
                                
                                # Get file name directly from the result
                                project_info["file"] = result.get("name", "")
                                
                                # Get other metadata
                                project_info["language_id"] = result.get("languageId", "")
                                project_info["compiler_spec_id"] = result.get("compilerSpecId", "")
                                project_info["image_base"] = result.get("imageBase", result.get("image_base", ""))
                                project_info["headless"] = bool(result.get("headless", False))
                                
                                # Store _links from result for HATEOAS navigation
                                if "_links" in result:
                                    project_info["_links"] = result.get("_links", {})
                    except Exception as e:
                        print(f"Error parsing info endpoint: {e}", file=sys.stderr)
            except Exception as e:
                print(f"Error connecting to info endpoint: {e}", file=sys.stderr)
        except Exception:
            # Non-critical, continue with registration even if project info fails
            pass

        with instances_lock:
            active_instances[port] = project_info

        return f"Registered instance on port {port} at {url}"
    except Exception as e:
        return f"Error: Could not connect to instance at {url}: {str(e)}"

def _probe_instance(port, scan_host, timeout):
    """Probe one port for a GhidraMCP instance.

    Returns the plugin-version payload when the port answers with the HATEOAS
    envelope, or None when nothing is there.
    """
    url = f"http://{scan_host}:{port}"
    try:
        response = _http_session().get(f"{url}/plugin-version",
                                       headers={'Accept': 'application/json',
                                                'X-Request-ID': f"discovery-{int(time.time() * 1000)}"},
                                       timeout=timeout)
        if not response.ok:
            return None
        try:
            json_data = response.json()
        except ValueError:
            print(f"Port {port} returned non-HATEOAS response", file=sys.stderr)
            return None
        if not ("success" in json_data and json_data["success"] and "result" in json_data):
            return None
        return json_data
    except requests.exceptions.RequestException:
        return None


def _quick_scan(force: bool = False) -> None:
    """Scan the quick range, at most once per QUICK_SCAN_TTL.

    The scan is the only slow part of listing the instances, and a run of
    calls does not need a fresh scan each time: the background daemon keeps
    the registry up to date.
    """
    global _last_quick_scan
    with _scan_lock:
        now = time.monotonic()
        if not force and (now - _last_quick_scan) < QUICK_SCAN_TTL:
            return
        _last_quick_scan = now
        _discover_instances(QUICK_DISCOVERY_RANGE, host=None, timeout=DISCOVERY_PROBE_TIMEOUT)


def _discover_instances(port_range, host=None, timeout=0.5) -> dict:
    """Internal function to discover NEW Ghidra instances by scanning ports

    This function only returns newly discovered instances that weren't already
    in the active_instances registry. Use instances_discover() for a complete
    list including already known instances.
    """
    found_instances = []
    scan_host = host if host is not None else ghidra_host

    with instances_lock:
        known = set(active_instances)
    candidates = [port for port in port_range if port not in known]
    if not candidates:
        return {"found": 0, "instances": found_instances}

    # Probe the ports concurrently. The scan is I/O bound, and going one port
    # at a time meant every closed port cost a full round trip before the next
    # one was tried.
    with ThreadPoolExecutor(max_workers=min(16, len(candidates))) as pool:
        payloads = list(pool.map(lambda p: _probe_instance(p, scan_host, timeout), candidates))

    for port, json_data in zip(candidates, payloads):
        if json_data is None:
            continue
        url = f"http://{scan_host}:{port}"
        # Instead of relying only on register_instance, which already checks program info,
        # extract additional information here for more detailed discovery results
        result = register_instance(port, url)

        # Initialize report info
        instance_info = {
            "port": port,
            "url": url
        }

        # Extract version info for reporting
        if isinstance(json_data["result"], dict):
            instance_info["plugin_version"] = json_data["result"].get("plugin_version", "unknown")
            instance_info["api_version"] = json_data["result"].get("api_version", "unknown")
        else:
            instance_info["plugin_version"] = "unknown"
            instance_info["api_version"] = "unknown"

        # Include project details from registered instance in the report
        if port in active_instances:
            instance_info["project"] = active_instances[port].get("project", "")
            instance_info["file"] = active_instances[port].get("file", "")

        instance_info["result"] = result
        found_instances.append(instance_info)

    return {
        "found": len(found_instances),
        "instances": found_instances
    }

def periodic_discovery():
    """Periodically discover new instances"""
    while True:
        try:
            _discover_instances(FULL_DISCOVERY_RANGE, timeout=DISCOVERY_PROBE_TIMEOUT)

            # Snapshot the registry under the lock and do the HTTP checks
            # outside it. Holding instances_lock across the network calls made
            # every tool call queue behind the discovery round-trip, because
            # get_instance_url takes the same lock.
            with instances_lock:
                snapshot = list(active_instances.items())

            ports_to_remove = []
            for port, info in snapshot:
                url = info["url"]
                try:
                    # Check HATEOAS API via plugin-version endpoint
                    response = _http_session().get(f"{url}/plugin-version", timeout=1)
                    if not response.ok:
                        ports_to_remove.append(port)
                        continue

                    # Update program info if available (especially to get project name)
                    try:
                        info_url = f"{url}/program"
                        info_response = _http_session().get(info_url, timeout=1)
                        if info_response.ok:
                            try:
                                info_data = info_response.json()
                                if "result" in info_data:
                                    result = info_data["result"]
                                    if isinstance(result, dict):
                                        # Extract project and file from programId (format: "project:/file")
                                        program_id = result.get("programId", "")
                                        if ":" in program_id:
                                            project_name, file_path = program_id.split(":", 1)
                                            info["project"] = project_name
                                            # Remove leading slash from file path if present
                                            if file_path.startswith("/"):
                                                file_path = file_path[1:]
                                            info["path"] = file_path

                                        # Get file name directly from the result
                                        info["file"] = result.get("name", "")

                                        # Get other metadata
                                        info["language_id"] = result.get("languageId", "")
                                        info["compiler_spec_id"] = result.get("compilerSpecId", "")
                                        info["image_base"] = result.get("imageBase", result.get("image_base", ""))
                            except Exception as e:
                                print(f"Error parsing info endpoint during discovery: {e}", file=sys.stderr)
                    except Exception:
                        # Non-critical, continue even if update fails
                        pass

                except requests.exceptions.RequestException:
                    ports_to_remove.append(port)

            with instances_lock:
                for port in ports_to_remove:
                    if port in active_instances:
                        del active_instances[port]
                        print(f"Removed unreachable instance on port {port}")
        except Exception as e:
            print(f"Error in periodic discovery: {e}")

        time.sleep(10)

def handle_sigint(signum, frame):
    os._exit(0)

# ================= MCP Resources =================
# Resources provide information that can be loaded directly into context
# They focus on data and minimize metadata
#
# The URIs carry the ghidra:// scheme because a relative one is refused:
# the protocol types the URI of a read as a URL, and the server validates
# it before the resource is looked up. A resource whose URI no client can
# name is a resource nobody can read.

@mcp.resource(uri="ghidra://instance/{port}")
def ghidra_instance(port: int | None = None) -> dict:
    """Get detailed information about a Ghidra instance and the loaded program
    
    Args:
        port: Specific Ghidra instance port (optional, uses current if omitted)
        
    Returns:
        dict: Detailed information about the Ghidra instance and loaded program
    """
    port = _get_instance_port(port)
    response = safe_get(port, "program")
    
    if not isinstance(response, dict) or not response.get("success", False):
        return {"error": f"Unable to access Ghidra instance on port {port}"}
    
    # Extract only the most relevant information for the resource
    result = response.get("result", {})
    
    if not isinstance(result, dict):
        return {
            "success": False,
            "error": {
                "code": "INVALID_RESPONSE",
                "message": "Invalid response format from Ghidra instance"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    stats = result.get("statistics") or {}
    instance_info = {
        "port": port,
        "url": get_instance_url(port),
        "program_name": result.get("name", "unknown"),
        "program_id": result.get("programId", "unknown"),
        "language": result.get("languageId", "unknown"),
        "compiler": result.get("compilerSpecId", "unknown"),
        "base_address": result.get("imageBase", "0x0"),
        "function_count": stats.get("functionCount"),
        "symbol_count": stats.get("symbolCount")
    }
    
    # Add project information if available
    if "project" in active_instances[port]:
        instance_info["project"] = active_instances[port]["project"]
    
    return instance_info

@mcp.resource(uri="ghidra://instance/{port}/function/decompile/address/{address}")
def decompiled_function_by_address(port: int | None = None, address: str | None = None) -> str:
    """Get decompiled C code for a function by address
    
    Args:
        port: Specific Ghidra instance port
        address: Function address in hex format
        
    Returns:
        str: The decompiled C code as a string, or error message
    """
    if not address:
        return "Error: Address parameter is required"
    
    port = _get_instance_port(port)
    
    params = {
        "syntax_tree": "false",
        "style": "normalize"
    }
    
    endpoint = f"functions/{address}/decompile"
    
    response = safe_get(port, endpoint, params)
    simplified = simplify_response(response)
    
    # For a resource, we want to directly return just the decompiled code
    if (not isinstance(simplified, dict) or 
        not simplified.get("success", False) or 
        "result" not in simplified):
        error_message = "Error: Could not decompile function"
        if isinstance(simplified, dict) and "error" in simplified:
            if isinstance(simplified["error"], dict):
                error_message = simplified["error"].get("message", error_message)
            else:
                error_message = str(simplified["error"])
        return error_message
    
    # Extract just the decompiled code text
    result = simplified["result"]
    
    # Different endpoints may return the code in different fields, try all of them
    if isinstance(result, dict):
        for key in ["decompiled_text", "decompilation", "ccode", "decompiled"]:
            if key in result:
                return result[key]
    
    return "Error: Could not extract decompiled code from response"

@mcp.resource(uri="ghidra://instance/{port}/function/decompile/name/{name}")
def decompiled_function_by_name(port: int | None = None, name: str | None = None) -> str:
    """Get decompiled C code for a function by name
    
    Args:
        port: Specific Ghidra instance port
        name: Function name
        
    Returns:
        str: The decompiled C code as a string, or error message
    """
    if not name:
        return "Error: Name parameter is required"
    
    port = _get_instance_port(port)
    
    params = {
        "syntax_tree": "false",
        "style": "normalize"
    }
    
    endpoint = f"functions/by-name/{quote(name)}/decompile"
    
    response = safe_get(port, endpoint, params)
    simplified = simplify_response(response)
    
    # For a resource, we want to directly return just the decompiled code
    if (not isinstance(simplified, dict) or 
        not simplified.get("success", False) or 
        "result" not in simplified):
        error_message = "Error: Could not decompile function"
        if isinstance(simplified, dict) and "error" in simplified:
            if isinstance(simplified["error"], dict):
                error_message = simplified["error"].get("message", error_message)
            else:
                error_message = str(simplified["error"])
        return error_message
    
    # Extract just the decompiled code text
    result = simplified["result"]
    
    # Different endpoints may return the code in different fields, try all of them
    if isinstance(result, dict):
        for key in ["decompiled_text", "decompilation", "ccode", "decompiled"]:
            if key in result:
                return result[key]
    
    return "Error: Could not extract decompiled code from response"

@mcp.resource(uri="ghidra://instance/{port}/function/info/address/{address}")
def function_info_by_address(port: int | None = None, address: str | None = None) -> dict:
    """Get detailed information about a function by address
    
    Args:
        port: Specific Ghidra instance port
        address: Function address in hex format
        
    Returns:
        dict: Complete function information including signature, parameters, etc.
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    endpoint = f"functions/{address}"
    
    response = safe_get(port, endpoint)
    simplified = simplify_response(response)
    
    if (not isinstance(simplified, dict) or 
        not simplified.get("success", False) or 
        "result" not in simplified):
        return {
            "success": False,
            "error": {
                "code": "FUNCTION_NOT_FOUND",
                "message": "Could not get function information",
                "details": simplified.get("error") if isinstance(simplified, dict) else None
            },
            "timestamp": int(time.time() * 1000)
        }
    
    # Return just the function data without API metadata
    return simplified["result"]

@mcp.resource(uri="ghidra://instance/{port}/function/info/name/{name}")
def function_info_by_name(port: int | None = None, name: str | None = None) -> dict:
    """Get detailed information about a function by name
    
    Args:
        port: Specific Ghidra instance port
        name: Function name
        
    Returns:
        dict: Complete function information including signature, parameters, etc.
    """
    if not name:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Name parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    endpoint = f"functions/by-name/{quote(name)}"
    
    response = safe_get(port, endpoint)
    simplified = simplify_response(response)
    
    if (not isinstance(simplified, dict) or 
        not simplified.get("success", False) or 
        "result" not in simplified):
        return {
            "success": False,
            "error": {
                "code": "FUNCTION_NOT_FOUND",
                "message": "Could not get function information",
                "details": simplified.get("error") if isinstance(simplified, dict) else None
            },
            "timestamp": int(time.time() * 1000)
        }
    
    # Return just the function data without API metadata
    return simplified["result"]

def _disassembly_text(result) -> str:
    """Turn a disassembly result into text.

    The v3000 API hands the instruction list back as the result itself; the
    older API nested it under result["instructions"]. Both shapes are read
    here, so the resources do not answer "could not extract" for a response
    that plainly carries the listing.
    """
    if isinstance(result, list):
        instructions = result
    elif isinstance(result, dict):
        if isinstance(result.get("disassembly_text"), str):
            return result["disassembly_text"]
        instructions = result.get("instructions") or []
        if not instructions and isinstance(result.get("disassembly"), str):
            return result["disassembly"]
    else:
        instructions = []

    if not instructions:
        return "Error: Could not extract disassembly from response"

    lines = []
    for instr in instructions:
        if not isinstance(instr, dict):
            continue
        addr = instr.get("address", "")
        bytes_str = instr.get("bytes", "")
        mnemonic = instr.get("mnemonic", "")
        operands = instr.get("operands", "")
        # Format: address: bytes  mnemonic operands
        lines.append(f"{addr}: {bytes_str.ljust(10)}  {mnemonic} {operands}")

    return "\n".join(lines)


@mcp.resource(uri="ghidra://instance/{port}/function/disassembly/address/{address}")
def disassembly_by_address(port: int | None = None, address: str | None = None) -> str:
    """Get disassembled instructions for a function by address
    
    Args:
        port: Specific Ghidra instance port
        address: Function address in hex format
        
    Returns:
        str: Formatted disassembly listing as a string
    """
    if not address:
        return "Error: Address parameter is required"
    
    port = _get_instance_port(port)
    
    endpoint = f"functions/{address}/disassembly"
    
    response = safe_get(port, endpoint)
    simplified = simplify_response(response)
    
    if (not isinstance(simplified, dict) or 
        not simplified.get("success", False) or 
        "result" not in simplified):
        error_message = "Error: Could not get disassembly"
        if isinstance(simplified, dict) and "error" in simplified:
            if isinstance(simplified["error"], dict):
                error_message = simplified["error"].get("message", error_message)
            else:
                error_message = str(simplified["error"])
        return error_message
    
    # For a resource, we want to directly return just the disassembly text
    result = simplified["result"]

    return _disassembly_text(result)


@mcp.resource(uri="ghidra://instance/{port}/function/disassembly/name/{name}")
def disassembly_by_name(port: int | None = None, name: str | None = None) -> str:
    """Get disassembled instructions for a function by name
    
    Args:
        port: Specific Ghidra instance port
        name: Function name
        
    Returns:
        str: Formatted disassembly listing as a string
    """
    if not name:
        return "Error: Name parameter is required"
    
    port = _get_instance_port(port)
    
    endpoint = f"functions/by-name/{quote(name)}/disassembly"
    
    response = safe_get(port, endpoint)
    simplified = simplify_response(response)
    
    if (not isinstance(simplified, dict) or 
        not simplified.get("success", False) or 
        "result" not in simplified):
        error_message = "Error: Could not get disassembly"
        if isinstance(simplified, dict) and "error" in simplified:
            if isinstance(simplified["error"], dict):
                error_message = simplified["error"].get("message", error_message)
            else:
                error_message = str(simplified["error"])
        return error_message
    
    # For a resource, we want to directly return just the disassembly text
    result = simplified["result"]

    return _disassembly_text(result)

# ================= MCP Prompts =================
# Prompts define reusable templates for LLM interactions

@mcp.prompt("analyze_function")
def analyze_function_prompt(name: str | None = None, address: str | None = None, port: int | None = None):
    """A prompt to guide the LLM through analyzing a function
    
    Args:
        name: Function fully-qualified name (e.g. "FOM::Read"; a bare name matches the global namespace only), mutually exclusive with address
        address: Function address in hex format (mutually exclusive with address)
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    
    # Get function name if only address is provided
    if address and not name:
        fn_info = function_info_by_address(address=address, port=port)
        if isinstance(fn_info, dict) and "name" in fn_info:
            name = fn_info["name"]
    
    # Create the template that guides analysis
    decompiled = ""
    disasm = ""
    fn_info = None
    
    if address:
        decompiled = decompiled_function_by_address(address=address, port=port)
        disasm = disassembly_by_address(address=address, port=port)
        fn_info = function_info_by_address(address=address, port=port)
    elif name:
        decompiled = decompiled_function_by_name(name=name, port=port)
        disasm = disassembly_by_name(name=name, port=port)
        fn_info = function_info_by_name(name=name, port=port)
    
    return {
        "prompt": f"""
        Analyze the following function: {name or address}
        
        Decompiled code:
        ```c
        {decompiled}
        ```
        
        Disassembly:
        ```
        {disasm}
        ```
        
        1. What is the purpose of this function?
        2. What are the key parameters and their uses?
        3. What are the return values and their meanings?
        4. Are there any security concerns in this implementation?
        5. Describe the algorithm or process being implemented.
        """,
        "context": {
            "function_info": fn_info
        }
    }

@mcp.prompt("identify_vulnerabilities")
def identify_vulnerabilities_prompt(name: str | None = None, address: str | None = None, port: int | None = None):
    """A prompt to help identify potential vulnerabilities in a function
    
    Args:
        name: Function fully-qualified name (e.g. "FOM::Read"; a bare name matches the global namespace only), mutually exclusive with address
        address: Function address in hex format (mutually exclusive with address)
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    
    # Get function name if only address is provided
    if address and not name:
        fn_info = function_info_by_address(address=address, port=port)
        if isinstance(fn_info, dict) and "name" in fn_info:
            name = fn_info["name"]
    
    # Create the template focused on security analysis
    decompiled = ""
    disasm = ""
    fn_info = None
    
    if address:
        decompiled = decompiled_function_by_address(address=address, port=port)
        disasm = disassembly_by_address(address=address, port=port)
        fn_info = function_info_by_address(address=address, port=port)
    elif name:
        decompiled = decompiled_function_by_name(name=name, port=port)
        disasm = disassembly_by_name(name=name, port=port)
        fn_info = function_info_by_name(name=name, port=port)
    
    return {
        "prompt": f"""
        Analyze the following function for security vulnerabilities: {name or address}
        
        Decompiled code:
        ```c
        {decompiled}
        ```
        
        Look for these vulnerability types:
        1. Buffer overflows or underflows
        2. Integer overflow/underflow
        3. Use-after-free or double-free bugs
        4. Format string vulnerabilities
        5. Missing bounds checks
        6. Insecure memory operations
        7. Race conditions or timing issues
        8. Input validation problems
        
        For each potential vulnerability:
        - Describe the vulnerability and where it occurs
        - Explain the security impact
        - Suggest how it could be exploited
        - Recommend a fix
        """,
        "context": {
            "function_info": fn_info,
            "disassembly": disasm
        }
    }

@mcp.prompt("reverse_engineer_binary")
def reverse_engineer_binary_prompt(port: int | None = None):
    """A comprehensive prompt to guide the process of reverse engineering an entire binary
    
    Args:
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    
    # Get program info for context
    program_info = ghidra_instance(port=port)
    
    # Create a comprehensive reverse engineering guide
    return {
        "prompt": f"""
        # Comprehensive Binary Reverse Engineering Plan
        
        Begin reverse engineering the binary {program_info.get('program_name', 'unknown')} using a methodical approach.
        
        ## Phase 1: Initial Reconnaissance
        1. Analyze entry points and the main function
        2. Identify and catalog key functions and libraries
        3. Map the overall program structure
        4. Identify important data structures
        
        ## Phase 2: Functional Analysis
        1. Start with main() or entry point functions and trace the control flow
        2. Find and rename all unnamed functions (FUN_*) called from main
        3. For each function:
           - Decompile and analyze its purpose
           - Rename with descriptive names following consistent patterns
           - Add comments for complex logic
           - Identify parameters and return values
        4. Follow cross-references (xrefs) to understand context of function usage
        5. Pay special attention to:
           - File I/O operations
           - Network communication
           - Memory allocation/deallocation
           - Authentication/encryption routines
           - Data processing algorithms
        
        ## Phase 3: Data Flow Mapping
        1. Identify key data structures and rename them meaningfully
        2. Track global variables and their usage across functions
        3. Map data transformations through the program
        4. Identify sensitive data handling (keys, credentials, etc.)
        
        ## Phase 4: Deep Analysis
        1. For complex functions, perform deeper analysis using:
           - Data flow analysis
           - Call graph analysis
           - Security vulnerability scanning
        2. Look for interesting patterns:
           - Command processing routines
           - State machines
           - Protocol implementations
           - Cryptographic operations
        
        ## Implementation Strategy
        1. Start with functions called from main
        2. Search for unnamed functions with pattern "FUN_*"
        3. Decompile each function and analyze its purpose
        4. Look at its call graph and cross-references to understand context
        5. Rename the function based on its behavior
        6. Document key insights
        7. Continue iteratively until the entire program flow is mapped
        
        ## Function Prioritization
        1. Start with entry points and initialization functions
        2. Focus on functions with high centrality in the call graph
        3. Pay special attention to functions with:
           - Command processing logic
           - Error handling
           - Security checks
           - Data transformation
        
        Remember to use the available GhydraMCP tools:
        - Use functions_list to find functions matching patterns
        - Use xrefs_list to find cross-references
        - Use functions_decompile for C-like representations
        - Use functions_disassemble for lower-level analysis
        - Use functions_rename to apply meaningful names
        - Use data_* tools to work with program data
        """,
        "context": {
            "program_info": program_info 
        }
    }

# ================= MCP Tools =================
# Since we can't use tool groups, we'll use namespaces in the function names

# Instance management tools
@mcp.tool()
@text_output
def instances_list() -> dict:
    """List all known Ghidra instances with automatic discovery

    This is the PRIMARY tool for discovering instances. It automatically scans
    for new instances on the default host (ports 8192-8201) before returning the list.

    IMPORTANT: This performs discovery automatically. You do NOT need to call
    instances_discover() separately unless scanning a different host.

    Returns:
        dict: Contains 'instances' list with all available Ghidra instances,
              each showing port, url, project, and file
    """
    # Auto-discover new instances before listing
    _quick_scan()

    with instances_lock:
        return {
            "instances": [
                {
                    "port": port,
                    "url": info["url"],
                    "project": info.get("project", ""),
                    "file": info.get("file", ""),
                    "headless": bool(info.get("headless", False))
                }
                for port, info in active_instances.items()
            ]
        }

@mcp.tool()
@text_output
def instances_discover(host: str | None = None) -> dict:
    """Scan a specific host for Ghidra instances (RARELY NEEDED)

    Use this ONLY when scanning a different host than the default.

    For normal usage, use instances_list() instead - it performs discovery
    automatically on the default host.

    Args:
        host: Hostname or IP to scan (default: localhost/configured ghidra_host)

    Returns:
        dict: Contains 'instances' list with all available instances after discovery
    """
    # Discover instances on the specified host
    if host is None or host == ghidra_host:
        _quick_scan(force=True)
    else:
        _discover_instances(QUICK_DISCOVERY_RANGE, host=host, timeout=DISCOVERY_PROBE_TIMEOUT)

    # Return all instances (same format as instances_list for consistency)
    with instances_lock:
        return {
            "instances": [
                {
                    "port": port,
                    "url": info["url"],
                    "project": info.get("project", ""),
                    "file": info.get("file", ""),
                    "headless": bool(info.get("headless", False))
                }
                for port, info in active_instances.items()
            ]
        }

@mcp.tool()
@text_output
def instances_register(port: int, url: str | None = None) -> str:
    """Register a new Ghidra instance
    
    Args:
        port: Port number of the Ghidra instance
        url: Optional URL if different from default http://host:port
    
    Returns:
        str: Confirmation message or error
    """
    return register_instance(port, url)

@mcp.tool()
@text_output
def instances_unregister(port: int) -> str:
    """Unregister a Ghidra instance
    
    Args:
        port: Port number of the instance to unregister
    
    Returns:
        str: Confirmation message or error
    """
    with instances_lock:
        if port in active_instances:
            del active_instances[port]
            return f"Unregistered instance on port {port}"
        return f"No instance found on port {port}"

@mcp.tool()
@text_output
def instances_use(port: int) -> str:
    """Set the current working Ghidra instance
    
    Args:
        port: Port number of the instance to use
        
    Returns:
        str: Confirmation message or error
    """
    global current_instance_port
    
    # First validate that the instance exists and is active
    if port not in active_instances:
        # Try to register it if not found
        register_instance(port)
        if port not in active_instances:
            return f"Error: No active Ghidra instance found on port {port}"
    
    # Set as current instance
    current_instance_port = port
    
    # Return information about the selected instance
    with instances_lock:
        info = active_instances[port]
        program = info.get("file", "unknown program")
        project = info.get("project", "unknown project")
        return f"Now using Ghidra instance on port {port} with {program} in project {project}"

@mcp.tool()
@text_output
def instances_current() -> dict:
    """Get information about the current working instance set by instances_use()

    Shows which Ghidra instance will be used when port is omitted from other tools.
    The default current instance is port 8192.

    Returns:
        dict: Details about the current instance including port, program, and project
    """
    return ghidra_instance(port=current_instance_port)


@mcp.tool()
@text_output
def instances_capabilities(port: int | None = None) -> dict:
    """Describe what a Ghidra instance can do, for capability negotiation.

    Returns the plugin, API, Ghidra and Java versions, whether the instance is
    headless, which feature flags are actually enabled, and the limits a client
    must respect. Older plugins that only have /plugin-version are answered
    with the subset that endpoint provides.

    Args:
        port: Specific Ghidra instance port (optional). Defaults to the current instance.

    Returns:
        dict: Capability payload with plugin_version, api_version, ghidra_version,
              java_version, headless, features and limits.
    """
    port = _get_instance_port(port)
    response = safe_get(port, "capabilities")
    if not response.get("success", False):
        # Additive endpoint: an older plugin has no /capabilities route.
        legacy = simplify_response(safe_get(port, "plugin-version"))
        if legacy.get("success", False):
            return legacy
    return simplify_response(response)

# Function tools
@mcp.tool()
@text_output
def functions_list(offset: int = 0, limit: int = 100,
                  name_contains: str | None = None,
                  name_matches_regex: str | None = None,
                  addr_min: str | None = None,
                  addr_max: str | None = None,
                  count: bool = True,
                  port: int | None = None) -> dict:
    """List functions with filtering and pagination

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        name_contains: Substring name filter (case-insensitive)
        name_matches_regex: Regex name filter
        addr_min: Only return functions at or above this address (hex)
        addr_max: Only return functions at or below this address (hex)
        count: Compute the total (default True); false skips the counting scan (I10)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: List of functions with pagination information
    """
    port = _get_instance_port(port)

    params = {
        "offset": offset,
        "limit": limit,
        "count": "true" if count else "false",
    }
    if name_contains:
        params["name_contains"] = name_contains
    if name_matches_regex:
        params["name_matches_regex"] = name_matches_regex
    if addr_min:
        params["addr_min"] = addr_min
    if addr_max:
        params["addr_max"] = addr_max

    response = safe_get(port, "functions", params)
    simplified = simplify_response(response)

    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)

    return simplified

@mcp.tool()
@text_output
def functions_get(name: str | None = None, address: str | None = None, port: int | None = None) -> dict:
    """Get detailed information about a function
    
    Args:
        name: Function fully-qualified name (e.g. "FOM::Read"; a bare name matches the global namespace only), mutually exclusive with address
        address: Function address in hex format (mutually exclusive with name)
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Detailed function information
    """
    if not name and not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either name or address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    if address:
        endpoint = f"functions/{address}"
    else:
        endpoint = f"functions/by-name/{quote(name)}"
    
    response = safe_get(port, endpoint)
    return simplify_response(response)

@mcp.tool()
@text_output
def functions_get_containing(address: str, port: int | None = None) -> dict:
    """Find the function containing the specified address

    Args:
        address: Memory address in hex format
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: List containing the function information if found
    """
    port = _get_instance_port(port)
    
    params = {
        "containing_addr": address
    }
    
    response = safe_get(port, "functions", params)
    return simplify_response(response)

@mcp.tool()
@text_output
def functions_get_next(address: str, port: int | None = None) -> dict:
    """Get the next function after the given address (by memory order)

    Args:
        address: Reference address in hex format
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Function immediately after the given address, or empty result if none
    """
    port = _get_instance_port(port)
    response = safe_get(port, "functions", {"after": address})
    return simplify_response(response)


@mcp.tool()
@text_output
def functions_get_prev(address: str, port: int | None = None) -> dict:
    """Get the previous function before the given address (by memory order)

    Args:
        address: Reference address in hex format
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Function immediately before the given address, or empty result if none
    """
    port = _get_instance_port(port)
    response = safe_get(port, "functions", {"before": address})
    return simplify_response(response)


@mcp.tool()
@text_output
def functions_decompile(name: str | None = None, address: str | None = None,
                        syntax_tree: bool = False, style: str = "normalize",
                        show_constants: bool = True, timeout: int = DEFAULT_DECOMPILATION_TIMEOUT,
                        start_line: int | None = None, end_line: int | None = None, max_lines: int | None = None,
                        use_cache: bool = False, max_age: int = 86400,
                        port: int | None = None) -> dict:
    """Get decompiled code for a function with optional line filtering and configurable options

    Args:
        name: Function fully-qualified name (e.g. "FOM::Read"; a bare name matches the global namespace only), mutually exclusive with address
        address: Function address in hex format (mutually exclusive with name)
        syntax_tree: Include syntax tree (default: False)
        style: Decompiler style (default: "normalize")
        show_constants: Show actual constant values (strings, numbers) instead of placeholder addresses (default: True)
        timeout: Decompilation timeout in seconds (default: GHIDRA_DECOMP_TIMEOUT or auto default)
        start_line: Start at this line number (1-indexed, optional)
        end_line: End at this line number (inclusive, optional)
        max_lines: Maximum number of lines to return (optional, takes precedence over end_line)
        use_cache: Serve an unchanged program from the local cache (default False)
        max_age: How old a cached answer may be, in seconds (default 86400)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Contains function information and decompiled code (potentially filtered).
              If filtering is applied, includes a 'filter' object with total_lines and applied parameters.

    Examples:
        # Get first 20 lines of decompiled code
        functions_decompile(name="main", max_lines=20)

        # Get lines 10-30
        functions_decompile(name="main", start_line=10, end_line=30)

        # Get 15 lines starting from line 25
        functions_decompile(name="main", start_line=25, max_lines=15)
    """
    if not name and not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either name or address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)

    params = {
        "syntax_tree": str(syntax_tree).lower(),
        "style": style,
        "show_constants": str(show_constants).lower(),
        "timeout": str(timeout)
    }

    # Add line filtering parameters if provided
    if start_line is not None:
        params["start_line"] = str(start_line)
    if end_line is not None:
        params["end_line"] = str(end_line)
    if max_lines is not None:
        params["max_lines"] = str(max_lines)

    if address:
        endpoint = f"functions/{address}/decompile"
    else:
        endpoint = f"functions/by-name/{quote(name)}/decompile"

    if use_cache:
        response, _cached = _cache_get_or_compute(
            port, "decompile", {"endpoint": endpoint, "params": params},
            lambda: safe_get(port, endpoint, params), max_age=max_age)
    else:
        response = safe_get(port, endpoint, params)
    simplified = simplify_response(response)

    return simplified


def _targets_text(value: Any) -> Any:
    """Take a list of targets as one piece of text.

    A client that hands over a nested list flattens it, and every value of
    the list arrives as a string. The text is the form nothing gets in the
    way of, so the schema asks for it; a list is still accepted, for the
    clients that deliver one.
    """
    if isinstance(value, (list, tuple, dict)):
        return json.dumps(value)
    return value


# The targets of a batch, as JSON text. The schema says string on purpose.
TargetsText = Annotated[str, BeforeValidator(_targets_text)]


def _parse_targets(text: str) -> list[str]:
    """The targets of a batch, from JSON text, from a bare name, or from a list.

    Args:
        text: JSON text ('["main", "0x401000"]'), a single name, several names
              separated by commas or newlines, or the list itself.

    Returns:
        list[str]: The targets, in order, without the empty ones.

    Raises:
        ValueError: when the text is JSON that is not a list of names.
    """
    if isinstance(text, (list, tuple)):
        return [str(item).strip() for item in text if str(item).strip()]

    raw = str(text).strip()
    if not raw:
        return []

    try:
        parsed = json.loads(raw)
    except ValueError:
        # Not JSON: a single name, or several separated by commas or newlines.
        return [part.strip() for part in re.split(r"[,\n]", raw) if part.strip()]

    if isinstance(parsed, list):
        return [str(item).strip() for item in parsed if str(item).strip()]
    if isinstance(parsed, str):
        return [parsed.strip()] if parsed.strip() else []
    raise ValueError("the targets must be a list of function names or addresses")


@mcp.tool()
@text_output
def functions_batch_decompile(targets: TargetsText,
                              timeout: int = DEFAULT_DECOMPILATION_TIMEOUT,
                              async_mode: bool = False,
                              port: int | None = None) -> dict:
    """Decompile a list of functions in one call

    Args:
        targets: The functions to decompile, as JSON text (e.g. '["main","0x401000"]').
                 A bare name or a comma-separated list is accepted too. Each target
                 is a function name or an address.
        timeout: Decompilation timeout per function, in seconds (default: 60)
        async_mode: Return a task handle immediately instead of blocking for the
                    whole batch (which the server runs one target at a time and
                    can take timeout x targets). Poll tasks_get(task_id).
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: One entry per target, with the decompiled code or the reason it
              failed. A target that resolves to nothing does not stop the batch.
              With async_mode=True: a task handle for tasks_get/tasks_cancel.
    """
    port = _get_instance_port(port)

    try:
        wanted = _parse_targets(targets)
    except ValueError as e:
        return {
            "success": False,
            "error": {
                "code": "INVALID_TARGETS",
                "message": str(e)
            },
            "timestamp": int(time.time() * 1000)
        }

    if not wanted:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "The targets parameter is required — a list of function names or addresses"
            },
            "timestamp": int(time.time() * 1000)
        }

    payload = {"targets": wanted, "timeout": timeout}
    if async_mode:
        return _task_spawn(
            "batch_decompile",
            f"{len(wanted)} target(s) on port {port}",
            body=lambda: safe_post(port, "functions/decompile-batch", payload),
            result_of=simplify_response)

    response = safe_post(port, "functions/decompile-batch", payload)
    return simplify_response(response)


@mcp.tool()
@text_output
def functions_analyze(name: str | None = None, address: str | None = None,
                      xref_limit: int = 50, port: int | None = None) -> dict:
    """Everything about one function, in one call

    The pieces were all there - the decompilation, the callers, the callees,
    the references - and an agent that had just found a function paid a
    round trip for each one.

    Args:
        name: The function name (fully-qualified)
        address: The function address (hex)
        xref_limit: How many references to return (default: 50)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: The function, its decompilation, its callers, its callees and
              the references to it
    """
    if not name and not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either name or address is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)

    if address:
        info = safe_get(port, f"functions/{quote(address)}")
    else:
        info = safe_get(port, f"functions/by-name/{quote(name)}")

    if not info.get("success", False):
        return info

    function = info.get("result") or {}
    resolved = function.get("address") or address
    if not resolved:
        return {
            "success": False,
            "error": {
                "code": "FUNCTION_NOT_FOUND",
                "message": f"The function '{name or address}' has no address"
            },
            "timestamp": int(time.time() * 1000)
        }

    decompile = safe_get(port, f"functions/{quote(resolved)}/decompile")
    callers = safe_get(port, f"analysis/callers/{quote(resolved)}")
    callees = safe_get(port, f"analysis/callees/{quote(resolved)}")
    xrefs = safe_get(port, "xrefs", {"to_addr": resolved, "limit": xref_limit})

    decompiled = decompile.get("result") or {}

    def _result_of(response: dict) -> list:
        payload = response.get("result")
        return payload if isinstance(payload, list) else []

    return {
        "success": True,
        "result": {
            "function": function,
            "decompilation": decompiled.get("decompilation"),
            "decompileError": decompiled.get("errorMessage"),
            "callers": _result_of(callers),
            "callees": _result_of(callees),
            "xrefs": _result_of(xrefs),
        }
    }

@mcp.tool()
@text_output
def functions_disassemble(name: str | None = None, address: str | None = None, offset: int = 0, limit: int = 100, port: int | None = None) -> dict:
    """Get disassembly for a function

    Args:
        name: Function fully-qualified name (e.g. "FOM::Read"; a bare name matches the global namespace only), mutually exclusive with address
        address: Function address in hex format (mutually exclusive with name)
        offset: Number of instructions to skip (default 0)
        limit: Maximum number of instructions per page (default 100, server max 1000).
            Long functions are paginated; the text output footer reports the total
            instruction count and the next offset to fetch the rest.
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Contains function information and disassembly text
    """
    if not name and not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either name or address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)

    if address:
        endpoint = f"functions/{address}/disassembly"
    else:
        endpoint = f"functions/by-name/{quote(name)}/disassembly"

    params = {}
    if offset > 0:
        params["offset"] = offset
    if limit > 0:
        params["limit"] = limit

    response = safe_get(port, endpoint, params)
    return simplify_response(response)

@mcp.tool()
@text_output
def functions_create(address: str, port: int | None = None) -> dict:
    """Create a new function at the specified address
    
    Args:
        address: Memory address in hex format where function starts
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Operation result with the created function information
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    payload = {
        "address": address
    }
    
    response = safe_post(port, "functions", payload)
    return simplify_response(response)

@mcp.tool()
@text_output
def functions_rename(old_name: str | None = None, address: str | None = None, new_name: str = "", port: int | None = None) -> dict:
    """Rename a function
    
    Args:
        old_name: Current fully-qualified function name (e.g. "FOM::Read"; bare = global only), mutually exclusive with address
        address: Function address in hex format (mutually exclusive with name)
        new_name: New fully-qualified name; "A::B::foo" moves into namespace A::B (created if absent), a leading "::" or "Global::" moves to the global namespace, a bare name keeps the current namespace
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Operation result with the updated function information
    """
    if not (old_name or address) or not new_name:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either old_name or address, and new_name parameters are required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    payload = {
        "name": new_name
    }
    
    if address:
        endpoint = f"functions/{address}"
    else:
        endpoint = f"functions/by-name/{quote(old_name)}"
    
    response = safe_patch(port, endpoint, payload)
    return simplify_response(response)

@mcp.tool()
@text_output
def functions_set_signature(name: str | None = None, address: str | None = None, signature: str = "", port: int | None = None) -> dict:
    """Set function signature/prototype
    
    Args:
        name: Function fully-qualified name (e.g. "FOM::Read"; a bare name matches the global namespace only), mutually exclusive with address
        address: Function address in hex format (mutually exclusive with name)
        signature: New function signature (e.g., "int func(char *data, int size)")
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Operation result with the updated function information
    """
    if not (name or address) or not signature:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either name or address, and signature parameters are required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    payload = {
        "signature": signature
    }
    
    if address:
        endpoint = f"functions/{address}"
    else:
        endpoint = f"functions/by-name/{quote(name)}"
    
    response = safe_patch(port, endpoint, payload)
    return simplify_response(response)

@mcp.tool()
@text_output
def functions_delete(name: str | None = None, address: str | None = None, port: int | None = None) -> dict:
    """Delete a function

    Args:
        name: Function fully-qualified name (e.g. "FOM::Read"; a bare name matches the global namespace only), mutually exclusive with address
        address: Function address in hex format (mutually exclusive with name)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Operation result with deletion status
    """
    if not name and not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either name or address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)

    if address:
        endpoint = f"functions/{address}"
    else:
        endpoint = f"functions/by-name/{quote(name)}"

    response = safe_delete(port, endpoint)
    return simplify_response(response)

@mcp.tool()
@text_output
def functions_update_variable(address: str, variable_name: str,
                              new_name: str | None = None, new_data_type: str | None = None,
                              port: int | None = None) -> dict:
    """Update a local variable in a function

    Args:
        address: Function address in hex format
        variable_name: Existing variable name
        new_name: New variable name (optional)
        new_data_type: New variable data type (optional)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Operation result
    """
    if not address or not variable_name:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "address and variable_name parameters are required"
            },
            "timestamp": int(time.time() * 1000)
        }

    if not new_name and not new_data_type:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "At least one of new_name or new_data_type must be provided"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)

    payload = {}
    if new_name:
        payload["name"] = new_name
    if new_data_type:
        payload["data_type"] = new_data_type

    endpoint = f"functions/{address}/variables/{quote(variable_name)}"
    response = safe_patch(port, endpoint, payload)
    return simplify_response(response)

@mcp.tool()
@text_output
def functions_get_variables(name: str | None = None, address: str | None = None, port: int | None = None) -> dict:
    """Get variables for a function
    
    Args:
        name: Function fully-qualified name (e.g. "FOM::Read"; a bare name matches the global namespace only), mutually exclusive with address
        address: Function address in hex format (mutually exclusive with name)
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Contains function information and list of variables
    """
    if not name and not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either name or address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    if address:
        endpoint = f"functions/{address}/variables"
    else:
        endpoint = f"functions/by-name/{quote(name)}/variables"
    
    response = safe_get(port, endpoint)
    return simplify_response(response)

# Memory tools
@mcp.tool()
@text_output
def memory_read(address: str, length: int = 16, format: str = "hex", segment: str | None = None,
                port: int | None = None) -> dict:
    """Read bytes from memory

    Args:
        address: Memory address in hex format
        length: Number of bytes to read (default: 16)
        format: Output format - "hex", "base64", or "string" (default: "hex")
        segment: Optional memory segment/overlay name to qualify the address (e.g. "runtime")
        port: Specific Ghidra instance port (optional)
    
    Returns:
        dict: {
            "address": original address,
            "length": bytes read,
            "format": output format,
            "hexBytes": the memory contents as hex string,
            "rawBytes": the memory contents as base64 string,
            "timestamp": response timestamp
        }
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)

    # GET /memory is the block list; the read endpoint is GET /memory/{address}.
    params = {
        "length": length,
        "format": format
    }
    if segment and ":" not in address:
        address = f"{segment}:{address}"

    response = safe_get(port, f"memory/{quote(address, safe=':')}", params)
    simplified = simplify_response(response)

    # Ensure the result is simple and directly usable
    if "result" in simplified and isinstance(simplified["result"], dict):
        result = simplified["result"]

        memory_info = {
            "success": True,
            "address": result.get("address", address),
            "length": result.get("length", result.get("bytesRead", length)),
            "format": format,
            "timestamp": simplified.get("timestamp", int(time.time() * 1000))
        }

        # Server sends "hex" (hex string) or "bytes" (int array); accept the
        # legacy field names too for older plugin builds.
        if "hex" in result:
            memory_info["hexBytes"] = result["hex"]
        elif "hexBytes" in result:
            memory_info["hexBytes"] = result["hexBytes"]
        if "bytes" in result:
            memory_info["bytes"] = result["bytes"]
        if "rawBytes" in result:
            memory_info["rawBytes"] = result["rawBytes"]
        elif "bytes" in result and isinstance(result["bytes"], list):
            # The server answers with an int array; the tool promises base64.
            try:
                memory_info["rawBytes"] = base64.b64encode(
                    bytes(int(b) & 0xFF for b in result["bytes"])
                ).decode("ascii")
            except (TypeError, ValueError):
                pass
        elif isinstance(memory_info.get("hexBytes"), str):
            # The server answers with hex; the tool promises base64 as well.
            try:
                memory_info["rawBytes"] = base64.b64encode(
                    bytes.fromhex(memory_info["hexBytes"])
                ).decode("ascii")
            except ValueError:
                pass
        if "block" in result:
            memory_info["block"] = result["block"]
            memory_info["permissions"] = result.get("permissions")

        return memory_info

    return simplified

@mcp.tool()
@text_output
def memory_write(address: str, bytes_data: str, format: str = "hex", port: int | None = None) -> dict:
    """Write bytes to memory (use with caution)
    
    Args:
        address: Memory address in hex format
        bytes_data: Data to write (format depends on 'format' parameter)
        format: Input format - "hex", "base64", or "string" (default: "hex")
        port: Specific Ghidra instance port (optional)
    
    Returns:
        dict: Operation result with success status
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    if not bytes_data:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Bytes parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)

    # The server only understands hex (it strips non-hex chars from the payload,
    # which would silently corrupt base64/string input). Convert client-side.
    if format == "base64":
        try:
            bytes_data = base64.b64decode(bytes_data).hex()
        except Exception as e:
            return {
                "success": False,
                "error": {"code": "INVALID_BASE64", "message": f"Invalid base64 data: {e}"},
                "timestamp": int(time.time() * 1000)
            }
    elif format == "string":
        bytes_data = bytes_data.encode("utf-8").hex()
    elif format == "hex":
        cleaned = bytes_data.replace(" ", "")
        if len(cleaned) % 2 != 0 or any(c not in "0123456789abcdefABCDEF" for c in cleaned):
            return {
                "success": False,
                "error": {"code": "INVALID_HEX", "message": "bytes_data must be an even-length hex string"},
                "timestamp": int(time.time() * 1000)
            }
        bytes_data = cleaned

    payload = {
        "bytes": bytes_data,
        "format": "hex"
    }

    # Memory write is handled by ProgramEndpoints, not MemoryEndpoints
    response = safe_patch(port, f"programs/current/memory/{address}", payload)
    return simplify_response(response)

@mcp.tool()
@text_output
def memory_disassemble(address: str, limit: int = 50, offset: int = 0, port: int | None = None) -> dict:
    """Disassemble instructions at an arbitrary address (not tied to a function)

    Args:
        address: Start address in hex format
        limit: Number of instructions to return (default: 50)
        offset: Number of instructions to skip (default: 0)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Contains instructions list with address, bytes, mnemonic, operands
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)

    params = {"limit": limit}
    if offset > 0:
        params["offset"] = offset

    response = safe_get(port, f"memory/{address}/disassembly", params)
    return simplify_response(response)

# Xrefs tools
@mcp.tool()
@text_output
def xrefs_list(to_addr: str | None = None, from_addr: str | None = None, type: str | None = None,
              offset: int = 0, limit: int = 100, port: int | None = None) -> dict:
    """List cross-references with filtering and pagination
    
    Args:
        to_addr: Filter references to this address (hexadecimal)
        from_addr: Filter references from this address (hexadecimal)  
        type: Filter by reference type (e.g. "CALL", "READ", "WRITE")
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        port: Specific Ghidra instance port (optional)
    
    Returns:
        dict: Cross-references matching the filters
    """
    # At least one of the address parameters must be provided
    if not to_addr and not from_addr:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER", 
                "message": "Either to_addr or from_addr parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    params = {
        "offset": offset,
        "limit": limit,
    }
    if to_addr:
        params["to_addr"] = to_addr
    if from_addr:
        params["from_addr"] = from_addr
    if type:
        params["type"] = type

    response = safe_get(port, "xrefs", params)
    simplified = simplify_response(response)

    # Ensure we maintain pagination metadata
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)

    return simplified


@mcp.tool()
@text_output
def xrefs_find_by_name(name: str, offset: int = 0, limit: int = 100,
                       port: int | None = None) -> dict:
    """Find the cross-references to a symbol, by name

    The xrefs are addressed by address, so an agent holding a name had to
    resolve it first and then ask again. This does both in one call.

    Args:
        name: The symbol name (e.g. "strlen"). A bare name matches every
              namespace; a qualified name ("NS::strlen") matches that one.
        offset: Pagination offset (default: 0)
        limit: Maximum references to return (default: 100)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: The symbols that carry the name, and the references to them
    """
    if not name:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "The name parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)

    params = {
        "offset": offset,
        "limit": limit,
    }

    response = safe_get(port, f"xrefs/to-name/{quote(name)}", params)
    return simplify_response(response)

# Data tools
@mcp.tool()
@text_output
def data_list(offset: int = 0, limit: int = 100, addr: str | None = None,
            name: str | None = None, name_contains: str | None = None, type: str | None = None,
            port: int | None = None) -> dict:
    """List data items with filtering and pagination
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        addr: Filter by address (hexadecimal)
        name: Exact name match filter (case-sensitive)
        name_contains: Substring name filter (case-insensitive)
        type: Filter by data type (e.g. "string", "dword")
        port: Specific Ghidra instance port (optional)
    
    Returns:
        dict: Data items matching the filters. For address lookups, returns
              defined data first and falls back to symbol labels if no defined
              data exists at that address.
    """
    port = _get_instance_port(port)
    
    # Address lookup has its own route; the /data list filters are label-based.
    if addr:
        response = safe_get(port, f"data/{quote(addr)}", {})
        simplified = simplify_response(response)
        if isinstance(simplified, dict) and simplified.get("success") and "result" in simplified:
            # normalize single item to a list so formatters keep working
            if isinstance(simplified["result"], dict):
                simplified["result"] = [simplified["result"]]
            simplified.setdefault("size", len(simplified["result"]))
        return simplified

    params = {
        "offset": offset,
        "limit": limit,
    }
    # Server filters are label/label_contains; map the friendlier arg names.
    if name:
        params["label"] = name
    if name_contains:
        params["label_contains"] = name_contains
    if type:
        params["type"] = type

    response = safe_get(port, "data", params)
    simplified = simplify_response(response)
    
    # Ensure we maintain pagination metadata
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)
    
    return simplified

@mcp.tool()
@text_output
def data_create(address: str, data_type: str, size: int | None = None, port: int | None = None) -> dict:
    """Define a new data item at the specified address
    
    Args:
        address: Memory address in hex format
        data_type: Data type (e.g. "string", "dword", "byte")
        size: Optional size in bytes for the data item
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Operation result with the created data information
    """
    if not address or not data_type:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address and data_type parameters are required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    payload = {"type": data_type}
    if size is not None:
        payload["size"] = size

    response = safe_post(port, f"data/{address}", payload)
    return simplify_response(response)

@mcp.tool()
@text_output
def data_list_strings(offset: int = 0, limit: int = 2000, filter: str | None = None, port: int | None = None) -> dict:
    """List all defined strings in the binary with their memory addresses
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum strings to return (default: 2000)
        filter: Optional string content filter
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: List of string data with addresses, values, and metadata
    """
    port = _get_instance_port(port)
    
    params = {
        "offset": offset,
        "limit": limit,
    }
    
    if filter:
        params["filter"] = filter
    
    response = safe_get(port, "strings", params)
    return simplify_response(response)

@mcp.tool()
@text_output
def data_rename(address: str, name: str, port: int | None = None) -> dict:
    """Rename a data item
    
    Args:
        address: Memory address in hex format
        name: New name for the data item
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Operation result with the updated data information
    """
    if not address or not name:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address and name parameters are required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)

    response = safe_patch(port, f"data/{address}", {"name": name})
    return simplify_response(response)

@mcp.tool()
@text_output
def data_delete(address: str, port: int | None = None) -> dict:
    """Delete data at the specified address
    
    Args:
        address: Memory address in hex format
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Operation result
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)

    response = safe_delete(port, f"data/{address}")
    return simplify_response(response)

@mcp.tool()
@text_output
def data_set_type(address: str, data_type: str, port: int | None = None) -> dict:
    """Set the data type of a data item
    
    Args:
        address: Memory address in hex format
        data_type: Data type name (e.g. "uint32_t", "char[10]")
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Operation result with the updated data information
    """
    if not address or not data_type:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address and data_type parameters are required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)

    response = safe_patch(port, f"data/{address}/type", {"type": data_type})
    return simplify_response(response)

# Scalar tools
@mcp.tool()
@text_output
def scalars_search(value: str, in_function: str | None = None, to_function: str | None = None,
                   offset: int = 0, limit: int = 100, port: int | None = None) -> dict:
    """Search for occurrences of a specific scalar (constant) value in instructions

    Finds where a constant appears as an instruction operand, like Ghidra's "Search For
    Scalars". For a named constant, resolve its value with data_list / datatypes first.

    Args:
        value: The scalar value to search for (hex "0x..." or decimal)
        in_function: Only matches inside functions whose name contains this substring
            (case-insensitive). Strongly preferred on large binaries: it scans only the
            matching functions instead of the whole program.
        to_function: Only matches where the instruction feeds a nearby call to a function
            whose name contains this substring (e.g. find the 0 passed to memset).
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Scalar occurrences with address, instruction, and function context. On a large
        program an unfiltered or to_function search may report scanTruncated when it hits a
        time budget; narrow it with in_function for complete results.
    """
    port = _get_instance_port(port)

    params = {"value": value, "offset": offset, "limit": limit}
    if in_function:
        params["in_function"] = in_function
    if to_function:
        params["to_function"] = to_function

    response = safe_get(port, "scalars", params)
    return simplify_response(response)

# Struct tools
@mcp.tool()
@text_output
def structs_list(offset: int = 0, limit: int = 100, category: str | None = None, port: int | None = None) -> dict:
    """List all struct data types in the program

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        category: Filter by category path (e.g. "/winapi")
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: List of structs with name, size, and field count
    """
    port = _get_instance_port(port)

    params = {
        "offset": offset,
        "limit": limit,
    }
    if category:
        params["category"] = category

    response = safe_get(port, "structs", params)
    simplified = simplify_response(response)

    # Ensure we maintain pagination metadata
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)

    return simplified

@mcp.tool()
@text_output
def structs_get(name: str, port: int | None = None) -> dict:
    """Get detailed information about a specific struct including all fields

    Args:
        name: Struct name
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Struct details including all fields with their names, types, and offsets
    """
    if not name:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Struct name parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)

    response = safe_get(port, f"structs/{quote(name)}")
    return simplify_response(response)

@mcp.tool()
@text_output
def structs_create(name: str, category: str | None = None, size: int | None = None,
                   description: str | None = None, port: int | None = None) -> dict:
    """Create a new struct data type

    Args:
        name: Name for the new struct
        category: Category path for the struct (e.g. "/custom")
        size: Optional initial struct size in bytes
        description: Optional description for the struct
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Created struct information
    """
    if not name:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Struct name parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)

    payload = {"name": name}
    if category:
        payload["category"] = category
    if size is not None:
        payload["size"] = size
    if description:
        payload["description"] = description

    response = safe_post(port, "structs", payload)
    return simplify_response(response)

@mcp.tool()
@text_output
def structs_add_field(struct_name: str, field_name: str, field_type: str,
                     offset: int | None = None, comment: str | None = None, port: int | None = None) -> dict:
    """Add a field to an existing struct

    Args:
        struct_name: Name of the struct to modify
        field_name: Name for the new field
        field_type: Data type for the field (e.g. "int", "char", "pointer")
        offset: Specific offset to insert field (optional, appends to end if not specified)
        comment: Optional comment for the field
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Operation result with updated struct size and field information
    """
    if not struct_name or not field_name or not field_type:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "struct_name, field_name, and field_type parameters are required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)

    payload = {
        "name": field_name,
        "type": field_type
    }
    if offset is not None:
        payload["offset"] = offset
    if comment:
        payload["comment"] = comment

    response = safe_post(port, f"structs/{quote(struct_name)}/fields", payload)
    return simplify_response(response)

@mcp.tool()
@text_output
def structs_update_field(struct_name: str, field_name: str | None = None, field_offset: int | None = None,
                        new_name: str | None = None, new_type: str | None = None, new_comment: str | None = None,
                        port: int | None = None) -> dict:
    """Update an existing field in a struct (change name, type, or comment)

    Args:
        struct_name: Name of the struct to modify
        field_name: Name of the field to update (use this OR field_offset)
        field_offset: Offset of the field to update (use this OR field_name)
        new_name: New name for the field (optional)
        new_type: New data type for the field (optional, e.g. "int", "pointer")
        new_comment: New comment for the field (optional)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Operation result with old and new field values
    """
    if not struct_name:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "struct_name parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    if not field_name and field_offset is None:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either field_name or field_offset must be provided"
            },
            "timestamp": int(time.time() * 1000)
        }

    if not new_name and not new_type and new_comment is None:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "At least one of new_name, new_type, or new_comment must be provided"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)

    # Identify field by offset (preferred) or name
    field_id = str(field_offset) if field_offset is not None else quote(field_name)

    payload = {}
    if new_name:
        payload["name"] = new_name
    if new_type:
        payload["type"] = new_type
    if new_comment is not None:
        payload["comment"] = new_comment

    response = safe_patch(port, f"structs/{quote(struct_name)}/fields/{field_id}", payload)
    return simplify_response(response)

@mcp.tool()
@text_output
def structs_delete(name: str, port: int | None = None) -> dict:
    """Delete a struct data type

    Args:
        name: Name of the struct to delete
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Operation result confirming deletion
    """
    if not name:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Struct name parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)

    response = safe_delete(port, f"structs/{quote(name)}")
    return simplify_response(response)

# Analysis tools
@mcp.tool()
@text_output
def analysis_run(port: int | None = None, analysis_options: dict | None = None, background: bool | None = None) -> dict:
    """Run analysis on the current program
    
    Args:
        analysis_options: Dictionary of analysis options to enable/disable
                         (e.g. {"background": True, "functionRecovery": True})
        background: Convenience override for background analysis execution
        port: Specific Ghidra instance port (optional)
    
    Returns:
        dict: Analysis operation result with status
    """
    port = _get_instance_port(port)
    payload = dict(analysis_options or {})
    if background is not None:
        payload["background"] = str(background).lower()
    if "background" not in payload:
        payload["background"] = "true"

    response = safe_post(port, "analysis/run", payload)
    return simplify_response(response)

@mcp.tool()
@text_output
def analysis_get_callgraph(name: str | None = None, address: str | None = None, max_depth: int = 3, port: int | None = None) -> dict:
    """Get function call graph visualization data

    Args:
        name: Starting function fully-qualified name (e.g. "FOM::Read"; bare = global only), mutually exclusive with address
        address: Starting function address (mutually exclusive with name)
        max_depth: Maximum call depth to analyze (default: 3). Increase for deeper call chains (e.g., 10-15 for complex functions)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Graph data with nodes and edges
    """
    port = _get_instance_port(port)
    
    # Server reads "depth"; send both for compatibility with older builds.
    params = {"depth": max_depth, "max_depth": max_depth}

    # Explicitly pass either name or address parameter based on what was provided
    if address:
        params["address"] = address
    elif name:
        params["name"] = name
    else:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Either name or address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    response = safe_get(port, "analysis/callgraph", params)
    return simplify_response(response)


@mcp.tool()
@text_output
def analysis_trace_call_path(from_function: str, to_function: str,
                             max_depth: int = 8, port: int | None = None) -> dict:
    """Trace how one function reaches another

    The call graph says who calls whom; this answers the question an agent
    asks when it holds the two ends: how does A reach B.

    Args:
        from_function: Where the path starts — a function name or an address
        to_function: Where the path must end — a function name or an address
        max_depth: Maximum number of hops to look for (default: 8, the server
            accepts at most 16)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: The shortest call path found, or the reason there is none
    """
    if not from_function or not to_function:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Both from_function and to_function are required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)

    params = {
        "from": from_function,
        "to": to_function,
        "max_depth": max_depth
    }

    response = safe_get(port, "analysis/call-path", params)
    return simplify_response(response)


@mcp.tool()
@text_output
def analysis_callers(address: str, offset: int = 0, limit: int = 100,
                     port: int | None = None) -> dict:
    """Get the functions that call this function

    The call graph says who calls whom; this answers the one question an
    agent asks about a single address: who reaches it.

    Args:
        address: The function address (hex)
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: The functions that call it, one page of them
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "The address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)

    response = safe_get(port, f"analysis/callers/{quote(address)}",
                        params={"offset": offset, "limit": limit})
    return simplify_response(response)


@mcp.tool()
@text_output
def analysis_callees(address: str, offset: int = 0, limit: int = 100,
                     port: int | None = None) -> dict:
    """Get the functions this function calls

    Args:
        address: The function address (hex)
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: The functions it calls, one page of them
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "The address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)

    response = safe_get(port, f"analysis/callees/{quote(address)}",
                        params={"offset": offset, "limit": limit})
    return simplify_response(response)

@mcp.tool()
@text_output
def analysis_get_dataflow(address: str, direction: str = "forward", max_steps: int = 50, port: int | None = None) -> dict:
    """Perform data flow analysis from an address
    
    Args:
        address: Starting address in hex format
        direction: "forward" or "backward" (default: "forward")
        max_steps: Maximum analysis steps (default: 50)
        port: Specific Ghidra instance port (optional)
        
    Returns:
        dict: Data flow analysis results
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }
    
    port = _get_instance_port(port)
    
    params = {
        "address": address,
        "direction": direction,
        "max_steps": max_steps
    }
    
    response = safe_get(port, "analysis/dataflow", params)
    return simplify_response(response)

@mcp.tool()
@text_output
def ui_get_current_address(port: int | None = None) -> dict:
    """Get the address currently selected in Ghidra's UI

    Args:
        port: Specific Ghidra instance port (optional)

    Returns:
        Dict containing address information or error
    """
    port = _get_instance_port(port)
    response = safe_get(port, "address")
    return simplify_response(response)

@mcp.tool()
@text_output
def ui_get_current_function(port: int | None = None) -> dict:
    """Get the function currently selected in Ghidra's UI

    Args:
        port: Specific Ghidra instance port (optional)

    Returns:
        Dict containing function information or error
    """
    port = _get_instance_port(port)
    response = safe_get(port, "function")
    return simplify_response(response)

@mcp.tool()
@text_output
def comments_set(address: str, comment: str = "", comment_type: str = "plate", port: int | None = None) -> dict:
    """Set a comment at the specified address

    Args:
        address: Memory address in hex format
        comment: Comment text (empty string removes comment)
        comment_type: Type of comment - "plate", "pre", "post", "eol", "repeatable" (default: "plate")
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Operation result
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)
    payload = {
        "comment": comment
    }

    response = safe_post(port, f"memory/{address}/comments/{comment_type}", payload)
    return simplify_response(response)

@mcp.tool()
@text_output
def comments_get(address: str, comment_type: str = "plate", port: int | None = None) -> dict:
    """Get a comment at the specified address

    Args:
        address: Memory address in hex format
        comment_type: Type of comment - "plate", "pre", "post", "eol", "repeatable"
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Operation result containing comment text
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)
    response = safe_get(port, f"memory/{address}/comments/{comment_type}")
    return simplify_response(response)

@mcp.tool()
@text_output
def functions_set_comment(address: str, comment: str = "", port: int | None = None) -> dict:
    """Set a decompiler-friendly comment (tries function comment, falls back to pre-comment)

    Args:
        address: Memory address in hex format (preferably function entry point)
        comment: Comment text (empty string removes comment)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Operation result
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "Address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port_to_use = _get_instance_port(port)

    # Try setting as a function comment first using PATCH
    try:
        func_patch_payload = {
            "comment": comment
        }
        patch_response = safe_patch(port_to_use, f"functions/{address}", func_patch_payload)
        if patch_response.get("success", False):
            return simplify_response(patch_response) # Success setting function comment
        else:
             print(f"Note: Failed to set function comment via PATCH on {address}, falling back. Error: {patch_response.get('error')}", file=sys.stderr)
    except Exception as e:
        print(f"Exception trying function comment PATCH: {e}. Falling back.", file=sys.stderr)
        # Fall through to set pre-comment if PATCH fails

    # Fallback: Set as a "pre" comment using the comments_set tool
    print(f"Falling back to setting 'pre' comment for address {address}", file=sys.stderr)
    return comments_set(address=address, comment=comment, comment_type="pre", port=port_to_use)


# ================= Kuna tools =================
# Kuna is a standalone decompiler CLI. These tools drive it on the machine
# where the bridge runs: they need no Ghidra instance and never touch the
# REST API. The integration is opt-in (see the Kuna integration section).

@mcp.tool()
@text_output
def kuna_status() -> dict:
    """Report whether the Kuna integration is enabled and ready to use.

    Kuna (https://github.com/Noelo-Lab/kuna) is a standalone decompiler CLI
    that the bridge drives directly, so the kuna_* tools need no running
    Ghidra instance and work with any Ghidra version.

    The integration is opt-in, because it lets the bridge run a program on
    the host: enable it with the GHYDRA_KUNA=1 environment variable, or with
    "kuna": {"enabled": true} in ~/.ghydra/config.json. The config file wins
    when both are set.

    The report carries two lists: the export jobs this bridge process knows
    about, and the exports on disk. The second one outlives the bridge, and
    is what the kuna://export/ resources are addressed by.

    Returns:
        dict: 'enabled', the resolved binary path and version, where the
              opt-in came from, the export jobs known to this bridge and the
              exports on disk
    """
    config = _kuna_config()
    if config.get("enabled") is not None:
        source = "the config file"
    elif KUNA_ENV_ENABLED in os.environ:
        source = f"${KUNA_ENV_ENABLED}"
    else:
        source = "nothing (the integration is off)"

    executable = _kuna_binary()
    version = None
    if executable:
        outcome = _kuna_run(["--version"], timeout=30)
        if outcome["code"] == 0:
            version = outcome["stdout"].strip() or None

    with _kuna_jobs_lock:
        jobs = [_kuna_job_view(job) for job in _kuna_jobs.values()]

    return {
        "success": True,
        "result": {
            "enabled": _kuna_enabled(),
            "source": source,
            "binary": executable,
            "version": version,
            "config_file": KUNA_CONFIG_FILE,
            "work_dir": KUNA_WORK_DIR,
            "jobs": jobs,
            "exports": _kuna_list_exports(),
        },
    }


@mcp.tool()
@text_output
def kuna_summary(binary_path: str, mode: str | None = None) -> dict:
    """Summarize a binary: function count, entry point, reachability, size.

    This is the cheapest way to size up an image. It still loads and
    analyses the whole binary, so a large file costs seconds - for a full
    analysis, start an export with kuna_export_start and read the result
    from disk.

    Args:
        binary_path: Path to the executable to analyze
        mode: Optional kuna mode preset (auto, reliable, aggressive, fast)

    Returns:
        dict: The kuna summary document
    """
    guard = _kuna_guard()
    if guard:
        return guard

    target = _kuna_target(binary_path)
    if isinstance(target, dict):
        return target

    args = ["functions", target, "--summary", "--json"]
    if mode:
        args += ["--mode", mode]
    return _kuna_json(args)


@mcp.tool()
@text_output
def kuna_functions(binary_path: str, name_filter: str | None = None,
                   offset: int = 0, limit: int = 100) -> dict:
    """List the functions kuna recovered from a binary.

    Args:
        binary_path: Path to the executable to analyze
        name_filter: Optional case-insensitive substring filter on the name
        offset: Pagination offset
        limit: Maximum number of functions to return

    Returns:
        dict: The function list, with 'meta.total' holding the full count
    """
    guard = _kuna_guard()
    if guard:
        return guard

    target = _kuna_target(binary_path)
    if isinstance(target, dict):
        return target

    outcome = _kuna_json(["functions", target, "--json"])
    if not outcome.get("success"):
        return outcome

    result = outcome["result"]
    functions = result.get("functions", []) if isinstance(result, dict) else []
    if name_filter:
        needle = name_filter.lower()
        functions = [fn for fn in functions if needle in str(fn.get("name", "")).lower()]

    total = len(functions)
    window = functions[offset:offset + limit]
    return {
        "success": True,
        "result": window,
        "meta": {"total": total, "offset": offset, "limit": limit},
    }


@mcp.tool()
@text_output
def kuna_decompile(binary_path: str, function: str, addr: bool = False,
                   mode: str | None = None, max_lines: int | None = None) -> dict:
    """Decompile one function with kuna.

    Args:
        binary_path: Path to the executable
        function: Function name, or an address when addr is true
        addr: Treat the target as an address instead of a name
        mode: Optional kuna mode preset (auto, reliable, aggressive, fast)
        max_lines: Optional cap on the number of returned lines

    Returns:
        dict: The decompiled function
    """
    guard = _kuna_guard()
    if guard:
        return guard

    target = _kuna_target(binary_path)
    if isinstance(target, dict):
        return target

    args = ["decompile", target, function, "--json"]
    if addr:
        args.append("--addr")
    if mode:
        args += ["--mode", mode]
    return _kuna_json(args)


@mcp.tool()
@text_output
def kuna_disassemble(binary_path: str, target: str, count: int | None = None,
                     bytes: int | None = None, addr: bool = False,
                     mode: str | None = None) -> dict:
    """Disassemble a function or an address range with kuna.

    Args:
        binary_path: Path to the executable
        target: Function name, address, or "0xstart-0xend" range
        count: Optional maximum number of instructions
        bytes: Optional maximum number of bytes
        addr: Treat the target as an address instead of a name
        mode: Optional kuna mode preset

    Returns:
        dict: The disassembled instructions
    """
    guard = _kuna_guard()
    if guard:
        return guard

    binary = _kuna_target(binary_path)
    if isinstance(binary, dict):
        return binary

    args = ["disassemble", binary, target, "--json"]
    if count is not None:
        args += ["--count", str(count)]
    if bytes is not None:
        args += ["--bytes", str(bytes)]
    if addr:
        args.append("--addr")
    if mode:
        args += ["--mode", mode]
    return _kuna_json(args)


@mcp.tool()
@text_output
def kuna_read(binary_path: str, target: str, bytes: int = 64,
              addr: bool = False) -> dict:
    """Read raw bytes with kuna, as a hex dump.

    Args:
        binary_path: Path to the executable
        target: Function name, address, or "0xstart-0xend" range
        bytes: Number of bytes to read
        addr: Treat the target as an address instead of a name

    Returns:
        dict: The bytes, as a hex dump
    """
    guard = _kuna_guard()
    if guard:
        return guard

    binary = _kuna_target(binary_path)
    if isinstance(binary, dict):
        return binary

    args = ["read", binary, target, "--bytes", str(bytes), "--json"]
    if addr:
        args.append("--addr")
    return _kuna_json(args)


@mcp.tool()
@text_output
def kuna_strings(binary_path: str, pattern: str, limit: int = 50,
                 min_length: int = 5, encoding: str = "ascii",
                 section: str | None = None) -> dict:
    """Search the strings of a binary with kuna.

    A filter is mandatory: an unfiltered scan of a large binary returns
    hundreds of kilobytes of text, which is noise for the caller.

    Args:
        binary_path: Path to the executable
        pattern: Regular expression the string must match
        limit: Maximum number of strings to return
        min_length: Minimum length of a string
        encoding: ascii, utf16 or all
        section: Optional section name to restrict the scan to

    Returns:
        dict: The matching strings, with the functions that reference them
    """
    guard = _kuna_guard()
    if guard:
        return guard

    if not pattern:
        return _kuna_error("pattern is required: an unfiltered string scan is too large to return")

    binary = _kuna_target(binary_path)
    if isinstance(binary, dict):
        return binary

    args = ["strings", binary, "--filter", pattern, "--min-length", str(min_length),
            "--encoding", encoding, "--json"]
    if section:
        args += ["--section", section]

    outcome = _kuna_json(args)
    if not outcome.get("success"):
        return outcome

    result = outcome["result"]
    strings = result.get("strings", []) if isinstance(result, dict) else []
    total = result.get("count", len(strings))
    trimmed = dict(result) if isinstance(result, dict) else {}
    trimmed["strings"] = strings[:limit]
    trimmed["count"] = total
    trimmed["returned"] = len(trimmed["strings"])
    return {"success": True, "result": trimmed}


@mcp.tool()
@text_output
def kuna_crypto(binary_path: str, algorithm: str | None = None,
                section: str | None = None) -> dict:
    """Scan a binary for crypto constants with kuna.

    Finds AES/SHA/MD5/CRC/TEA/Base64 constants and the functions that use
    them, which is where a cryptographic routine usually starts.

    Args:
        binary_path: Path to the executable
        algorithm: Optional algorithm name filter (e.g. AES, SHA)
        section: Optional section name to restrict the scan to

    Returns:
        dict: The constants found, with their referencing functions
    """
    guard = _kuna_guard()
    if guard:
        return guard

    binary = _kuna_target(binary_path)
    if isinstance(binary, dict):
        return binary

    args = ["crypto", binary, "--json"]
    if algorithm:
        args += ["--algorithm", algorithm]
    if section:
        args += ["--section", section]
    return _kuna_json(args)


@mcp.tool()
@text_output
def kuna_xrefs(binary_path: str, target: str, direction: str = "from",
               kind: str | None = None) -> dict:
    """Find the cross-references of a symbol or address with kuna.

    Args:
        binary_path: Path to the executable
        target: Function name or address
        direction: "from" (who references it) or "to" (what it references)
        kind: Optional reference kind filter (call, jump, data, read, write)

    Returns:
        dict: The cross-references
    """
    guard = _kuna_guard()
    if guard:
        return guard

    binary = _kuna_target(binary_path)
    if isinstance(binary, dict):
        return binary

    if direction not in ("from", "to"):
        return _kuna_error("direction must be 'from' or 'to'")

    args = ["xrefs", binary, f"--{direction}", target, "--json"]
    if kind:
        args += ["--kind", kind]
    return _kuna_json(args)


@mcp.tool()
@text_output
def kuna_unpack(binary_path: str, output: str | None = None) -> dict:
    """Unpack a UPX-packed executable with kuna.

    Args:
        binary_path: Path to the packed executable
        output: Optional path for the unpacked file

    Returns:
        dict: The unpack result
    """
    guard = _kuna_guard()
    if guard:
        return guard

    binary = _kuna_target(binary_path)
    if isinstance(binary, dict):
        return binary

    args = ["unpack", binary, "--json"]
    if output:
        args += ["-o", os.path.abspath(os.path.expanduser(output))]
    return _kuna_json(args)


@mcp.tool()
@text_output
def kuna_export_start(binary_path: str, functions: str | None = None,
                      jobs: str = "auto", job_id: str | None = None) -> dict:
    """Export a binary to disk with kuna, in the background.

    "kuna decompile-project" loads and analyses the image once, then writes
    the recovered C, the disassembly and an index.jsonl into a directory.
    That export is the cheap way to work on a large binary: every function is
    then read from the files on disk instead of paying the analysis cost
    again on each call.

    A complete export that already covers the request is reused instead of
    re-analysed, and the job record says so with "reused": true. The export
    directory is named after a digest of the path and the mtime, so the files
    on disk belong to this binary.

    The export can also be read as MCP resources, addressed by that digest:
    kuna://exports lists them, and kuna://export/{digest}/index.jsonl,
    kuna://export/{digest}/{function}.c and kuna://export/{digest}/{function}.asm
    serve the files themselves. Those URIs survive a restart of this bridge,
    which a job id does not.

    Args:
        binary_path: Path to the executable to export
        functions: Optional comma-separated function names to export
        jobs: Worker count for the export ("auto" by default)
        job_id: Optional id for the job (generated when omitted)

    Returns:
        dict: The job record: id, binary, directory and status
    """
    guard = _kuna_guard()
    if guard:
        return guard

    target = _kuna_target(binary_path)
    if isinstance(target, dict):
        return target

    executable = _kuna_binary()
    if not executable:
        return _kuna_error("the kuna binary was not found")

    work_dir = _kuna_work_dir(target)

    with _kuna_jobs_lock:
        for job in _kuna_jobs.values():
            if job["dir"] == work_dir and job["status"] == "running":
                return _kuna_error(
                    f"an export is already running for this binary (job {job['id']})"
                )

    try:
        os.makedirs(work_dir, exist_ok=True)
    except OSError as exc:
        return _kuna_error(
            f"could not create the export directory {work_dir}: {exc}", code="KUNA_IO"
        )

    # Reuse a complete export instead of paying the analysis again. Kuna loads
    # and analyses the whole image on every invocation, so a second export of
    # the same binary is the most expensive no-op there is. The digest covers
    # the path and the mtime, so the files on disk belong to this binary.
    state = _kuna_export_state(work_dir)
    if state and _kuna_export_covers(state, functions):
        if not _kuna_read_export_meta(work_dir):
            _kuna_write_export_meta(work_dir, target)
        _kuna_sync_resources()
        identifier = job_id or ("kuna-" + hashlib.sha256(
            f"{target}|{time.time()}".encode("utf-8")).hexdigest()[:8])
        now = time.time()
        job = {
            "id": identifier,
            "binary": target,
            "dir": work_dir,
            "status": "done",
            "started_at": now,
            "finished_at": now,
            "returncode": 0,
            "error": None,
            "pid": None,
            "reused": True,
            "functions": state["functions"],
            "failed": state["failed"],
        }
        with _kuna_jobs_lock:
            _kuna_jobs[identifier] = job
        return {"success": True, "result": _kuna_job_view(job)}

    args = ["decompile-project", target, "-o", work_dir, "--stream", "--jobs", str(jobs)]
    if functions:
        args += ["--functions", functions]

    identifier = job_id or ("kuna-" + hashlib.sha256(
        f"{target}|{time.time()}".encode("utf-8")).hexdigest()[:8])

    log_path = os.path.join(work_dir, "export.log")
    err_path = os.path.join(work_dir, "export.err")
    try:
        log_handle = open(log_path, "w", encoding="utf-8")
        err_handle = open(err_path, "w", encoding="utf-8")
    except OSError as exc:
        return _kuna_error(f"could not open the export logs: {exc}", code="KUNA_IO")

    try:
        process = subprocess.Popen(
            [executable, *args],
            stdout=log_handle,
            stderr=err_handle,
            stdin=subprocess.DEVNULL,
        )
    except OSError as exc:
        log_handle.close()
        err_handle.close()
        return _kuna_error(f"could not launch kuna: {exc}", code="KUNA_LAUNCH")

    job = {
        "id": identifier,
        "binary": target,
        "dir": work_dir,
        "status": "running",
        "started_at": time.time(),
        "finished_at": None,
        "returncode": None,
        "error": None,
        "pid": process.pid,
        "reused": False,
    }
    with _kuna_jobs_lock:
        _kuna_jobs[identifier] = job

    def _watch() -> None:
        returncode = process.wait()
        log_handle.close()
        err_handle.close()
        detail = None
        if returncode != 0:
            try:
                with open(err_path, "r", encoding="utf-8", errors="replace") as handle:
                    detail = handle.read().strip()[-2000:] or None
            except OSError:
                detail = None
        if returncode == 0:
            _kuna_write_export_meta(work_dir, target, functions=functions)
            _kuna_sync_resources()
        with _kuna_jobs_lock:
            job["status"] = "failed" if returncode != 0 else "done"
            job["returncode"] = returncode
            job["finished_at"] = time.time()
            job["error"] = detail

    threading.Thread(target=_watch, daemon=True, name=f"KunaExport-{identifier}").start()

    return {"success": True, "result": _kuna_job_view(job)}


@mcp.tool()
@text_output
def kuna_export_status(job_id: str) -> dict:
    """Report the progress of a kuna export job.

    Args:
        job_id: The id returned by kuna_export_start

    Returns:
        dict: The job record, including the live counters kuna writes while
              it streams
    """
    guard = _kuna_guard()
    if guard:
        return guard

    with _kuna_jobs_lock:
        job = _kuna_jobs.get(job_id)
    if job is None:
        return _kuna_error(
            f"unknown job id '{job_id}'; jobs live in the bridge process that started them"
        )
    return {"success": True, "result": _kuna_job_view(job)}


@mcp.tool()
@text_output
def kuna_export_read(job_id: str | None = None, function: str | None = None,
                     artifact: str = "c", max_bytes: int = 40000,
                     directory: str | None = None) -> dict:
    """Read a function out of a kuna export.

    The export is addressed either by the job that made it, or by its
    directory. The directory may be a path or the 12-character digest the
    export is named after, which is what the kuna://export/ resources use.
    A digest outlives the bridge process that made the export, so an export
    written by the CLI is readable here too.

    Args:
        job_id: The id returned by kuna_export_start
        function: Function name to read. Without it, the exported function
                  names are listed.
        artifact: "c" (recovered C), "asm" (disassembly), "index" (the
                  function index) or "readme" (the export report)
        max_bytes: Maximum bytes of text to return
        directory: The export directory, or its digest. Used when job_id is
                   not given.

    Returns:
        dict: The requested text, or the list of exported functions
    """
    guard = _kuna_guard()
    if guard:
        return guard

    work_dir = None
    binary = None
    status = "unknown"
    if directory:
        try:
            work_dir = _kuna_resolve_export_dir(directory)
        except ValueError as exc:
            return _kuna_error(str(exc), code="KUNA_NO_DIR")
    elif job_id:
        with _kuna_jobs_lock:
            job = _kuna_jobs.get(job_id)
        if job is None:
            return _kuna_error(
                f"unknown job id '{job_id}'; jobs live in the bridge process that "
                f"started them, so address the export by its directory or digest",
                code="KUNA_NO_DIR",
            )
        work_dir = job["dir"]
        binary = job["binary"]
        status = job["status"]
    else:
        return _kuna_error(
            "either job_id or directory is required", code="KUNA_NO_DIR"
        )

    if not work_dir or not os.path.isdir(work_dir):
        return _kuna_error(f"no such export directory: {work_dir}", code="KUNA_NO_DIR")

    if not binary:
        binary = _kuna_export_binary(work_dir)

    records = _kuna_index_records(work_dir)

    if artifact == "readme":
        path = os.path.join(work_dir, "README.md")
        if not os.path.isfile(path):
            return _kuna_error("the export has no README.md", code="KUNA_NO_FILE")
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                text = handle.read(max_bytes if max_bytes else -1)
        except OSError as exc:
            return _kuna_error(
                f"could not read the export README: {exc}", code="KUNA_IO"
            )
        return {"success": True, "result": {"artifact": "readme", "text": text}}

    if not records:
        return _kuna_error(
            f"the export for {binary or work_dir} has no index yet "
            f"(job status: {status})",
            code="KUNA_NO_INDEX",
        )

    if artifact == "index":
        return {
            "success": True,
            "result": {
                "artifact": "index",
                "binary": binary,
                "total": len(records),
                "functions": [
                    {
                        "name": record.get("name"),
                        "addr": record.get("addr"),
                        "size": record.get("size"),
                        "error": record.get("error"),
                    }
                    for record in records
                ],
            },
        }

    if artifact not in ("c", "asm"):
        return _kuna_error(
            "artifact must be one of: c, asm, index, readme", code="KUNA_BAD_ARTIFACT"
        )

    if not function:
        return {
            "success": True,
            "result": {
                "artifact": artifact,
                "binary": binary,
                "total": len(records),
                "functions": [
                    {
                        "name": record.get("name"),
                        "addr": record.get("addr"),
                        "size": record.get("size"),
                        "error": record.get("error"),
                    }
                    for record in records
                ],
            },
        }

    record = _kuna_find_record(records, function)
    if record is None:
        return _kuna_error(
            f"function '{function}' is not in the export index", code="KUNA_NO_FUNCTION"
        )

    if artifact == "c":
        text = _kuna_extract_c(work_dir, record, max_bytes)
    else:
        text = _kuna_extract_asm(work_dir, record.get("name", function), max_bytes)

    if text is None:
        return _kuna_error(
            f"could not read the {artifact} of '{function}' from the export",
            code="KUNA_IO",
        )

    return {
        "success": True,
        "result": {
            "artifact": artifact,
            "function": record.get("name"),
            "addr": record.get("addr"),
            "size": record.get("size"),
            "text": text,
        },
    }


# ================= Kuna resources =================
#
# The export is the durable artifact: the analysis is expensive and the files
# on disk are the cheap way to read it. The job registry is not durable - it
# lives in this process - so the export is also exposed as MCP resources,
# addressed by the digest it is named after. A digest outlives the bridge, so
# an export written by the CLI is readable here too.
#
# The retrieval loop is the RAG loop with exact addressing:
#   1. read kuna://exports                   - which binaries have been exported
#   2. read kuna://export/<digest>/index.jsonl - the function list
#   3. read kuna://export/<digest>/<function>.c - that one function
#
# A function name goes into the URI percent-encoded, because a name may hold
# a slash and the URI may not.

KUNA_RESOURCE_ROOT = "kuna://export"

# The URIs already registered as concrete resources, so a rescan does not
# register the same export twice.
_kuna_registered_resources: set = set()


def _kuna_export_dir_for(digest: str) -> str:
    """The export directory a digest names.

    A digest is 12 hex characters. Anything else could name a path outside
    the work directory, so it is refused rather than resolved.
    """
    if not KUNA_DIGEST_RE.match(str(digest or "")):
        raise ValueError(
            f"'{digest}' is not an export digest; it is 12 hex characters"
        )
    return os.path.join(KUNA_WORK_DIR, digest)


def _kuna_resource_text(directory: str, relative: str) -> str:
    """Read a file out of an export directory."""
    path = os.path.join(directory, relative)
    if not os.path.isfile(path):
        raise ValueError(f"the export has no {relative}")
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def _kuna_resource_function(digest: str, function: str, artifact: str) -> str:
    """Read one function's artifact out of an export."""
    directory = _kuna_export_dir_for(digest)
    name = unquote(function)
    records = _kuna_index_records(directory)
    record = _kuna_find_record(records, name)
    if record is None:
        raise ValueError(f"function '{name}' is not in the export index")
    if artifact == "c":
        text = _kuna_extract_c(directory, record, 0)
    else:
        text = _kuna_extract_asm(directory, record.get("name", name), 0)
    if text is None:
        raise ValueError(f"could not read the {artifact} of '{name}' from the export")
    return text


@mcp.resource("kuna://exports", name="kuna-exports", mime_type="application/json")
def kuna_exports_resource() -> str:
    """Every Kuna export on this machine, as a JSON manifest.

    Each entry carries the digest the export is named after, the binary it
    came from, how many functions it holds and whether it is still being
    written. The digest is what the kuna://export/ resources are addressed
    by, and it is the only identifier that survives a restart of the bridge.
    """
    exports = _kuna_list_exports()
    return json.dumps({"count": len(exports), "exports": exports}, indent=2)


@mcp.resource("kuna://export/{digest}/index.jsonl", name="kuna-export-index",
              mime_type="application/x-ndjson")
def kuna_export_index_resource(digest: str) -> str:
    """The function index of one export: one JSON record per line.

    Each record names a function, its address and its size, and points at the
    block of recovered C that belongs to it.
    """
    return _kuna_resource_text(_kuna_export_dir_for(digest), "index.jsonl")


@mcp.resource("kuna://export/{digest}/README.md", name="kuna-export-readme",
              mime_type="text/markdown")
def kuna_export_readme_resource(digest: str) -> str:
    """The report Kuna wrote next to an export."""
    return _kuna_resource_text(_kuna_export_dir_for(digest), "README.md")


@mcp.resource("kuna://export/{digest}/{function}.c", name="kuna-export-c",
              mime_type="text/x-c")
def kuna_export_c_resource(digest: str, function: str) -> str:
    """The recovered C of one function in one export.

    The function name is percent-encoded in the URI.
    """
    return _kuna_resource_function(digest, function, "c")


@mcp.resource("kuna://export/{digest}/{function}.asm", name="kuna-export-asm",
              mime_type="text/plain")
def kuna_export_asm_resource(digest: str, function: str) -> str:
    """The disassembly of one function in one export.

    The function name is percent-encoded in the URI.
    """
    return _kuna_resource_function(digest, function, "asm")


def _kuna_sync_resources() -> None:
    """Register the exports on disk as concrete resources.

    The templates above serve any export by digest, but a client that only
    reads resources/list would not see them. This puts the index and the
    report of every export on disk into that listing.
    """
    for export in _kuna_list_exports():
        digest = export["digest"]
        directory = export["dir"]
        for relative, mime in (("index.jsonl", "application/x-ndjson"),
                               ("README.md", "text/markdown")):
            uri = f"{KUNA_RESOURCE_ROOT}/{digest}/{relative}"
            if uri in _kuna_registered_resources:
                continue
            if not os.path.isfile(os.path.join(directory, relative)):
                continue
            _kuna_registered_resources.add(uri)
            mcp.add_resource(FunctionResource(
                uri=AnyUrl(uri),
                name=f"kuna-export-{digest}-{relative}",
                description=f"The {relative} of the Kuna export {digest}.",
                mime_type=mime,
                fn=(lambda d=directory, r=relative: _kuna_resource_text(d, r)),
            ))


# The exports that already exist on disk are worth showing before the first
# export of this session.
_kuna_sync_resources()


# ================= x64dbg integration =================
# The x64dbg plugin (https://github.com/duty1g/x64dbg-mcp-server) is an MCP
# server that lives inside the debugger: it answers JSON-RPC 2.0 POSTed to "/"
# with a bearer token, and every request stands alone - there is no session
# and no handshake to keep alive.
#
# These tools drive it from the bridge, so an agent gets the static side
# (Ghidra) and the dynamic side (x64dbg) in one place. The two disagree
# about addresses: Ghidra works on the image as it sits in the file, x64dbg on
# the loaded process. The translation between them is what makes the pair
# worth having, and it is what x64dbg_target and x64dbg_breakpoint_at do.
#
# The plugin's own tools are not proxied one by one - eighty of them would
# drown the agent's tool list. The catalogue is exposed instead, and
# x64dbg_call invokes any of them by name.

X64DBG_DEFAULT_PORT = 9094        # the plugin's default for a 64-bit debuggee
X64DBG_X32_PORT = 9095            # and for a 32-bit one
X64DBG_PORT_SCAN = 32             # ports to try when looking for an instance
X64DBG_ENV_HOST = "GHYDRA_X64DBG_HOST"
X64DBG_ENV_PORT = "GHYDRA_X64DBG_PORT"
X64DBG_ENV_TOKEN = "GHYDRA_X64DBG_TOKEN"
# The installation, where the plugin's own mcp_config.json - and with it the
# token - is found. The token is the one thing that cannot be guessed, so
# this is what makes the integration usable without editing a config file.
X64DBG_ENV_PATH = "GHYDRA_X64DBG_PATH"
# The plugin asks the OS for the path of the *process*, so the file lands
# next to x64dbg.exe and not next to the plugin DLL.
X64DBG_PLUGIN_CONFIG_NAME = "mcp_config.json"
X64DBG_PROTOCOL_VERSION = "2024-11-05"

# How many times a connection error is retried. The plugin hangs up after
# every response, and a local TCP connection is reset every now and then on
# Windows - measured at 7% of the connections on this machine, with curl and
# with plain sockets alike, so it is the network stack and not this client.
X64DBG_CONNECT_ATTEMPTS = 3

# How many times a request that is safe to repeat is sent in all. A reset is
# 7% of the connections, so two in a row - what a read-only request has to
# survive - happens about once in every two hundred calls. Three attempts,
# two re-sends, make that rare enough not to be a test flake.
X64DBG_DELIVERED_ATTEMPTS = 3

# How long a connection may take to come up, and how long the server may
# take to answer. The two are separate because they mean different things: a
# closed local port does not refuse straight away on Windows - the SYN hangs
# and is only refused about two seconds later - so a probe must not wait for
# that, while a tool that blocks (WaitForEvent, run) must be allowed to take
# its time.
X64DBG_CONNECT_TIMEOUT = 2.0
X64DBG_READ_TIMEOUT = 30.0
X64DBG_PROBE_CONNECT_TIMEOUT = 0.35
X64DBG_PROBE_READ_TIMEOUT = 2.0

# How many times the ports where the server almost always is - the configured
# one and the two defaults - are probed. The walk asks for one attempt per
# port: a closed port stays closed, and every extra attempt costs the whole
# connect timeout again. The likely ones get more, because the machine
# resets about one loopback connection in fourteen, and one reset must not
# make the bridge say that the debugger is not there.
X64DBG_PROBE_ATTEMPTS = 3

# How long the likely ports are given to answer. A closed port is out at the
# connect stage, so this only bounds a server that accepted the connection
# and went quiet - and a loaded machine can take a couple of seconds to give
# that answer. Writing the debugger off for that would be wrong.
X64DBG_LIKELY_PROBE_READ_TIMEOUT = 5.0

# Which plugin tools may be repeated when the transport fails. The plugin
# marks every tool as read-only or not, and the hint is in its catalogue.
_X64DBG_READ_ONLY: Dict[str, bool] = {}

# The input schema of each plugin tool, from the same catalogue. It says what
# type every parameter is, which is what puts back the types a client
# flattened into text.
_X64DBG_SCHEMAS: Dict[str, dict] = {}

# Where the plugin was found, keyed by the configuration it was found with.
# The plugin does not move while the debugger runs, and the scan that looks
# for it opens ninety connections - so the port is kept and probed once
# before it is used.
_X64DBG_INSTANCE: Dict[str, dict] = {}

# The machine-readable reasons a call can fail. The CLI carries the same list,
# so an agent sees one taxonomy whichever side it drives.
X64DBG_ERROR_CODES = (
    "X64DBG_ERROR",         # the generic fallback
    "X64DBG_DISABLED",      # no token, so no way to talk to the server
    "X64DBG_MISSING",       # nothing answered on the port
    "X64DBG_TIMEOUT",       # the server did not answer in time
    "X64DBG_UNCERTAIN",     # the request was sent but the answer was lost
    "X64DBG_UNAUTHORIZED",  # the bearer token did not match
    "X64DBG_NO_SESSION",    # no debug session in x64dbg
    "X64DBG_NO_TOOL",       # the plugin has no tool with that name
    "X64DBG_BAD_ARGS",      # the tool rejected the arguments
    "X64DBG_NO_MATCH",      # the binary does not match any loaded module
)


def _x64dbg_error(message: str, code: str = "X64DBG_ERROR") -> dict:
    """The error envelope, with a code the agent can branch on."""
    return {"success": False, "error": {"code": code, "message": message}}


def _x64dbg_config() -> dict:
    """Read the "x64dbg" section of ~/.ghydra/config.json.

    Never raises: a missing or malformed config simply means "not configured".
    """
    try:
        # The same file the Kuna integration reads: ~/.ghydra/config.json.
        with open(KUNA_CONFIG_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    section = data.get("x64dbg")
    return section if isinstance(section, dict) else {}


def _x64dbg_plugin_config(install: str) -> dict:
    """The plugin's own settings, from the mcp_config.json next to x64dbg.exe.

    The file sits next to the executable, or in one of the plugin folders;
    which one depends on how x64dbg was unpacked.
    """
    root = os.path.abspath(os.path.expanduser(str(install or "")))
    candidates = [
        os.path.join(root, X64DBG_PLUGIN_CONFIG_NAME),
        os.path.join(root, "x64", X64DBG_PLUGIN_CONFIG_NAME),
        os.path.join(root, "x32", X64DBG_PLUGIN_CONFIG_NAME),
        os.path.join(root, "release", "x64", X64DBG_PLUGIN_CONFIG_NAME),
        os.path.join(root, "release", "x32", X64DBG_PLUGIN_CONFIG_NAME),
        os.path.join(root, "x64", "plugins", X64DBG_PLUGIN_CONFIG_NAME),
        os.path.join(root, "x32", "plugins", X64DBG_PLUGIN_CONFIG_NAME),
        os.path.join(root, "release", "x64", "plugins", X64DBG_PLUGIN_CONFIG_NAME),
        os.path.join(root, "release", "x32", "plugins", X64DBG_PLUGIN_CONFIG_NAME),
        os.path.join(root, "plugins", X64DBG_PLUGIN_CONFIG_NAME),
    ]
    for candidate in candidates:
        try:
            with open(candidate, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            return data
    return {}


def _x64dbg_settings() -> dict:
    """Where the x64dbg MCP server is, and the token to talk to it.

    The configuration file wins over the environment. The token cannot be
    guessed: the plugin writes it to "mcp_config.json" next to x64dbg.exe, so
    pointing at an installed x64dbg with "path" - or GHYDRA_X64DBG_PATH - is
    enough to find it.
    """
    section = _x64dbg_config()
    host = section.get("host") or os.environ.get(X64DBG_ENV_HOST) or "127.0.0.1"
    port = section.get("port") or os.environ.get(X64DBG_ENV_PORT) or X64DBG_DEFAULT_PORT
    token = section.get("token") or os.environ.get(X64DBG_ENV_TOKEN) or ""
    install = section.get("path") or os.environ.get(X64DBG_ENV_PATH) or ""

    plugin = _x64dbg_plugin_config(install) if install else {}
    if not token:
        token = plugin.get("AuthToken") or ""
    # The plugin file fills the blanks and only the blanks: a host or a port
    # that came from the config file or from the environment is a decision
    # the user made, and the plugin file does not get to overrule it.
    if (not section.get("host") and not os.environ.get(X64DBG_ENV_HOST)
            and plugin.get("IpAddress")):
        host = plugin["IpAddress"]
    if (not section.get("port") and not os.environ.get(X64DBG_ENV_PORT)
            and plugin.get("Port")):
        port = plugin["Port"]

    try:
        port = int(port)
    except (TypeError, ValueError):
        port = X64DBG_DEFAULT_PORT

    return {"host": str(host), "port": port, "token": str(token), "path": str(install)}


def _x64dbg_classify(message: str) -> str:
    """The code that matches an error message from the plugin.

    The plugin answers with prose - "Error: No active debug session." - so
    the reason has to be read out of it.
    """
    text = str(message or "").lower()
    if "no active debug session" in text or "tool requires an active" in text:
        return "X64DBG_NO_SESSION"
    if "no such tool" in text or "unknown tool" in text or "not found" in text:
        return "X64DBG_NO_TOOL"
    if "required" in text or "invalid" in text or "missing" in text:
        return "X64DBG_BAD_ARGS"
    return "X64DBG_ERROR"


def _x64dbg_never_sent(exc: BaseException) -> bool:
    """Whether the request was never handed to the server.

    A connection that could not be established is one thing: the request
    never left, so trying again is safe. A connection that died while the
    answer was coming is another - there the server may already have acted
    on the request, and only a request that is safe to repeat may be tried
    again.

    urllib3 names the two cases "NewConnectionError" and "ProtocolError".
    The name is checked instead of the class, so this file does not have to
    depend on urllib3 directly: it comes with requests, but the bridge is a
    standalone script with its own dependency list.
    """
    cause: Optional[BaseException] = exc
    while cause is not None:
        if type(cause).__name__ == "NewConnectionError":
            return True
        cause = cause.__cause__ or cause.__context__
    return False


def _x64dbg_uncertain(reason: str) -> str:
    """The failure when a request was delivered and its answer was lost.

    The local network stack resets a loopback connection every now and then,
    so a request can reach the debugger and still lose its answer on the way
    back. The debugger may then have acted on it - and a request that changes
    the debuggee is never sent twice, because the second one would act on an
    unknown state. The caller has to be told that the state is unknown
    instead of being told that the server is gone.
    """
    return ("the x64dbg MCP server took the request but the answer was lost "
            f"({reason}). The request was not repeated, so the debugger may "
            "already have acted on it.")


def _x64dbg_repeatable(reason: str) -> str:
    """The failure when a request that may be sent again did not get through."""
    return f"{reason}. The request is safe to repeat."


def _x64dbg_post(host: str, port: int, token: str, method: str,
                 params: Optional[dict] = None, timeout: Optional[float] = None,
                 connect_timeout: Optional[float] = None,
                 idempotent: bool = False,
                 connect_attempts: int = X64DBG_CONNECT_ATTEMPTS) -> Any:
    """One JSON-RPC request to the x64dbg MCP server, and its result.

    Raises _X64dbgFailure with a machine-readable code.

    The request does not go through the shared session: the plugin closes the
    connection after every response, and a pooled connection would be reused
    after the server had already hung up on it.

    idempotent says the request may be sent again when the transport fails:
    a handshake, the catalogue, or a tool the plugin marks as read-only. A
    tool that changes the debuggee is never repeated that way, because the
    first attempt may already have reached it.

    connect_attempts is how many times to try when the connection never
    came up. The request was never sent in that case, so trying again is
    safe - but a closed port stays closed, so the port scan asks for one
    attempt only.
    """
    payload: Dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": int(time.time() * 1000) % 1000000,
        "method": method,
    }
    if params is not None:
        payload["params"] = params

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    url = f"http://{host}:{int(port)}/"
    connect_limit = connect_timeout if connect_timeout is not None else X64DBG_CONNECT_TIMEOUT
    read_limit = timeout if timeout is not None else X64DBG_READ_TIMEOUT
    connect_left = max(1, int(connect_attempts))
    delivered_left = X64DBG_DELIVERED_ATTEMPTS if idempotent else 1

    while True:
        try:
            response = requests.post(
                url, json=payload, headers=headers,
                timeout=(connect_limit, read_limit),
            )
            break
        except requests.ConnectTimeout as exc:
            # The connection never came up: the request was never sent.
            connect_left -= 1
            if connect_left > 0:
                continue
            raise _X64dbgFailure(
                f"could not reach the x64dbg MCP server at {url}: {exc}", "X64DBG_MISSING"
            ) from None
        except requests.ReadTimeout as exc:
            # The request was delivered and the answer did not come back.
            # Only a request that is safe to repeat may be tried again.
            delivered_left -= 1
            if delivered_left > 0:
                continue
            reason = f"the x64dbg MCP server did not answer within {read_limit}s"
            if idempotent:
                raise _X64dbgFailure(_x64dbg_repeatable(reason), "X64DBG_TIMEOUT") from None
            raise _X64dbgFailure(_x64dbg_uncertain(reason), "X64DBG_UNCERTAIN") from None
        except requests.Timeout as exc:
            raise _X64dbgFailure(
                f"the x64dbg MCP server did not answer within {read_limit}s",
                "X64DBG_TIMEOUT",
            ) from None
        except requests.ConnectionError as exc:
            if _x64dbg_never_sent(exc):
                # The connection was never established, so the request never
                # left: trying again is safe for any request.
                connect_left -= 1
                if connect_left > 0:
                    continue
                raise _X64dbgFailure(
                    f"could not reach the x64dbg MCP server at {url}: {exc}", "X64DBG_MISSING"
                ) from None
            # The connection died while the answer was coming. The plugin
            # hangs up after every response, and the local network stack
            # resets a connection every now and then, but the server may
            # already have acted on the request - so only a request that is
            # safe to repeat is tried again.
            delivered_left -= 1
            if delivered_left > 0:
                continue
            reason = (f"the connection to {url} died while the answer was coming: {exc}")
            if idempotent:
                raise _X64dbgFailure(_x64dbg_repeatable(reason), "X64DBG_MISSING") from None
            raise _X64dbgFailure(_x64dbg_uncertain(reason), "X64DBG_UNCERTAIN") from None
        except requests.RequestException as exc:
            raise _X64dbgFailure(
                f"could not reach the x64dbg MCP server at {url}: {exc}", "X64DBG_MISSING"
            ) from None

    if response.status_code == 401:
        raise _X64dbgFailure(
            "the x64dbg MCP server rejected the bearer token", "X64DBG_UNAUTHORIZED"
        )
    if response.status_code >= 400:
        raise _X64dbgFailure(
            f"the x64dbg MCP server answered {response.status_code}", "X64DBG_ERROR"
        )

    body = (response.text or "").strip()
    if not body:
        raise _X64dbgFailure(
            "the x64dbg MCP server answered with an empty body", "X64DBG_ERROR"
        )
    try:
        data = json.loads(body)
    except ValueError:
        raise _X64dbgFailure(
            f"the x64dbg MCP server did not answer JSON: {body[:200]}", "X64DBG_ERROR"
        ) from None

    if isinstance(data, dict) and data.get("error"):
        error = data["error"]
        message = error.get("message", "") if isinstance(error, dict) else str(error)
        raise _X64dbgFailure(message or "the call failed", _x64dbg_classify(message))
    if isinstance(data, dict):
        return data.get("result")
    return data


class _X64dbgFailure(Exception):
    """A failure from the x64dbg side, with a machine-readable code."""

    def __init__(self, message: str, code: str = "X64DBG_ERROR") -> None:
        super().__init__(message)
        self.code = code


def _x64dbg_candidate_ports(port: int) -> tuple:
    """The ports to try: the likely ones first, then the walk.

    The walk starts from the configured port as well as from the two
    defaults: the fixed plugin walks up from the port it was told to use, so
    a server on the configured port plus one has to be reachable.
    """
    likely = list(dict.fromkeys([port, X64DBG_DEFAULT_PORT, X64DBG_X32_PORT]))
    bases = tuple(dict.fromkeys((port, X64DBG_DEFAULT_PORT, X64DBG_X32_PORT)))
    others = [
        candidate + offset
        for offset in range(1, X64DBG_PORT_SCAN)
        for candidate in bases
        if (candidate + offset) not in likely
    ]
    return likely, others


def _x64dbg_instance() -> dict:
    """Find an x64dbg MCP server.

    The plugin binds 9094 for a 64-bit debuggee and 9095 for a 32-bit one,
    and the ports around them are tried too. A server that answers 401 is
    still a server: it means the token is wrong, which is worth saying.

    The ports are probed concurrently, and the probe timeout is short. A
    closed local port does not refuse straight away on Windows - it hangs on
    the first SYN and is only refused about two seconds later - so probing
    them one at a time with a long timeout would cost a couple of seconds per
    port. A live instance answers in milliseconds, so a third of a second is
    plenty to tell it from a closed port.
    """
    settings = _x64dbg_settings()
    if not settings["token"]:
        # A token is the one thing that cannot be guessed. Without one there
        # is no way to talk to the server, and probing the ports would only
        # report a missing server or a rejected token - neither of which says
        # what is actually wrong.
        raise _X64dbgFailure(
            "no bearer token for the x64dbg MCP server. Set "
            '"x64dbg": {"token": "..."} in ~/.ghydra/config.json, or point '
            '"x64dbg": {"path": "C:/tools/x64dbg"} - or GHYDRA_X64DBG_PATH - '
            "to read it from the plugin's own mcp_config.json.",
            "X64DBG_DISABLED",
        )

    def _probe(port: int, patient: bool) -> Optional[str]:
        """The port that answered, or None.

        The likely ports are probed with more than one attempt: the machine
        resets about one loopback connection in fourteen, and a single reset
        must not be reported as "the debugger is not running".
        """
        try:
            _x64dbg_post(settings["host"], port, settings["token"], "initialize", {
                "protocolVersion": X64DBG_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "ghydramcp", "version": BRIDGE_VERSION},
            }, timeout=X64DBG_LIKELY_PROBE_READ_TIMEOUT if patient else X64DBG_PROBE_READ_TIMEOUT,
                connect_timeout=X64DBG_PROBE_CONNECT_TIMEOUT, idempotent=True,
                connect_attempts=X64DBG_PROBE_ATTEMPTS if patient else 1)
        except _X64dbgFailure as exc:
            return "unauthorized" if exc.code == "X64DBG_UNAUTHORIZED" else None
        return str(port)

    # The plugin does not move while the debugger runs, so the port it was
    # found on is kept. The scan opens ninety connections, and a machine
    # under load resets one of them in fourteen - so a scan per call is a
    # lot of exposure for an answer that does not change. The port that was
    # found is probed once before it is used, and a port that stops
    # answering sends the scan back out.
    cache_key = f"{settings['host']}:{settings['port']}:{settings['token']}"
    cached = _X64DBG_INSTANCE.get(cache_key)
    if cached:
        answer = _probe(cached["port"], True)
        if answer and answer != "unauthorized":
            return cached
        # The port stopped answering, or the token was refused: the scan
        # says so, and says it properly.
        _X64DBG_INSTANCE.pop(cache_key, None)

    # The configured port and the two defaults are where the server almost
    # always is, so they are probed first, and the wider walk only happens
    # when none of them answered.
    likely, others = _x64dbg_candidate_ports(settings["port"])

    unauthorized = False
    for group, patient in ((likely, True), (others, False)):
        if not group:
            continue
        with ThreadPoolExecutor(max_workers=min(16, len(group))) as pool:
            answers = list(pool.map(lambda port: _probe(port, patient), group))
        for port, answer in zip(group, answers):
            if answer and answer != "unauthorized":
                instance = {
                    "host": settings["host"], "port": port, "token": settings["token"],
                    "path": settings["path"], "unauthorized": False,
                }
                _X64DBG_INSTANCE[cache_key] = instance
                return instance
        if any(answer == "unauthorized" for answer in answers):
            unauthorized = True
            break

    if unauthorized:
        raise _X64dbgFailure(
            "an x64dbg MCP server answered but rejected the bearer token; set "
            '"x64dbg": {"token": ...} in ~/.ghydra/config.json, or point '
            '"x64dbg": {"path": ...} at the x64dbg installation',
            "X64DBG_UNAUTHORIZED",
        )
    raise _X64dbgFailure(
        "no x64dbg MCP server answered on the ports around 9094; is x64dbg running "
        "with the plugin loaded?",
        "X64DBG_MISSING",
    )


def _x64dbg_is_read_only(instance: dict, name: str) -> bool:
    """Whether the plugin marks a tool as read-only.

    The catalogue carries the hint, and it is fetched once and kept: the tool
    set does not change while the debugger runs.
    """
    key = f"{instance['host']}:{instance['port']}:{name}"
    if key not in _X64DBG_READ_ONLY:
        try:
            result = _x64dbg_post(
                instance["host"], instance["port"], instance["token"], "tools/list",
                timeout=X64DBG_READ_TIMEOUT, idempotent=True,
            )
        except _X64dbgFailure:
            return False
        tools = result.get("tools") if isinstance(result, dict) else None
        for tool in tools or []:
            if not isinstance(tool, dict):
                continue
            annotations = tool.get("annotations") or {}
            tool_key = f"{instance['host']}:{instance['port']}:{tool.get('name')}"
            _X64DBG_READ_ONLY[tool_key] = bool(annotations.get("readOnlyHint"))
            schema = tool.get("inputSchema")
            _X64DBG_SCHEMAS[tool_key] = schema if isinstance(schema, dict) else {}
    return _X64DBG_READ_ONLY.get(key, False)


def _x64dbg_restore_types(instance: dict, name: str, arguments: dict) -> dict:
    """Put back the types a client flattened into text.

    A client that re-encodes the container the protocol uses for a tool's
    parameters turns what is nested in it into text: measured on this
    desktop, where an integer count arrived as the string "3". The plugin
    ignores a parameter it cannot read and does something else instead of
    failing - the call came back with the default count rather than the
    one that was asked for.

    The plugin's own schema says what every parameter is, so the type is
    restored here, from the schema, rather than left to the plugin. A value
    the schema does not describe is left alone.
    """
    key = f"{instance['host']}:{instance['port']}:{name}"
    schema = _X64DBG_SCHEMAS.get(key)
    properties = schema.get("properties") if isinstance(schema, dict) else None
    if not isinstance(properties, dict) or not arguments:
        return arguments
    restored = dict(arguments)
    for field, value in arguments.items():
        if not isinstance(value, str):
            continue
        declared = properties.get(field)
        if not isinstance(declared, dict):
            continue
        kind = declared.get("type")
        if kind == "integer":
            try:
                restored[field] = int(value, 0)
            except ValueError:
                pass
        elif kind == "number":
            try:
                restored[field] = float(value)
            except ValueError:
                pass
        elif kind == "boolean":
            if value.lower() in ("true", "false"):
                restored[field] = value.lower() == "true"
        elif kind in ("array", "object"):
            try:
                parsed = json.loads(value)
            except ValueError:
                continue
            if kind == "array" and isinstance(parsed, list):
                restored[field] = parsed
            elif kind == "object" and isinstance(parsed, dict):
                restored[field] = parsed
    return restored


def _x64dbg_call_tool(instance: dict, name: str, arguments: Optional[dict] = None,
                      timeout: Optional[float] = None) -> str:
    """Call one plugin tool and return its text.

    A read-only tool may be called again when the transport fails; a tool
    that changes the debuggee may not, because the first attempt may already
    have reached it.
    """
    # The catalogue is read first: it carries the read-only hint and the
    # input schema, and the schema is what says what type a parameter is.
    read_only = _x64dbg_is_read_only(instance, name)
    payload = {
        "name": name,
        "arguments": _x64dbg_restore_types(instance, name, arguments or {}),
    }
    result = _x64dbg_post(
        instance["host"], instance["port"], instance["token"], "tools/call",
        payload, timeout=timeout, idempotent=read_only,
    )
    if isinstance(result, dict):
        content = result.get("content")
        if isinstance(content, list):
            parts = [
                str(item.get("text", ""))
                for item in content
                if isinstance(item, dict) and item.get("type") == "text"
            ]
            if parts:
                return "\n".join(parts)
        if result.get("isError"):
            raise _X64dbgFailure("the tool reported an error", "X64DBG_ERROR")
        if "text" in result:
            return str(result["text"])
    return ""


def _x64dbg_normalize_path(path: str) -> str:
    """A path that the two sides can be compared on.

    The x64dbg side reports the module path with the Win32 extended-length
    prefix and in its own case; Ghidra reports the executable path as the
    file system gave it.
    """
    text = str(path or "").strip().strip('"')
    if text.startswith("\\\\?\\"):
        text = text[4:]
    if not text:
        return ""
    try:
        return os.path.normcase(os.path.abspath(text))
    except (OSError, ValueError):
        return os.path.normcase(text)


def _x64dbg_parse_modules(text: str) -> List[dict]:
    """The modules out of the ListModules text.

    The tool answers one module per line, "0xBASE | 0xSIZE | PATH".
    """
    modules: List[dict] = []
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = [part.strip() for part in line.split("|")]
        if len(parts) < 3:
            continue
        try:
            base = int(parts[0], 16)
            size = int(parts[1], 16)
        except ValueError:
            continue
        modules.append({"base": base, "size": size, "path": "|".join(parts[2:]).strip()})
    return modules


def _x64dbg_path_name(path: str) -> str:
    """The file name of a path, on any platform.

    os.path.basename only knows the separators of the machine it runs on, so
    on POSIX it takes the whole "C:\\dir\\cmd.exe" as the name and the by-name
    module match silently fails. The two sides of this integration always
    speak Windows paths, so both separators are separators here.
    """
    text = str(path or "").strip().strip('"')
    if text.startswith("\\\\?\\"):
        text = text[4:]
    return text.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


def _x64dbg_find_module(modules: List[dict], binary_path: str) -> Optional[dict]:
    """The module that is the given binary.

    The paths are compared first as full paths and then by file name: the two
    sides can disagree about the directory - a copy, a symlink, a different
    drive letter - but not about the file.
    """
    wanted = _x64dbg_normalize_path(binary_path)
    if not wanted:
        return None
    for module in modules:
        if _x64dbg_normalize_path(module.get("path", "")) == wanted:
            return module
    wanted_name = _x64dbg_path_name(wanted).lower()
    for module in modules:
        candidate = _x64dbg_normalize_path(module.get("path", ""))
        if candidate and _x64dbg_path_name(candidate).lower() == wanted_name:
            return module
    return None


def _x64dbg_parse_int(value: Any) -> Optional[int]:
    """An address, however it was written: "0x140001000", "140001000" or 0."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value or "").strip()
    if not text:
        return None
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text, 16) if all(char in "0123456789abcdefABCDEF" for char in text) \
            else int(text, 10)
    except ValueError:
        return None


def _x64dbg_program_info(port: int) -> dict:
    """The Ghidra program's image base and executable path."""
    response = safe_get(port, "/program")
    if not response.get("success", False):
        error = response.get("error") or {}
        raise _X64dbgFailure(
            error.get("message", "the Ghidra instance did not answer /program"),
            "X64DBG_ERROR",
        )
    result = response.get("result") or {}
    return {
        "path": result.get("path") or result.get("executable") or "",
        "image_base": _x64dbg_parse_int(result.get("imageBase", result.get("image_base"))),
        "name": result.get("name") or "",
    }


def _x64dbg_target_descriptor(port: int | None = None) -> dict:
    """Correlate the Ghidra program with the x64dbg session.

    The two sides disagree about addresses by a constant, and this is what
    works out that constant: the image base Ghidra loads the file at, and the
    base the loader gave the module in the process.
    """
    ghidra_port = _get_instance_port(port)
    program = _x64dbg_program_info(ghidra_port)
    instance = _x64dbg_instance()
    text = _x64dbg_call_tool(instance, "ListModules")
    modules = _x64dbg_parse_modules(text)

    binary_path = program.get("path") or ""
    module = _x64dbg_find_module(modules, binary_path)
    if module is None:
        raise _X64dbgFailure(
            f"no loaded module matches the binary Ghidra has open ({binary_path or 'unknown'}); "
            f"the loaded modules are: " + ", ".join(item["path"] for item in modules),
            "X64DBG_NO_MATCH",
        )

    image_base = program.get("image_base")
    if image_base is None:
        raise _X64dbgFailure(
            "the Ghidra instance did not report an image base for this program",
            "X64DBG_ERROR",
        )

    module_base = module["base"]
    return {
        "ghidra_port": ghidra_port,
        "binary": binary_path,
        "image_base": image_base,
        "module_base": module_base,
        "module_size": module.get("size"),
        "module_path": module.get("path"),
        "delta": module_base - image_base,
        "x64dbg_host": instance["host"],
        "x64dbg_port": instance["port"],
    }


@mcp.tool()
@text_output
def x64dbg_status() -> dict:
    """Whether the x64dbg MCP server is reachable, and what it is doing.

    The x64dbg plugin is an MCP server that lives inside the debugger. It
    answers on 127.0.0.1:9094 for a 64-bit debuggee and :9095 for a 32-bit
    one, and it wants a bearer token. Point at it with "x64dbg": {"port": ...,
    "token": ...} in ~/.ghydra/config.json, or with "path" - or
    GHYDRA_X64DBG_PATH - pointing at the x64dbg installation, and the token is
    read from the plugin's own mcp_config.json.

    Returns:
        dict: Whether the server answered, where it is, how many tools it
              has and the modules it has loaded
    """
    try:
        instance = _x64dbg_instance()
    except _X64dbgFailure as exc:
        return _x64dbg_error(str(exc), code=exc.code)

    try:
        tools = _x64dbg_post(
            instance["host"], instance["port"], instance["token"], "tools/list",
            timeout=X64DBG_READ_TIMEOUT, idempotent=True,
        )
        tool_list = tools.get("tools") if isinstance(tools, dict) else None
        tool_list = tool_list if isinstance(tool_list, list) else []
    except _X64dbgFailure as exc:
        return _x64dbg_error(str(exc), code=exc.code)

    modules: List[dict] = []
    debug_state = None
    try:
        text = _x64dbg_call_tool(instance, "ListModules")
        modules = _x64dbg_parse_modules(text)
    except _X64dbgFailure:
        modules = []
    try:
        debug_state = _x64dbg_call_tool(instance, "GetDebugState").strip()
    except _X64dbgFailure:
        debug_state = None

    return {
        "success": True,
        "result": {
            "reachable": True,
            "host": instance["host"],
            "port": instance["port"],
            "tools": len(tool_list),
            "modules": modules,
            "debug_state": debug_state,
        },
    }


@mcp.tool()
@text_output
def x64dbg_tools() -> dict:
    """The x64dbg plugin's tool catalogue, with the schema of each tool.

    The plugin carries eighty tools. They are not exposed one by one here -
    that would drown the agent's tool list - so the catalogue is exposed
    instead, and x64dbg_call invokes any of them by name.

    Returns:
        dict: The tools: name, description and input schema
    """
    try:
        instance = _x64dbg_instance()
    except _X64dbgFailure as exc:
        return _x64dbg_error(str(exc), code=exc.code)

    try:
        result = _x64dbg_post(
            instance["host"], instance["port"], instance["token"], "tools/list",
            timeout=X64DBG_READ_TIMEOUT, idempotent=True,
        )
    except _X64dbgFailure as exc:
        return _x64dbg_error(str(exc), code=exc.code)

    tools = result.get("tools") if isinstance(result, dict) else None
    tools = tools if isinstance(tools, list) else []
    return {
        "success": True,
        "result": {
            "count": len(tools),
            "tools": [
                {
                    "name": tool.get("name"),
                    "description": tool.get("description"),
                    "input_schema": tool.get("inputSchema"),
                    "read_only": bool(
                        (tool.get("annotations") or {}).get("readOnlyHint")),
                }
                for tool in tools if isinstance(tool, dict)
            ],
        },
    }


def _x64dbg_arguments_text(value: Any) -> Any:
    """Take the plugin's arguments as one piece of text.

    A client that re-encodes the container the protocol uses for a tool's
    parameters flattens what is nested in it, and every value of a nested
    object arrives as a string - measured on this desktop, where an integer
    count arrived as "3" and the plugin, ignoring what it could not read,
    did something else instead of failing.

    The text is the form nothing gets in the way of, so it is the form the
    schema asks for. An object is still accepted, for the clients that
    deliver one, and its types are restored from the plugin's own schema.
    """
    if isinstance(value, dict):
        return json.dumps(value)
    return value


# The arguments of a plugin tool, as JSON text. The schema says string on
# purpose: a client that hands over a nested object flattens it.
X64dbgArguments = Annotated[str, BeforeValidator(_x64dbg_arguments_text)]


def _x64dbg_parse_arguments(value: Any) -> dict:
    """The plugin's arguments, from their JSON text or from an object.

    Some MCP clients re-encode the container the protocol uses for a tool's
    parameters, and a nested object does not always survive that. The text
    is parsed here, so the caller may pass either and the bridge does not
    rely on the client to get it right.
    """
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    text = str(value).strip()
    if not text:
        return {}
    try:
        parsed = json.loads(text)
    except ValueError:
        raise _X64dbgFailure(
            "the arguments are not JSON", "X64DBG_BAD_ARGS") from None
    if not isinstance(parsed, dict):
        raise _X64dbgFailure(
            "the arguments are not a JSON object", "X64DBG_BAD_ARGS") from None
    return parsed


@mcp.tool()
@text_output
def x64dbg_call(tool: str, tool_arguments: X64dbgArguments | None = None,
                timeout: int | None = None) -> dict:
    """Call one of the x64dbg plugin's tools by name.

    The name and the arguments are the ones x64dbg_tools reports. Every
    response carries a "[state]" line and any debugger events that fired
    since the last call, so read them.

    A tool the plugin marks as read-only may be called again when the
    transport fails; one that changes the debuggee is never repeated, because
    the first attempt may already have reached it.

    Send the arguments as one piece of JSON text - '{"target": "0x140001234"}' -
    rather than as a nested object. A client that re-encodes the container
    the protocol uses for a tool's parameters flattens what is nested in it:
    every value of the object arrives as a string, and the plugin ignores a
    parameter it cannot read and does something else instead of failing.
    Measured here - an integer count arrived as "3" and the call came back
    with the default count. The text is parsed here. An object is still
    accepted, and its types are restored from the plugin's own schema.

    The parameter is not called "arguments" for a reason of its own: that is
    the name of the container the protocol itself uses for a tool's
    parameters, and the two get confused easily.

    Args:
        tool: The plugin tool to call, for example "SetBreakpoint"
        tool_arguments: The arguments for that tool, as JSON text
        timeout: How long to wait, in seconds (30 by default). The tools that
            block - run, WaitForEvent, WaitForPause - need more than that.

    Returns:
        dict: The tool's text
    """
    if not tool:
        return _x64dbg_error("tool is required", code="X64DBG_BAD_ARGS")
    try:
        instance = _x64dbg_instance()
    except _X64dbgFailure as exc:
        return _x64dbg_error(str(exc), code=exc.code)
    try:
        text = _x64dbg_call_tool(
            instance, tool, _x64dbg_parse_arguments(tool_arguments),
            timeout=float(timeout) if timeout else None,
        )
    except _X64dbgFailure as exc:
        return _x64dbg_error(str(exc), code=exc.code)
    return {"success": True, "result": {"tool": tool, "text": text}}


@mcp.tool()
@text_output
def x64dbg_target(port: int | None = None) -> dict:
    """Correlate the Ghidra program with the x64dbg session.

    Ghidra works on the image as it sits in the file, at the image base.
    x64dbg works on the live process, where the loader put the module
    somewhere else. The two differ by a constant, and this is what works it
    out: the image base of the program Ghidra has open, and the base of the
    module x64dbg has loaded.

    The result carries both bases and the delta between them, so a static
    address can be turned into a runtime one and back.

    Args:
        port: The Ghidra instance (the current one by default)

    Returns:
        dict: The image base, the module base, the delta and the binary
    """
    try:
        descriptor = _x64dbg_target_descriptor(port)
    except _X64dbgFailure as exc:
        return _x64dbg_error(str(exc), code=exc.code)
    except ValueError as exc:
        return _x64dbg_error(str(exc), code="X64DBG_ERROR")
    return {"success": True, "result": descriptor}


@mcp.tool()
@text_output
def x64dbg_breakpoint_at(address: str, port: int | None = None) -> dict:
    """Set a breakpoint on a Ghidra address.

    The address is the static one - the one Ghidra shows, the one static
    analysis just found - and it is translated into the runtime address
    before the breakpoint is set. This is the step that turns a function
    recovered by decompilation into a place the debugger actually stops.

    Args:
        address: The static address, as Ghidra shows it ("0x140001234")
        port: The Ghidra instance (the current one by default)

    Returns:
        dict: The static and the runtime address, and what the plugin said
    """
    static_address = _x64dbg_parse_int(address)
    if static_address is None:
        return _x64dbg_error(
            f"'{address}' is not an address", code="X64DBG_BAD_ARGS"
        )
    try:
        descriptor = _x64dbg_target_descriptor(port)
    except _X64dbgFailure as exc:
        return _x64dbg_error(str(exc), code=exc.code)
    except ValueError as exc:
        return _x64dbg_error(str(exc), code="X64DBG_ERROR")

    runtime = static_address - descriptor["image_base"] + descriptor["module_base"]
    try:
        # The descriptor already found the server; looking for it again
        # would probe the ports a second time. The token comes from the
        # settings, not from the descriptor: the descriptor is returned to
        # the agent as it is.
        settings = _x64dbg_settings()
        instance = {
            "host": descriptor["x64dbg_host"], "port": descriptor["x64dbg_port"],
            "token": settings["token"], "path": settings["path"],
        }
        text = _x64dbg_call_tool(instance, "SetBreakpoint", {"target": hex(runtime)})
    except _X64dbgFailure as exc:
        return _x64dbg_error(str(exc), code=exc.code)

    return {
        "success": True,
        "result": {
            "static_address": hex(static_address),
            "runtime_address": hex(runtime),
            "image_base": hex(descriptor["image_base"]),
            "module_base": hex(descriptor["module_base"]),
            "binary": descriptor["binary"],
            "text": text,
        },
    }


@mcp.tool()
@text_output
def x64dbg_go_to(address: str, port: int | None = None) -> dict:
    """Move the instruction pointer to a Ghidra address.

    The address is translated from the static one into the runtime one, the
    same way x64dbg_breakpoint_at does it. The debuggee has to be paused: a
    running target has no instruction pointer to move.

    Args:
        address: The static address, as Ghidra shows it ("0x140001234")
        port: The Ghidra instance (the current one by default)

    Returns:
        dict: The static and the runtime address, and what the plugin said
    """
    static_address = _x64dbg_parse_int(address)
    if static_address is None:
        return _x64dbg_error(
            f"'{address}' is not an address", code="X64DBG_BAD_ARGS"
        )
    try:
        descriptor = _x64dbg_target_descriptor(port)
    except _X64dbgFailure as exc:
        return _x64dbg_error(str(exc), code=exc.code)
    except ValueError as exc:
        return _x64dbg_error(str(exc), code="X64DBG_ERROR")

    runtime = static_address - descriptor["image_base"] + descriptor["module_base"]
    try:
        # The descriptor already found the server; looking for it again
        # would probe the ports a second time. The token comes from the
        # settings, not from the descriptor: the descriptor is returned to
        # the agent as it is.
        settings = _x64dbg_settings()
        instance = {
            "host": descriptor["x64dbg_host"], "port": descriptor["x64dbg_port"],
            "token": settings["token"], "path": settings["path"],
        }
        # "cip" is the x64dbg name for the instruction pointer, in a 64-bit
        # debuggee and in a 32-bit one alike; the plugin turns it into
        # "mov cip, <address>".
        text = _x64dbg_call_tool(
            instance, "SetRegister",
            {"register": "cip", "value": hex(runtime)},
        )
    except _X64dbgFailure as exc:
        return _x64dbg_error(str(exc), code=exc.code)

    return {
        "success": True,
        "result": {
            "static_address": hex(static_address),
            "runtime_address": hex(runtime),
            "binary": descriptor["binary"],
            "text": text,
        },
    }


# ================= Project Management =================

@mcp.tool()
@text_output
def project_info(port: int | None = None) -> dict:
    """Get information about the currently open Ghidra project

    Args:
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Project information including name, location, file counts
    """
    port = _get_instance_port(port)
    response = safe_get(port, "project")
    return simplify_response(response)


@mcp.tool()
@text_output
def project_list_files(folder: str = "/", recursive: bool = True,
                       offset: int = 0, limit: int = 100, port: int | None = None) -> dict:
    """List files in the current Ghidra project

    Args:
        folder: Folder path to list (default: "/")
        recursive: Recursively list all files (default: True)
        offset: Pagination offset (default: 0)
        limit: Maximum number of items to return (default: 100)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: List of project files and folders
    """
    port = _get_instance_port(port)

    params = {
        "folder": folder,
        "recursive": str(recursive).lower(),
        "offset": str(offset),
        "limit": str(limit)
    }

    response = safe_get(port, "project/files", params)
    return simplify_response(response)


@mcp.tool()
@text_output
def project_open_file(path: str, port: int | None = None) -> dict:
    """Open a file from the project in CodeBrowser

    This will open the file in a new CodeBrowser window, creating a new instance.
    Use instances_discover after opening to find the new instance port.

    Args:
        path: Path to the file in the project (e.g., "/malware.exe")
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Result of the open operation with instructions to discover new instance
    """
    port = _get_instance_port(port)

    data = {"path": path}
    response = safe_post(port, "project/open", data)
    return simplify_response(response)


@mcp.tool()
@text_output
def projects_list(port: int | None = None) -> dict:
    """List projects visible to the plugin context

    Args:
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: List of projects
    """
    port = _get_instance_port(port)
    response = safe_get(port, "projects")
    return simplify_response(response)


@mcp.tool()
@text_output
def projects_get(name: str, port: int | None = None) -> dict:
    """Get a project by name

    Args:
        name: Project name
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Project details
    """
    if not name:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "name parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)
    response = safe_get(port, f"projects/{quote(name)}")
    return simplify_response(response)


@mcp.tool()
@text_output
def programs_list(project: str | None = None, offset: int = 0, limit: int = 100, port: int | None = None) -> dict:
    """List programs in the current project context

    Args:
        project: Optional project name filter
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: List of programs
    """
    port = _get_instance_port(port)
    params = {"offset": offset, "limit": limit}
    if project:
        params["project"] = project
    response = safe_get(port, "programs", params)
    return simplify_response(response)


@mcp.tool()
@text_output
def programs_get(program_id: str = "current", port: int | None = None) -> dict:
    """Get program details by program ID or 'current'

    Args:
        program_id: Program ID (e.g. 'MyProj:/sample.bin') or 'current'
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Program details
    """
    port = _get_instance_port(port)
    endpoint = "programs/current" if program_id == "current" else f"programs/{quote(program_id, safe='')}"
    response = safe_get(port, endpoint)
    return simplify_response(response)


@mcp.tool()
@text_output
def programs_overview(import_limit: int = 25, port: int | None = None) -> dict:
    """An overview of the loaded binary

    What it is, how it is laid out, how much is in it, and what it pulls
    in - the summary a triage pass starts from, instead of four calls.

    Args:
        import_limit: How many imports to list (default: 25)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: The program, its segments, its counts and its imports
    """
    port = _get_instance_port(port)

    program = safe_get(port, "program")
    if not program.get("success", False):
        # The program is the part the caller asked for: without it there is
        # no overview to give.
        return program

    segments = safe_get(port, "segments")
    imports = safe_get(port, "symbols/imports", {"limit": import_limit})

    def _list_of(response: dict) -> list:
        payload = response.get("result")
        return payload if isinstance(payload, list) else []

    meta = imports.get("meta") or {}
    statistics = (program.get("result") or {}).get("statistics") or {}

    return {
        "success": True,
        "result": {
            "program": program.get("result") or {},
            "segments": _list_of(segments),
            "imports": _list_of(imports),
            "statistics": {
                "functions": statistics.get("functionCount"),
                "symbols": statistics.get("symbolCount"),
                "memoryBlocks": statistics.get("memoryBlockCount"),
                "imports": meta.get("total"),
            }
        }
    }


@mcp.tool()
@text_output
def programs_delete(program_id: str = "current", port: int | None = None) -> dict:
    """Delete/close a program by program ID or 'current'

    Args:
        program_id: Program ID or 'current'
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Operation result
    """
    port = _get_instance_port(port)
    endpoint = "programs/current" if program_id == "current" else f"programs/{quote(program_id, safe='')}"
    response = safe_delete(port, endpoint)
    return simplify_response(response)


@mcp.tool()
@text_output
def programs_save(all: bool = False, port: int | None = None) -> dict:
    """Save the current program to the project (Ghidra's "Save")

    Persists analysis (renames, types, comments, etc.) so it survives a Ghidra restart.
    A program with no changes is a no-op (saved=false).

    Args:
        all: Save every open program with unsaved changes (default: just the current program)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Save result(s); saved=false means there were no unsaved changes
    """
    port = _get_instance_port(port)
    endpoint = "program/save?all=true" if all else "program/save"
    response = safe_post(port, endpoint, {})
    return simplify_response(response)


# Script tools
def _script_args_text(value: Any) -> Any:
    """A nested list arrives flattened from some MCP clients; take it back as text."""
    if isinstance(value, (list, tuple)):
        return json.dumps(list(value))
    return value


# The arguments of an ad-hoc script, as JSON text. The schema says string on
# purpose, the same way x64dbg_call and functions_batch_decompile do.
ScriptArgsText = Annotated[str, BeforeValidator(_script_args_text)]


def _parse_script_args(text: str | None) -> list[str]:
    """Script args from JSON text, a comma-separated list, or one bare value."""
    if text is None or text == "":
        return []
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        parsed = text
    if isinstance(parsed, list):
        return [str(item) for item in parsed]
    if isinstance(parsed, str) and "," in parsed:
        return [part.strip() for part in parsed.split(",") if part.strip()]
    return [str(parsed)]


@mcp.tool()
@text_output
def scripts_list(port: int | None = None) -> dict:
    """List Ghidra scripts available to run

    Requires the server started with script execution enabled
    (-Dghydra.dev.allowScripts=true or GHYDRA_ALLOW_SCRIPTS=1); otherwise returns 403.

    Args:
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: List of scripts with name, path, category
    """
    port = _get_instance_port(port)
    return simplify_response(safe_get(port, "scripts"))


@mcp.tool()
@text_output
def scripts_run(name: str | None = None, source: str | None = None,
                args: ScriptArgsText | None = None,
                language: str | None = None, filename: str | None = None,
                port: int | None = None) -> dict:
    """Run a Ghidra script: an existing one by name, or ad-hoc Java/Python source.

    Use this for multi-stage or batch operations that would otherwise need many tool calls
    (e.g. mass rename, signature transfer). Provide EITHER name OR source.

    For ad-hoc source, choose the runtime explicitly: language="python" (or a .py
    filename) runs a temporary .py file with PyGhidra/Python 3 explicitly selected;
    language="java" (the default) runs a .java GhidraScript. Python 3 requires
    Ghidra launched via pyghidraRun, not just the installed extension.

    WARNING: this is arbitrary code execution. It requires the server started with
    -Dghydra.dev.allowScripts=true (or GHYDRA_ALLOW_SCRIPTS=1); otherwise returns 403.

    Args:
        name: Name of an existing script (e.g. "MyScript.java" or "Probe.py")
        source: Ad-hoc source. Java needs a full 'public class <Name> extends
            GhidraScript { public void run() {...} }'; Python 3 uses currentProgram
            directly and prints with println(...)/print(...).
        args: Script arguments as ONE piece of text: a JSON array like '["a","b"]'
            or a comma-separated list. A nested list is flattened by some clients.
        language: Runtime for ad-hoc source: "java" (default) or "python"/"python3".
        filename: Original source filename; a .py extension also selects Python 3.
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: result with script, output (captured println text), success, error
    """
    if not name and not source:
        return {
            "success": False,
            "error": {"code": "MISSING_PARAMETER", "message": "Either name or source is required"},
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)
    payload = {}
    if name:
        payload["name"] = name
    if source:
        payload["source"] = source
    parsed_args = _parse_script_args(args)
    if parsed_args:
        payload["args"] = parsed_args
    if language:
        payload["language"] = language
    if filename:
        payload["filename"] = filename
    return simplify_response(safe_post(port, "scripts/run", payload))


# ================= Analysis =================

# Capability triage (R4). This is a copy of ghydra/capabilities.py: the bridge
# ships as one standalone file and must not import the ghydra package.
# test_capabilities_summary.py asserts the two copies stay byte-for-byte in
# agreement, the same way the Kuna error taxonomies are kept in step.
#: Defined once, in the generated core (I1).
CAPABILITY_RULES = _CORE_CAPABILITY_RULES


def build_capability_report(program: object, imports: object, strings: object,
                            include_strings: bool = True) -> dict:
    """Compose the three envelopes into a ranked capability triage report.

    Delegates to the generated core (I1): the CLI and the bridge rank the same
    evidence with the same rules, so the two cannot disagree about a binary.
    """
    return _core_build_capability_report(program, imports, strings,
                                         include_strings)



_CAPABILITY_PAGE_LIMIT = 1000      # the server clamps every page to this
_CAPABILITY_MAX_PAGES = 20         # a bound the answer must still respect


def _collect_capability_items(port: int, endpoint: str,
                              total_expected: int | None = None) -> dict:
    """Every item of a listing, paged through the advertised total.

    The server clamps every page to 1000 items, so a single request only sees
    the first page: a binary with 5000 imports could have all of its matching
    evidence on page three and still get an empty capability report. This
    follows meta.total, with a page cap so a listing that never ends cannot
    hang the tool.
    """
    items: list = []
    offset = 0
    first = None
    for _page in range(_CAPABILITY_MAX_PAGES):
        response = safe_get(port, endpoint,
                            {"offset": offset, "limit": _CAPABILITY_PAGE_LIMIT})
        if first is None:
            first = response
        page = _core_cap_items(response)
        items.extend(page)
        meta = response.get("meta") if isinstance(response, dict) else None
        total = meta.get("total") if isinstance(meta, dict) else None
        if not page or len(page) < _CAPABILITY_PAGE_LIMIT:
            break
        if isinstance(total, int) and len(items) >= total:
            break
        offset += len(page)
    if first is not None and isinstance(first, dict) \
            and first.get("success") is False:
        return first  # the report says which part failed, never hides it
    return {"success": True, "result": items}


@mcp.tool()
@text_output
def analysis_capabilities_summary(include_strings: bool = True,
                                  port: int | None = None) -> dict:
    """Rank ATT&CK/MBC-style capability leads for the loaded binary, in one call.

    Composes the program, imported symbols and defined strings into a ranked
    list of techniques, each with the evidence (name and address) behind it.
    This is a triage lead for an analyst, never a verdict: a technique is only
    reported when an import or a string in the binary actually matches one of
    the rules, and nothing is inferred from a missing match.

    Args:
        include_strings: Include defined strings as evidence (default: True)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: program name, scan counts, ranked findings with evidence and
              confidence, and the list of endpoints that failed (if any).
    """
    port = _get_instance_port(port)
    program = safe_get(port, "program")
    imports = _collect_capability_items(port, "symbols/imports")
    strings = (_collect_capability_items(port, "strings")
               if include_strings else None)
    return build_capability_report(program, imports, strings, include_strings)


# Context pack (R3): generated from ghydra/core/contextpack.py (I1).
_CONTEXT_CHAR_PER_TOKEN = _CORE_CONTEXT_CHAR_PER_TOKEN

_CONTEXT_TEMPLATES = _CORE_CONTEXT_TEMPLATES


def _ctx_classify_question(question: str) -> str:
    """Delegates to the generated core (I1)."""
    return _core_context_classify(question)


def _ctx_tokens(text: str) -> int:
    """Delegates to the generated core (I1)."""
    return _core_context_tokens(text)


def build_context_pack(question: str, template: str, program: str,
                       sections: list, budget_tokens: int = 4000) -> dict:
    """Assemble the fetched sections into one budgeted dossier (R3).

    Delegates to the generated core (I1): the same budget arithmetic decides
    what the CLI and the bridge leave out, and why.
    """
    return _core_build_context_pack(question, template, program, sections,
                                    budget_tokens)

def _ctx_section(title: str, response, key: str = "result",
                 citations: tuple = ()) -> dict:
    """One pack section from an endpoint envelope, or a failure note."""
    if isinstance(response, dict) and response.get("success", False):
        payload = response.get(key)
        body = payload if isinstance(payload, str) else json.dumps(
            payload, ensure_ascii=False, default=str)
        return {"title": title, "body": body, "citations": list(citations)}
    code = ""
    if isinstance(response, dict):
        error = response.get("error") or {}
        code = str(error.get("code", "unavailable")) if isinstance(error, dict) else str(error)
    return {"title": title, "body": f"(unavailable: {code or 'no answer'})",
            "citations": []}


def _ctx_text(response, *keys) -> str:
    """Best-effort plain text out of an envelope's result."""
    if not isinstance(response, dict) or not response.get("success", False):
        return ""
    payload = response.get("result")
    if isinstance(payload, dict):
        for key in keys:
            if isinstance(payload.get(key), str) and payload[key]:
                return payload[key]
    return ""


@mcp.tool()
@text_output
def analysis_context_pack(question: str, address: str | None = None,
                          budget_tokens: int = 4000,
                          port: int | None = None) -> dict:
    """Answer one question about the binary in a single budgeted dossier

    An agent otherwise pays 10-20 calls to answer "what does this function do
    and who calls it". This tool composes the relevant endpoints into ONE
    ranked answer — decompiled code, references, context — with citable
    addresses, truncated to your token budget, and with an explicit list of
    what was omitted and why. Three question models are recognised (either
    language): "what does it do" (needs an address), "where does this data
    come from" (needs an address) and "what changed" (program fingerprint; a
    real diff needs two snapshots). Anything else gets the overview template.

    Args:
        question: The question, free-form, PT or EN (e.g. "o que faz esta
                  função?", "where is this data written?")
        address: The hex address the question is about (required by the
                 what-it-does and data-origin templates)
        budget_tokens: Approximate token budget for the answer (default: 4000)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: The dossier — sections ranked by relevance, citations (every
              address mentioned), omissions with reasons, and the tokens used
    """
    template = _ctx_classify_question(question)

    if template in ("what_it_does", "data_origin") and not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": f"the '{template}' question needs the address of "
                           f"the function or data item it is about",
            },
        }

    port = _get_instance_port(port)

    program = safe_get(port, "program")
    program_name = ""
    if isinstance(program, dict) and isinstance(program.get("result"), dict):
        program_name = program["result"].get("name") or ""

    sections = []
    if template == "what_it_does":
        resolved = quote(address)
        info = safe_get(port, f"functions/{resolved}")
        sections.append(_ctx_section(
            "function", info, citations=(address,)))
        decompile = safe_get(port, f"functions/{resolved}/decompile")
        code = _ctx_text(decompile, "ccode", "decompilation", "decompiled",
                         "code", "implementation")
        sections.append(_ctx_section(
            "decompilation", decompile if not code else
            {"success": True, "result": code},
            citations=(address,)))
        sections.append(_ctx_section(
            "callers", safe_get(port, f"analysis/callers/{resolved}",
                                {"limit": 10})))
        sections.append(_ctx_section(
            "callees", safe_get(port, f"analysis/callees/{resolved}",
                                {"limit": 10})))
    elif template == "data_origin":
        resolved = quote(address)
        sections.append(_ctx_section(
            "address context",
            safe_get(port, f"inspect/address/{resolved}"),
            citations=(address,)))
        sections.append(_ctx_section(
            "references to it",
            safe_get(port, "xrefs", {"to_addr": address, "limit": 50})))
    elif template == "what_changed":
        sections.append(_ctx_section("program", program))
        sections.append(_ctx_section(
            "segments", safe_get(port, "segments", {"limit": 50})))
        sections.append({
            "title": "how to diff",
            "body": "A change diff needs two fingerprints: keep this pack, "
                    "re-ask after your edits, and compare the statistics and "
                    "segments above.",
            "citations": [],
        })
    else:  # overview
        sections.append(_ctx_section("program", program))
        sections.append(_ctx_section(
            "segments", safe_get(port, "segments", {"limit": 50})))
        sections.append(_ctx_section(
            "imports", safe_get(port, "symbols/imports", {"limit": 100})))

    return build_context_pack(question, template, program_name,
                              sections, budget_tokens)


@mcp.tool()
@text_output
def analysis_status(port: int | None = None) -> dict:
    """Get analysis status for the current program

    Args:
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Analysis status including whether analysis is running
    """
    port = _get_instance_port(port)
    response = safe_get(port, "analysis/status")
    return simplify_response(response)


def _analysis_run_legacy(background: bool = True, port: int | None = None) -> dict:
    """Legacy helper retained for backward compatibility inside this module."""
    return analysis_run(port=port, background=background)


# ================= Inspect =================

@mcp.tool()
@text_output
def inspect_address(address: str, port: int | None = None) -> dict:
    """Say what an address is, in one call

    An agent that lands on an address has to ask four questions: what is
    called here, what function is it in, what does it hold, and who refers
    to it. This answers all four at once.

    Args:
        address: The address in hex format (e.g. "0x140001008")
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: The symbol, the containing function, the data, the instruction,
              the comments and the references on both sides of the address
    """
    if not address:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "The address parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)

    response = safe_get(port, f"inspect/address/{quote(address)}")
    return simplify_response(response)


# ================= Classes, Symbols, Segments, Namespaces, Variables, DataTypes =================

@mcp.tool()
@text_output
def classes_list(offset: int = 0, limit: int = 100, port: int | None = None) -> dict:
    """List classes and namespaces in the program

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: List of classes with pagination
    """
    port = _get_instance_port(port)
    params = {"offset": offset, "limit": limit}
    response = safe_get(port, "classes", params)
    simplified = simplify_response(response)
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)
    return simplified


@mcp.tool()
@text_output
def symbols_list(offset: int = 0, limit: int = 100, count: bool = True,
                port: int | None = None) -> dict:
    """List all symbols in the program

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        count: Compute the total (default True); false skips the counting scan (I10)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: List of symbols with name, address, type, and namespace
    """
    port = _get_instance_port(port)
    params = {"offset": offset, "limit": limit,
              "count": "true" if count else "false"}
    response = safe_get(port, "symbols", params)
    simplified = simplify_response(response)
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)
    return simplified


@mcp.tool()
@text_output
def symbols_imports(offset: int = 0, limit: int = 100, port: int | None = None) -> dict:
    """List imported symbols (external function references)

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: List of imported symbols with name and address
    """
    port = _get_instance_port(port)
    params = {"offset": offset, "limit": limit}
    response = safe_get(port, "symbols/imports", params)
    simplified = simplify_response(response)
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)
    return simplified


@mcp.tool()
@text_output
def symbols_exports(offset: int = 0, limit: int = 100, port: int | None = None) -> dict:
    """List exported symbols

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: List of exported symbols with name and address
    """
    port = _get_instance_port(port)
    params = {"offset": offset, "limit": limit}
    response = safe_get(port, "symbols/exports", params)
    simplified = simplify_response(response)
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)
    return simplified


@mcp.tool()
@text_output
def segments_list(offset: int = 0, limit: int = 100, name: str | None = None, port: int | None = None) -> dict:
    """List memory segments/blocks with permissions

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        name: Filter segments by name substring (optional)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: List of segments with name, address range, size, and RWX permissions
    """
    port = _get_instance_port(port)
    params = {"offset": offset, "limit": limit}
    if name:
        params["name"] = name
    response = safe_get(port, "segments", params)
    simplified = simplify_response(response)
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)
    return simplified


@mcp.tool()
@text_output
def namespaces_list(offset: int = 0, limit: int = 100, port: int | None = None) -> dict:
    """List namespaces in the program

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: List of namespace names
    """
    port = _get_instance_port(port)
    params = {"offset": offset, "limit": limit}
    response = safe_get(port, "namespaces", params)
    simplified = simplify_response(response)
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)
    return simplified


@mcp.tool()
@text_output
def variables_list(offset: int = 0, limit: int = 100, search: str | None = None,
                   global_only: bool = False, source: str = "database", port: int | None = None) -> dict:
    """List variables in the program

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        search: Filter variables by name (optional)
        global_only: Only show global variables (default: False)
        source: Local-variable source. "database" (default) reads committed locals/params
            directly from the program DB - cheap, complete, exactly paginated (the "all
            locals" view). "decompiler" runs the decompiler per function to surface inferred
            locals - richer but slow and approximately paginated.
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: List of variables with name, address, type, and data type
    """
    port = _get_instance_port(port)
    params = {"offset": offset, "limit": limit}
    if search:
        params["search"] = search
    if global_only:
        params["global_only"] = "true"
    if source and source != "database":
        params["source"] = source
    response = safe_get(port, "variables", params)
    simplified = simplify_response(response)
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", simplified.get("total_estimate", len(simplified.get("result", []))))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)
    return simplified


@mcp.tool()
@text_output
def datatypes_list(offset: int = 0, limit: int = 100, category: str | None = None,
                   kind: str | None = None, port: int | None = None) -> dict:
    """List data types defined in the program

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        category: Filter by category path (optional)
        kind: Filter by kind: "struct", "enum", or "union" (optional)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: List of data types with name, kind, category, and size
    """
    port = _get_instance_port(port)
    params = {"offset": offset, "limit": limit}
    if category:
        params["category"] = category
    if kind:
        params["kind"] = kind
    response = safe_get(port, "datatypes", params)
    simplified = simplify_response(response)
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)
    return simplified


@mcp.tool()
@text_output
def datatypes_search(name: str, offset: int = 0, limit: int = 100, port: int | None = None) -> dict:
    """Search for data types by name

    Args:
        name: Data type name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum items to return (default: 100)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Matching data types
    """
    port = _get_instance_port(port)
    params = {"offset": offset, "limit": limit, "name": name}
    response = safe_get(port, "datatypes", params)
    simplified = simplify_response(response)
    if isinstance(simplified, dict) and "error" not in simplified:
        simplified.setdefault("size", len(simplified.get("result", [])))
        simplified.setdefault("offset", offset)
        simplified.setdefault("limit", limit)
    return simplified


@mcp.tool()
@text_output
def datatypes_create_struct(name: str, category: str = "/", fields: list | None = None,
                            port: int | None = None) -> dict:
    """Create a struct datatype

    Args:
        name: Struct name
        category: Category path (default: '/')
        fields: Optional list of field objects, each with 'name', 'type', and optionally 'size', 'offset', 'comment'
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Created datatype info
    """
    if not name:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "name parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)
    payload = {"name": name, "category": category}
    if fields:
        payload["fields"] = fields
    response = safe_post(port, "datatypes/struct", payload)
    return simplify_response(response)


@mcp.tool()
@text_output
def datatypes_create_enum(name: str, size: int = 4, category: str = "/", values: dict | None = None,
                          port: int | None = None) -> dict:
    """Create an enum datatype

    Args:
        name: Enum name
        size: Enum storage size in bytes (default: 4)
        category: Category path (default: '/')
        values: Optional dict mapping enum value names to integer values, e.g. {"VALUE_A": 0, "VALUE_B": 1}
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Created datatype info
    """
    if not name:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "name parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)
    payload = {"name": name, "size": size, "category": category}
    if values:
        payload["values"] = values
    response = safe_post(port, "datatypes/enum", payload)
    return simplify_response(response)


@mcp.tool()
@text_output
def datatypes_create_union(name: str, category: str = "/", fields: list | None = None,
                           port: int | None = None) -> dict:
    """Create a union datatype

    Args:
        name: Union name
        category: Category path (default: '/')
        fields: Optional list of field objects, each with 'name', 'type', and optionally 'size', 'comment'
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Created datatype info
    """
    if not name:
        return {
            "success": False,
            "error": {
                "code": "MISSING_PARAMETER",
                "message": "name parameter is required"
            },
            "timestamp": int(time.time() * 1000)
        }

    port = _get_instance_port(port)
    payload = {"name": name, "category": category}
    if fields:
        payload["fields"] = fields
    response = safe_post(port, "datatypes/union", payload)
    return simplify_response(response)


# ================= CFG, Pcode, and Raw Image (fork-specific) =================

@mcp.tool()
@text_output
def functions_get_cfg(name: str | None = None, address: str | None = None,
                      port: int | None = None) -> dict:
    """Get control flow graph (basic blocks and edges) for a function

    Args:
        name: Function fully-qualified name (mutually exclusive with address)
        address: Function address in hex format (mutually exclusive with name)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Contains blocks (start, end, size) and edges (from, to, type)
    """
    if not name and not address:
        return _missing_param("Either name or address parameter is required")

    port = _get_instance_port(port)
    if address:
        response = safe_get(port, f"functions/{address}/cfg")
    else:
        response = safe_get(port, f"functions/by-name/{quote(name)}/cfg")
    return simplify_response(response)


@mcp.tool()
@text_output
def functions_get_pcode(name: str | None = None, address: str | None = None,
                        port: int | None = None) -> dict:
    """Get pcode operations (low-level IR) for a function

    Pcode is Ghidra's intermediate representation - useful for understanding
    data flow, identifying obfuscated patterns, and tracing CFF state machines.

    Args:
        name: Function fully-qualified name (mutually exclusive with address)
        address: Function address in hex format (mutually exclusive with name)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Contains list of pcode operations with address, opcode, output, inputs
    """
    if not name and not address:
        return _missing_param("Either name or address parameter is required")

    port = _get_instance_port(port)
    if address:
        response = safe_get(port, f"functions/{address}/pcode")
    else:
        response = safe_get(port, f"functions/by-name/{quote(name)}/pcode")
    return simplify_response(response)


@mcp.tool()
@text_output
def raw_image_define(address: str, width: int, height: int,
                     format: str = "RGB565", endian: str = "little",
                     port: int | None = None) -> dict:
    """Define a raw image at the specified address for inline Listing rendering

    Creates a RawImage data type at the address with the given dimensions and pixel format.
    The image will render inline in Ghidra's Listing view.

    Supported formats: RGB565, RGB888, ARGB8888, RGB332, ARGB4444,
                       1bpp, 2bpp, 4bpp, 8bpp (grayscale variants)

    Args:
        address: Memory address in hex format where the raw image data starts
        width: Image width in pixels
        height: Image height in pixels
        format: Pixel format (default: "RGB565")
        endian: Byte order - "little" or "big" (default: "little")
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Operation result with confirmation
    """
    if not address:
        return _missing_param("Address parameter is required")
    if width <= 0 or height <= 0:
        return {"success": False, "error": {"code": "INVALID_DIMENSIONS",
                "message": "Width and height must be positive integers"},
                "timestamp": int(time.time() * 1000)}

    port = _get_instance_port(port)
    payload = {
        "address": address,
        "width": width,
        "height": height,
        "format": format,
        "endian": endian,
    }
    response = safe_post(port, "raw-image/define", payload)
    return simplify_response(response)


@mcp.tool()
@text_output
def raw_image_cleanup(address: str = "", all: bool = False,
                      port: int | None = None) -> dict:
    """Remove RawImage data items created by raw_image_define

    Clears the RawImage data at one address, or every RawImage in the program with all=True.
    Clearing a code unit leaves the underlying bytes undefined again. Idempotent: cleaning up
    when nothing is defined is not an error and reports removed=0.

    Collection and clearing run in a single transaction, so a failure part-way through a
    whole-program sweep rolls back everything.

    Args:
        address: Address of the raw image to clear. Ignored when all=True.
        all: If True, clear every RawImage data item in the program (default: False)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Counts of what was cleared — mode, removed, bytes, and the addresses removed
    """
    if not all and not address:
        return _missing_param("Provide an address, or set all=True to sweep the whole program")

    port = _get_instance_port(port)
    payload: dict = {}
    if all:
        payload["all"] = True
    else:
        payload["address"] = address

    response = safe_post(port, "raw-image/cleanup", payload)
    return simplify_response(response)


def _missing_param(msg: str) -> dict:
    return {"success": False, "error": {"code": "MISSING_PARAMETER", "message": msg},
            "timestamp": int(time.time() * 1000)}


# ================= The target triage =================
#
# What is this file, and what does it need? The format comes from the bytes
# and never from the name of the file.
#
# The bridge ships as one file and imports nothing from the "ghydra"
# package, so the identification is written out here. The CLI carries the
# deeper version - the resources of a PE, the sections of an ELF, the
# entries of an APK - and this one answers the question the agent asks
# first: which tool is this for.

TRIAGE_MAX_LIST = 200


def _triage_read(path: str, length: int = 4096) -> bytes:
    """The first bytes of a file, or nothing."""
    try:
        with open(path, "rb") as handle:
            return handle.read(length)
    except OSError:
        return b""


def _triage_entropy(data: bytes) -> float:
    """The Shannon entropy of the bytes, in bits per byte."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = float(len(data))
    entropy = 0.0
    for count in counts:
        if count:
            share = count / total
            entropy -= share * math.log(share, 2)
    return entropy


def _triage_u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 2], "little") if len(data) >= offset + 2 else 0


def _triage_u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "little") if len(data) >= offset + 4 else 0


def _triage_u64(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 8], "little") if len(data) >= offset + 8 else 0


def _triage_is_text(data: bytes) -> bool:
    """Whether the bytes look like text."""
    if not data:
        return False
    printable = sum(1 for byte in data if 32 <= byte < 127 or byte in (9, 10, 13))
    return printable / len(data) > 0.85


def _triage_identify(path: str) -> dict:
    """What the file is, from its bytes."""
    data = _triage_read(path)
    facts: dict = {}
    fmt = "unknown"

    if data[:2] == b"MZ":
        fmt = "pe"
        lfanew = _triage_u32(data, 0x3c)
        facts["machine"] = _triage_u16(data, lfanew + 4)
        facts["section_count"] = _triage_u16(data, lfanew + 6)
        facts["timestamp"] = _triage_u32(data, lfanew + 8)
        optional = lfanew + 24
        magic = _triage_u16(data, optional)
        facts["is_64bit"] = magic == 0x20b
        facts["subsystem"] = _triage_u16(data, optional + 68)
        facts["image_base"] = hex(_triage_u64(data, optional + 24) if magic == 0x20b
                                  else _triage_u32(data, optional + 28))
        facts["entry_point"] = hex(_triage_u32(data, optional + 16))
        characteristics = _triage_u16(data, lfanew + 22)
        facts["is_dll"] = bool(characteristics & 0x2000)
        # The COM descriptor is the fifteenth data directory: a managed
        # assembly has one, and a native one does not.
        directories = optional + (112 if magic == 0x20b else 96)
        facts["is_dotnet"] = _triage_u32(data, directories + 14 * 8) != 0
    elif data[:4] == b"\x7fELF":
        fmt = "elf"
        is_64 = data[4] == 2
        little = data[5] == 1
        order = "little" if little else "big"
        facts["class"] = 64 if is_64 else 32
        facts["endianness"] = order
        facts["type"] = int.from_bytes(data[16:18], order)
        facts["machine"] = int.from_bytes(data[18:20], order)
        facts["is_core"] = facts["type"] == 4
        if facts["is_core"]:
            fmt = "core"
        facts["entry_point"] = hex(int.from_bytes(data[24:32] if is_64 else data[24:28], order))
    elif data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                      b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        fmt = "mach-o"
        facts["bits"] = 64 if data[4] in (0xCF, 0xCF) or data[:4] in (b"\xfe\xed\xfa\xcf",
                                                                     b"\xcf\xfa\xed\xfe") else 32
        facts["cputype"] = int.from_bytes(data[4:8], "little")
        facts["filetype"] = int.from_bytes(data[12:16], "little")
    elif data[:4] == b"dex\n":
        fmt = "dex"
        facts["version"] = data[4:7].decode("ascii", "replace")
        facts["class_count"] = _triage_u32(data, 96)
    elif data[:4] == b"\x00asm":
        fmt = "wasm"
        facts["version"] = int.from_bytes(data[4:8], "little")
    elif data[:4] == b"CAFE":
        fmt = "class"
        facts["version"] = f"{_triage_u16(data, 6)}.{_triage_u16(data, 4)}"
    elif data[:4] == b"MDMP":
        fmt = "core"
        facts["kind"] = "windows minidump"
    elif data[:3] == b"\x60\x80\x60":
        fmt = "evm"
        facts["code_size"] = len(data)
    elif data[:2] == b"PK":
        fmt = "zip"
        try:
            import zipfile
            with zipfile.ZipFile(path) as archive:
                names = archive.namelist()
            facts["entry_count"] = len(names)
            if any(name.startswith("AndroidManifest.xml") for name in names):
                fmt = "apk"
                facts["entry_count"] = len(names)
                facts["has_dex"] = any(name.endswith(".dex") for name in names)
                facts["native_libraries"] = [
                    name for name in names if name.endswith(".so")][:TRIAGE_MAX_LIST]
            elif any(name.endswith("app.asar") or "/app.asar" in name for name in names):
                facts["has_asar"] = True
        except Exception:
            facts["entry_count"] = 0
    elif data[:2] == b"\x1f\x8b":
        fmt = "gzip"
    elif data[:4] == b"%PDF":
        fmt = "pdf"
    elif data[:16] == b"SQLite format 3\x00":
        fmt = "sqlite"
    elif data[:6] in (b"bplist", b"<?xml "):
        fmt = "plist"
    elif data[:4] == b"\x27\x05\x19\x56":
        fmt = "firmware"
        facts["kind"] = "uImage"
        facts["payload_size"] = _triage_u32(data, 4)
    elif data[:4] == b"hsqs":
        fmt = "firmware"
        facts["kind"] = "squashfs"
    elif data[:4] == b"\x85\x19\x19\x98":
        fmt = "firmware"
        facts["kind"] = "jffs2"
    elif data[:4] == b"\x45\x3d\xcd\x28":
        fmt = "firmware"
        facts["kind"] = "cramfs"
    elif _triage_is_text(data):
        fmt = "text"
        stripped = data.strip()
        if stripped.startswith(b"{") and b'"log"' in stripped:
            try:
                import json
                document = json.loads(open(path, "r", encoding="utf-8",
                                          errors="replace").read())
                entries = (document.get("log") or {}).get("entries")
                if isinstance(entries, list):
                    fmt = "har"
                    facts["entry_count"] = len(entries)
            except Exception:
                pass

    # A script is a script, whatever it holds. The extension is the only
    # thing that says so here - the bytes of a JavaScript file are text,
    # and text is not a format on its own.
    if fmt in ("text", "unknown") and path.lower().endswith((".js", ".mjs", ".cjs")):
        fmt = "javascript"
        facts["kind"] = "javascript"

    return {"format": fmt, "facts": facts}


def _triage_recommendations(fmt: str, facts: dict) -> list:
    """What a target of this kind needs."""
    out = []
    if fmt == "pe":
        if facts.get("is_dotnet"):
            out.append("managed .NET assembly: a .NET decompiler will read it "
                       "better than a native one")
        else:
            out.append("native PE: run 'ghydra report build <path>'")
        if facts.get("is_64bit"):
            out.append("64-bit: the pointers are eight bytes wide")
    elif fmt == "elf":
        out.append("native ELF: run 'ghydra report build <path>'")
    elif fmt == "mach-o":
        out.append("Mach-O: run 'ghydra report build <path>'")
    elif fmt == "dex":
        out.append("Android DEX: the classes are Dalvik bytecode, not native code")
    elif fmt == "apk":
        out.append("Android package: unpack it and look at the classes.dex and "
                   "the native libraries")
    elif fmt == "wasm":
        out.append("WASM module: the exports are the entry points")
    elif fmt == "evm":
        out.append("EVM contract: the 4-byte selectors are in the dispatcher")
    elif fmt == "core":
        out.append("core dump: the registers of the crashing thread are the "
                   "beginning of the analysis")
    elif fmt == "javascript":
        out.append("JavaScript: look for the entry point and the source maps")
    elif fmt == "firmware":
        out.append("firmware image: unpack it before anything else")
    elif fmt == "har":
        out.append("HAR capture: the requests are the surface of the "
                   "application")
    return out


@mcp.tool()
@text_output
def inspect_target(path: str) -> dict:
    """Say what a file is, and what it needs.

    The format comes from the bytes and never from the name of the file: a
    PE, an ELF, a Mach-O, a DEX, an APK, a WASM module, an EVM contract, a
    firmware image, a JavaScript or Electron application, a core dump, a
    plist, a HAR capture. It needs neither Ghidra nor the network.

    Args:
        path: The file to look at

    Returns:
        dict: The format, the facts that identify it, and what it needs
    """
    target = os.path.abspath(os.path.expanduser(path))
    if not os.path.isfile(target):
        return {"success": False,
                "error": {"code": "TRIAGE_NO_FILE",
                          "message": f"no such file: {path}"}}
    try:
        identified = _triage_identify(target)
    except Exception as exc:
        return {"success": False,
                "error": {"code": "TRIAGE_ERROR", "message": str(exc)}}

    size = 0
    try:
        size = os.path.getsize(target)
    except OSError:
        pass

    facts = identified.get("facts") or {}
    fmt = identified.get("format", "unknown")
    return {"success": True,
            "result": {
                "path": target,
                "format": fmt,
                "size": size,
                "facts": facts,
                "recommendations": _triage_recommendations(fmt, facts),
            }}




# ================= Headless: the API without a window =================
#
# The bridge is a standalone script: it ships as one file and imports
# nothing from the "ghydra" package. The helpers below are therefore the
# same ones the CLI has, written out again - the pattern the Kuna
# integration already follows.
#
# What is here: a headless Ghidra run that serves the same REST API from
# an analysis, with no window and nobody watching. The run outlives the
# call that started it, so an agent can analyse a binary and then use the
# ordinary tools on it.

HEADLESS_DEFAULT_PORT = 8192
HEADLESS_SCRIPT = "GhidraHeadlessServer"
HEADLESS_POLL = 0.25

# The headless analyzer's own heap default, and the two flags it uses to
# keep the GC and the JIT compiler from taking a thread per core.
HEADLESS_MAXMEM = "2G"
HEADLESS_VMARGS = ["-XX:ParallelGCThreads=2", "-XX:CICompilerCount=2"]


def _headless_state_dir() -> str:
    """Where the state of the runs lives."""
    base = os.environ.get("GHYDRA_STATE_DIR")
    if not base:
        base = os.path.join(os.path.expanduser("~"), ".ghydra")
    try:
        os.makedirs(base, exist_ok=True)
    except OSError:
        pass
    return base


def _headless_state_path(port: int) -> str:
    return os.path.join(_headless_state_dir(), f"headless-{int(port)}.json")


def _headless_log_path(port: int) -> str:
    return os.path.join(_headless_state_dir(), f"headless-{int(port)}.log")


def _headless_stop_file(port: int) -> str:
    """The file the launcher leaves behind to stop the run."""
    return os.path.join(os.path.expanduser("~"), ".ghidra", f"headless-{int(port)}.stop")


def _headless_candidate_homes() -> list:
    """The places Ghidra is usually installed."""
    home = os.path.expanduser("~")
    candidates = []
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA", "")
        program = os.environ.get("ProgramFiles", r"C:\Program Files")
        if local:
            candidates.append(os.path.join(local, "Programs", "Ghidra"))
        if program:
            candidates.append(os.path.join(program, "Ghidra"))
        candidates.append(os.path.join(home, "scoop", "apps", "ghidra", "current"))
        candidates.append(os.path.join(home, "ghidra"))
    else:
        candidates.extend(["/opt/ghidra", "/usr/local/ghidra", "/usr/share/ghidra",
                           os.path.join(home, "ghidra"), os.path.join(home, "opt", "ghidra")])
    return candidates


def _headless_find_ghidra(explicit: str = "") -> str:
    """Where the Ghidra installation is."""
    for candidate in (explicit, os.environ.get("GHIDRA_HOME")):
        if candidate and os.path.isdir(candidate):
            return os.path.abspath(candidate)
    for candidate in _headless_candidate_homes():
        if os.path.isdir(candidate):
            return os.path.abspath(candidate)
    raise FileNotFoundError(
        "no Ghidra installation found. Set GHIDRA_HOME, or pass ghidra_home.")


def _headless_properties(path: str) -> dict:
    """The key/value pairs of a Java properties file."""
    out = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                if key.strip():
                    out[key.strip()] = value.strip()
    except OSError:
        pass
    return out


def _headless_java_version(java_home: str):
    """The version of a JDK, read from the release file it ships."""
    try:
        with open(os.path.join(java_home, "release"), "r", encoding="utf-8",
                  errors="replace") as handle:
            text = handle.read()
    except OSError:
        return None
    match = re.search(r'JAVA_VERSION="?(\d+)', text)
    return int(match.group(1)) if match else None


def _headless_find_java(ghidra_home: str, explicit: str = "") -> str:
    """The JDK to run Ghidra with.

    Ghidra's own LaunchSupport is asked first when there is a java to ask
    it with: it answers with a JDK the installation supports, which is
    better than any search.
    """
    properties = _headless_properties(
        os.path.join(ghidra_home, "Ghidra", "application.properties"))
    required = properties.get("application.java.min", "")
    try:
        required = int(required) if required else 0
    except ValueError:
        required = 0

    candidates = []
    if explicit:
        candidates.append(explicit)
    env_home = os.environ.get("JAVA_HOME", "")
    if env_home:
        candidates.append(env_home)

    support = os.path.join(ghidra_home, "support", "LaunchSupport.jar")
    probe = os.path.join(env_home, "bin", "java.exe" if os.name == "nt" else "java")
    if not os.path.isfile(probe):
        probe = shutil.which("java") or ""
    if probe and os.path.isfile(support):
        try:
            output = subprocess.run(
                [probe, "-cp", support, "LaunchSupport", ghidra_home, "-jdk_home", "-save"],
                capture_output=True, text=True, timeout=120).stdout or ""
            for line in output.splitlines():
                candidate = line.strip()
                if candidate and os.path.isdir(candidate):
                    candidates.append(candidate)
        except (OSError, subprocess.SubprocessError):
            pass

    for candidate in candidates:
        version = _headless_java_version(candidate)
        if version is None:
            continue
        if required and version < required:
            continue
        return os.path.abspath(candidate)

    raise FileNotFoundError(
        f"no JDK {required or ''} or newer was found. Set JAVA_HOME, or pass "
        "java_home.")


def _headless_vmargs(ghidra_home: str, java_home: str) -> list:
    """The VM arguments of the installation, as Ghidra itself reads them."""
    support = os.path.join(ghidra_home, "support", "LaunchSupport.jar")
    java = os.path.join(java_home, "bin", "java.exe" if os.name == "nt" else "java")
    if not os.path.isfile(support) or not os.path.isfile(java):
        return []
    try:
        output = subprocess.run(
            [java, "-cp", support, "LaunchSupport", ghidra_home, "-vmargs"],
            capture_output=True, text=True, timeout=120).stdout or ""
    except (OSError, subprocess.SubprocessError):
        return []
    return [line.strip() for line in output.splitlines() if line.strip()]


def _headless_project_index(project_dir: str, project_name: str) -> str:
    """The index of the files in a project.

    Ghidra keeps it as plain text: one line per file, with the name of the
    file and the id of its content. It is what says whether a program is
    already in the project.
    """
    path = os.path.join(project_dir, f"{project_name}.rep", "idata", "~index.dat")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def _headless_program_in_project(project_dir: str, project_name: str, program: str) -> bool:
    """Whether the program is already in the project.

    Importing a program that is already there fails, and the run ends
    without ever reaching the script that starts the server. When the
    program is there, the run has to process it instead of importing it.
    """
    index = _headless_project_index(project_dir, project_name)
    if not index:
        return False
    return f":{os.path.basename(program)}:" in index


def _headless_command(ghidra_home: str, java_home: str, project_dir: str,
                      project_name: str, binary: str, port: int,
                      process: bool = False) -> list:
    """The command that starts a headless run.

    It is the JVM invocation the launcher makes, not the launcher itself:
    the Windows launcher asks "press any key to continue" when it fails,
    because it cannot tell a double-click from a shell - and a launcher
    that was started by another program is exactly that case.
    """
    utility = os.path.join(ghidra_home, "Ghidra", "Framework", "Utility", "lib", "Utility.jar")
    if not os.path.isfile(utility):
        raise FileNotFoundError(f"no Utility.jar in {utility}")
    java = os.path.join(java_home, "bin", "java.exe" if os.name == "nt" else "java")
    command = [java]
    command += _headless_vmargs(ghidra_home, java_home)
    command.append(f"-Xmx{HEADLESS_MAXMEM}")
    command += HEADLESS_VMARGS
    for name in ("GHIDRA_JAVA_OPTIONS", "GHIDRA_HEADLESS_JAVA_OPTIONS"):
        value = os.environ.get(name, "")
        if value.strip():
            command += [part for part in re.split(r"\s+", value.strip()) if part]
    command.append(f"-Duser.home={os.path.expanduser('~')}")
    command += ["-cp", utility, "ghidra.Ghidra", "ghidra.app.util.headless.AnalyzeHeadless"]
    command += [project_dir, project_name]
    if process:
        command += ["-process", os.path.basename(binary)]
    else:
        command += ["-import", binary]
    command += ["-postScript", HEADLESS_SCRIPT, f"port={int(port)}"]
    return command


def _headless_project_dir() -> str:
    """Where the projects live.

    Ghidra refuses a project path with an element that starts with a dot,
    and ".ghidra" is exactly that - so the projects live in Ghidra's own
    convention, in the home directory.
    """
    return os.path.join(os.path.expanduser("~"), "ghidra_projects")


def _headless_api_answers(host: str, port: int, timeout: float = 5.0) -> bool:
    """Whether the API answers on the port."""
    try:
        response = requests.get(f"http://{host}:{int(port)}/", timeout=timeout)
    except Exception:
        return False
    return response.status_code == 200


def _headless_process_alive(pid: int) -> bool:
    """Whether the process of a run is still there."""
    if not pid:
        return False
    if os.name == "nt":
        try:
            output = subprocess.run(["tasklist", "/FI", f"PID eq {int(pid)}", "/NH"],
                                    capture_output=True, text=True, timeout=10).stdout or ""
        except (OSError, subprocess.SubprocessError):
            return False
        return str(pid) in output
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _headless_process_is_ours(pid: int) -> bool:
    """Whether the process is the headless run this bridge started.

    A PID on its own says nothing - the operating system reuses them, and
    a run that died leaves its state behind. The command line is read, and
    the process is only ours when it carries the marker of the headless
    script.
    """
    if not pid:
        return False
    try:
        if os.name == "nt":
            command = ("Get-CimInstance Win32_Process -Filter "
                       f"'ProcessId={int(pid)}' | Select-Object -ExpandProperty CommandLine")
            output = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
                capture_output=True, text=True, timeout=30).stdout or ""
        else:
            output = subprocess.run(["ps", "-p", str(int(pid)), "-o", "command="],
                                    capture_output=True, text=True, timeout=30).stdout or ""
    except (OSError, subprocess.SubprocessError):
        return False
    return HEADLESS_SCRIPT.lower() in (output or "").lower()


def _headless_load_state(port: int) -> dict:
    """The run remembered for a port."""
    try:
        with open(_headless_state_path(port), "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _headless_save_state(port: int, state: dict) -> None:
    """Remember a run."""
    try:
        with open(_headless_state_path(port), "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2)
    except OSError:
        pass


def _headless_clear_state(port: int) -> None:
    """Forget a run."""
    try:
        os.remove(_headless_state_path(port))
    except OSError:
        pass


def _headless_slug(binary: str) -> str:
    """A project name for a binary."""
    stem = os.path.splitext(os.path.basename(binary))[0]
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", stem).strip("_") or "binary"


@mcp.tool()
@text_output
def headless_start(binary: str, port: int = HEADLESS_DEFAULT_PORT,
                   timeout: int = 900, ghidra_home: str = "",
                   java_home: str = "", async_mode: bool = False) -> dict:
    """Analyse a binary and serve the API from it, with no window.

    The run imports the binary, analyses it, and then answers the ordinary
    GhidraMCP tools on that analysis - with no CodeBrowser and nobody
    watching. It outlives this call: the tools keep working until
    "headless_stop" is called.

    The analysis of a big binary takes minutes, so the call waits for the
    API to come up (the "timeout" is how long it waits). With async_mode=True
    it does not wait at all: a task handle comes back immediately, the wait
    runs in the background, and tasks_get(task_id) says when the API is up.
    The run itself is not affected by cancelling the task - it is meant to
    outlive this call; use headless_stop for that.

    Args:
        binary: The file to analyse
        port: The port to serve on (default: 8192)
        timeout: Seconds to wait for the API (default: 900)
        ghidra_home: Path of the Ghidra installation (default: GHIDRA_HOME)
        java_home: Path of the JDK (default: the one Ghidra supports)
        async_mode: Return a task handle immediately; the wait for the API
                    runs in the background (poll tasks_get).

    Returns:
        dict: The port, the url, the pid, the project and the log
    """
    raw = lambda: _headless_start_raw(binary, port, timeout, ghidra_home, java_home)
    if async_mode:
        return _task_spawn(
            "headless_start",
            f"{os.path.basename(binary)} on port {port}",
            body=raw,
            result_of=lambda outcome: outcome)
    return raw()


def _headless_start_raw(binary: str, port: int = HEADLESS_DEFAULT_PORT,
                        timeout: int = 900, ghidra_home: str = "",
                        java_home: str = "") -> dict:
    """The run itself, without the tool around it.

    The session tools need the same thing the headless tools do, so the
    work is here and the tool is the wrapper around it.
    """
    path = os.path.abspath(os.path.expanduser(binary))
    if not os.path.isfile(path):
        return {"success": False,
                "error": {"code": "HEADLESS_NO_FILE",
                          "message": f"no such binary: {path}"}}

    try:
        home = _headless_find_ghidra(ghidra_home)
    except FileNotFoundError as exc:
        return {"success": False,
                "error": {"code": "HEADLESS_NO_GHIDRA", "message": str(exc)}}

    try:
        java = _headless_find_java(home, java_home)
    except FileNotFoundError as exc:
        return {"success": False,
                "error": {"code": "HEADLESS_NO_JDK", "message": str(exc)}}

    if _headless_api_answers(ghidra_host, port):
        return {"success": False,
                "error": {"code": "HEADLESS_PORT_IN_USE",
                          "message": f"something is already serving the API on "
                                     f"{ghidra_host}:{port}"}}

    project_dir = _headless_project_dir()
    project_name = _headless_slug(path)
    try:
        os.makedirs(project_dir, exist_ok=True)
    except OSError as exc:
        return {"success": False,
                "error": {"code": "HEADLESS_BAD_PROJECT_DIR", "message": str(exc)}}

    try:
        command = _headless_command(
            home, java, project_dir, project_name, path, port,
            process=_headless_program_in_project(project_dir, project_name, path))
    except FileNotFoundError as exc:
        return {"success": False,
                "error": {"code": "HEADLESS_LAUNCH", "message": str(exc)}}

    log = _headless_log_path(port)
    try:
        handle = open(log, "a", encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"success": False,
                "error": {"code": "HEADLESS_LAUNCH", "message": str(exc)}}

    kwargs = {"stdout": handle, "stderr": subprocess.STDOUT,
              "stdin": subprocess.DEVNULL, "cwd": project_dir}
    if os.name == "nt":
        kwargs["creationflags"] = (subprocess.CREATE_NEW_PROCESS_GROUP
                                   | getattr(subprocess, "DETACHED_PROCESS", 0))
    else:
        kwargs["start_new_session"] = True

    try:
        process = subprocess.Popen(command, **kwargs)
    except OSError as exc:
        handle.close()
        return {"success": False,
                "error": {"code": "HEADLESS_LAUNCH", "message": str(exc)}}
    finally:
        handle.close()

    _headless_save_state(port, {
        "port": int(port), "pid": process.pid, "binary": path,
        "project_dir": project_dir, "project_name": project_name,
        "ghidra_home": home, "java_home": java, "log": log,
        "started_at": time.time(),
    })

    deadline = time.time() + max(1, int(timeout))
    while time.time() < deadline:
        if process.poll() is not None:
            return {"success": False,
                    "error": {"code": "HEADLESS_DIED",
                              "message": f"the headless run ended before the API came "
                                         f"up. See {log}"}}
        if _headless_api_answers(ghidra_host, port):
            register_instance(int(port), f"http://{ghidra_host}:{int(port)}")
            return {"success": True,
                    "result": {
                        "message": f"The API is serving on http://{ghidra_host}:{int(port)}",
                        "port": int(port), "pid": process.pid, "binary": path,
                        "project": f"{project_dir}/{project_name}", "log": log}}
        time.sleep(HEADLESS_POLL)

    return {"success": False,
            "error": {"code": "HEADLESS_TIMEOUT",
                      "message": f"the API did not answer within {timeout}s. See {log}"}}


@mcp.tool()
@text_output
def headless_stop(port: int = HEADLESS_DEFAULT_PORT, timeout: int = 20) -> dict:
    """Stop a headless run, saving the analysis on its way out.

    The stop is polite: the run is asked to end, so that Ghidra saves the
    program and closes the project, and the project is left unlocked. The
    analysis stays in the project and the program can be opened in Ghidra
    later.

    Args:
        port: The port of the run (default: 8192)
        timeout: Seconds to wait for the run to end (default: 20)

    Returns:
        dict: Whether the run was stopped and whether it was saved
    """
    return _headless_stop_raw(port, timeout)


def _headless_stop_raw(port: int = HEADLESS_DEFAULT_PORT, timeout: int = 20) -> dict:
    """The stop itself, without the tool around it."""
    state = _headless_load_state(port)
    if not state:
        return {"success": False,
                "error": {"code": "HEADLESS_NO_RUN",
                          "message": f"no headless run is known on port {port}"}}

    saved = False
    try:
        requests.post(f"http://{ghidra_host}:{int(port)}/program/save", timeout=30)
        saved = True
    except Exception:
        saved = False

    pid = int(state.get("pid") or 0)
    if not pid or not _headless_process_is_ours(pid):
        # The state outlived the run, and the PID may belong to something
        # else by now. Nothing is killed.
        _headless_clear_state(port)
        return {"success": True,
                "result": {"message": f"the run on port {port} was not there "
                                      f"anymore; the stale state was cleared",
                           "port": int(port), "saved": saved, "stopped": False}}

    flag = _headless_stop_file(port)
    try:
        os.makedirs(os.path.dirname(flag), exist_ok=True)
        with open(flag, "w", encoding="utf-8") as handle:
            handle.write(str(time.time()))
    except OSError:
        flag = ""

    stopped = False
    if flag:
        deadline = time.time() + max(1, int(timeout))
        while time.time() < deadline:
            if not _headless_process_alive(pid):
                stopped = True
                break
            time.sleep(HEADLESS_POLL)

    if not stopped:
        if os.name == "nt":
            try:
                subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                               capture_output=True, timeout=timeout)
            except (OSError, subprocess.SubprocessError):
                pass
        else:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
        deadline = time.time() + max(1, int(timeout))
        while time.time() < deadline and _headless_process_alive(pid):
            time.sleep(HEADLESS_POLL)
        if _headless_process_alive(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        stopped = True

    _headless_clear_state(port)
    with instances_lock:
        active_instances.pop(int(port), None)
    return {"success": True,
            "result": {"message": f"the run on port {port} was stopped",
                       "port": int(port), "saved": saved, "stopped": True}}


@mcp.tool()
@text_output
def headless_status(port: int = HEADLESS_DEFAULT_PORT) -> dict:
    """What is known about the headless run on a port.

    Args:
        port: The port to look at (default: 8192)

    Returns:
        dict: Whether the run is alive, what it analyses and where its log is
    """
    state = _headless_load_state(port)
    if not state:
        return {"success": True,
                "result": {"port": int(port), "known": False, "running": False,
                           "api": _headless_api_answers(ghidra_host, port)}}
    pid = int(state.get("pid") or 0)
    return {"success": True,
            "result": {"port": int(port), "known": True,
                       "running": _headless_process_alive(pid),
                       "api": _headless_api_answers(ghidra_host, port),
                       "pid": pid, "binary": state.get("binary", ""),
                       "project_dir": state.get("project_dir", ""),
                       "project_name": state.get("project_name", ""),
                       "log": state.get("log", ""),
                       "started_at": state.get("started_at", 0)}}


# ================= The doctor =================

@mcp.tool()
@text_output
def doctor_check() -> dict:
    """Check that everything is in place, and say what is not.

    The Ghidra installation, the JDK it needs, the extension, the port,
    the project directory, the API, Kuna and the x64dbg plugin. Every
    problem comes with the command that solves it.

    Returns:
        dict: One entry per check, with its status and its hint
    """
    checks = []

    def add(name: str, status: str, detail: str, hint: str = "") -> None:
        checks.append({"name": name, "status": status, "detail": detail, "hint": hint})

    home = ""
    try:
        home = _headless_find_ghidra()
        properties = _headless_properties(
            os.path.join(home, "Ghidra", "application.properties"))
        version = properties.get("application.version", "")
        add("ghidra", "ok", f"{home}" + (f" (version {version})" if version else ""))
    except FileNotFoundError as exc:
        add("ghidra", "fail", str(exc),
            'Set GHIDRA_HOME, or put "ghidra_home" in ~/.ghydra/config.json.')

    if home:
        try:
            java = _headless_find_java(home)
            version = _headless_java_version(java)
            add("jdk", "ok", f"{java}" + (f" (JDK {version})" if version else ""))
        except FileNotFoundError as exc:
            add("jdk", "fail", str(exc),
                'Install a JDK and point at it: "java_home" in ~/.ghydra/config.json.')

        settings = os.path.join(os.environ.get("APPDATA", ""), "ghidra") if os.name == "nt" \
            else os.path.join(os.path.expanduser("~"), ".config", "ghidra")
        installed = False
        for root, directories, files in os.walk(settings):
            if "extension.properties" in files and "Ghydra" in root:
                installed = True
                break
            if len(root.split(os.sep)) > len(settings.split(os.sep)) + 3:
                directories[:] = []
        add("extension", "ok" if installed else "fail",
            "installed" if installed else f"not installed under {settings}",
            "" if installed else "Install the extension in the directory Ghidra loads from.")
    else:
        add("jdk", "warn", "not checked - there is no Ghidra installation")
        add("extension", "warn", "not checked - there is no Ghidra installation")

    api = _headless_api_answers(ghidra_host, DEFAULT_GHIDRA_PORT)
    add("api", "ok" if api else "warn",
        f"an instance is serving on {ghidra_host}:{DEFAULT_GHIDRA_PORT}" if api
        else f"nothing is serving on {ghidra_host}:{DEFAULT_GHIDRA_PORT}",
        "" if api else "A headless run starts one when it is needed.")

    failures = [check for check in checks if check["status"] == "fail"]
    return {"success": not failures,
            "result": {"ok": not failures, "checks": checks,
                       "failures": len(failures),
                       "warnings": len([c for c in checks if c["status"] == "warn"])}}


# ================= The evidence ledger =================
#
# Every finding gets an ID, and the ledger can be exported as a bundle.
# It is what keeps the result of an analysis from dying with the session
# it was made in.

EVIDENCE_KINDS = ("function", "string", "xref", "data", "note", "vulnerability", "custom")
EVIDENCE_ID_PREFIX = "EV-"
EVIDENCE_ID_WIDTH = 4


def _evidence_dir() -> str:
    """Where the ledgers live."""
    base = os.path.join(_headless_state_dir(), "evidence")
    try:
        os.makedirs(base, exist_ok=True)
    except OSError:
        pass
    return base


def _evidence_path(name: str) -> str:
    """The file of a ledger."""
    clean = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(name or "default")).strip("_") or "default"
    return os.path.join(_evidence_dir(), f"{clean}.json")


def _evidence_normalize_address(address: str) -> str:
    """The address in one shape: a lowercase hex with the 0x in front."""
    text = str(address or "").strip()
    if not text:
        return ""
    try:
        return hex(int(text, 16))
    except ValueError:
        return text


def _evidence_load(name: str) -> dict:
    """The ledger, as it is on disk."""
    try:
        with open(_evidence_path(name), "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _evidence_save(name: str, data: dict) -> None:
    """Write the ledger."""
    try:
        with open(_evidence_path(name), "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
    except OSError:
        pass


def _evidence_next_id(data: dict) -> str:
    """The next ID. An ID is never given out twice."""
    highest = 0
    for finding in data.get("findings") or []:
        text = str(finding.get("id") or "")
        if text.startswith(EVIDENCE_ID_PREFIX):
            try:
                highest = max(highest, int(text[len(EVIDENCE_ID_PREFIX):]))
            except ValueError:
                continue
    try:
        highest = max(highest, int(data.get("next_id") or 0))
    except (TypeError, ValueError):
        pass
    return f"{EVIDENCE_ID_PREFIX}{highest + 1:0{EVIDENCE_ID_WIDTH}d}"


@mcp.tool()
@text_output
def evidence_add(kind: str, address: str = "", name: str = "", note: str = "",
                  tags: str = "", source: str = "", code: str = "",
                  confidence: str = "medium", ledger: str = "default") -> dict:
    """Record a finding, and give it an ID.

    A finding is something that was learned about the binary: a function
    that matters, a string that is a key, an xref that explains a call. It
    gets an ID that never changes, so it can be referred to later - in a
    report, in a note, in a conversation.

    Args:
        kind: What the finding is: function, string, xref, data, note,
            vulnerability or custom
        address: Where it is, as the static address (0x140001000)
        name: The name of the thing
        note: What was learned about it
        tags: Tags, separated by commas
        source: Where it was seen - a tool, an instance, a report
        code: A snippet of code, when there is one
        confidence: high, medium or low (default: medium)
        ledger: The ledger to write into (default: "default")

    Returns:
        dict: The finding, with the ID it was given
    """
    if kind not in EVIDENCE_KINDS:
        return {"success": False,
                "error": {"code": "EVIDENCE_BAD_KIND",
                          "message": f"'{kind}' is not a kind. Use one of: "
                                     + ", ".join(EVIDENCE_KINDS)}}
    if confidence not in ("high", "medium", "low"):
        confidence = "medium"

    data = _evidence_load(ledger)
    data.setdefault("name", ledger)
    data.setdefault("created_at", time.time())
    findings = data.get("findings")
    if not isinstance(findings, list):
        findings = []
    finding_id = _evidence_next_id(data)
    tag_list = [tag.strip() for tag in str(tags or "").split(",") if tag.strip()]
    finding = {
        "id": finding_id,
        "kind": kind,
        "address": _evidence_normalize_address(address),
        "name": str(name or ""),
        "note": str(note or ""),
        "tags": tag_list,
        "source": str(source or ""),
        "code": str(code or ""),
        "confidence": confidence,
        "created_at": time.time(),
    }
    findings.append(finding)
    data["findings"] = findings
    data["updated_at"] = time.time()
    data["next_id"] = int(finding_id[len(EVIDENCE_ID_PREFIX):]) + 1
    _evidence_save(ledger, data)

    return {"success": True, "result": {"message": f"{finding_id} was recorded",
                                        "finding": finding,
                                        "ledger": _evidence_path(ledger)}}


@mcp.tool()
@text_output
def evidence_list(ledger: str = "default", kind: str = "", tag: str = "",
                  address: str = "", query: str = "") -> dict:
    """The findings of a ledger.

    Args:
        ledger: The ledger to read (default: "default")
        kind: Only the findings of this kind
        tag: Only the findings with this tag
        address: Only the findings at this address
        query: Only the findings whose name, note or address holds this text

    Returns:
        dict: The findings that matched
    """
    data = _evidence_load(ledger)
    findings = data.get("findings") or []
    wanted_address = _evidence_normalize_address(address)
    lowered = str(query or "").lower()

    out = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        if kind and finding.get("kind") != kind:
            continue
        if tag and tag not in (finding.get("tags") or []):
            continue
        if wanted_address and finding.get("address") != wanted_address:
            continue
        if lowered:
            haystack = " ".join([
                str(finding.get("name") or ""),
                str(finding.get("note") or ""),
                str(finding.get("address") or ""),
            ]).lower()
            if lowered not in haystack:
                continue
        out.append(finding)

    return {"success": True,
            "result": {"ledger": ledger, "count": len(out),
                       "total": len(findings), "findings": out}}


@mcp.tool()
@text_output
def evidence_export(ledger: str = "default", output: str = "",
                    binary: str = "") -> dict:
    """Export the ledger as a bundle: a document to read and one to read
    with a program.

    Args:
        ledger: The ledger to export (default: "default")
        output: The directory the files go to (default: the current one)
        binary: The binary the findings are about, for the header

    Returns:
        dict: Where the two files are, and how many findings there are
    """
    data = _evidence_load(ledger)
    findings = data.get("findings") or []
    directory = os.path.abspath(os.path.expanduser(output)) if output else os.getcwd()
    try:
        os.makedirs(directory, exist_ok=True)
    except OSError as exc:
        return {"success": False,
                "error": {"code": "EVIDENCE_IO", "message": str(exc)}}

    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(ledger or "default")).strip("_") or "default"
    markdown_path = os.path.join(directory, f"{stem}-evidence.md")
    json_path = os.path.join(directory, f"{stem}-evidence.json")

    lines = [f"# {ledger} - evidence\n"]
    if binary:
        lines.append(f"- Binary: `{binary}`")
    lines.append(f"- Exported: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"- Findings: {len(findings)}\n")

    by_kind = {}
    for finding in findings:
        by_kind.setdefault(str(finding.get("kind") or "note"), 0)
        by_kind[str(finding.get("kind") or "note")] += 1
    if by_kind:
        lines.append("| Kind | How many |")
        lines.append("| --- | --- |")
        for kind in sorted(by_kind):
            lines.append(f"| {kind} | {by_kind[kind]} |")
        lines.append("")

    for finding in findings:
        lines.append(f"## {finding.get('id')} - {finding.get('name') or finding.get('kind')}\n")
        lines.append(f"- Kind: {finding.get('kind')}")
        if finding.get("address"):
            lines.append(f"- Address: `{finding.get('address')}`")
        if finding.get("tags"):
            lines.append(f"- Tags: {', '.join(finding.get('tags') or [])}")
        if finding.get("source"):
            lines.append(f"- Source: {finding.get('source')}")
        lines.append(f"- Confidence: {finding.get('confidence', 'medium')}")
        if finding.get("note"):
            lines.append(f"\n{finding.get('note')}")
        if finding.get("code"):
            lines.append("\n```c")
            lines.append(str(finding.get("code")).rstrip())
            lines.append("```")
        lines.append("")

    try:
        with open(markdown_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines))
        with open(json_path, "w", encoding="utf-8") as handle:
            json.dump({"ledger": ledger, "binary": binary,
                       "exported_at": time.time(), "findings": findings},
                      handle, indent=2, ensure_ascii=False)
    except OSError as exc:
        return {"success": False,
                "error": {"code": "EVIDENCE_IO", "message": str(exc)}}

    return {"success": True,
            "result": {"message": f"the bundle is in {directory}",
                       "markdown": markdown_path, "json": json_path,
                       "findings": len(findings)}}


# ================= Sessions =================
#
# A session is a named working context: the binary, the port that serves
# it, and the state. It survives the shell that opened it.

def _sessions_path() -> str:
    """Where the sessions are kept."""
    return os.path.join(_headless_state_dir(), "sessions.json")


def _sessions_load() -> list:
    """The sessions, as they are on disk."""
    try:
        with open(_sessions_path(), "r", encoding="utf-8") as handle:
            data = json.load(handle)
        sessions = data.get("sessions") if isinstance(data, dict) else None
        return sessions if isinstance(sessions, list) else []
    except (OSError, ValueError):
        return []


def _sessions_save(sessions: list) -> None:
    """Write the sessions."""
    try:
        with open(_sessions_path(), "w", encoding="utf-8") as handle:
            json.dump({"sessions": sessions}, handle, indent=2, ensure_ascii=False)
    except OSError:
        pass


def _session_id(name: str, created_at: float) -> str:
    """A short, stable ID for a session."""
    digest = hashlib.sha256(f"{name}:{created_at}".encode("utf-8")).hexdigest()
    return f"s-{digest[:8]}"


@mcp.tool()
@text_output
def session_open(binary: str, name: str = "", port: int = HEADLESS_DEFAULT_PORT,
                 timeout: int = 900) -> dict:
    """Open a session on a binary: analyse it and keep it available.

    A session is a named working context - the binary, the port that
    serves it and the state of the work. It outlives the call that opened
    it, and the tools keep working on it until it is closed.

    Args:
        binary: The file to analyse
        name: What to call the session (default: the name of the binary)
        port: The port to serve on (default: 8192)
        timeout: Seconds to wait for the API (default: 900)

    Returns:
        dict: The session, with its ID and the port it serves on
    """
    path = os.path.abspath(os.path.expanduser(binary))
    label = name or _headless_slug(path)
    sessions = _sessions_load()
    for session in sessions:
        if session.get("name") == label:
            return {"success": False,
                    "error": {"code": "SESSION_ALREADY",
                              "message": f"there is already a session named '{label}'"}}

    started = _headless_start_raw(path, port, timeout)
    if not started.get("success"):
        return started

    created = time.time()
    session = {
        "id": _session_id(label, created),
        "name": label,
        "binary": path,
        "port": int(port),
        "provider": "ghidra",
        "state": "running",
        "pid": started.get("result", {}).get("pid", 0),
        "project": started.get("result", {}).get("project", ""),
        "created_at": created,
        "updated_at": created,
        "extra": {},
    }
    sessions.append(session)
    _sessions_save(sessions)
    return {"success": True, "result": {"message": f"the session '{label}' is open",
                                        "session": session}}


@mcp.tool()
@text_output
def session_list() -> dict:
    """The sessions that are open, and the ones that were closed.

    Returns:
        dict: Every session, with its state
    """
    sessions = _sessions_load()
    for session in sessions:
        pid = int(session.get("pid") or 0)
        if session.get("state") == "running" and pid and not _headless_process_alive(pid):
            session["state"] = "stopped"
    _sessions_save(sessions)
    return {"success": True, "result": {"count": len(sessions), "sessions": sessions}}


@mcp.tool()
@text_output
def session_close(session_id: str) -> dict:
    """Close a session, saving the analysis on its way out.

    Args:
        session_id: The ID of the session, as "session_list" shows it

    Returns:
        dict: Whether the session was closed and whether it was saved
    """
    sessions = _sessions_load()
    for session in sessions:
        if session.get("id") != session_id:
            continue
        if session.get("state") != "running":
            return {"success": False,
                    "error": {"code": "SESSION_NOT_RUNNING",
                              "message": f"the session '{session.get('name')}' is "
                                         f"not running"}}
        stopped = _headless_stop_raw(int(session.get("port") or 8192))
        session["state"] = "stopped"
        session["updated_at"] = time.time()
        _sessions_save(sessions)
        return {"success": True,
                "result": {"message": f"the session '{session.get('name')}' was closed",
                           "session": session, "stopped": stopped}}

    return {"success": False,
            "error": {"code": "SESSION_NO_SUCH",
                      "message": f"no session with the ID '{session_id}'"}}


# ================= Background tasks (I7) =================

@mcp.tool()
@text_output
def tasks_list() -> dict:
    """List the background tasks started with async_mode=True

    The registry lives in this bridge process, like the Kuna export jobs: a
    task started by a previous bridge is not addressable here.

    Returns:
        dict: Every task with its id, kind, status and elapsed time
    """
    with _bg_tasks_lock:
        tasks = [_task_view(record) for record in
                 sorted(_bg_tasks.values(), key=lambda r: r["id"])]
    return {"success": True, "result": {"count": len(tasks), "tasks": tasks}}


@mcp.tool()
@text_output
def tasks_get(task_id: str) -> dict:
    """Get the status and outcome of a background task

    Args:
        task_id: The task ID returned by the async_mode call (e.g. "T-0001")

    Returns:
        dict: The task view — status working/completed/failed/cancelled,
              elapsed seconds, and the result once it has one
    """
    with _bg_tasks_lock:
        record = _bg_tasks.get(task_id)
        if record is None:
            return {"success": False,
                    "error": {"code": "TASK_NOT_FOUND",
                              "message": f"no task with the ID '{task_id}' "
                                         f"(tasks live in the bridge process "
                                         f"that started them)"}}
        view = _task_view(record)
    return {"success": True, "result": view}


@mcp.tool()
@text_output
def tasks_cancel(task_id: str) -> dict:
    """Stop waiting for a background task

    Cancelling marks the task and frees the caller. The work already sent to
    the server is not interrupted — a batch keeps decompiling server-side and
    a headless run keeps running (that is what headless_stop is for); what
    cancel stops is the waiting, and the task's result is discarded when it
    arrives.

    Args:
        task_id: The task ID returned by the async_mode call (e.g. "T-0001")

    Returns:
        dict: The task view after the cancel was requested
    """
    with _bg_tasks_lock:
        record = _bg_tasks.get(task_id)
        if record is None:
            return {"success": False,
                    "error": {"code": "TASK_NOT_FOUND",
                              "message": f"no task with the ID '{task_id}'"}}
        if record["status"] == "working":
            record["cancel_requested"] = True
        view = _task_view(record)
    return {"success": True, "result": view}


# ================= Progressive tool discovery (I15) =================
# 116 tools in one list degrade tool selection: an agent that has to pick
# from everything picks worse. The bridge groups them by workflow and can
# load only the groups a session asked for (`GHYDRA_TOOL_GROUPS=core,functions`
# or at runtime with tools_load_group). The four tools_* meta-tools are always
# loaded, and the full catalogue stays searchable even when a tool is hidden.

# ================= Reproducible runbooks and analysis diff (R6) =================
# The bridge is a standalone script and must not import the ghydra package, so
# the runbook and diff logic is duplicated from ghydra/runbook.py and
# ghydra/diff.py. test_runbook.py asserts the two sides agree.

RUNBOOK_VERSION = 1
_RUNBOOK_VOLATILE_KEYS = ("id", "timestamp", "instance", "_links", "api_links")
_DIFF_PAGE_LIMIT = 1000
_DIFF_MAX_PAGES = 20
#: Defined once, in the core (I1).
_DIFF_PROGRAM_FIELDS = _CORE_DIFF_PROGRAM_FIELDS


def _runbook_canonical(value: Any) -> str:
    """Delegates to the generated core (I1): one definition, two surfaces."""
    return _core_canonical(value)


def _runbook_digest(value: Any) -> str:
    """Delegates to the generated core (I1)."""
    return _core_digest(value)


def _runbook_stable_result(envelope: Any) -> Any:
    """Delegates to the generated core (I1), with the runbook's key set."""
    return _core_stable_result(envelope, _RUNBOOK_VOLATILE_KEYS)


def _runbook_load_steps(steps: str) -> list:
    """The steps to record: JSON text, or the path of a JSON file.

    A tool parameter that takes a nested object is declared as text because a
    client flattens what is nested; the same rule makes a file path and an
    inline document the same parameter.
    """
    text = (steps or "").strip()
    if not text:
        raise ValueError("steps is required")
    if not text.startswith(("[", "{")):
        try:
            with open(text, encoding="utf-8") as handle:
                text = handle.read()
        except OSError as exc:
            raise ValueError(f"cannot read {steps}: {exc}") from exc
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ValueError(f"steps is not valid JSON: {exc}") from exc
    # The rules live in the generated core (I1): one definition, two surfaces.
    # _CoreBadSteps/_CoreBadEntry subclass ValueError, which is what this
    # function's callers already catch.
    return _core_validate_steps(data)


def _runbook_program(port: int) -> dict:
    response = safe_get(port, "program")
    payload = response.get("result") if isinstance(response, dict) else None
    return _core_cache_fingerprint(payload)


def _runbook_call(port: int, step: dict) -> dict:
    method = step["method"]
    endpoint = step["endpoint"]
    params = step.get("params")
    payload = step.get("payload")
    if method == "GET":
        return safe_get(port, endpoint, params)
    # safe_post/safe_patch/safe_put pop "headers" from the payload, so a copy
    # goes in: the runbook must not lose what it recorded.
    body = dict(payload) if isinstance(payload, dict) else (payload or {})
    # The parameters travel with the step: a POST BSim step carries its address
    # and its dry-run arguments there, and dropping them made the replay a
    # different request from the one that was recorded.
    if method == "POST":
        return safe_post(port, endpoint, body, params=params)
    if method == "PATCH":
        return safe_patch(port, endpoint, body, params=params)
    if method == "PUT":
        return safe_put(port, endpoint, body, params=params)
    return safe_delete(port, endpoint, params=params)


def _runbook_record(port: int, steps: list) -> dict:
    header = {"runbook": RUNBOOK_VERSION, "created": int(time.time()),
              "program": _runbook_program(port), "steps": len(steps)}
    entries = []
    for index, step in enumerate(steps, start=1):
        response = _runbook_call(port, step)
        ok = bool(isinstance(response, dict) and response.get("success", False))
        code = None
        if not ok and isinstance(response, dict):
            error = response.get("error")
            if isinstance(error, dict):
                code = error.get("code")
        entries.append({
            "step": index,
            "request": {key: step[key] for key in
                        ("method", "endpoint", "params", "payload")
                        if step.get(key) is not None},
            "ok": ok, "code": code,
            "digest": _runbook_digest(_runbook_stable_result(response)),
        })
    return {"header": header, "entries": entries}


def _runbook_save(document: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(_runbook_canonical(document["header"]) + "\n")
        for entry in document["entries"]:
            handle.write(_runbook_canonical(entry) + "\n")


def _runbook_load(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        lines = [line for line in handle.read().splitlines() if line.strip()]
    if not lines:
        raise ValueError(f"{path} is empty")
    header = json.loads(lines[0])
    if not isinstance(header, dict) or "runbook" not in header:
        raise ValueError(f"{path}: the first line is not a runbook header")
    if header.get("runbook") != RUNBOOK_VERSION:
        raise ValueError(f"runbook version {header.get('runbook')!r} is not supported")
    entries = []
    for line in lines[1:]:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict):
            entries.append(entry)
    return {"header": header, "entries": entries}


def _runbook_replay(port: int, document: dict) -> dict:
    recorded = document.get("entries") or []
    now = _runbook_program(port)
    recorded_program = (document.get("header") or {}).get("program") or {}
    program_changed = bool(recorded_program and now
                           and _runbook_canonical(recorded_program)
                           != _runbook_canonical(now))
    results = []
    for entry in recorded:
        request = entry.get("request") or {}
        step = {"method": request.get("method") or "GET",
                "endpoint": request.get("endpoint") or "",
                "params": request.get("params"), "payload": request.get("payload")}
        response = _runbook_call(port, step)
        ok = bool(isinstance(response, dict) and response.get("success", False))
        if not ok:
            error = response.get("error") if isinstance(response, dict) else None
            results.append({"step": entry.get("step"),
                            "endpoint": step["endpoint"], "status": "failed",
                            "code": (error or {}).get("code") if isinstance(error, dict) else None,
                            "reason": (error or {}).get("message") if isinstance(error, dict) else None})
            continue
        current = _runbook_digest(_runbook_stable_result(response))
        results.append({
            "step": entry.get("step"), "endpoint": step["endpoint"],
            "status": "identical" if current == entry.get("digest") else "changed",
            "digest_recorded": entry.get("digest"), "digest_current": current,
        })
    changed = [item for item in results if item["status"] == "changed"]
    failed = [item for item in results if item["status"] == "failed"]
    return {"success": True, "result": {
        "steps": results, "total": len(results),
        "identical": len(results) - len(changed) - len(failed),
        "changed": len(changed), "failed": len(failed),
        "program_changed": program_changed,
        "recorded_program": recorded_program, "current_program": now,
        "ok": not changed and not failed}}


def _diff_page(port: int, endpoint: str, keys=("name", "value")) -> dict:
    """A listing read to its end, saying whether it was read completely."""
    items = []
    complete = True
    offset = 0
    for _page_number in range(_DIFF_MAX_PAGES):
        response = safe_get(port, endpoint, {"offset": offset, "limit": _DIFF_PAGE_LIMIT})
        if not isinstance(response, dict) or not response.get("success", False):
            return {"items": items, "complete": False, "error": True}
        payload = response.get("result")
        page = payload if isinstance(payload, list) else []
        items.extend(page)
        meta = response.get("meta") or {}
        total = meta.get("total") if isinstance(meta, dict) else None
        if not page or len(page) < _DIFF_PAGE_LIMIT:
            break
        if isinstance(total, int) and len(items) >= total:
            break
        offset += len(page)
    else:
        complete = False
    names = []
    for item in items:
        if not isinstance(item, dict):
            continue
        for key in keys:
            value = item.get(key)
            if isinstance(value, str) and value:
                names.append(value)
                break
    return {"items": items, "complete": complete, "error": False, "names": names}


def _diff_collect(port: int, include_strings: bool = True) -> dict:
    response = safe_get(port, "program")
    payload = response.get("result") if isinstance(response, dict) else None
    program = _core_cache_fingerprint(payload)
    functions_page = _diff_page(port, "functions")
    functions = [{"address": str(item.get("address") or ""),
                  "name": item.get("name"), "size": item.get("size")}
                 for item in functions_page["items"] if isinstance(item, dict)]
    imports_page = _diff_page(port, "symbols/imports", ("name", "label", "symbol"))
    if include_strings:
        strings_page = _diff_page(port, "strings", ("value", "name", "string"))
    else:
        strings_page = {"items": [], "complete": True, "error": False, "names": []}
    return {"program": program, "functions": functions,
            "functions_complete": functions_page["complete"],
            "imports": sorted(set(imports_page["names"])),
            "imports_complete": imports_page["complete"],
            "strings": sorted(set(strings_page["names"])),
            "strings_complete": strings_page["complete"]}


def _diff_names(before: set, after: set) -> dict:
    """Delegates to the generated core (I1)."""
    return _core_diff_names(before, after)


def _diff_snapshots(a: dict, b: dict) -> dict:
    """Delegates to the generated core (I1): one comparison, two surfaces."""
    return _core_diff_snapshots(a, b)


@mcp.tool()
@text_output
def runbook_record(steps: str, output: str | None = None,
                   port: int | None = None) -> dict:
    """Record a reproducible sequence of API calls into a runbook file

    Each step is called once and its answer digested, so a later replay can say
    what changed. The runbook is JSONL and diffs well in git.

    Args:
        steps: JSON text (or the path of a JSON file) with the steps: a list of
            {"endpoint": "...", "method": "GET|POST|PATCH|PUT|DELETE",
             "params": {...}, "payload": {...}}
        output: Where to write the runbook (default: CWD/runbook.ghydrarb.jsonl)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: The path written, the step count and the steps that failed
    """
    port = _get_instance_port(port)
    try:
        parsed = _runbook_load_steps(steps)
    except ValueError as exc:
        return {"success": False, "error": {"code": "RUNBOOK_BAD_STEPS",
                                            "message": str(exc)}}
    document = _runbook_record(port, parsed)
    target = output or os.path.join(os.getcwd(), "runbook.ghydrarb.jsonl")
    try:
        _runbook_save(document, target)
    except OSError as exc:
        return {"success": False, "error": {"code": "RUNBOOK_IO",
                                            "message": f"cannot write {target}: {exc}"}}
    failed = [{"step": entry["step"],
               "endpoint": entry["request"].get("endpoint"),
               "code": entry.get("code")}
              for entry in document["entries"] if not entry.get("ok")]
    return {"success": True, "result": {"path": target,
                                        "steps": len(document["entries"]),
                                        "failed": failed}}


@mcp.tool()
@text_output
def runbook_replay(path: str, port: int | None = None) -> dict:
    """Re-run a runbook and report which answers moved

    Args:
        path: The runbook file (.ghydrarb.jsonl) to replay
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Per-step identical/changed/failed, and whether the program changed
    """
    port = _get_instance_port(port)
    try:
        document = _runbook_load(path)
    except (OSError, ValueError) as exc:
        return {"success": False, "error": {"code": "RUNBOOK_BAD_FILE",
                                            "message": str(exc)}}
    return _runbook_replay(port, document)


@mcp.tool()
@text_output
def analysis_diff(b_port: int, include_strings: bool = True,
                  port: int | None = None) -> dict:
    """Compare this instance with another one and report what changed

    Composes the program fingerprint, the functions (by address, with renames
    told apart from additions and removals), the imports and the defined
    strings. A listing that could not be read to its end is reported as a
    floor, never as a removal.

    Args:
        b_port: Port of the instance to compare against
        include_strings: Compare the defined strings (default True)
        port: Specific Ghidra instance port for the left side (optional)

    Returns:
        dict: Functions added/removed/renamed, imports and strings added/removed
    """
    port = _get_instance_port(port)
    left = _diff_collect(port, include_strings=include_strings)
    right = _diff_collect(int(b_port), include_strings=include_strings)
    return {"success": True, "result": _diff_snapshots(left, right)}


# ================= Source-to-sink hypotheses (R5) =================
# Duplicated from ghydra/taint.py: the bridge is a standalone script and must
# not import the ghydra package. test_taint.py asserts the two sides agree.

#: All of these are defined once, in the generated core (I1).
_TAINT_CALL_OPCODES = _CORE_TAINT_CALL_OPCODES
_TAINT_DISCLAIMER = _CORE_TAINT_DISCLAIMER


def _taint_result(envelope: Any) -> Any:
    if isinstance(envelope, dict) and envelope.get("success", False):
        return envelope.get("result")
    return None


def _taint_resolve_name(port: int, name: str) -> dict:
    addresses = []
    references = []
    function = _taint_result(safe_get(port, f"functions/by-name/{quote(name)}"))
    if isinstance(function, dict) and function.get("address"):
        addresses.append(str(function["address"]))
    xrefs = _taint_result(safe_get(port, f"xrefs/to-name/{quote(name)}",
                                   {"limit": 1000}))
    # `XrefResource.getRefsToName()` answers `{name, symbols, references, total}`,
    # not a list: testing `isinstance(xrefs, list)` skipped every real reference.
    if isinstance(xrefs, dict):
        xrefs = xrefs.get("references")
    for item in xrefs if isinstance(xrefs, list) else []:
        if not isinstance(item, dict):
            continue
        reference = {
            "from_address": item.get("fromAddress") or item.get("from_address"),
            "to_address": item.get("toAddress") or item.get("to_address"),
            "type": (item.get("refType") or item.get("type")
                     or item.get("ref_type")),
            "function": item.get("fromFunction") or item.get("function"),
            "function_address": (item.get("fromFunctionAddress")
                                 or item.get("from_function_address")),
        }
        references.append(reference)
        if reference["to_address"]:
            addresses.append(str(reference["to_address"]))
    return {"name": name, "addresses": list(dict.fromkeys(addresses)),
            "references": references}


def _taint_calls_in_function(port: int, function_address: str) -> list:
    payload = _taint_result(safe_get(port, f"functions/{function_address}/pcode"))
    if not isinstance(payload, dict):
        return []
    operations = payload.get("operations")
    if not isinstance(operations, list):
        return []
    calls = []
    for op in operations:
        if not isinstance(op, dict):
            continue
        if op.get("opcode") not in _TAINT_CALL_OPCODES:
            continue
        inputs = op.get("inputs") or []
        calls.append({"at": str(op.get("address") or ""),
                      "target": str(inputs[0]) if inputs else "",
                      "inputs": [str(value) for value in inputs]})
    return calls


def _taint_site_for(calls: list, wanted: str, wanted_name: str):
    """Delegates to the generated core (I1)."""
    return _core_taint_site_for(calls, wanted, wanted_name)


def _taint_function_of(port: int, address: str) -> dict:
    payload = _taint_result(safe_get(port, f"functions/containing/{quote(address)}"))
    if isinstance(payload, dict):
        return payload
    return {}


def _taint_call_path(port: int, source_function: str, sink_function: str,
                     max_depth: int = 8) -> dict:
    payload = _taint_result(safe_get(port, "analysis/call-path",
                                     {"from": source_function,
                                      "to": sink_function,
                                      "max_depth": max_depth}))
    return payload if isinstance(payload, dict) else {}


def _taint_address_key(address: str) -> tuple:
    """Delegates to the generated core (I1)."""
    return _core_taint_address_key(address)


def _taint_functions_referencing(port: int, info: dict,
                                 examined: list) -> dict:
    found = {}
    for reference in info.get("references") or []:
        address = reference.get("from_address")
        if not address:
            continue
        function_address = reference.get("function_address")
        if not function_address:
            function = reference.get("function")
            if isinstance(function, dict):
                function_address = (function.get("address")
                                    or function.get("entry"))
            elif isinstance(function, str) and _core_taint_looks_like_address(
                    function):
                function_address = function
        if not function_address:
            containing = _taint_function_of(port, str(address))
            function_address = containing.get("address") or containing.get("entry")
        if function_address:
            found[str(function_address)] = info["name"]
    for address in info.get("addresses") or []:
        if not address or str(address) in found:
            continue
        containing = _taint_function_of(port, str(address))
        function_address = containing.get("address") or containing.get("entry")
        if function_address:
            found[str(function_address)] = info["name"]
    examined.extend(found.keys())
    return found


def _taint_find_hypotheses(port: int, source: str, sink: str,
                           max_depth: int = 8) -> dict:
    source_info = _taint_resolve_name(port, source)
    sink_info = _taint_resolve_name(port, sink)
    examined = []
    hypotheses = []
    source_functions = _taint_functions_referencing(port, source_info, examined)
    sink_functions = _taint_functions_referencing(port, sink_info, examined)

    for function_address in sorted(set(source_functions) & set(sink_functions)):
        calls = _taint_calls_in_function(port, function_address)
        source_at = _taint_site_for(calls, (source_info["addresses"] or [""])[0], source)
        sink_at = _taint_site_for(calls, (sink_info["addresses"] or [""])[0], sink)
        if not source_at or not sink_at:
            continue
        if _taint_address_key(sink_at) <= _taint_address_key(source_at):
            hypotheses.append({
                "confidence": "weak",
                "reason": "the sink call precedes the source call in this function",
                "source_call": source_at, "sink_call": sink_at,
                "hops": [function_address]})
            continue
        hypotheses.append({
            "confidence": "direct",
            "reason": "source and sink are called in the same function, sink after source",
            "source_call": source_at, "sink_call": sink_at,
            "hops": [function_address]})

    for source_function in sorted(set(source_functions) - set(sink_functions)):
        for sink_function in sorted(sink_functions):
            path = _taint_call_path(port, source_function, sink_function, max_depth)
            hops = path.get("path") or []
            if not hops:
                continue
            if path.get("truncated"):
                hypotheses.append({
                    "confidence": "weak",
                    "reason": "the call-path search hit its cap; a path was not proven",
                    "source_call": None, "sink_call": None,
                    "hops": [str(hop) for hop in hops]})
                continue
            hypotheses.append({
                "confidence": "reachable",
                "reason": f"a call path connects the source's function to the sink's "
                          f"({len(hops)} hop(s))",
                "source_call": None, "sink_call": None,
                "hops": [str(hop) for hop in hops]})

    return {
        "source": {"name": source, "addresses": source_info["addresses"],
                   "sites": len(source_info["references"])},
        "sink": {"name": sink, "addresses": sink_info["addresses"],
                 "sites": len(sink_info["references"])},
        "hypotheses": hypotheses,
        "functions_examined": len(set(examined)),
        "max_depth": max_depth,
        "disclaimer": _TAINT_DISCLAIMER}


def _taint_summarize(report: dict) -> dict:
    """Delegates to the generated core (I1)."""
    return _core_taint_summarize(report)


@mcp.tool()
@text_output
def analysis_taint(source: str, sink: str, max_depth: int = 8,
                   port: int | None = None) -> dict:
    """Hypothesise whether data from a source reaches a dangerous sink

    Composes the references to each name, the pcode of the functions that call
    them and the call graph. The answer is a set of hypotheses with evidence
    addresses and a confidence - not proof of exploitability, and no finding is
    not proof of safety.

    Args:
        source: Where the data enters (e.g. recv, ReadFile)
        sink: Where it would be dangerous (e.g. system, WinExec)
        max_depth: How many call hops to look for (default 8)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: Hypotheses with confidence, source and sink call sites, and hops
    """
    port = _get_instance_port(port)
    return {"success": True,
            "result": _taint_find_hypotheses(port, source, sink, max_depth)}


# ================= Mission mode (R8) =================
# Duplicated from ghydra/mission.py: the bridge is a standalone script and must
# not import the ghydra package. test_mission.py asserts the two sides agree on
# the hints, the findings and the budget.

_MISSION_VERSION = 1
#: The hint patterns are generated from ghydra/core/hints.py (I1).
_MISSION_HINT_PATTERNS = _CORE_HINT_PATTERNS


def _mission_parse_goal(goal: str) -> dict:
    """Delegates to the generated core (I1)."""
    return _core_parse_goal(goal)


def _mission_dir() -> str:
    base = os.environ.get("GHYDRA_STATE_DIR")
    root = base if base else os.path.join(os.path.expanduser("~"), ".ghydra")
    path = os.path.join(root, "missions")
    os.makedirs(path, exist_ok=True)
    return path


class _MissionBudget:
    def __init__(self, max_calls: int, max_tokens: int):
        self.max_calls = max(1, int(max_calls))
        self.max_tokens = max(1, int(max_tokens))
        self.calls = 0
        self.tokens = 0
        self.started = time.time()

    def exhausted(self):
        """Delegates the order of the limits to the generated core (I1)."""
        return _core_mission_budget_exhausted(
            self.calls, self.max_calls, self.tokens, self.max_tokens,
            time.time() - self.started)

    def spend(self, payload) -> None:
        """The count is the core's; the clock and the calls stay here."""
        self.calls += 1
        self.tokens += _core_mission_tokens_of(payload)

    def as_dict(self) -> dict:
        return _core_mission_budget_row(
            self.calls, self.max_calls, self.tokens, self.max_tokens,
            time.time() - self.started)


class _Mission:
    """The state a bridge-side mission carries."""

    def __init__(self, goal: str, budget: _MissionBudget, port: int):
        self.goal = goal
        self.id = f"m{int(time.time())}"
        self.budget = budget
        self.port = port
        self.hints = _mission_parse_goal(goal)
        self.findings = []
        self.steps = []
        self.skipped = []
        self.program = {}
        self.failed = None

    def add_finding(self, kind: str, title: str, detail: str = "",
                    confidence: str = "medium", evidence=None,
                    status: str = "open") -> dict:
        finding = {"id": f"EV-{len(self.findings) + 1:04d}", "kind": kind,
                   "title": title, "detail": detail, "confidence": confidence,
                   "status": status, "evidence": evidence or []}
        self.findings.append(finding)
        return finding

    def add_unknown(self, question: str, reason: str) -> dict:
        return self.add_finding("unknown", question, reason,
                                confidence="low", status="unknown")

    def evidence(self, endpoint: str, payload, params=None) -> dict:
        return {"endpoint": endpoint, "params": params,
                "digest": _runbook_digest(_runbook_stable_result(payload))}

    def as_dict(self) -> dict:
        return {"mission": _MISSION_VERSION, "id": self.id, "goal": self.goal,
                "hints": self.hints, "program": self.program,
                "findings": self.findings, "steps": self.steps,
                "skipped": self.skipped, "failed": self.failed,
                "budget": self.budget.as_dict()}


def _mission_get(mission: _Mission, endpoint: str, params=None):
    reason = mission.budget.exhausted()
    if reason:
        raise _MissionBudgetSpent(reason)
    response = safe_get(mission.port, endpoint, params)
    mission.budget.spend(response)
    return response


class _MissionBudgetSpent(Exception):
    pass


def _mission_result(envelope):
    if isinstance(envelope, dict) and envelope.get("success", False):
        return envelope.get("result")
    return None


def _mission_error_code(envelope) -> str:
    if isinstance(envelope, dict):
        error = envelope.get("error")
        if isinstance(error, dict):
            return str(error.get("code") or "UNKNOWN")
    return "UNKNOWN"


def _mission_step_overview(mission: _Mission) -> None:
    envelope = _mission_get(mission, "program")
    payload = _mission_result(envelope)
    if not isinstance(payload, dict):
        mission.failed = "MISSION_NO_PROGRAM"
        mission.add_unknown("What is this binary?",
                            f"the program could not be read ({_mission_error_code(envelope)})")
        return
    mission.program = _core_cache_fingerprint(payload)
    mission.add_finding("data", "Program fingerprint",
                        json.dumps(mission.program, ensure_ascii=False),
                        confidence="high",
                        evidence=[mission.evidence("program", envelope)])


def _mission_step_capabilities(mission: _Mission) -> None:
    imports_envelope = _mission_get(mission, "symbols/imports", {"limit": 1000})
    strings_envelope = _mission_get(mission, "strings", {"limit": 1000})
    report = build_capability_report({"success": True, "result": mission.program},
                                    imports_envelope, strings_envelope,
                                    include_strings=True)
    leads = report.get("findings") or []
    if not isinstance(leads, list) or not leads:
        mission.add_unknown("What does this binary do?",
                            "no ATT&CK/MBC lead matched the imports or strings")
        return
    for lead in leads[:10]:
        if not isinstance(lead, dict):
            continue
        mission.add_finding(
            "data", str(lead.get("technique") or lead.get("name") or "capability lead"),
            json.dumps(lead.get("evidence") or lead, ensure_ascii=False),
            confidence=str(lead.get("confidence") or "medium"),
            evidence=[mission.evidence("symbols/imports", imports_envelope),
                      mission.evidence("strings", strings_envelope)])


def _mission_step_taint(mission: _Mission) -> None:
    source = mission.hints.get("source")
    sink = mission.hints.get("sink")
    if not source or not sink:
        mission.add_unknown(
            "Does untrusted data reach a dangerous sink?",
            "the goal names no source and sink, so no hypothesis was formed")
        return
    report = _taint_find_hypotheses(mission.port, source, sink)
    hypotheses = report.get("hypotheses") or []
    if not hypotheses:
        mission.add_unknown(
            f"Does data from {source} reach {sink}?",
            "no source-to-sink path was found; the search is linear and "
            "bounded, so this is not proof of safety")
        return
    for hypothesis in hypotheses[:10]:
        mission.add_finding(
            "vulnerability",
            f"{source} -> {sink} ({hypothesis.get('confidence')})",
            str(hypothesis.get("reason") or ""),
            confidence="high" if hypothesis.get("confidence") == "direct" else "medium",
            evidence=[mission.evidence("analysis/call-path",
                                       {"path": hypothesis.get("hops")},
                                       {"from": source, "to": sink})])


def _mission_step_address(mission: _Mission) -> None:
    address = mission.hints.get("address")
    if not address:
        return
    envelope = _mission_get(mission, f"inspect/address/{address}")
    payload = _mission_result(envelope)
    if not isinstance(payload, dict):
        mission.add_unknown(f"What is at {address}?",
                            f"the address could not be inspected ({_mission_error_code(envelope)})")
        return
    mission.add_finding("xref", f"Address context at {address}",
                        json.dumps(payload, ensure_ascii=False)[:2000],
                        confidence="high",
                        evidence=[mission.evidence(f"inspect/address/{address}", envelope)])


_MISSION_STEPS = (
    ("overview", _mission_step_overview),
    ("capabilities", _mission_step_capabilities),
    ("taint", _mission_step_taint),
    ("address", _mission_step_address),
)


def _mission_run(mission: _Mission) -> _Mission:
    for index, (name, step) in enumerate(_MISSION_STEPS):
        if mission.failed:
            mission.skipped.extend(other for other, _ in _MISSION_STEPS[index:])
            break
        reason = mission.budget.exhausted()
        if reason:
            mission.skipped.extend(other for other, _ in _MISSION_STEPS[index:])
            mission.add_unknown("Was the whole plan run?",
                                f"{reason}; the steps "
                                f"{', '.join(other for other, _ in _MISSION_STEPS[index:])} "
                                f"were not run")
            break
        try:
            step(mission)
            mission.steps.append({"step": name, "status": "done"})
        except _MissionBudgetSpent as exc:
            mission.skipped.append(name)
            mission.add_unknown("Was the whole plan run?", str(exc))
            break
    return mission


def _mission_verify(mission: _Mission) -> dict:
    checked = 0
    for finding in mission.findings:
        if finding.get("status") == "unknown" or not finding.get("evidence"):
            continue
        verified = True
        for item in finding["evidence"]:
            if item.get("endpoint") == "analysis/call-path":
                continue
            checked += 1
            response = safe_get(mission.port, item["endpoint"], item.get("params"))
            current = _runbook_digest(_runbook_stable_result(response))
            if current != item.get("digest"):
                verified = False
        finding["status"] = "verified" if verified else "unverified"
    unverified = [f["id"] for f in mission.findings if f["status"] == "unverified"]
    return {"checked": checked,
            "verified": sum(1 for f in mission.findings if f["status"] == "verified"),
            "unverified": unverified, "ok": not unverified}


def _mission_markdown(mission: _Mission, verification) -> str:
    """Delegates the rendering to the generated core (I1)."""
    return _core_mission_dossier(
        mission.goal, mission.id, mission.program, mission.hints,
        mission.budget.as_dict(), mission.failed, mission.skipped,
        mission.findings, verification)


@mcp.tool()
@text_output
def mission_start(goal: str, max_calls: int = 60, max_tokens: int = 200000,
                  output: str | None = None, verify: bool = True,
                  port: int | None = None) -> dict:
    """Run an objective against the binary and produce an auditable dossier

    Runs a plan - program fingerprint, capability leads, source-to-sink
    hypotheses, address context - against a hard budget. It asks nothing: a
    doubt becomes an ``unknown`` finding. Before keeping a conclusion it
    re-reads its evidence and compares the digests, so a finding whose evidence
    moved is reported as ``unverified``.

    Args:
        goal: The objective, in words (source, sink, address and function hints
            are read from the text)
        max_calls: How many API calls the mission may spend (default 60)
        max_tokens: Approximate token budget for the answers (default 200000)
        output: Write the dossier here (default: ~/.ghydra/missions/<id>.md)
        verify: Re-read the evidence before keeping a conclusion (default True)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: The dossier text, where it was written, and the verification
    """
    port = _get_instance_port(port)
    mission = _Mission(str(goal or ""), _MissionBudget(max_calls, max_tokens), port)
    _mission_run(mission)
    verification = _mission_verify(mission) if verify else None
    dossier = _mission_markdown(mission, verification)
    target = output or os.path.join(_mission_dir(), f"{mission.id}.md")
    try:
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(dossier)
    except OSError as exc:
        return {"success": False,
                "error": {"code": "MISSION_IO",
                          "message": f"cannot write {target}: {exc}"}}
    return {"success": True,
            "result": {"id": mission.id, "dossier": dossier, "path": target,
                       "verification": verification,
                       "unverified": (verification or {}).get("unverified") or [],
                       "mission": mission.as_dict()}}


# ================= Decompile cache (I11) =================
# Duplicated from ghydra/cache.py: the bridge is a standalone script and must
# not import the ghydra package. test_cache.py asserts the two sides agree on
# the identity, the key and the stored shape.

#: The version comes from the core (I1): one bump retires every entry.
_CACHE_VERSION = _CORE_CACHE_VERSION
_CACHE_DEFAULT_MAX_BYTES = 50_000_000
_CACHE_DEFAULT_MAX_AGE = 24 * 60 * 60
#: Both defined once, in the core (I1).
_CACHE_IDENTITY_FIELDS = _CORE_CACHE_IDENTITY_FIELDS
_CACHE_STATISTIC_FIELDS = _CORE_CACHE_STATISTIC_FIELDS


def _cache_canonical(value: Any) -> str:
    """Delegates to the generated core (I1)."""
    return _core_canonical(value)


def _cache_digest(value: Any) -> str:
    """Delegates to the generated core (I1)."""
    return _core_digest(value)


def _cache_root() -> str:
    base = os.environ.get("GHYDRA_STATE_DIR")
    root = base if base else os.path.join(os.path.expanduser("~"), ".ghydra")
    return os.path.join(root, "cache")


def _cache_entries_dir() -> str:
    return os.path.join(_cache_root(), f"v{_CACHE_VERSION}")


def _cache_program_identity(port: int) -> dict:
    """Delegates the identity's definition to the generated core (I1)."""
    response = safe_get(port, "program")
    payload = response.get("result") if isinstance(response, dict) else None
    return _core_cache_identity(payload)


def _cache_key(identity: dict, kind: str, request: dict) -> str:
    """Delegates to the generated core (I1): same key on both surfaces."""
    return _core_cache_key(identity, kind, request)


def _cache_entry_path(key: str) -> str:
    return os.path.join(_cache_entries_dir(), key[:2], f"{key}.json")


def _cache_get(key: str, max_age: int = _CACHE_DEFAULT_MAX_AGE):
    try:
        with open(_cache_entry_path(key), encoding="utf-8") as handle:
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


def _cache_put(key: str, identity: dict, kind: str, request: dict,
               response: dict, max_bytes: int = _CACHE_DEFAULT_MAX_BYTES) -> bool:
    if not isinstance(response, dict):
        return False
    path = _cache_entry_path(key)
    entry = {"key": key, "created": time.time(), "kind": kind,
             "program": identity, "request": request, "response": response}
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        temporary = path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            handle.write(_cache_canonical(entry))
        os.replace(temporary, path)
    except OSError:
        return False
    _cache_evict(max_bytes)
    return True


def _cache_iter_entries() -> list:
    found = []
    root = _cache_entries_dir()
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
            try:
                with open(path, encoding="utf-8") as handle:
                    entry = json.load(handle)
            except (OSError, ValueError):
                entry = {}
            found.append((path, entry if isinstance(entry, dict) else {}, size))
    return found


def _cache_stats() -> dict:
    entries = _cache_iter_entries()
    created = [entry["created"] for _path, entry, _size in entries
               if isinstance(entry.get("created"), (int, float))]
    return {"path": _cache_entries_dir(), "entries": len(entries),
            "bytes": sum(size for _p, _e, size in entries),
            "max_bytes": _CACHE_DEFAULT_MAX_BYTES,
            "oldest": min(created) if created else None,
            "newest": max(created) if created else None,
            "programs": len({_cache_canonical(entry.get("program"))
                             for _p, entry, _s in entries}),
            "kinds": sorted({str(entry.get("kind")) for _p, entry, _s in entries
                             if entry.get("kind")})}


def _cache_clear() -> int:
    removed = 0
    for path, _entry, _size in _cache_iter_entries():
        try:
            os.unlink(path)
            removed += 1
        except OSError:
            continue
    return removed


def _cache_evict(max_bytes: int = _CACHE_DEFAULT_MAX_BYTES) -> int:
    entries = _cache_iter_entries()
    total = sum(size for _p, _e, size in entries)
    if total <= max_bytes:
        return 0
    removed = 0

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


def _cache_get_or_compute(port: int, kind: str, request: dict, compute,
                          identity=None, max_age: int = _CACHE_DEFAULT_MAX_AGE):
    """Serve from the cache, or compute and store. (response, cached)"""
    identity = identity if identity is not None else _cache_program_identity(port)
    if not identity:
        return compute(), False
    key = _cache_key(identity, kind, request)
    if max_age == 0:
        response = compute()
        if isinstance(response, dict) and response.get("success", False):
            _cache_put(key, identity, kind, request, response)
        return response, False
    entry = _cache_get(key, max_age=max_age)
    if entry is not None:
        return entry["response"], True
    response = compute()
    if isinstance(response, dict) and response.get("success", False):
        _cache_put(key, identity, kind, request, response)
    return response, False


@mcp.tool()
@text_output
def cache_stats(port: int | None = None) -> dict:
    """Show what the local decompile cache holds

    The cache is opt-in (``functions_decompile(use_cache=True)``), local only,
    bounded, and keyed on the program the answer belongs to.

    Args:
        port: Unused; accepted for symmetry with the other tools (optional)

    Returns:
        dict: Entries, bytes, programs, kinds and the age of the cache
    """
    return {"success": True, "result": _cache_stats()}


@mcp.tool()
@text_output
def cache_clear(port: int | None = None) -> dict:
    """Remove every cached decompile answer

    Needed when a program is edited in a way the cache cannot see: the server
    exposes no modification counter, so a rename does not change the identity
    the key is built from.

    Args:
        port: Unused; accepted for symmetry with the other tools (optional)

    Returns:
        dict: How many entries were removed
    """
    removed = _cache_clear()
    return {"success": True,
            "result": {"removed": removed,
                       "message": f"Removed {removed} cached entr"
                                  f"{'y' if removed == 1 else 'ies'}."}}


# ================= Fleet queries (R7) =================
# Duplicated from ghydra/fleet.py: the bridge is a standalone script and must
# not import the ghydra package. test_fleet.py asserts the two sides agree.

_FLEET_PAGE_LIMIT = 1000
_FLEET_MAX_PAGES = 5
#: Defined once, in the core (I1).
_FLEET_KINDS = _CORE_FLEET_KINDS
#: Defined once, in the core (I1).
_FLEET_IDENTITY_FIELDS = _CORE_FLEET_IDENTITY_FIELDS


def _fleet_result(envelope):
    if isinstance(envelope, dict) and envelope.get("success", False):
        return envelope.get("result")
    return None


def _fleet_identity_of(program) -> str:
    """Delegates to the generated core (I1)."""
    return _core_fleet_identity_of(program)


def _fleet_collect_member(port: int) -> dict:
    response = safe_get(port, "program")
    program = _fleet_result(response)
    identity = _fleet_identity_of(program)
    if not identity:
        error = (response.get("error") or {}) if isinstance(response, dict) else {}
        code = error.get("code") if isinstance(error, dict) else None
        return {"port": port, "reachable": False, "error": code or "FLEET_NO_PROGRAM"}
    return {"port": port, "reachable": True, "identity": identity,
            "program": program,
            "name": program.get("name") if isinstance(program, dict) else None}


def _fleet_paged_names(port: int, endpoint: str, keys) -> dict:
    names = []
    offset = 0
    complete = True
    for _page in range(_FLEET_MAX_PAGES):
        response = safe_get(port, endpoint, {"offset": offset,
                                            "limit": _FLEET_PAGE_LIMIT})
        if not isinstance(response, dict) or not response.get("success", False):
            return {"names": names, "complete": False, "error": True}
        payload = response.get("result")
        page = payload if isinstance(payload, list) else []
        for item in page:
            if not isinstance(item, dict):
                continue
            for key in keys:
                value = item.get(key)
                if isinstance(value, str) and value:
                    names.append(value)
                    break
        meta = response.get("meta") or {}
        total = meta.get("total") if isinstance(meta, dict) else None
        if not page or len(page) < _FLEET_PAGE_LIMIT:
            break
        if isinstance(total, int) and len(names) >= total:
            break
        offset += len(page)
    else:
        complete = False
    return {"names": names, "complete": complete, "error": False}


def _fleet_ask(port: int, kind: str, target=None) -> dict:
    if kind == "overview":
        response = safe_get(port, "program")
        program = _fleet_result(response)
        if not isinstance(program, dict):
            return {"ok": False, "error": "FLEET_NO_PROGRAM"}
        return {"ok": True, "present": True,
                "detail": {"name": program.get("name"),
                           "path": program.get("executablePath") or program.get("path"),
                           "language": program.get("language"),
                           "statistics": program.get("statistics")}}
    if kind == "has_function":
        response = safe_get(port, f"functions/by-name/{quote(str(target))}")
        payload = _fleet_result(response)
        if isinstance(payload, dict) and payload.get("address"):
            return {"ok": True, "present": True,
                    "detail": {"address": str(payload["address"])}}
        error = (response.get("error") or {}) if isinstance(response, dict) else {}
        code = error.get("code") if isinstance(error, dict) else None
        if code in ("FUNCTION_NOT_FOUND", "SYMBOL_NOT_FOUND", "NOT_FOUND"):
            return {"ok": True, "present": False, "detail": {}}
        return {"ok": False, "error": code or "FLEET_QUERY_FAILED"}
    if kind == "has_import":
        listing = _fleet_paged_names(port, "symbols/imports",
                                    ("name", "label", "symbol"))
        wanted = str(target or "").lower()
        matched = [name for name in listing["names"] if wanted and wanted in name.lower()]
        result = {"ok": not listing["error"], "present": bool(matched),
                  "detail": {"matched": matched[:5]},
                  "complete": listing["complete"]}
        if listing["error"]:
            result["error"] = "FLEET_QUERY_FAILED"
        return result
    if kind == "has_string":
        listing = _fleet_paged_names(port, "strings", ("value", "name", "string"))
        wanted = str(target or "")
        matched = [value for value in listing["names"] if wanted and wanted in value]
        result = {"ok": not listing["error"], "present": bool(matched),
                  "detail": {"matched": matched[:5]},
                  "complete": listing["complete"]}
        if listing["error"]:
            result["error"] = "FLEET_QUERY_FAILED"
        return result
    if kind == "xrefs_to":
        response = safe_get(port, f"xrefs/to-name/{quote(str(target))}")
        payload = _fleet_result(response)
        items = payload if isinstance(payload, list) else []
        meta = response.get("meta") or {} if isinstance(response, dict) else {}
        total = meta.get("total") if isinstance(meta, dict) else None
        count = total if isinstance(total, int) else len(items)
        return {"ok": True, "present": bool(count), "detail": {"count": count}}
    return {"ok": False, "error": f"FLEET_UNKNOWN_KIND: {kind}"}


def _fleet_query(ports, kind: str, target=None) -> dict:
    if kind not in _FLEET_KINDS:
        return {"success": False,
                "error": {"code": "FLEET_UNKNOWN_KIND",
                          "message": "the kinds are: " + ", ".join(_FLEET_KINDS)}}

    # The merge is pure and generated from the core (I1); the I/O stays here.
    seen = []
    unreachable = []
    for port in sorted(int(p) for p in ports):
        member = _fleet_collect_member(port)
        if not member["reachable"]:
            unreachable.append({"port": port, "reason": member.get("error")})
            continue
        seen.append({"port": port, "identity": member["identity"],
                     "name": member.get("name"),
                     "program": member.get("program"),
                     "answer": _fleet_ask(port, kind, target)})

    return _core_fleet_merge(seen, kind, target, unreachable)


def _fleet_ports(text) -> list:
    if isinstance(text, (list, tuple)):
        return [int(value) for value in text]
    ports = []
    for piece in str(text or "").replace(";", ",").split(","):
        piece = piece.strip()
        if piece:
            ports.append(int(piece))
    return ports


@mcp.tool()
@text_output
def fleet_query(kind: str, ports: str, target: str | None = None) -> dict:
    """Ask one question of several instances and merge by file

    A port that does not answer is reported, never dropped; two ports serving
    the same program are one row (merged on the program's identity, not on the
    port). An import/string absence is only claimed from a complete listing.

    Args:
        kind: overview | has_function | has_import | has_string | xrefs_to
        ports: The instances to ask, comma-separated (e.g. "8192,8193")
        target: The name, string or value the question is about (not used by
            overview)

    Returns:
        dict: One row per binary, with its ports, the answer and what failed
    """
    try:
        parsed = _fleet_ports(ports)
    except (TypeError, ValueError) as exc:
        return {"success": False,
                "error": {"code": "FLEET_BAD_PORTS", "message": str(exc)}}
    if not parsed:
        return {"success": False,
                "error": {"code": "FLEET_BAD_PORTS",
                          "message": "give at least one port, e.g. \"8192,8193\""}}
    if kind in ("has_function", "has_import", "has_string", "xrefs_to") and not target:
        return {"success": False,
                "error": {"code": "FLEET_MISSING_TARGET",
                          "message": f"'{kind}' needs a target"}}
    return _fleet_query(parsed, kind, target)


# ================= BSim discovery (R1) =================


@mcp.tool()
@text_output
def bsim_status(port: int | None = None) -> dict:
    """Is a BSim signature query possible here, and against which database?

    BSim is a Ghidra feature, not a plugin API, so it is discovered by loading
    the class: a build may ship without it. The database is configuration
    (-Dghydra.bsim.database or GHYDRA_BSIM_DATABASE), and the answer names it
    rather than pretending a query would work.

    Args:
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: available, database, database_exists, ready and the reason
    """
    port = _get_instance_port(port)
    return simplify_response(safe_get(port, "bsim/status"))


@mcp.tool()
@text_output
def bsim_ingest(max_functions: int = 0, track_call_graph: bool = False,
                port: int | None = None) -> dict:
    """Generate BSim signatures for this program and insert them into the database

    Ingests the *open* program: every function with a body is decompiled and its
    signature stored in the configured database (-Dghydra.bsim.database or
    GHYDRA_BSIM_DATABASE), which is created when it does not exist yet. That is
    what makes a signature query possible later, and what a corpus is built from.

    The call graph is **not** recorded by default: measured on Ghidra 12.2/H2, a
    database created with `trackcallgraph=true` rejects the insert with a
    duplicate `callgraphtable(src,dest)` key on ordinary recursion, and the
    signature tables are what a similarity query needs. Pass
    `track_call_graph=True` to ask for it anyway.

    Re-ingesting a program that is already there is not an error: the answer says
    `already_present` and inserted 0, because the goal — the program is in the
    database — is already true.

    Args:
        max_functions: How many functions to scan at most (0 = all, default 0)
        track_call_graph: Record the call graph in the database (default False)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: discovered/scanned/described/inserted counts, whether the database
              was created, and the reason when nothing was inserted
    """
    port = _get_instance_port(port)
    params = {}
    if max_functions:
        params["max_functions"] = int(max_functions)
    params["track_call_graph"] = "true" if track_call_graph else "false"
    return simplify_response(safe_post(port, "bsim/ingest", params=params))








@mcp.tool()
@text_output
def bsim_query(address: str = "", name: str = "", min_similarity: float = 0.0,
               min_significance: float = 0.0, max_matches: int = 0,
               port: int | None = None) -> dict:
    """Which stored functions look like this one, according to BSim signatures

    Asks the signature database which of its functions are similar to one
    function of the open program, and returns BSim's own similarity and
    significance for each match. Give exactly one of `address` or `name`.

    A match is a **lead, not an identification**: similarity 1.0 means the bytes
    of the two functions' vectors are the same, not that they are the same
    source. The corpus is whatever was ingested into the configured database
    (-Dghydra.bsim.database or GHYDRA_BSIM_DATABASE).

    Args:
        address: The function address to ask about
        name: The function name to ask about (when no address is given)
        min_similarity: Similarity floor, 0..1 (0 = BSim's default 0.7)
        min_significance: Significance floor (0 = no floor)
        max_matches: How many matches to return (0 = default 10, cap 200)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: the function asked about, the thresholds used, and the matches
              with similarity, significance, function, address and executable
    """
    port = _get_instance_port(port)
    params = {}
    if address:
        params["address"] = address
    if name:
        params["name"] = name
    if min_similarity:
        params["min_similarity"] = min_similarity
    if min_significance:
        params["min_significance"] = min_significance
    if max_matches:
        params["max_matches"] = int(max_matches)
    return simplify_response(safe_get(port, "bsim/query", params=params or None))



@mcp.tool()
@text_output
def bsim_apply_names(address: str = "", name: str = "", min_similarity: float = 0.0,
                     dry_run: bool = True, port: int | None = None) -> dict:
    """Name a function after the stored function it most resembles

    Queries the signature database for this function's best match and renames it
    to the matched name — **only when asked**: `dry_run` is true by default, so
    the call reports what it would do and changes nothing. The answer always
    carries the match's similarity and significance, because a signature match is
    a heuristic and the rename has to be judgeable (and undoable in Ghidra).

    Nothing is applied below `min_similarity` (default 0.8), and a function that
    already carries the matched name is reported instead of rewritten.

    Args:
        address: The function address to name
        name: The function name to look up (when no address is given)
        min_similarity: The floor for applying (0 = default 0.8)
        dry_run: Report the change without making it (default True)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: from/to, whether the rename was applied (or would be), the match
              with its similarity, and the reason when nothing was applied
    """
    port = _get_instance_port(port)
    params = {"dry_run": "false" if not dry_run else "true"}
    if address:
        params["address"] = address
    if name:
        params["name"] = name
    if min_similarity:
        params["min_similarity"] = min_similarity
    return simplify_response(
        safe_post(port, "bsim/apply-names", params=params))



@mcp.tool()
@text_output
def bsim_diff_versions(other_executable: str, max_functions: int = 0,
                       min_similarity: float = 0.0,
                       port: int | None = None) -> dict:
    """What changed between two versions, paired by BSim signature

    The complement of `analysis_diff`: that one compares by address and name,
    this one **pairs by shape**, so a function that moved address — or lost its
    name in the rebuild — is reported as the same function relocated instead of
    as one removal plus one addition. Both versions must have been ingested into
    the configured database first.

    One BSim query runs per function, measured at about 0.2-0.8 s each, so the
    walk is bounded by `max_functions` and the answer says how many functions
    were not compared. A function with no pair is listed, never dropped: a thunk
    that was never ingested appears as `not_found`, and a function without a body
    as `no_signature`.

    Args:
        other_executable: The executable name the database recorded for the other
            version (the file name, e.g. `app-1.2.exe`)
        max_functions: How many functions of this program to compare (0 = 25,
            cap 500)
        min_similarity: The floor for calling two functions a pair (0 = 0.8)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: one row per function compared with its class (`same`, `moved`,
              `not_found`, `no_signature`), the counts, and the query failures
    """
    port = _get_instance_port(port)
    params = {"other_executable": other_executable}
    if max_functions:
        params["max_functions"] = int(max_functions)
    if min_similarity:
        params["min_similarity"] = min_similarity
    return simplify_response(safe_get(port, "bsim/diff", params=params))



_TOOL_GROUPS = {
    "core": {"programs", "project", "projects", "instances", "ui", "doctor",
             "evidence", "session", "tasks", "tools", "mission", "cache"},
    "functions": {"functions", "analysis", "inspect", "variables", "memory",
                  "bsim"},
    "data": {"data", "xrefs", "scalars", "comments", "segments"},
    "types": {"structs", "datatypes", "classes", "raw", "symbols",
              "namespaces"},
    "scripts": {"scripts"},
    "headless": {"headless"},
    "kuna": {"kuna"},
    "x64dbg": {"x64dbg"},
    "runbook": {"runbook"},
    "fleet": {"fleet"},
}

_META_NAMESPACE = "tools"
_tool_stash: Dict[str, Dict[str, object]] = {}
_loaded_groups: set[str] = set(_TOOL_GROUPS)


def _tool_namespace(tool_name: str) -> str:
    return tool_name.split("_", 1)[0]


def _tool_group(tool_name: str) -> str:
    """The group a tool belongs to; an unknown namespace is always loaded."""
    namespace = _tool_namespace(tool_name)
    for group, namespaces in _TOOL_GROUPS.items():
        if namespace in namespaces:
            return group
    return "core"


def _tool_catalog() -> Dict[str, dict]:
    """The FULL catalogue, including tools a profile has hidden."""
    catalog = {}
    manager = getattr(mcp, "_tool_manager", None)
    live = getattr(manager, "_tools", {}) if manager else {}
    for name, tool in live.items():
        catalog[name] = _catalog_entry(name, tool)
    for tools in _tool_stash.values():
        for name, tool in tools.items():
            catalog.setdefault(name, _catalog_entry(name, tool))
    return catalog


def _catalog_entry(name: str, tool) -> dict:
    description = str(getattr(tool, "description", "") or "")
    summary = description.strip().splitlines()[0] if description.strip() else ""
    return {
        "name": name,
        "namespace": _tool_namespace(name),
        "group": _tool_group(name),
        "summary": summary[:160],
    }


def _tool_loaded(name: str) -> bool:
    manager = getattr(mcp, "_tool_manager", None)
    return name in getattr(manager, "_tools", {}) if manager else False


def apply_tool_groups(spec: str | None = None) -> dict:
    """Load only the named groups (comma-separated), or all of them.

    Called at startup from GHYDRA_TOOL_GROUPS and at runtime from
    tools_load_group/tools_unload_group. The tools_* meta-tools are never
    removed, and the full catalogue stays searchable: a hidden tool can be
    found with tools_search and loaded with tools_load_group.
    """
    global _loaded_groups
    requested = [part.strip().lower() for part in (spec or "").split(",")
                 if part.strip()]
    unknown = [group for group in requested if group not in _TOOL_GROUPS]
    if unknown:
        return {"success": False,
                "error": {"code": "TOOL_GROUP_UNKNOWN",
                          "message": f"unknown group(s): {', '.join(unknown)}",
                          "known": sorted(_TOOL_GROUPS)}}
    target = set(requested) if requested else set(_TOOL_GROUPS)
    target.add("core")  # the basics are always available
    manager = getattr(mcp, "_tool_manager", None)
    if manager is None:
        return {"success": False,
                "error": {"code": "TOOL_GROUP_UNAVAILABLE",
                          "message": "this bridge has no tool manager"}}

    loaded_now = set()
    for name, tool in list(manager._tools.items()):
        group = _tool_group(name)
        if group in target:
            loaded_now.add(name)
            continue
        if _tool_namespace(name) == _META_NAMESPACE:
            loaded_now.add(name)  # the meta-tools are the way back
            continue
        _tool_stash.setdefault(group, {})[name] = tool
        manager._tools.pop(name, None)

    _loaded_groups = target
    return {"success": True,
            "result": {"groups": sorted(_loaded_groups),
                       "loaded": len(loaded_now),
                       "loaded_tools": sorted(loaded_now)[:200]}}


@mcp.tool()
@text_output
def tools_groups() -> dict:
    """List the tool groups, their sizes and whether they are loaded

    The bridge groups its tools by workflow so a session can keep only the
    namespaces its work needs. `core` is always loaded; the rest are opt-in
    with GHYDRA_TOOL_GROUPS or tools_load_group.

    Returns:
        dict: Every group with its tool count and loaded state
    """
    catalog = _tool_catalog()
    counts: Dict[str, int] = {}
    for entry in catalog.values():
        counts[entry["group"]] = counts.get(entry["group"], 0) + 1
    groups = []
    for group in sorted(_TOOL_GROUPS):
        groups.append({
            "group": group,
            "tools": counts.get(group, 0),
            "loaded": group in _loaded_groups,
            "namespaces": sorted(_TOOL_GROUPS[group]),
        })
    return {"success": True,
            "result": {"count": len(groups), "groups": groups,
                       "visible_tools": len(getattr(
                           getattr(mcp, "_tool_manager", None), "_tools", {})),
                       "total_tools": len(catalog)}}


@mcp.tool()
@text_output
def tools_search(query: str, limit: int = 20) -> dict:
    """Search every tool, including those a loaded profile hides

    Matches the query against tool names, their one-line summaries and their
    namespaces — so an agent that needs a capability can find the tool and
    the group to load, instead of carrying the whole list in context.

    Args:
        query: What to look for (e.g. "decompile", "struct", "x64dbg")
        limit: Maximum matches to return (default: 20)

    Returns:
        dict: The matching tools with name, group, namespace, summary and
              whether each one is currently loaded
    """
    needle = (query or "").lower()
    matches = []
    for name, entry in sorted(_tool_catalog().items()):
        haystack = f"{name} {entry['summary']} {entry['namespace']} " \
                   f"{entry['group']}".lower()
        if needle not in haystack:
            continue
        matches.append({**entry, "loaded": _tool_loaded(name)})
        if len(matches) >= limit:
            break
    return {"success": True,
            "result": {"query": query, "count": len(matches),
                       "matches": matches}}


@mcp.tool()
@text_output
def tools_load_group(group: str) -> dict:
    """Load one tool group into this session

    The tools come back into the server's list; MCP clients that cache the
    tool list should re-read it (most read it on demand). For a guaranteed
    profile, restart the bridge with GHYDRA_TOOL_GROUPS.

    Args:
        group: The group to load (see tools_groups)

    Returns:
        dict: The groups now loaded and how many tools they hold
    """
    if group not in _TOOL_GROUPS:
        return {"success": False,
                "error": {"code": "TOOL_GROUP_UNKNOWN",
                          "message": f"unknown group '{group}'",
                          "known": sorted(_TOOL_GROUPS)}}
    stashed = _tool_stash.pop(group, {})
    manager = getattr(mcp, "_tool_manager", None)
    if manager is None:
        return {"success": False,
                "error": {"code": "TOOL_GROUP_UNAVAILABLE",
                          "message": "this bridge has no tool manager"}}
    for name, tool in stashed.items():
        manager._tools[name] = tool
    _loaded_groups.add(group)
    return {"success": True,
            "result": {"group": group, "restored": len(stashed),
                       "groups": sorted(_loaded_groups),
                       "note": "re-read the tool list to see them; a restart "
                               "with GHYDRA_TOOL_GROUPS gives a guaranteed "
                               "profile"}}


@mcp.tool()
@text_output
def tools_unload_group(group: str) -> dict:
    """Remove one tool group from this session, keeping the meta-tools

    Args:
        group: The group to unload

    Returns:
        dict: The groups now loaded and how many tools were removed
    """
    if group not in _TOOL_GROUPS:
        return {"success": False,
                "error": {"code": "TOOL_GROUP_UNKNOWN",
                          "message": f"unknown group '{group}'",
                          "known": sorted(_TOOL_GROUPS)}}
    if group == "core":
        return {"success": False,
                "error": {"code": "TOOL_GROUP_CORE",
                          "message": "the core group cannot be unloaded"}}
    manager = getattr(mcp, "_tool_manager", None)
    if manager is None:
        return {"success": False,
                "error": {"code": "TOOL_GROUP_UNAVAILABLE",
                          "message": "this bridge has no tool manager"}}
    removed = 0
    for name, tool in list(manager._tools.items()):
        if _tool_group(name) == group and _tool_namespace(name) != _META_NAMESPACE:
            _tool_stash.setdefault(group, {})[name] = manager._tools.pop(name)
            removed += 1
    _loaded_groups.discard(group)
    return {"success": True,
            "result": {"group": group, "removed": removed,
                       "groups": sorted(_loaded_groups)}}


# ================= Local telemetry (I14) =================
# What this bridge actually did, recorded on this machine only. Nothing is
# ever sent anywhere: the file is ~/.ghydra/telemetry.jsonl (or under
# GHYDRA_STATE_DIR), one JSON object per call, capped at ~1 MB. Disabled with
# GHYDRA_TELEMETRY=0. The recorder must never break a tool call, so every
# failure in it is swallowed.
#: Both defined once, in the generated core (I1).
_TELEMETRY_MAX_BYTES = _CORE_TELEMETRY_MAX_BYTES
_TELEMETRY_KEEP_LINES = _CORE_TELEMETRY_KEEP_LINES


def _telemetry_path() -> str:
    return os.path.join(_headless_state_dir(), "telemetry.jsonl")


def _telemetry_enabled() -> bool:
    return os.environ.get("GHYDRA_TELEMETRY", "1").strip().lower() not in (
        "0", "false", "off", "no")


def _telemetry_trim(path: str) -> None:
    """Keep the log bounded by dropping the oldest lines."""
    try:
        if os.path.getsize(path) <= _TELEMETRY_MAX_BYTES:
            return
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()[-_TELEMETRY_KEEP_LINES:]
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    except OSError:
        pass


def _telemetry_record(tool: str, ok: bool, code: str | None,
                      duration_ms: float, tokens: int) -> None:
    if not _telemetry_enabled():
        return
    try:
        path = _telemetry_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        entry = {"ts": round(time.time(), 3), "tool": tool, "ok": bool(ok),
                 "code": code, "ms": round(float(duration_ms), 1),
                 "tokens": int(tokens)}
        _telemetry_trim(path)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass  # telemetry must never break a tool call


def _telemetry_safely(tool: str, started: float, response, text) -> None:
    """Record one call from the RAW response, without ever raising.

    The envelope decides success, not the rendered text: with
    GHYDRA_MCP_OUTPUT=json an error is a string starting with "{" and a
    prefix check would count every failure as a success.
    """
    try:
        failed = False
        code = None
        if isinstance(response, dict):
            failed = response.get("success") is False
            error = response.get("error")
            if failed and isinstance(error, dict):
                code = error.get("code")
        elif isinstance(response, str):
            failed = response.startswith("Error")
        _telemetry_record(
            tool, not failed, code,
            (time.perf_counter() - started) * 1000.0,
            max(1, len(text) // 4) if isinstance(text, str) else 0)
    except Exception:
        pass


def _telemetry_read(max_entries: int = 5000) -> list:
    try:
        with open(_telemetry_path(), encoding="utf-8") as handle:
            lines = handle.read().splitlines()[-max_entries:]
    except OSError:
        return []
    entries = []
    for line in lines:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and entry.get("tool"):
            entries.append(entry)
    return entries


def _telemetry_recommendations(entries: list) -> list:
    """Delegates to the generated core (I1)."""
    return _core_telemetry_recommendations(entries)


@mcp.tool()
@text_output
def telemetry_summary(days: int = 7) -> dict:
    """Summarize what this bridge has actually done, from the local log

    The log is local only (never sent anywhere): one JSON object per tool
    call under ~/.ghydra/telemetry.jsonl, capped at about 1 MB and trimmed
    oldest first. A record holds the tool name, a timestamp, whether the call
    failed, its error code, the duration and an estimate of the answer's size —
    never the arguments, the results, a path, a symbol, an address or any
    binary content, and no identifier of any kind. Set GHYDRA_TELEMETRY=0 to
    stop recording; deleting the file erases what was recorded. This tool
    aggregates it — calls, failures, latency and estimated token volume per
    tool, the error codes seen — and names the composed tool when the log
    shows a pattern one of them replaces.

    Args:
        days: Only count entries from the last N days (default: 7)

    Returns:
        dict: totals, per-tool rows, error codes and recommendations
    """
    # The window and the aggregate are pure and generated from the core (I1);
    # reading the file and finding its path stay here.
    entries = _core_telemetry_recent(_telemetry_read(), days)
    return {"success": True,
            "result": _core_telemetry_summarize(entries, days,
                                               _telemetry_path())}


# ================= Startup =================

def main():
    register_instance(DEFAULT_GHIDRA_PORT,
                      f"http://{ghidra_host}:{DEFAULT_GHIDRA_PORT}")

    # Use quick discovery on startup
    _quick_scan(force=True)

    # Start background discovery thread
    discovery_thread = threading.Thread(
        target=periodic_discovery,
        daemon=True,
        name="GhydraMCP-Discovery"
    )
    discovery_thread.start()

    signal.signal(signal.SIGINT, handle_sigint)

    # Progressive tool discovery (I15): a profile keeps only the groups the
    # session asked for. Unset loads everything, which is the old behaviour.
    profile = os.environ.get("GHYDRA_TOOL_GROUPS", "").strip()
    if profile:
        applied = apply_tool_groups(profile)
        if applied.get("success"):
            print(f"GhydraMCP: tool profile loaded — "
                  f"{', '.join(applied['result']['groups'])} "
                  f"({applied['result']['loaded']} tools)",
                  file=sys.stderr, flush=True)
        else:
            print(f"GhydraMCP: ignored GHYDRA_TOOL_GROUPS '{profile}': "
                  f"{applied['error']['message']}", file=sys.stderr, flush=True)

    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
