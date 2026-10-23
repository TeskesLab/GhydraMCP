"""Kuna integration for the GhydraMCP CLI.

Kuna (https://github.com/Noelo-Lab/kuna) is a standalone decompiler CLI. The
CLI drives it directly, on the machine where the CLI runs, so no Ghidra
instance is involved and the commands work against any Ghidra version.

Running a program is an elevation of privilege for a tool that otherwise
only speaks HTTP to Ghidra, so the integration is opt-in: the GHYDRA_KUNA
environment variable, or the "kuna" section of ~/.ghydra/config.json. The
config file wins when both are set.

The MCP bridge carries its own copy of this logic: the bridge is a standalone
script that must not depend on the ghydra package.
"""

import json
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Sequence

from .utils.validators import truthy as _truthy


ENV_ENABLED = "GHYDRA_KUNA"
ENV_PATH = "GHYDRA_KUNA_PATH"

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".ghydra")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
WORK_DIR = os.path.join(CONFIG_DIR, "kuna")

DEFAULT_TIMEOUT = int(os.environ.get("GHYDRA_KUNA_TIMEOUT", "900"))

# A kuna answer larger than this is not worth printing: it would flood the
# terminal, or an agent's context.
MAX_OUTPUT = 8 * 1024 * 1024


class KunaError(Exception):
    """A Kuna invocation failed.

    Attributes:
        code: Short machine-readable reason (KUNA_DISABLED, KUNA_MISSING,
              KUNA_TIMEOUT, KUNA_FAILED).
    """

    def __init__(self, message: str, code: str = "KUNA_ERROR"):
        super().__init__(message)
        self.code = code


def truthy(value: Any) -> bool:
    """Interpret an opt-in value coming from the environment or the config.

    Kept here as a re-export so callers of this module do not need to know
    where the helper lives.
    """
    return _truthy(value)


def config_section() -> Dict[str, Any]:
    """Read the "kuna" section of ~/.ghydra/config.json.

    Never raises: a missing or malformed config simply means "not configured".
    """
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    section = data.get("kuna")
    return section if isinstance(section, dict) else {}


def is_enabled(config: Optional[Dict[str, Any]] = None) -> bool:
    """Is the integration enabled? The config file wins over the env var.

    A config section that carries no "enabled" value (or a null one) leaves
    the decision to GHYDRA_KUNA; an explicit true or false wins.
    """
    section = config_section() if config is None else config
    if section.get("enabled") is not None:
        return truthy(section["enabled"])
    return truthy(os.environ.get(ENV_ENABLED))


def find_binary(config: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """Resolve the kuna executable, or None when it is not installed.

    A configured path wins, then whatever is on PATH, and finally the
    Scoop install locations - those only exist on Windows.
    """
    section = config_section() if config is None else config
    candidates: List[str] = []

    configured = section.get("path") or os.environ.get(ENV_PATH)
    if configured:
        candidates.append(os.path.expanduser(str(configured)))

    found = shutil.which("kuna")
    if found:
        candidates.append(found)

    if os.name == "nt":
        home = os.path.expanduser("~")
        candidates.append(os.path.join(home, "scoop", "shims", "kuna.exe"))
        candidates.append(os.path.join(home, "scoop", "apps", "kuna", "current", "kuna.exe"))

    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


def require_binary(config: Optional[Dict[str, Any]] = None) -> str:
    """Return the kuna executable path, or raise KunaError."""
    section = config_section() if config is None else config
    if not is_enabled(section):
        raise KunaError(
            f"the Kuna integration is disabled. Enable it with the "
            f"{ENV_ENABLED}=1 environment variable, or by adding "
            f"'kuna': {{'enabled': true}} to {CONFIG_FILE}",
            code="KUNA_DISABLED",
        )
    executable = find_binary(section)
    if not executable:
        raise KunaError("the kuna binary was not found", code="KUNA_MISSING")
    return executable


def run(args: Sequence[str], config: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None) -> Dict[str, Any]:
    """Run kuna and return its parsed JSON output.

    Args:
        args: kuna subcommand and flags
        config: Optional "kuna" config section
        timeout: Optional timeout in seconds

    Returns:
        dict: The parsed JSON document

    Raises:
        KunaError: When the integration is off, the binary is missing, the
            call times out or kuna reports a failure.
    """
    executable = require_binary(config)
    limit = timeout if timeout is not None else DEFAULT_TIMEOUT

    try:
        completed = subprocess.run(
            [executable, *args],
            capture_output=True,
            text=True,
            # Kuna writes UTF-8; decoding with the locale instead would
            # mangle the output when no UTF-8 locale is set.
            encoding="utf-8",
            errors="replace",
            timeout=limit,
        )
    except subprocess.TimeoutExpired:
        raise KunaError(f"kuna timed out after {limit}s", code="KUNA_TIMEOUT") from None
    except OSError as exc:
        raise KunaError(f"could not launch kuna: {exc}", code="KUNA_LAUNCH") from None

    stdout = completed.stdout.strip()
    parsed: Any = None
    if stdout:
        try:
            parsed = json.loads(stdout)
        except ValueError:
            parsed = None

    if completed.returncode != 0:
        detail = completed.stderr.strip() or stdout or "no output"
        if isinstance(parsed, dict) and parsed.get("error"):
            detail = str(parsed["error"])
        raise KunaError(
            f"kuna {args[0]} failed (exit {completed.returncode}): {detail}",
            code="KUNA_FAILED",
        )

    if parsed is None:
        raise KunaError(f"kuna {args[0]} did not return JSON", code="KUNA_NO_JSON")

    if len(stdout) > MAX_OUTPUT:
        raise KunaError(
            f"kuna {args[0]} returned {len(stdout)} bytes of JSON, above the "
            f"{MAX_OUTPUT} byte cap; narrow the request",
            code="KUNA_TOO_LARGE",
        )

    if isinstance(parsed, dict) and parsed.get("error"):
        raise KunaError(f"kuna {args[0]}: {parsed['error']}", code="KUNA_FAILED")

    return parsed


def work_dir(binary: str) -> str:
    """Where the export of a binary lives.

    Keyed by path and mtime, so a rebuilt binary gets a fresh directory while
    a re-analysis of the same file reuses it.
    """
    import hashlib

    path = os.path.abspath(os.path.expanduser(binary))
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = 0.0
    digest = hashlib.sha256(f"{path}|{mtime}".encode("utf-8")).hexdigest()[:12]
    return os.path.join(WORK_DIR, digest)


def index_records(directory: str) -> List[dict]:
    """Read index.jsonl from an export directory.

    Only newline-terminated records are read: an unfinished last record is
    deferred until the next read, because a streamed export appends a record
    only after that function's C block is complete.
    """
    path = os.path.join(directory, "index.jsonl")
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


def export_file(directory: str, suffix: str) -> Optional[str]:
    """Find the single export artifact with the given suffix."""
    try:
        entries = sorted(os.listdir(directory))
    except OSError:
        return None
    for entry in entries:
        if entry.endswith(suffix) and os.path.isfile(os.path.join(directory, entry)):
            return os.path.join(directory, entry)
    return None


def extract_c(directory: str, record: dict, max_bytes: int) -> Optional[str]:
    """Slice one function's C block out of the exported .c file."""
    path = export_file(directory, ".c")
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


def extract_asm(directory: str, name: str, max_bytes: int) -> Optional[str]:
    """Slice one function's disassembly out of the exported .asm file.

    The file is streamed: a function block runs from its label line to the
    next label, and labels sit at column zero while instructions are
    indented.
    """
    path = export_file(directory, ".asm")
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


def find_record(records: List[dict], function: str) -> Optional[dict]:
    """Find an index record by exact name, then case-insensitively."""
    for record in records:
        if record.get("name") == function:
            return record
    lowered = function.lower()
    for record in records:
        if str(record.get("name", "")).lower() == lowered:
            return record
    return None


def export(binary: str, output: Optional[str] = None,
           functions: Optional[str] = None, jobs: str = "auto",
           config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Export a binary to disk with "kuna decompile-project".

    The image is loaded and analysed once, and the recovered C, the
    disassembly and an index.jsonl land in a directory. Every function is
    then read from those files instead of paying the analysis cost again.

    Args:
        binary: Path to the executable
        output: Directory to write to (a per-binary directory by default)
        functions: Optional comma-separated function names to export
        jobs: Worker count ("auto" by default)
        config: Optional "kuna" config section

    Returns:
        dict: The export report: directory, function counts and failures
    """
    executable = require_binary(config)
    target = os.path.abspath(os.path.expanduser(binary))
    if not os.path.isfile(target):
        raise KunaError(f"no such file: {binary}", code="KUNA_NO_FILE")

    directory = os.path.abspath(os.path.expanduser(output)) if output else work_dir(target)
    try:
        os.makedirs(directory, exist_ok=True)
    except OSError as exc:
        raise KunaError(f"could not create {directory}: {exc}", code="KUNA_IO") from None

    args = ["decompile-project", target, "-o", directory, "--stream", "--jobs", str(jobs)]
    if functions:
        args += ["--functions", functions]

    try:
        completed = subprocess.run(
            [executable, *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=DEFAULT_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        raise KunaError(
            f"kuna timed out after {DEFAULT_TIMEOUT}s", code="KUNA_TIMEOUT"
        ) from None
    except OSError as exc:
        raise KunaError(f"could not launch kuna: {exc}", code="KUNA_LAUNCH") from None

    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "no output"
        raise KunaError(
            f"kuna decompile-project failed (exit {completed.returncode}): {detail}",
            code="KUNA_FAILED",
        )

    records = index_records(directory)
    failures = [record for record in records if record.get("error")]
    return {
        "binary": target,
        "dir": directory,
        "functions": len(records),
        "failed": len(failures),
        "failures": [
            {"name": record.get("name"), "addr": record.get("addr"), "error": record.get("error")}
            for record in failures[:20]
        ],
    }


def read_export(directory: str, function: Optional[str] = None,
                artifact: str = "c", max_bytes: int = 40000) -> Dict[str, Any]:
    """Read a function out of an export directory.

    Args:
        directory: The export directory
        function: Function name to read; without it the names are listed
        artifact: "c", "asm", "index" or "readme"
        max_bytes: Maximum bytes of text to return

    Returns:
        dict: The requested text, or the list of exported functions

    Raises:
        KunaError: When the directory holds no export, or the artifact is
            unknown.
    """
    if not os.path.isdir(directory):
        raise KunaError(f"no such directory: {directory}", code="KUNA_NO_DIR")

    if artifact == "readme":
        path = os.path.join(directory, "README.md")
        if not os.path.isfile(path):
            raise KunaError("the export has no README.md", code="KUNA_NO_FILE")
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                text = handle.read(max_bytes if max_bytes else -1)
        except OSError as exc:
            raise KunaError(f"could not read the export README: {exc}", code="KUNA_IO") from None
        return {"artifact": "readme", "text": text}

    records = index_records(directory)
    if not records:
        raise KunaError("the export has no index yet", code="KUNA_NO_INDEX")

    if artifact == "index":
        return {
            "artifact": "index",
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
        }

    if artifact not in ("c", "asm"):
        raise KunaError("artifact must be one of: c, asm, index, readme", code="KUNA_BAD_ARTIFACT")

    if not function:
        return {
            "artifact": artifact,
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
        }

    record = find_record(records, function)
    if record is None:
        raise KunaError(f"function '{function}' is not in the export index", code="KUNA_NO_FUNCTION")

    if artifact == "c":
        text = extract_c(directory, record, max_bytes)
    else:
        text = extract_asm(directory, record.get("name", function), max_bytes)

    if text is None:
        raise KunaError(
            f"could not read the {artifact} of '{function}' from the export",
            code="KUNA_IO",
        )

    return {
        "artifact": artifact,
        "function": record.get("name"),
        "addr": record.get("addr"),
        "size": record.get("size"),
        "text": text,
    }
