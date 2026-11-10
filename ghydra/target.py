"""The target descriptor: what both sides agree a target *is*.

The unification plan (`docs/UNIFICATION-PLAN.md` §3.2) asks for one address model
between the static side (Ghidra, working on the image at its image base) and the
dynamic side (x64dbg, working on the module wherever the loader put it):

    runtime = static - image_base + module_base

That conversion is mechanical; the part that is not mechanical is trusting it. The
same formula applied to two different binaries produces plausible garbage, so a
descriptor also carries **which file each side is looking at**, and it refuses to
correlate when those are not the same file. That refusal is the point: the plan's
§7 lists "Ghidra and x64dbg end up on different builds and address correlation
silently produces garbage" as the risk this shape exists to remove.

The shape is `contract/target-descriptor.schema.json`; this module is the
GhydraMCP-side implementation of it.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

CONTRACT_VERSION = 1

#: The schema this dict claims to follow.
SCHEMA_NAME = "target-descriptor.schema.json"

#: The key the descriptor uses for the conversion constant.
DELTA_KEY = "delta"


#: A drive-letter prefix, the mark of a Windows path.
_DRIVE = re.compile(r"^[A-Za-z]:")


def normalize_path(path: Any) -> str:
    """A path in the form two sides can compare, whatever machine compares it.

    The rule is about the path, not about the host: `os.path.normcase` lower-cases
    on Windows and does nothing elsewhere, which made the same pair of paths compare
    equal here and different on the Linux CI. A **Windows** path compares
    case-insensitively (the file system does), a POSIX path does not, both separators
    mean the same thing, and a UNC path keeps its `//`.
    """
    text = str(path or "").strip()
    if not text:
        return ""
    windows = bool(_DRIVE.match(text)) or "\\" in text
    text = text.replace("\\", "/")
    prefix = "//" if text.startswith("//") else ""
    body = text[2:] if prefix else text
    body = re.sub(r"/+", "/", body)
    if len(body) > 1:
        body = body.rstrip("/")
    normalized = prefix + body
    return normalized.lower() if windows else normalized


def path_name(path: Any) -> str:
    """The file name of a path, with both separators understood."""
    text = str(path or "").strip().replace("\\", "/")
    return text.rsplit("/", 1)[-1]


@dataclass(frozen=True)
class TargetDescriptor:
    """One target, as both sides see it.

    `binary` is the file the static side has open; `module_path` is what the
    debugger says it loaded. `image_base` and `module_base` are the two numbers the
    conversion needs, and `module_base` may be None when only the static side is
    available (a descriptor that cannot translate says so instead of guessing).
    """

    binary: str
    arch: str = ""
    image_base: int = 0
    module_base: Optional[int] = None
    module_size: Optional[int] = None
    module_path: str = ""
    session: Dict[str, Any] = field(default_factory=dict)
    source: Dict[str, Any] = field(default_factory=dict)

    # ---------------------------------------------------------------- construction
    @classmethod
    def from_program_and_module(cls, program: Dict[str, Any],
                                module: Dict[str, Any],
                                session: Optional[Dict[str, Any]] = None,
                                source: Optional[Dict[str, Any]] = None):
        """Build one from a Ghidra `/program` payload and an x64dbg module."""
        program = program or {}
        module = module or {}
        # `ProgramResource.getCurrentProgram()` emits `imageBase`, as
        # `program.getImageBase().toString()`: unprefixed hexadecimal. Reading only
        # `image_base` left the descriptor at 0, `correlatable()` refused it, and
        # every breakpoint and run-to failed with TARGET_NOT_SAME_BINARY even when
        # both paths matched.
        image_base = _ghidra_int(program.get("imageBase"))
        if image_base is None:
            image_base = _ghidra_int(program.get("image_base"))
        module_base = _as_int(module.get("base"))
        return cls(
            binary=str(program.get("path") or program.get("name") or ""),
            arch=str(program.get("language") or program.get("architecture") or ""),
            image_base=image_base or 0,
            module_base=module_base,
            module_size=_as_int(module.get("size")),
            module_path=str(module.get("path") or ""),
            session=dict(session or {}),
            source=dict(source or {}),
        )

    # ------------------------------------------------------------------ identity
    def same_binary(self) -> bool:
        """True when both sides name the same file by the same path.

        A matching *file name* in another directory is not enough: it is a copy, a
        symlink or a rebuild, and the addresses of one do not describe the other.
        """
        left = normalize_path(self.binary)
        right = normalize_path(self.module_path)
        return bool(left) and left == right

    def identity(self) -> Dict[str, Any]:
        """What the two paths say about each other, with the reason."""
        left = normalize_path(self.binary)
        right = normalize_path(self.module_path)
        if not left:
            return {"same_binary": False, "match": "unknown",
                    "reason": "the Ghidra program did not report a path"}
        if not right:
            return {"same_binary": False, "match": "unknown",
                    "reason": "the debugger did not report a module path"}
        if left == right:
            return {"same_binary": True, "match": "path", "reason": None}
        if path_name(left).lower() == path_name(right).lower():
            return {"same_binary": False, "match": "name-only",
                    "reason": "same file name in different directories: this is a "
                              "copy, a symlink or a rebuild, and the addresses of "
                              "one do not describe the other"}
        return {"same_binary": False, "match": "different",
                "reason": "the two sides are looking at different files"}

    def correlatable(self) -> bool:
        """Whether the conversion may be used at all."""
        return self.same_binary() and self.image_base > 0 and self.module_base is not None

    # -------------------------------------------------------------- the conversion
    def to_runtime(self, static_address: int) -> int:
        """The runtime address of a static one; refuses rather than guessing."""
        if self.image_base <= 0 or self.module_base is None:
            raise ValueError("the descriptor has no image base or module base, so "
                             "a static address cannot be translated")
        return int(static_address) - self.image_base + self.module_base

    def to_static(self, runtime_address: int) -> int:
        """The static address of a runtime one."""
        if self.image_base <= 0 or self.module_base is None:
            raise ValueError("the descriptor has no image base or module base, so "
                             "a runtime address cannot be translated")
        return int(runtime_address) - self.module_base + self.image_base

    def delta(self) -> Optional[int]:
        """`module_base - image_base`, the constant the conversion adds."""
        if self.module_base is None:
            return None
        return self.module_base - self.image_base

    # ------------------------------------------------------------------ the wire
    def as_dict(self) -> Dict[str, Any]:
        """The shape the schema describes; addresses as hex strings."""
        return {
            "contract_version": CONTRACT_VERSION,
            "schema": SCHEMA_NAME,
            "binary": self.binary,
            "binary_name": path_name(self.binary),
            "arch": self.arch,
            "image_base": _hex(self.image_base),
            "module_base": _hex(self.module_base),
            "module_size": self.module_size,
            "module_path": self.module_path,
            "module_name": path_name(self.module_path),
            "session": dict(self.session),
            "source": dict(self.source),
            DELTA_KEY: _hex(self.delta()) if self.delta() is not None else None,
            "identity": self.identity(),
            "correlatable": self.correlatable(),
        }

    # -------------------------------------------------------------- the problems
    def problems(self) -> List[str]:
        """What is missing or cannot be trusted, in the schema's terms."""
        found = []
        if not self.binary:
            found.append("binary is empty: the static side reported no path")
        if self.image_base <= 0:
            found.append("image_base is not a positive address")
        if self.image_base and self.image_base % 0x1000:
            found.append("image_base is not page-aligned")
        if self.module_base is not None and self.module_base % 0x1000:
            found.append("module_base is not page-aligned")
        if not self.identity()["same_binary"]:
            found.append("the two sides are not the same file: "
                         + str(self.identity()["reason"]))
        return found


#: Codes this workflow answers with. Stable, because a caller branches on them.
ERROR_NO_PROGRAM = "TARGET_NO_PROGRAM"
ERROR_NOT_LOADED = "TARGET_NOT_LOADED"
ERROR_NOT_FOUND = "TARGET_NOT_FOUND"
ERROR_NOT_SAME_BINARY = "TARGET_NOT_SAME_BINARY"
ERROR_BAD_ADDRESS = "TARGET_BAD_ADDRESS"
ERROR_NO_CODE = "TARGET_NO_CODE"


class TargetError(Exception):
    """A failure of the cross-tool workflow, with its code."""

    def __init__(self, message: str, code: str = "TARGET_ERROR") -> None:
        super().__init__(message)
        self.code = code


# --------------------------------------------------------------------- reading
def _reason(exc: BaseException) -> str:
    """What the failure said, with the server's own code when it carried one.

    The code the client raises with is the server's code, and it is the only
    thing that tells "the instance is down" from "the server refused this one".
    Discarding it left both looking the same.
    """
    code = str(getattr(exc, "code", "") or "")
    text = str(exc)
    return f"{text} [{code}]" if code else text


def _program(ghidra_client) -> Dict[str, Any]:
    """The static side's program, from `GET /program`."""
    try:
        envelope = ghidra_client.get("program")
    except Exception as exc:  # noqa: BLE001 - the reason is the message
        raise TargetError(
            f"the Ghidra instance did not answer: {_reason(exc)}",
            ERROR_NO_PROGRAM)
    result = (envelope or {}).get("result")
    if not isinstance(result, dict) or not result:
        raise TargetError("the Ghidra instance reports no open program",
                          ERROR_NO_PROGRAM)
    return result


def _modules(debugger_client) -> List[Dict[str, Any]]:
    """The debugger's loaded modules, through its own `ListModules`."""
    from . import x64dbg as debugger

    text = debugger_client.call_tool("ListModules")
    return debugger.parse_modules(text)


def _function(ghidra_client, target: str) -> Dict[str, Any]:
    """One function, by address (`0x…`) or by name."""
    from urllib.parse import quote

    text = str(target or "").strip()
    if not text:
        raise TargetError("no function was named", ERROR_NOT_FOUND)
    address = _parse_address(text)
    endpoint = (f"functions/{text}" if address is not None
                else f"functions/by-name/{quote(text, safe='')}")
    try:
        envelope = ghidra_client.get(endpoint)
    except Exception as exc:  # noqa: BLE001
        # The client raises on a non-2xx, so the code it carries is the honest
        # answer: a function that is not there is NOT_FOUND, an instance that
        # does not answer is NO_PROGRAM. They call for different actions.
        code = str(getattr(exc, "code", "") or "")
        if "NOT_FOUND" in code:
            raise TargetError(f"no function matches {target!r}", ERROR_NOT_FOUND)
        raise TargetError(
            f"the Ghidra instance did not answer: {_reason(exc)}",
            ERROR_NO_PROGRAM)
    result = (envelope or {}).get("result")
    if not isinstance(result, dict) or not result:
        raise TargetError(f"no function matches {target!r}", ERROR_NOT_FOUND)
    if not result.get("address"):
        raise TargetError(f"the function {target!r} has no address",
                          ERROR_BAD_ADDRESS)
    return result


# ------------------------------------------------------------------ the workflow
def describe(ghidra_client, debugger_client) -> TargetDescriptor:
    """`analyze_open`: both sides, one descriptor, with the identity verdict."""
    from . import x64dbg as debugger

    program = _program(ghidra_client)
    modules = _modules(debugger_client)
    module = debugger.find_module(modules, program.get("path") or "")
    if module is None:
        raise TargetError(
            "no loaded module matches the binary Ghidra has open "
            f"({program.get('path') or 'unknown'})", ERROR_NOT_LOADED)
    return TargetDescriptor.from_program_and_module(program, module)


def locate(ghidra_client, target: str) -> Dict[str, Any]:
    """`function_locate`: the static address of a function, by name or address."""
    function = _function(ghidra_client, target)
    # `FunctionDto` serialises `getEntryPoint().toString()`: unprefixed hexadecimal.
    address = _ghidra_int(function.get("address"))
    if address is None:
        raise TargetError(f"{target!r} resolved to an address that cannot be read",
                          ERROR_BAD_ADDRESS)
    return {
        "name": function.get("name"),
        "signature": function.get("signature"),
        "static_address": hex(address),
        "matched_by": ("address" if _parse_address(target) is not None else "name"),
        # The API's function detail carries no size; saying so is better than a
        # number nobody measured.
        "size": None,
    }


def breakpoint(ghidra_client, debugger_client, target: str,
               dry_run: bool = False) -> Dict[str, Any]:
    """`breakpoint_set`: locate statically, translate, set it in the debugger.

    Refuses with `TARGET_NOT_SAME_BINARY` — **before** touching the debugger —
    when the two sides are not the same file: a breakpoint at a translated address
    of another build is a breakpoint in the wrong place.

    With `dry_run`, everything except the write happens: the address is located
    and translated, and the answer says what would have been set. A preview that
    skips the reads could not name the address, and one that skips only the write
    cannot change anything.
    """
    descriptor = describe(ghidra_client, debugger_client)
    identity = descriptor.identity()
    if not descriptor.correlatable():
        raise TargetError(
            "the two sides are not the same target: " + str(identity["reason"]),
            ERROR_NOT_SAME_BINARY)

    found = locate(ghidra_client, target)
    static_address = _ghidra_int(found["static_address"])
    runtime = descriptor.to_runtime(static_address)
    plan = {"tool": "SetBreakpoint", "arguments": {"target": hex(runtime)}}
    if not dry_run:
        debugger_client.call_tool(plan["tool"], plan["arguments"])
    return {
        "function": found["name"],
        "static_address": hex(static_address),
        "runtime_address": hex(runtime),
        "delta": hex(descriptor.delta()) if descriptor.delta() is not None else None,
        "identity": identity,
        "dry_run": bool(dry_run),
        "plan": plan,
    }


#: `RunToAddress` blocks, and its default (30 000 ms) is the client's read timeout:
#: a run that takes the full time loses its answer. Asking for less keeps the
#: server answering before the client gives up.
RUN_TO_TIMEOUT_MS = 10_000


def decompile(ghidra_client, target: str, style: str = "normalize") -> Dict[str, Any]:
    """`decompile`: the recovered C of one function, addressed statically.

    The address comes from `locate`, so a name works as well as an address, and the
    caller gets both forms back.
    """
    found = locate(ghidra_client, target)
    address = found["static_address"]
    try:
        envelope = ghidra_client.get(f"functions/{address}/decompile",
                                     params={"style": style})
    except Exception as exc:  # noqa: BLE001 - the reason is the message
        code = str(getattr(exc, "code", "") or "")
        if "NOT_FOUND" in code:
            raise TargetError(f"the function at {address} cannot be decompiled: {exc}",
                              ERROR_NOT_FOUND)
        raise TargetError(f"the decompiler did not answer: {_reason(exc)}",
                          ERROR_NO_PROGRAM)
    result = (envelope or {}).get("result") or {}
    code = result.get("decompilation")
    if not code:
        raise TargetError(
            result.get("errorMessage")
            or f"the decompiler returned no code for {address}", ERROR_NO_CODE)
    # `functionAddress` arrives in Ghidra's own form (`140001234`); every other
    # address this module answers with is `0x`-prefixed, so a caller can compare
    # the two without knowing which endpoint produced each one.
    reported = _ghidra_int(result.get("functionAddress"))
    return {
        "function": result.get("functionName") or found["name"],
        "static_address": hex(reported) if reported is not None else address,
        "style": style,
        "code": code,
    }


def run_to(ghidra_client, debugger_client, target: str,
           timeout_ms: int = RUN_TO_TIMEOUT_MS,
           dry_run: bool = False) -> Dict[str, Any]:
    """`run_to`: run the debuggee to a function, and report the registers at the stop.

    Refuses with `TARGET_NOT_SAME_BINARY` before resuming anything when the two
    sides are not the same file — resuming a different build is worse than setting a
    breakpoint in it.

    With `dry_run`, the debuggee is **not resumed**: the address is located and
    translated, and the answer says what would have been run to. Resuming is the
    most expensive thing this workflow does, so it is the last thing a preview
    should do.
    """
    if int(timeout_ms) <= 0:
        raise TargetError("the timeout must be positive", ERROR_BAD_ADDRESS)
    descriptor = describe(ghidra_client, debugger_client)
    identity = descriptor.identity()
    if not descriptor.correlatable():
        raise TargetError(
            "the two sides are not the same target: " + str(identity["reason"]),
            ERROR_NOT_SAME_BINARY)

    found = locate(ghidra_client, target)
    static_address = _ghidra_int(found["static_address"])
    runtime = descriptor.to_runtime(static_address)
    plan = {"tool": "RunToAddress",
            "arguments": {"address": hex(runtime), "timeoutMs": int(timeout_ms)}}
    registers = None
    if not dry_run:
        debugger_client.call_tool(plan["tool"], plan["arguments"])
        # Read-only, and it cannot change the debuggee: the state is read after the
        # stop. A preview has no stop to read.
        registers = debugger_client.call_tool("GetAllRegisters")
    return {
        "function": found["name"],
        "static_address": hex(static_address),
        "runtime_address": hex(runtime),
        "timeout_ms": int(timeout_ms),
        "registers": registers,
        "identity": identity,
        "dry_run": bool(dry_run),
        "plan": plan,
    }


def _as_int(value: Any) -> Optional[int]:
    """An integer out of a number or a `0x` string.

    For fields that really are numbers: the debugger's `ListModules` parses its
    base and size into `int` already, and the CLI's own output is `0x`-prefixed.
    **Not** for Ghidra's wire addresses — see `_ghidra_int`.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _ghidra_int(value: Any) -> Optional[int]:
    """An integer out of Ghidra's own address text.

    Ghidra serialises an address with `Address.toString()` and the program payload's
    `imageBase` the same way: **unprefixed hexadecimal** (`00401000`, `140000000`).
    `int(text, 0)` is the wrong parser for that — it reads `140001234` as decimal
    (returning `0x8583FD2`) and rejects `00401000` outright as a bad octal literal.
    A value that carries an address space (`ram:00401000`) keeps the offset.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    if ":" in text:
        # `Address.toString()` prefixes the space only when it is not the default
        # one: `ram:00401000`. The offset is what the arithmetic needs.
        text = text.rsplit(":", 1)[-1].strip()
    if text.lower().startswith("0x"):
        text = text[2:]
    try:
        return int(text, 16)
    except ValueError:
        return None


def _parse_address(value: Any) -> Optional[int]:
    """The value of an address a caller typed, or None when it is a name.

    A caller writes `0x401000`, `401000` or `00401000`; Ghidra's API reads a bare
    address as hexadecimal, so this does too. Only the *decision* uses this — the
    endpoint keeps the text the caller wrote, because that is what the API parses.
    """
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    text = str(value or "").strip()
    if not text:
        return None
    if text.lower().startswith("0x"):
        try:
            return int(text, 16)
        except ValueError:
            return None
    return _ghidra_int(text)


def _hex(value: Optional[int]) -> Optional[str]:
    return None if value is None else hex(int(value))