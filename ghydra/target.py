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
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

CONTRACT_VERSION = 1

#: The schema this dict claims to follow.
SCHEMA_NAME = "target-descriptor.schema.json"

#: The key the descriptor uses for the conversion constant.
DELTA_KEY = "delta"


def normalize_path(path: Any) -> str:
    """A path in the form two sides can compare.

    Windows compares case-insensitively and tolerates both separators, and the two
    sides here (a JVM plugin and a native debugger) can disagree about drive-letter
    case and about `/` versus `\\` for the same file.
    """
    text = str(path or "").strip()
    if not text:
        return ""
    return os.path.normcase(os.path.normpath(text.replace("/", os.sep)))


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
        image_base = _as_int(program.get("image_base"))
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


def _as_int(value: Any) -> Optional[int]:
    """An integer out of a number or a `0x` string."""
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


def _hex(value: Optional[int]) -> Optional[str]:
    return None if value is None else hex(int(value))