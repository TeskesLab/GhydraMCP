"""Target triage: what is this file, and what can be done with it.

GhydraMCP drives three tools that want very different things: Ghidra for
static analysis, Kuna as a second decompiler, x64dbg for the live process.
Which of them deserves a target is decided by what the target *is*. A .NET
assembly, an Android APK, an EVM contract, a WASM module, an Electron app, a
firmware image, a Windows minidump and a native PE all need a different
treatment, and most of them need a different tool entirely. Today the answer
to that question is a guess made from the file name.

This module answers it from the bytes. It reads the headers, says what the
file is, and says what can be done with it - with no Ghidra, no network and
no guesswork: every fact it reports was read out of the file, and a field
that could not be read is left out rather than filled in.

It is the first step of every other workflow. A report on a WASM module, the
crash triage of a core dump, the Kuna export of a JavaScript bundle - each of
them starts by knowing what the file is.

The formats are read, not sniffed: the PE resource directory is walked, the
ELF program headers are decoded, the binary Android manifest is parsed, the
asar archive header is unpacked. A truncated or corrupt file yields the facts
that could be read and the rest is omitted; only a path that does not exist
or cannot be read at all raises.
"""

from __future__ import annotations

import collections
import hashlib
import json
import math
import os
import plistlib
import struct
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

__all__ = [
    "TriageError",
    "FORMATS",
    "identify",
    "overview",
    "format_of",
    "entropy",
    "hashes",
]


# The formats the triage can name.
FORMATS = (
    "pe",
    "elf",
    "mach-o",
    "dex",
    "apk",
    "wasm",
    "evm",
    "core",
    "plist",
    "har",
    "javascript",
    "firmware",
    "class",
    "pdf",
    "zip",
    "gzip",
    "sqlite",
    "text",
    "unknown",
)


# How many items a list may carry before it is cut. Every list that is cut
# says so with a "truncated" flag.
MAX_ITEMS = 200

# How much is read at once when a file is streamed.
CHUNK_SIZE = 1 << 20

# A JSON file bigger than this is not parsed; it is reported as text.
MAX_JSON_BYTES = 64 * 1024 * 1024

# How much of a text file is read for the statistics.
MAX_TEXT_BYTES = 8 * 1024 * 1024

# The entropy above which a blob is probably packed or encrypted.
PACKED_ENTROPY = 7.2


class TriageError(Exception):
    """A triage could not be carried out.

    Attributes:
        code: Short machine-readable reason (TRIAGE_NO_FILE when the path
              does not exist, TRIAGE_UNREADABLE when it cannot be read).
    """

    def __init__(self, message: str, code: str = "TRIAGE_ERROR") -> None:
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _hex(value: int) -> str:
    """Format an address as a lowercase hex string with the 0x prefix."""
    return "0x%x" % int(value)


def _iso(timestamp: int) -> str:
    """Format a Unix timestamp as an ISO-8601 UTC string."""
    try:
        moment = datetime.fromtimestamp(int(timestamp), tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return ""
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _cstr(data: bytes, offset: int = 0, limit: int = 512) -> str:
    """Read a NUL-terminated ASCII string out of a buffer."""
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset)
    if end == -1:
        end = min(len(data), offset + limit)
    else:
        end = min(end, offset + limit)
    return data[offset:end].decode("utf-8", "replace")


def _u16(data: bytes, offset: int, endian: str = "<") -> Optional[int]:
    """Read an unsigned 16-bit integer, or None when it is out of bounds."""
    if offset < 0 or offset + 2 > len(data):
        return None
    return struct.unpack_from(endian + "H", data, offset)[0]


def _u32(data: bytes, offset: int, endian: str = "<") -> Optional[int]:
    """Read an unsigned 32-bit integer, or None when it is out of bounds."""
    if offset < 0 or offset + 4 > len(data):
        return None
    return struct.unpack_from(endian + "I", data, offset)[0]


def _u64(data: bytes, offset: int, endian: str = "<") -> Optional[int]:
    """Read an unsigned 64-bit integer, or None when it is out of bounds."""
    if offset < 0 or offset + 8 > len(data):
        return None
    return struct.unpack_from(endian + "Q", data, offset)[0]


def _flag_names(value: int, table: Dict[int, str]) -> List[str]:
    """Turn a bit field into the names of the bits that are set."""
    return [name for bit, name in sorted(table.items()) if value & bit]


def _capped(items: List[Any]) -> Tuple[List[Any], bool]:
    """Cut a list to MAX_ITEMS and say whether it was cut."""
    if len(items) <= MAX_ITEMS:
        return items, False
    return items[:MAX_ITEMS], True


class _File:
    """A file opened for reading, with random access.

    The triage reads headers at scattered offsets, so the file is kept open
    and seeked rather than read whole.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        try:
            self._handle = open(path, "rb")
        except OSError as exc:
            raise TriageError("cannot open %s: %s" % (path, exc),
                              "TRIAGE_UNREADABLE") from exc
        try:
            self.size = os.fstat(self._handle.fileno()).st_size
        except OSError as exc:
            self._handle.close()
            raise TriageError("cannot stat %s: %s" % (path, exc),
                              "TRIAGE_UNREADABLE") from exc

    def read_at(self, offset: int, size: int) -> bytes:
        """Read up to `size` bytes at `offset`; a short read is not an error."""
        if offset < 0 or size <= 0:
            return b""
        try:
            self._handle.seek(offset)
            return self._handle.read(size)
        except OSError:
            return b""

    def read(self, size: int) -> bytes:
        """Read up to `size` bytes from the start of the file."""
        return self.read_at(0, size)

    def close(self) -> None:
        """Close the file."""
        try:
            self._handle.close()
        except OSError:
            pass

    def __enter__(self) -> "_File":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def entropy(data: bytes) -> float:
    """Compute the Shannon entropy of a buffer, in bits per byte.

    A value of 0.0 means every byte is the same; 8.0 means every byte value
    appears equally often. Above roughly 7.2 the content is very likely
    packed or encrypted, which is the usual reason to reach for a triage in
    the first place.

    Args:
        data: The bytes to measure.

    Returns:
        The entropy, between 0.0 and 8.0.
    """
    if not data:
        return 0.0
    total = len(data)
    value = 0.0
    for count in collections.Counter(data).values():
        probability = count / total
        value -= probability * math.log2(probability)
    return round(value, 4)


def hashes(path: str) -> Dict[str, str]:
    """Compute the MD5, SHA-1 and SHA-256 of a path.

    A file is streamed, so a file that does not fit in memory costs nothing
    extra. A directory is hashed over its contents: the relative path of
    every file, in sorted order, followed by its bytes.

    Args:
        path: The file or the directory to hash.

    Returns:
        A dictionary with the "md5", "sha1" and "sha256" digests.

    Raises:
        TriageError: When the path does not exist or cannot be read.
    """
    if not os.path.exists(path):
        raise TriageError("no such path: %s" % path, "TRIAGE_NO_FILE")

    digests = []
    for factory in (hashlib.md5, hashlib.sha1, hashlib.sha256):
        try:
            digests.append(factory(usedforsecurity=False))
        except TypeError:  # pragma: no cover - Python without the keyword
            digests.append(factory())

    if os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            dirs.sort()
            for name in sorted(files):
                full = os.path.join(root, name)
                relative = os.path.relpath(full, path).replace(os.sep, "/")
                for digest in digests:
                    digest.update(relative.encode("utf-8", "replace"))
                    digest.update(b"\x00")
                try:
                    with open(full, "rb") as handle:
                        while True:
                            chunk = handle.read(CHUNK_SIZE)
                            if not chunk:
                                break
                            for digest in digests:
                                digest.update(chunk)
                except OSError:
                    continue
    else:
        try:
            with open(path, "rb") as handle:
                while True:
                    chunk = handle.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    for digest in digests:
                        digest.update(chunk)
        except OSError as exc:
            raise TriageError("cannot read %s: %s" % (path, exc),
                              "TRIAGE_UNREADABLE") from exc

    return {
        "md5": digests[0].hexdigest(),
        "sha1": digests[1].hexdigest(),
        "sha256": digests[2].hexdigest(),
    }


def format_of(path: str) -> str:
    """Detect the format of a path.

    Args:
        path: The file or the directory to look at.

    Returns:
        One of: "pe", "elf", "mach-o", "dex", "apk", "wasm", "evm", "core",
        "plist", "har", "javascript", "firmware", "class", "pdf", "zip",
        "gzip", "sqlite", "text", "unknown".

    Raises:
        TriageError: When the path does not exist or cannot be read.
    """
    return _analyze(path)["format"]


def identify(path: str) -> Dict[str, Any]:
    """Identify a path and return the facts that say what it is.

    Args:
        path: The file or the directory to look at.

    Returns:
        A dictionary with the "format", the "size" in bytes and the "facts"
        that identify the format. A fact that could not be read is left out.

    Raises:
        TriageError: When the path does not exist or cannot be read.
    """
    result = _analyze(path)
    return {
        "format": result["format"],
        "size": result["size"],
        "facts": result["facts"],
    }


def overview(path: str) -> Dict[str, Any]:
    """Identify a path and describe what can be done with it.

    Args:
        path: The file or the directory to look at.

    Returns:
        A dictionary with the "format", the "size" in bytes, the "sha256"
        digest, the "facts" that identify the format, the "details" that
        describe it and the "recommendations" that say what to do next.

    Raises:
        TriageError: When the path does not exist or cannot be read.
    """
    result = _analyze(path)
    return {
        "format": result["format"],
        "size": result["size"],
        "sha256": hashes(path)["sha256"],
        "facts": result["facts"],
        "details": result["details"],
        "recommendations": result["recommendations"],
    }


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

# The Mach-O magic numbers, in the four combinations of bits and endianness.
MACHO_MAGICS = {
    b"\xce\xfa\xed\xfe": (32, "little"),
    b"\xcf\xfa\xed\xfe": (64, "little"),
    b"\xfe\xed\xfa\xce": (32, "big"),
    b"\xfe\xed\xfa\xcf": (64, "big"),
}

# The internal marker for a ZIP whose real format is decided by its content.
_ZIP_CONTAINER = "zip-container"


def _detect_format(head: bytes, path: str = "") -> str:
    """Decide the format of a file from its first bytes.

    Only the magic bytes and magic numbers are used - never the file name -
    with one exception: JavaScript has no magic at all, so a script is
    recognised by its name.
    """
    if len(head) < 2:
        return "unknown"

    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:2] == b"MZ":
        return "pe"
    if head[:4] in MACHO_MAGICS:
        return "mach-o"
    if head[:4] == b"\xca\xfe\xba\xbe":
        # A Java class file and a fat Mach-O share the magic; the major
        # version of a class file is always in a narrow range, and a class
        # file is big-endian.
        major = _u16(head, 6, ">")
        if major is not None and 45 <= major <= 100:
            return "class"
        return "mach-o"
    if head[:4] == b"dex\n":
        return "dex"
    if head[:4] == b"\x00asm":
        return "wasm"
    if head[:2] == b"PK":
        return _ZIP_CONTAINER
    if head[:5] == b"%PDF-":
        return "pdf"
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if head[:16] == b"SQLite format 3\x00":
        return "sqlite"
    if head[:6] == b"bplist":
        return "plist"
    if head[:4] == b"MDMP":
        return "core"
    if head[:4] == b"\x60\x80\x60\x40":
        return "evm"
    if head[:4] == b"\x27\x05\x19\x56":
        return "firmware"
    if head[:4] == b"hsqs":
        return "firmware"
    if head[:2] == b"\x85\x19":
        return "firmware"
    if head[:4] == b"\x45\x3d\xcd\x28":
        return "firmware"
    if head[:5] == b"<?xml":
        return "plist"
    if path.lower().endswith((".js", ".mjs", ".cjs")):
        # JavaScript has no magic number; the name is what says it is code.
        return "javascript"
    if head[:1] in (b"{", b"["):
        return "text"  # may still be a HAR; the JSON reader decides
    if _printable_ratio(head[:4096]) >= 0.95:
        return "text"
    return "unknown"


def _printable_ratio(data: bytes) -> float:
    """How much of a buffer is printable text."""
    if not data:
        return 0.0
    printable = sum(
        1 for byte in data
        if 0x20 <= byte <= 0x7e or byte in (0x09, 0x0a, 0x0b, 0x0c, 0x0d)
        or byte >= 0x80
    )
    return printable / len(data)


# ---------------------------------------------------------------------------
# PE
# ---------------------------------------------------------------------------

PE_MACHINES = {
    0x0000: "unknown",
    0x014c: "i386",
    0x014d: "i386",
    0x0166: "mips",
    0x0169: "powerpc",
    0x01a2: "sh3",
    0x01a3: "sh3",
    0x01a6: "sh4",
    0x01c0: "arm",
    0x01c2: "arm-thumb",
    0x01c4: "arm",
    0x0200: "ia64",
    0x8664: "x86-64",
    0xaa64: "arm64",
    0x5032: "riscv32",
    0x5064: "riscv64",
}

PE_SUBSYSTEMS = {
    0: "unknown",
    1: "native",
    2: "windows-gui",
    3: "windows-cui",
    5: "os2-cui",
    7: "posix-cui",
    9: "windows-ce-gui",
    10: "efi-application",
    11: "efi-boot-service-driver",
    12: "efi-runtime-driver",
    13: "efi-rom",
    14: "xbox",
    16: "windows-boot-application",
}

PE_CHARACTERISTICS = {
    0x0001: "relocs-stripped",
    0x0002: "executable-image",
    0x0004: "line-nums-stripped",
    0x0008: "local-syms-stripped",
    0x0020: "large-address-aware",
    0x0100: "32bit-machine",
    0x0200: "debug-stripped",
    0x2000: "dll",
}

PE_DLL_CHARACTERISTICS = {
    0x0020: "high-entropy-va",
    0x0040: "dynamic-base",
    0x0080: "force-integrity",
    0x0100: "nx-compat",
    0x0200: "no-isolation",
    0x0400: "no-seh",
    0x0800: "no-bind",
    0x1000: "app-container",
    0x2000: "wdm-driver",
    0x4000: "guard-cf",
    0x8000: "terminal-server-aware",
}

# The data directories that are worth reporting, by index.
PE_DATA_DIRECTORIES = {
    1: "import",
    2: "resource",
    3: "exception",
    5: "relocation",
    6: "debug",
    9: "tls",
    14: "clr",
}

PE_RESOURCE_TYPES = {
    1: "RT_CURSOR",
    2: "RT_BITMAP",
    3: "RT_ICON",
    4: "RT_MENU",
    5: "RT_DIALOG",
    6: "RT_STRING",
    7: "RT_FONTDIR",
    8: "RT_FONT",
    9: "RT_ACCELERATOR",
    10: "RT_RCDATA",
    11: "RT_MESSAGETABLE",
    12: "RT_GROUP_CURSOR",
    14: "RT_GROUP_ICON",
    16: "RT_VERSION",
    17: "RT_DLGINCLUDE",
    19: "RT_PLUGPLAY",
    20: "RT_VXD",
    21: "RT_ANICURSOR",
    22: "RT_ANIICON",
    23: "RT_HTML",
    24: "RT_MANIFEST",
}


def _rva_to_offset(sections: List[Dict[str, Any]], rva: int) -> Optional[int]:
    """Turn a relative virtual address into a file offset, through the sections."""
    for section in sections:
        start = section["_virtual_address"]
        size = max(section["_virtual_size"], section["_raw_size"])
        if start <= rva < start + size:
            return section["_raw_offset"] + (rva - start)
    return None


def _parse_pe_sections(f: _File, offset: int, count: int) -> List[Dict[str, Any]]:
    """Read the PE section table."""
    sections: List[Dict[str, Any]] = []
    raw = f.read_at(offset, count * 40)
    for index in range(count):
        base = index * 40
        if base + 40 > len(raw):
            break
        (name_raw, virtual_size, virtual_address, raw_size, raw_offset,
         _reloc_ptr, _line_ptr, _reloc_num, _line_num,
         characteristics) = struct.unpack_from("<8sIIIIIIHHI", raw, base)
        name = name_raw.split(b"\x00")[0].decode("utf-8", "replace")
        sections.append({
            "name": name,
            "virtual_address": _hex(virtual_address),
            "virtual_size": virtual_size,
            "raw_size": raw_size,
            "raw_offset": _hex(raw_offset),
            "readable": bool(characteristics & 0x40000000),
            "writable": bool(characteristics & 0x80000000),
            "executable": bool(characteristics & 0x20000000),
            "characteristics": characteristics,
            "_virtual_address": virtual_address,
            "_virtual_size": virtual_size,
            "_raw_size": raw_size,
            "_raw_offset": raw_offset,
        })
    return sections


def _parse_pe_imports(f: _File, rva: int, sections: List[Dict[str, Any]],
                      is_64bit: bool) -> Tuple[List[Dict[str, Any]], bool]:
    """Read the PE import directory: the DLLs and the functions they bring in."""
    imports: List[Dict[str, Any]] = []
    truncated = False
    base = _rva_to_offset(sections, rva)
    if base is None:
        return imports, truncated
    thunk_size = 8 if is_64bit else 4
    ordinal_flag = 1 << (63 if is_64bit else 31)
    total = 0
    for index in range(256):
        descriptor = f.read_at(base + index * 20, 20)
        if len(descriptor) < 20:
            break
        original_thunk, _stamp, _chain, name_rva, first_thunk = struct.unpack(
            "<IIIII", descriptor)
        if not any((original_thunk, name_rva, first_thunk)):
            break
        name_offset = _rva_to_offset(sections, name_rva)
        dll = _cstr(f.read_at(name_offset, 256)) if name_offset is not None else ""
        thunk_rva = original_thunk or first_thunk
        thunk_offset = _rva_to_offset(sections, thunk_rva)
        functions: List[str] = []
        if thunk_offset is not None:
            for slot in range(1024):
                entry = f.read_at(thunk_offset + slot * thunk_size, thunk_size)
                if len(entry) < thunk_size:
                    break
                value = struct.unpack("<Q" if is_64bit else "<I", entry)[0]
                if value == 0:
                    break
                if value & ordinal_flag:
                    functions.append("ordinal:%d" % (value & 0xFFFF))
                else:
                    hint_offset = _rva_to_offset(sections, value)
                    if hint_offset is None:
                        functions.append("unresolved")
                    else:
                        functions.append(_cstr(f.read_at(hint_offset + 2, 256)))
                if total + len(functions) >= MAX_ITEMS:
                    truncated = True
                    break
        total += len(functions)
        imports.append({"dll": dll, "functions": functions})
        if total >= MAX_ITEMS:
            truncated = truncated or len(functions) >= 1024
            break
    return imports, truncated


def _pe_resource_string(f: _File, resource_base: int, name_id: int) -> str:
    """Read a resource name that is stored as a string."""
    offset = resource_base + (name_id & 0x7FFFFFFF)
    head = f.read_at(offset, 2)
    if len(head) < 2:
        return ""
    length = struct.unpack_from("<H", head, 0)[0]
    return f.read_at(offset + 2, length * 2).decode("utf-16-le", "replace")


def _parse_pe_resources(f: _File, rva: int,
                        sections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Walk the PE resource directory tree and report every leaf."""
    resources: List[Dict[str, Any]] = []
    base = _rva_to_offset(sections, rva)
    if base is None:
        return resources

    def walk(directory_offset: int, level: int, entry: Dict[str, Any]) -> None:
        if len(resources) >= MAX_ITEMS or level > 2:
            return
        header = f.read_at(directory_offset, 16)
        if len(header) < 16:
            return
        named = struct.unpack_from("<H", header, 12)[0]
        identified = struct.unpack_from("<H", header, 14)[0]
        count = min(named + identified, 1024)
        table = f.read_at(directory_offset + 16, count * 8)
        for index in range(count):
            if len(resources) >= MAX_ITEMS:
                return
            base_index = index * 8
            if base_index + 8 > len(table):
                break
            name_id, offset = struct.unpack_from("<II", table, base_index)
            is_directory = bool(offset & 0x80000000)
            offset &= 0x7FFFFFFF
            if level == 0:
                type_name = PE_RESOURCE_TYPES.get(name_id)
                if type_name is None:
                    type_name = _pe_resource_string(f, base, name_id)
                current = {"type": type_name, "type_id": name_id}
            elif level == 1:
                name = _pe_resource_string(f, base, name_id) if name_id & 0x80000000 \
                    else str(name_id)
                current = dict(entry)
                current["name"] = name
            else:
                current = dict(entry)
                current["language"] = name_id
            if is_directory:
                walk(base + offset, level + 1, current)
            else:
                data_entry = f.read_at(base + offset, 16)
                if len(data_entry) < 16:
                    continue
                data_rva, size, code_page = struct.unpack_from("<III", data_entry, 0)
                leaf = dict(current)
                leaf["size"] = size
                leaf["offset"] = _hex(data_rva)
                leaf["code_page"] = code_page
                resources.append(leaf)

    walk(base, 0, {})
    return resources


def _parse_dotnet(f: _File, rva: int, sections: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Read the CLR header and the metadata version of a managed assembly."""
    info: Dict[str, Any] = {"managed": True}
    offset = _rva_to_offset(sections, rva)
    if offset is None:
        return info
    header = f.read_at(offset, 24)
    if len(header) < 24:
        return info
    _cb, major, minor, meta_rva, meta_size, flags, token = struct.unpack_from(
        "<IHHIIII", header, 0)
    info["runtime_version"] = "%d.%d" % (major, minor)
    info["flags"] = flags
    info["entry_point_token"] = _hex(token)
    meta_offset = _rva_to_offset(sections, meta_rva)
    if meta_offset is None:
        return info
    meta = f.read_at(meta_offset, 32)
    if len(meta) < 16 or meta[:4] != b"BSJB":
        return info
    length = struct.unpack_from("<I", meta, 12)[0]
    if 0 < length <= 256:
        version = f.read_at(meta_offset + 16, length).split(b"\x00")[0]
        info["metadata_version"] = version.decode("utf-8", "replace")
    return info


def _analyze_pe(f: _File) -> Dict[str, Any]:
    """Read a PE image: the header, the sections, the imports and the resources."""
    facts: Dict[str, Any] = {}
    details: Dict[str, Any] = {}
    dos = f.read_at(0, 0x40)
    if len(dos) < 0x40:
        return {"facts": facts, "details": details}
    e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
    if e_lfanew <= 0 or e_lfanew > f.size:
        return {"facts": facts, "details": details}
    coff = f.read_at(e_lfanew, 24)
    if len(coff) < 24 or coff[:4] != b"PE\x00\x00":
        return {"facts": facts, "details": details}

    (machine, section_count, timestamp, _sym_ptr, _sym_num,
     optional_size, characteristics) = struct.unpack_from("<HHIIIHH", coff, 4)

    optional = f.read_at(e_lfanew + 24, optional_size)
    magic = _u16(optional, 0)
    if magic not in (0x10B, 0x20B):
        return {"facts": facts, "details": details}
    is_64bit = magic == 0x20B

    facts["machine_name"] = PE_MACHINES.get(machine, "unknown")
    facts["machine"] = machine
    facts["characteristics"] = characteristics
    facts["characteristics_flags"] = _flag_names(characteristics, PE_CHARACTERISTICS)
    facts["timestamp"] = _iso(timestamp)
    facts["is_64bit"] = is_64bit
    facts["is_dll"] = bool(characteristics & 0x2000)

    subsystem = _u16(optional, 68)
    if subsystem is not None:
        facts["subsystem_name"] = PE_SUBSYSTEMS.get(subsystem, "unknown")
        facts["subsystem"] = subsystem
    dll_characteristics = _u16(optional, 70)
    if dll_characteristics is not None:
        facts["dll_characteristics"] = dll_characteristics
        facts["dll_characteristics_flags"] = _flag_names(
            dll_characteristics, PE_DLL_CHARACTERISTICS)

    image_base = _u64(optional, 24) if is_64bit else _u32(optional, 28)
    if image_base is not None:
        facts["image_base"] = _hex(image_base)
    entry_rva = _u32(optional, 16)
    if entry_rva is not None:
        facts["entry_point"] = _hex(entry_rva)
        if image_base is not None:
            facts["entry_point_va"] = _hex(image_base + entry_rva)

    # The data directories: the count sits before them, and they follow.
    directory_count = _u32(optional, 108 if is_64bit else 92) or 0
    directory_base = 112 if is_64bit else 96
    directories: Dict[str, Tuple[int, int]] = {}
    for index in range(min(directory_count, 16)):
        rva = _u32(optional, directory_base + index * 8)
        size = _u32(optional, directory_base + index * 8 + 4)
        if rva is None or size is None:
            break
        directories[index] = (rva, size)
    facts["data_directories"] = {
        name: bool(directories.get(index, (0, 0))[0])
        for index, name in PE_DATA_DIRECTORIES.items()
    }

    section_offset = e_lfanew + 24 + optional_size
    sections = _parse_pe_sections(f, section_offset, min(section_count, 96))
    facts["section_count"] = len(sections)

    if directories.get(1, (0, 0))[0]:
        imports, truncated = _parse_pe_imports(
            f, directories[1][0], sections, is_64bit)
        details["imports"] = imports
        details["imports_truncated"] = truncated
        facts["import_count"] = sum(len(item["functions"]) for item in imports)

    if directories.get(2, (0, 0))[0]:
        resources = _parse_pe_resources(f, directories[2][0], sections)
        details["resources"] = resources
        facts["resource_count"] = len(resources)

    if directories.get(14, (0, 0))[0]:
        dotnet = _parse_dotnet(f, directories[14][0], sections)
        facts["is_dotnet"] = True
        facts["dotnet"] = dotnet
    else:
        facts["is_dotnet"] = False

    visible = []
    for section in sections:
        item = {key: value for key, value in section.items()
                if not key.startswith("_")}
        visible.append(item)
    details["sections"] = visible

    return {"facts": facts, "details": details}


# ---------------------------------------------------------------------------
# ELF
# ---------------------------------------------------------------------------

ELF_TYPES = {
    0: "ET_NONE",
    1: "ET_REL",
    2: "ET_EXEC",
    3: "ET_DYN",
    4: "ET_CORE",
}

ELF_MACHINES = {
    0: "none",
    2: "sparc",
    3: "i386",
    8: "mips",
    15: "parisc",
    20: "powerpc",
    21: "powerpc64",
    40: "arm",
    43: "sparcv9",
    62: "x86-64",
    183: "arm64",
    243: "riscv",
}

ELF_OSABI = {
    0: "system-v",
    1: "hpux",
    2: "netbsd",
    3: "linux",
    6: "solaris",
    7: "aix",
    8: "irix",
    9: "freebsd",
    10: "tru64",
    11: "openbsd",
    12: "openvms",
    64: "arm-aeabi",
    97: "arm",
    255: "standalone",
}

ELF_SEGMENT_TYPES = {
    0: "PT_NULL",
    1: "PT_LOAD",
    2: "PT_DYNAMIC",
    3: "PT_INTERP",
    4: "PT_NOTE",
    5: "PT_SHLIB",
    6: "PT_PHDR",
    7: "PT_TLS",
    0x6474E550: "PT_GNU_EH_FRAME",
    0x6474E551: "PT_GNU_STACK",
    0x6474E552: "PT_GNU_RELRO",
}

ELF_SECTION_TYPES = {
    0: "SHT_NULL",
    1: "SHT_PROGBITS",
    2: "SHT_SYMTAB",
    3: "SHT_STRTAB",
    4: "SHT_RELA",
    5: "SHT_HASH",
    6: "SHT_DYNAMIC",
    7: "SHT_NOTE",
    8: "SHT_NOBITS",
    9: "SHT_REL",
    10: "SHT_SHLIB",
    11: "SHT_DYNSYM",
    14: "SHT_INIT_ARRAY",
    15: "SHT_FINI_ARRAY",
    16: "SHT_PREINIT_ARRAY",
    17: "SHT_GROUP",
    18: "SHT_SYMTAB_SHNDX",
}

ELF_SIGNALS = {
    1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL", 5: "SIGTRAP",
    6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE", 9: "SIGKILL", 10: "SIGUSR1",
    11: "SIGSEGV", 12: "SIGUSR2", 13: "SIGPIPE", 14: "SIGALRM", 15: "SIGTERM",
    16: "SIGSTKFLT", 17: "SIGCHLD", 18: "SIGCONT", 19: "SIGSTOP", 20: "SIGTSTP",
    21: "SIGTTIN", 22: "SIGTTOU", 23: "SIGURG", 24: "SIGXCPU", 25: "SIGXFSZ",
    26: "SIGVTALRM", 27: "SIGPROF", 28: "SIGWINCH", 29: "SIGIO", 30: "SIGPWR",
    31: "SIGSYS",
}

# The general purpose registers of an x86-64 core dump, in the order the
# kernel writes them.
ELF_X86_64_REGISTERS = [
    "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8",
    "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags",
    "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs",
]

# The registers of an i386 core dump.
ELF_I386_REGISTERS = [
    "ebx", "ecx", "edx", "esi", "edi", "ebp", "eax", "ds", "es", "fs", "gs",
    "orig_eax", "eip", "cs", "eflags", "esp", "ss",
]

MINIDUMP_STREAMS = {
    0: "Unused", 1: "Reserved0", 2: "Reserved1", 3: "ThreadList",
    4: "ModuleList", 5: "MemoryList", 6: "Exception", 7: "SystemInfo",
    8: "ThreadExList", 9: "Memory64List", 10: "CommentA", 11: "CommentW",
    12: "HandleData", 13: "FunctionTable", 14: "UnloadedModuleList",
    15: "MiscInfo", 16: "MemoryInfoList", 17: "ThreadInfoList",
    18: "HandleOperationList",
}


def _elf_header(f: _File) -> Optional[Dict[str, Any]]:
    """Read the ELF header and the tables it points at."""
    ident = f.read_at(0, 16)
    if len(ident) < 16 or ident[:4] != b"\x7fELF":
        return None
    elf_class = ident[4]
    data_encoding = ident[5]
    os_abi = ident[7]
    if elf_class not in (1, 2) or data_encoding not in (1, 2):
        return None
    is_64bit = elf_class == 2
    endian = "<" if data_encoding == 1 else ">"
    header = f.read_at(0, 64 if is_64bit else 52)
    if len(header) < (64 if is_64bit else 52):
        return None
    elf_type = _u16(header, 16, endian)
    machine = _u16(header, 18, endian)
    entry = _u64(header, 24, endian) if is_64bit else _u32(header, 24, endian)
    phoff = _u64(header, 32, endian) if is_64bit else _u32(header, 28, endian)
    shoff = _u64(header, 40, endian) if is_64bit else _u32(header, 32, endian)
    phentsize = _u16(header, 54 if is_64bit else 42, endian)
    phnum = _u16(header, 56 if is_64bit else 44, endian)
    shentsize = _u16(header, 58 if is_64bit else 46, endian)
    shnum = _u16(header, 60 if is_64bit else 48, endian)
    shstrndx = _u16(header, 62 if is_64bit else 50, endian)
    return {
        "is_64bit": is_64bit,
        "endian": endian,
        "os_abi": os_abi,
        "type": elf_type,
        "machine": machine,
        "entry": entry,
        "phoff": phoff,
        "shoff": shoff,
        "phentsize": phentsize,
        "phnum": phnum,
        "shentsize": shentsize,
        "shnum": shnum,
        "shstrndx": shstrndx,
    }


def _elf_program_headers(f: _File, header: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Read the ELF program headers."""
    is_64bit = header["is_64bit"]
    endian = header["endian"]
    entry_size = 56 if is_64bit else 32
    count = min(header["phnum"] or 0, 512)
    raw = f.read_at(header["phoff"], count * entry_size)
    headers: List[Dict[str, Any]] = []
    for index in range(count):
        base = index * entry_size
        if base + entry_size > len(raw):
            break
        if is_64bit:
            p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, _align = \
                struct.unpack_from(endian + "IIQQQQQQ", raw, base)
        else:
            p_type, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_flags, _align = \
                struct.unpack_from(endian + "IIIIIIII", raw, base)
        headers.append({
            "type": ELF_SEGMENT_TYPES.get(p_type, "0x%x" % p_type),
            "offset": _hex(p_offset),
            "vaddr": _hex(p_vaddr),
            "filesz": p_filesz,
            "memsz": p_memsz,
            "flags": p_flags,
            "_type": p_type,
            "_offset": p_offset,
            "_vaddr": p_vaddr,
            "_filesz": p_filesz,
        })
    return headers


def _elf_section_headers(f: _File, header: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Read the ELF section headers, with their names resolved."""
    is_64bit = header["is_64bit"]
    endian = header["endian"]
    entry_size = 64 if is_64bit else 40
    count = min(header["shnum"] or 0, 4096)
    raw = f.read_at(header["shoff"], count * entry_size)
    sections: List[Dict[str, Any]] = []
    for index in range(count):
        base = index * entry_size
        if base + entry_size > len(raw):
            break
        if is_64bit:
            (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
             _link, _info, _align, _entsize) = struct.unpack_from(
                "<IIQQQQIIQQ", raw, base)
        else:
            (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
             _link, _info, _align, _entsize) = struct.unpack_from(
                "<IIIIIIIIII", raw, base)
        sections.append({
            "name_offset": sh_name,
            "type": ELF_SECTION_TYPES.get(sh_type, "0x%x" % sh_type),
            "flags": sh_flags,
            "address": _hex(sh_addr),
            "offset": _hex(sh_offset),
            "size": sh_size,
            "_offset": sh_offset,
            "_size": sh_size,
        })

    strtab_offset = None
    if header["shstrndx"] is not None and header["shstrndx"] < len(sections):
        strtab_offset = sections[header["shstrndx"]]["_offset"]
    for section in sections:
        if strtab_offset is None:
            section["name"] = ""
            continue
        name = _cstr(f.read_at(strtab_offset + section["name_offset"], 256))
        section["name"] = name
    return sections


def _elf_vaddr_to_offset(headers: List[Dict[str, Any]],
                         vaddr: int) -> Optional[int]:
    """Turn a virtual address into a file offset, through the program headers."""
    for header in headers:
        if header["_type"] != 1:  # PT_LOAD
            continue
        start = header["_vaddr"]
        end = start + max(header["_filesz"], 1)
        if start <= vaddr < end:
            return header["_offset"] + (vaddr - start)
    return None


def _elf_needed(f: _File, header: Dict[str, Any],
                segments: List[Dict[str, Any]]) -> List[str]:
    """Read the DT_NEEDED entries of the dynamic section."""
    needed: List[str] = []
    dynamic = None
    for segment in segments:
        if segment["_type"] == 2:  # PT_DYNAMIC
            dynamic = segment
            break
    if dynamic is None:
        return needed
    is_64bit = header["is_64bit"]
    endian = header["endian"]
    entry_size = 16 if is_64bit else 8
    count = min(dynamic["_filesz"] // entry_size, 4096)
    raw = f.read_at(dynamic["_offset"], count * entry_size)
    strtab_vaddr = None
    offsets: List[int] = []
    for index in range(count):
        base = index * entry_size
        if base + entry_size > len(raw):
            break
        if is_64bit:
            tag, value = struct.unpack_from("<QQ", raw, base)
        else:
            tag, value = struct.unpack_from("<II", raw, base)
        if tag == 0:
            break
        if tag == 1:  # DT_NEEDED
            offsets.append(value)
        elif tag == 5:  # DT_STRTAB
            strtab_vaddr = value
    if strtab_vaddr is None:
        return needed
    strtab_offset = _elf_vaddr_to_offset(segments, strtab_vaddr)
    if strtab_offset is None:
        return needed
    for offset in offsets[:MAX_ITEMS]:
        name = _cstr(f.read_at(strtab_offset + offset, 256))
        if name:
            needed.append(name)
    return needed


def _elf_notes(f: _File, header: Dict[str, Any],
               segments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Read the notes of the PT_NOTE segments."""
    notes: List[Dict[str, Any]] = []
    is_64bit = header["is_64bit"]
    endian = header["endian"]
    for segment in segments:
        if segment["_type"] != 4:  # PT_NOTE
            continue
        position = segment["_offset"]
        end = segment["_offset"] + segment["_filesz"]
        while position + 12 <= end:
            head = f.read_at(position, 12)
            if len(head) < 12:
                break
            namesz, descsz, ntype = struct.unpack_from("<III", head, 0)
            name_offset = position + 12
            name = f.read_at(name_offset, namesz).split(b"\x00")[0]
            desc_offset = name_offset + ((namesz + 3) & ~3)
            desc = f.read_at(desc_offset, descsz)
            notes.append({
                "name": name.decode("utf-8", "replace"),
                "type": ntype,
                "description": desc,
            })
            position = desc_offset + ((descsz + 3) & ~3)
        _ = is_64bit
        _ = endian
    return notes


def _parse_elf_prstatus(desc: bytes, is_64bit: bool,
                        machine: int, endian: str = "<") -> Dict[str, Any]:
    """Read the crash information out of an NT_PRSTATUS note."""
    info: Dict[str, Any] = {}
    if len(desc) < 16:
        return info
    si_signo = struct.unpack_from(endian + "i", desc, 0)[0]
    cursig = struct.unpack_from(endian + "h", desc, 12)[0]
    signal_number = cursig if cursig else si_signo
    if signal_number:
        info["signal"] = signal_number
        info["signal_name"] = ELF_SIGNALS.get(signal_number, "SIG%d" % signal_number)
    if si_signo:
        info["terminating_signal"] = si_signo
        info["terminating_signal_name"] = ELF_SIGNALS.get(
            si_signo, "SIG%d" % si_signo)

    if is_64bit:
        pid_offset, sid_offset, reg_offset = 32, 44, 112
        size = 8
        names = ELF_X86_64_REGISTERS
    else:
        pid_offset, sid_offset, reg_offset = 24, 36, 72
        size = 4
        names = ELF_I386_REGISTERS
    if len(desc) >= pid_offset + 4:
        info["thread_id"] = struct.unpack_from(endian + "i", desc, pid_offset)[0]
    if len(desc) >= sid_offset + 4:
        info["process_id"] = struct.unpack_from(endian + "i", desc, sid_offset)[0]

    if machine not in (3, 62) or len(desc) < reg_offset + len(names) * size:
        return info
    registers: Dict[str, str] = {}
    for index, name in enumerate(names):
        position = reg_offset + index * size
        if position + size > len(desc):
            break
        value = struct.unpack_from(
            endian + ("Q" if size == 8 else "I"), desc, position)[0]
        registers[name] = _hex(value)
    if registers:
        info["registers"] = registers
    return info


def _analyze_elf(f: _File) -> Dict[str, Any]:
    """Read an ELF object: the header, the tables and the dynamic section."""
    header = _elf_header(f)
    if header is None:
        return {"facts": {}, "details": {}}
    facts: Dict[str, Any] = {}
    details: Dict[str, Any] = {}
    facts["class"] = 64 if header["is_64bit"] else 32
    facts["endianness"] = "little" if header["endian"] == "<" else "big"
    facts["os_abi"] = ELF_OSABI.get(header["os_abi"], "unknown")
    facts["os_abi_number"] = header["os_abi"]
    facts["type"] = ELF_TYPES.get(header["type"], "0x%x" % header["type"])
    facts["machine_name"] = ELF_MACHINES.get(header["machine"], "unknown")
    facts["machine"] = header["machine"]
    if header["entry"] is not None:
        facts["entry_point"] = _hex(header["entry"])
    facts["program_header_count"] = header["phnum"] or 0
    facts["section_header_count"] = header["shnum"] or 0

    segments = _elf_program_headers(f, header)
    sections = _elf_section_headers(f, header)
    details["program_headers"] = segments
    details["section_headers"] = sections

    needed = _elf_needed(f, header, segments)
    if needed:
        details["needed"] = needed
    for segment in segments:
        if segment["_type"] == 3:  # PT_INTERP
            offset = segment["_offset"]
            details["interpreter"] = _cstr(f.read_at(offset, 512))
            break

    if header["type"] == 4:  # ET_CORE
        facts["is_core_dump"] = True
        notes = _elf_notes(f, header, segments)
        for note in notes:
            if note["type"] == 1 and note["name"] == "CORE":
                crash = _parse_elf_prstatus(
                    note["description"], header["is_64bit"], header["machine"],
                    header["endian"])
                facts.update(crash)
                details["note_types"] = [item["type"] for item in notes]
                break
    return {"facts": facts, "details": details}


def _analyze_minidump(f: _File) -> Dict[str, Any]:
    """Read a Windows minidump: the streams its directory holds."""
    header = f.read_at(0, 32)
    if len(header) < 32:
        return {"facts": {}, "details": {}}
    (_signature, version, stream_count, directory_rva,
     _checksum, timestamp, _flags) = struct.unpack_from("<IIIIIIQ", header, 0)
    facts: Dict[str, Any] = {
        "is_core_dump": True,
        "core_kind": "minidump",
        "version": version,
        "timestamp": _iso(timestamp),
        "stream_count": stream_count,
    }
    streams: List[Dict[str, Any]] = []
    raw = f.read_at(directory_rva, stream_count * 12)
    for index in range(stream_count):
        base = index * 12
        if base + 12 > len(raw):
            break
        stream_type, data_size, rva = struct.unpack_from("<III", raw, base)
        streams.append({
            "type": MINIDUMP_STREAMS.get(stream_type, "type-%d" % stream_type),
            "type_number": stream_type,
            "size": data_size,
            "offset": _hex(rva),
        })
    facts["streams"] = [item["type"] for item in streams]
    details: Dict[str, Any] = {"stream_directory": streams}
    if stream_count > MAX_ITEMS:
        details["stream_directory_truncated"] = True
    return {"facts": facts, "details": details}


# ---------------------------------------------------------------------------
# Mach-O
# ---------------------------------------------------------------------------

MACHO_CPUTYPES = {
    7: "x86",
    12: "arm",
    18: "powerpc",
    0x01000007: "x86-64",
    0x0100000C: "arm64",
}

MACHO_FILETYPES = {
    1: "MH_OBJECT",
    2: "MH_EXECUTE",
    3: "MH_FVMLIB",
    4: "MH_CORE",
    5: "MH_PRELOAD",
    6: "MH_DYLIB",
    7: "MH_DYLINKER",
    8: "MH_BUNDLE",
    9: "MH_DYLIB_STUB",
    10: "MH_DSYM",
    11: "MH_KEXT_BUNDLE",
    12: "MH_FILESET",
}

MACHO_SEGMENT_COMMANDS = (0x1, 0x19)


def _analyze_macho(f: _File) -> Dict[str, Any]:
    """Read a Mach-O image: the header and its load commands."""
    facts: Dict[str, Any] = {}
    details: Dict[str, Any] = {}
    head = f.read_at(0, 32)
    if len(head) < 28:
        return {"facts": facts, "details": details}

    if head[:4] == b"\xca\xfe\xba\xbe":
        return _analyze_macho_fat(f)

    magic = struct.unpack_from(">I", head, 0)[0]
    if magic == 0xFEEDFACE:
        bits, endian = 32, ">"
    elif magic == 0xFEEDFACF:
        bits, endian = 64, ">"
    elif magic == 0xCEFAEDFE:
        bits, endian = 32, "<"
    elif magic == 0xCFFAEDFE:
        bits, endian = 64, "<"
    else:
        return {"facts": facts, "details": details}

    cputype, _subtype, filetype, command_count = struct.unpack_from(
        endian + "iiii", head, 4)
    facts["bits"] = bits
    facts["endianness"] = "little" if endian == "<" else "big"
    facts["cputype_name"] = MACHO_CPUTYPES.get(cputype & 0xFFFFFFFF, "unknown")
    facts["cputype"] = cputype & 0xFFFFFFFF
    facts["filetype_name"] = MACHO_FILETYPES.get(filetype, "unknown")
    facts["filetype"] = filetype
    facts["load_command_count"] = command_count

    command_offset = 32 if bits == 64 else 28
    segments: List[Dict[str, Any]] = []
    position = command_offset
    for _ in range(min(command_count, 4096)):
        command = f.read_at(position, 8)
        if len(command) < 8:
            break
        cmd, size = struct.unpack_from(endian + "II", command, 0)
        if size < 8:
            break
        if cmd in MACHO_SEGMENT_COMMANDS:
            if bits == 64:
                name = f.read_at(position + 8, 16).split(b"\x00")[0].decode(
                    "utf-8", "replace")
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                    endian + "QQQQ", f.read_at(position + 24, 32), 0)
            else:
                name = f.read_at(position + 8, 16).split(b"\x00")[0].decode(
                    "utf-8", "replace")
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                    endian + "IIII", f.read_at(position + 24, 16), 0)
            segments.append({
                "name": name,
                "vmaddr": _hex(vmaddr),
                "vmsize": vmsize,
                "fileoff": _hex(fileoff),
                "filesize": filesize,
            })
        position += size
    details["segments"] = segments
    return {"facts": facts, "details": details}


def _analyze_macho_fat(f: _File) -> Dict[str, Any]:
    """Read the header of a fat Mach-O, which holds several images."""
    head = f.read_at(0, 8)
    if len(head) < 8:
        return {"facts": {}, "details": {}}
    count = struct.unpack_from(">I", head, 4)[0]
    facts: Dict[str, Any] = {"bits": 64, "endianness": "big", "is_fat": True,
                              "architecture_count": count}
    architectures: List[Dict[str, Any]] = []
    raw = f.read_at(8, min(count, 64) * 20)
    for index in range(min(count, 64)):
        base = index * 20
        if base + 20 > len(raw):
            break
        cputype, _subtype, offset, size, _align = struct.unpack_from(
            ">IIIII", raw, base)
        architectures.append({
            "cputype_name": MACHO_CPUTYPES.get(cputype & 0xFFFFFFFF, "unknown"),
            "cputype": cputype & 0xFFFFFFFF,
            "offset": _hex(offset),
            "size": size,
        })
    return {"facts": facts, "details": {"architectures": architectures}}


# ---------------------------------------------------------------------------
# DEX
# ---------------------------------------------------------------------------


def _analyze_dex(f: _File) -> Dict[str, Any]:
    """Read a DEX header: the version, the checksum and the table sizes."""
    header = f.read_at(0, 112)
    if len(header) < 112:
        return {"facts": {}, "details": {}}
    facts: Dict[str, Any] = {
        "version": header[4:7].decode("ascii", "replace"),
    }
    facts["checksum"] = struct.unpack_from("<I", header, 8)[0]
    facts["file_size"] = struct.unpack_from("<I", header, 32)[0]
    facts["header_size"] = struct.unpack_from("<I", header, 36)[0]
    facts["endian_tag"] = struct.unpack_from("<I", header, 40)[0]
    facts["string_ids_size"] = struct.unpack_from("<I", header, 56)[0]
    facts["type_ids_size"] = struct.unpack_from("<I", header, 64)[0]
    facts["method_ids_size"] = struct.unpack_from("<I", header, 88)[0]
    facts["class_defs_size"] = struct.unpack_from("<I", header, 96)[0]
    facts["field_ids_size"] = struct.unpack_from("<I", header, 80)[0]
    return {"facts": facts, "details": {}}


# ---------------------------------------------------------------------------
# ZIP, APK and firmware archives
# ---------------------------------------------------------------------------

# The entries that turn a ZIP into an Android package.
APK_MARKERS = ("AndroidManifest.xml", "classes.dex", "resources.arsc")

# The names that turn a ZIP into a firmware bundle.
FIRMWARE_MARKERS = ("kernel", "uimage", "rootfs", "squashfs", ".dtb", "bootloader")


def _zip_entries(archive: zipfile.ZipFile) -> List[Dict[str, Any]]:
    """List the entries of a ZIP archive."""
    entries: List[Dict[str, Any]] = []
    for info in archive.infolist():
        entries.append({
            "name": info.filename,
            "size": info.file_size,
            "compressed_size": info.compress_size,
        })
    return entries


def _looks_like_firmware(names: List[str]) -> bool:
    """Does this ZIP hold a firmware tree?"""
    for name in names:
        lowered = name.lower()
        base = lowered.rsplit("/", 1)[-1]
        for marker in FIRMWARE_MARKERS:
            if marker in base:
                return True
        if base.endswith(".img") or base.endswith(".bin"):
            return True
    return False


def _axml_string_pool(chunk: bytes) -> List[str]:
    """Read the string pool of a binary Android manifest."""
    if len(chunk) < 28:
        return []
    string_count, _style_count, flags, strings_start = struct.unpack_from(
        "<IIII", chunk, 8)
    is_utf8 = bool(flags & 0x100)
    strings: List[str] = []
    for index in range(min(string_count, 8192)):
        offset = _u32(chunk, 28 + index * 4)
        if offset is None:
            break
        position = strings_start + offset
        if position >= len(chunk):
            strings.append("")
            continue
        if is_utf8:
            _, position = _axml_utf8_length(chunk, position)
            byte_length, position = _axml_utf8_length(chunk, position)
            strings.append(chunk[position:position + byte_length].decode(
                "utf-8", "replace"))
        else:
            char_length = _u16(chunk, position)
            position += 2
            byte_length = _u16(chunk, position)
            position += 2
            if char_length is None or byte_length is None:
                strings.append("")
                continue
            strings.append(chunk[position:position + byte_length].decode(
                "utf-16-le", "replace"))
    return strings


def _axml_utf8_length(data: bytes, position: int) -> Tuple[int, int]:
    """Read the length prefix of a UTF-8 string in a binary manifest."""
    if position >= len(data):
        return 0, position
    first = data[position]
    position += 1
    if first & 0x80:
        if first & 0xC0 == 0x80:
            value = ((first & 0x3F) << 8) | data[position] if position < len(data) else 0
            return value, position + 1
        value = ((first & 0x1F) << 16) | (data[position] << 8) | data[position + 1] \
            if position + 1 < len(data) else 0
        return value, position + 2
    return first, position


def _axml_elements(data: bytes, strings: List[str]) -> List[Dict[str, Any]]:
    """Read the elements and their attributes of a binary Android manifest."""
    elements: List[Dict[str, Any]] = []
    position = 0
    total = len(data)
    while position + 8 <= total:
        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, position)
        if chunk_type == 0x0003:
            # The header of the tree covers the whole file; the chunks that
            # matter follow it.
            position += 8
            continue
        if chunk_size < 8 or position + chunk_size > total:
            break
        if chunk_type == 0x0102:  # RES_XML_START_ELEMENT_TYPE
            name_index = _u32(data, position + 20)
            attribute_start, attribute_size, attribute_count = struct.unpack_from(
                "<HHH", data, position + 24)
            attributes: Dict[str, Any] = {}
            base = position + 16 + (attribute_start or 20)
            for index in range(min(attribute_count or 0, 512)):
                entry = base + index * (attribute_size or 20)
                if entry + 20 > total:
                    break
                _ns, attribute_name, raw_index = struct.unpack_from(
                    "<III", data, entry)
                _size, _res0, data_type, value = struct.unpack_from(
                    "<HBB I", data, entry + 12)
                name = strings[attribute_name] if attribute_name < len(strings) else ""
                value_text: Any = None
                if data_type == 0x03 and value < len(strings):
                    value_text = strings[value]
                elif data_type in (0x10, 0x11):
                    value_text = value
                elif data_type == 0x12:
                    value_text = bool(value)
                elif raw_index != 0xFFFFFFFF and raw_index < len(strings):
                    value_text = strings[raw_index]
                if name and value_text is not None:
                    attributes[name] = value_text
            elements.append({
                "name": strings[name_index] if name_index < len(strings) else "",
                "attributes": attributes,
            })
        _ = header_size
        position += chunk_size
    return elements


def _parse_android_manifest(data: bytes) -> Dict[str, Any]:
    """Read a binary Android manifest: the package, the SDKs and the permissions."""
    info: Dict[str, Any] = {"parsed": False}
    if len(data) < 8:
        return info
    chunk_type, _header_size, chunk_size = struct.unpack_from("<HHI", data, 0)
    if chunk_type != 0x0003:
        return info
    end = min(len(data), chunk_size if chunk_size else len(data))
    position = 8
    strings: List[str] = []
    while position + 8 <= end:
        inner_type, _inner_header, inner_size = struct.unpack_from(
            "<HHI", data, position)
        if inner_size < 8 or position + inner_size > end:
            break
        if inner_type == 0x0001:  # RES_STRING_POOL_TYPE
            strings = _axml_string_pool(data[position:position + inner_size])
        position += inner_size

    elements = _axml_elements(data[:end], strings)
    if not elements:
        return info

    info["parsed"] = True
    permissions: List[str] = []
    for element in elements:
        attributes = element["attributes"]
        name = element["name"]
        if name == "manifest":
            if "package" in attributes:
                info["package"] = attributes["package"]
            if "versionName" in attributes:
                info["version_name"] = attributes["versionName"]
            if "versionCode" in attributes:
                info["version_code"] = attributes["versionCode"]
            if "compileSdkVersion" in attributes:
                info["compile_sdk"] = attributes["compileSdkVersion"]
        elif name == "uses-sdk":
            if "minSdkVersion" in attributes:
                info["min_sdk"] = attributes["minSdkVersion"]
            if "targetSdkVersion" in attributes:
                info["target_sdk"] = attributes["targetSdkVersion"]
        elif name in ("uses-permission", "uses-permission-sdk-23"):
            value = attributes.get("name")
            if isinstance(value, str) and value:
                permissions.append(value)
    if permissions:
        seen: List[str] = []
        for permission in permissions:
            if permission not in seen:
                seen.append(permission)
        info["permissions"] = seen[:MAX_ITEMS]
        info["permissions_truncated"] = len(seen) > MAX_ITEMS
    info["elements"] = [element["name"] for element in elements[:MAX_ITEMS]]
    return info


def _analyze_apk(path: str, archive: zipfile.ZipFile) -> Dict[str, Any]:
    """Read an Android package: the manifest, the native libraries and the dex."""
    names = archive.namelist()
    facts: Dict[str, Any] = {"entry_count": len(names)}
    details: Dict[str, Any] = {}

    manifest: Dict[str, Any] = {}
    try:
        with archive.open("AndroidManifest.xml") as handle:
            manifest = _parse_android_manifest(handle.read())
    except (KeyError, OSError, zipfile.BadZipFile, struct.error):
        manifest = {}

    for key in ("package", "version_name", "version_code", "min_sdk",
                "target_sdk", "compile_sdk"):
        if key in manifest:
            facts[key] = manifest[key]
    facts["manifest_parsed"] = bool(manifest.get("parsed"))
    if "permissions" in manifest:
        facts["permissions_extracted"] = manifest["permissions"]
        facts["permissions_truncated"] = manifest.get("permissions_truncated", False)
    facts["permissions_note"] = (
        "extracted from the binary manifest, not fully parsed")

    native_libraries: List[Dict[str, str]] = []
    dex_files: List[str] = []
    signatures: List[str] = []
    for name in names:
        lowered = name.lower()
        if lowered.startswith("lib/") and lowered.endswith(".so"):
            parts = name.split("/")
            architecture = parts[1] if len(parts) > 2 else "unknown"
            native_libraries.append({
                "name": name,
                "architecture": architecture,
            })
        elif lowered.endswith(".dex"):
            dex_files.append(name)
        elif name.startswith("META-INF/") and lowered.rsplit(".", 1)[-1] in (
                "rsa", "dsa", "ec", "sf"):
            signatures.append(name)
    facts["native_libraries"] = native_libraries[:MAX_ITEMS]
    facts["dex_files"] = dex_files[:MAX_ITEMS]
    facts["signature_files"] = signatures[:MAX_ITEMS]

    entries = _zip_entries(archive)
    entries, truncated = _capped(entries)
    details["entries"] = entries
    details["entries_truncated"] = truncated
    return {"facts": facts, "details": details}


def _analyze_zip(archive: zipfile.ZipFile) -> Dict[str, Any]:
    """Read a plain ZIP: the list of what it holds."""
    names = archive.namelist()
    facts: Dict[str, Any] = {"entry_count": len(names)}
    details: Dict[str, Any] = {}
    entries, truncated = _capped(_zip_entries(archive))
    details["entries"] = entries
    details["entries_truncated"] = truncated
    return {"facts": facts, "details": details}


def _analyze_zip_container(path: str, f: _File) -> Dict[str, Any]:
    """Read a ZIP and decide what it really is: an APK, a firmware bundle or a ZIP."""
    try:
        archive = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as exc:
        return {
            "format": "zip",
            "facts": {"error": "cannot read the archive: %s" % exc},
            "details": {},
        }
    with archive:
        names = archive.namelist()
        if any(name in APK_MARKERS for name in names):
            result = _analyze_apk(path, archive)
            result["format"] = "apk"
            return result
        if _looks_like_firmware(names):
            result = _analyze_zip(archive)
            result["format"] = "firmware"
            result["facts"]["firmware_format"] = "zip"
            result["facts"]["entry_count"] = len(names)
            return result
        result = _analyze_zip(archive)
        result["format"] = "zip"
        return result


# ---------------------------------------------------------------------------
# WASM
# ---------------------------------------------------------------------------

WASM_SECTIONS = {
    0: "custom", 1: "type", 2: "import", 3: "function", 4: "table",
    5: "memory", 6: "global", 7: "export", 8: "start", 9: "element",
    10: "code", 11: "data", 12: "datacount",
}


def _varuint(data: bytes, position: int) -> Tuple[Optional[int], int]:
    """Read an unsigned LEB128 integer."""
    result = 0
    shift = 0
    while position < len(data):
        byte = data[position]
        position += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, position
        shift += 7
        if shift > 35:
            break
    return None, position


def _wasm_name(data: bytes, position: int) -> Tuple[str, int]:
    """Read a length-prefixed name out of a WASM payload."""
    length, position = _varuint(data, position)
    if length is None:
        return "", position
    return data[position:position + length].decode("utf-8", "replace"), position + length


def _analyze_wasm(f: _File) -> Dict[str, Any]:
    """Read a WASM module: the sections, the imports and the exports."""
    head = f.read_at(0, 8)
    if len(head) < 8:
        return {"facts": {}, "details": {}}
    facts: Dict[str, Any] = {"version": struct.unpack_from("<I", head, 4)[0]}
    data = f.read_at(0, min(f.size, 16 * 1024 * 1024))
    position = 8
    sections: List[Dict[str, Any]] = []
    import_count = 0
    export_count = 0
    function_count = 0
    memory_pages = None
    while position < len(data):
        section_id = data[position]
        position += 1
        size, position = _varuint(data, position)
        if size is None:
            break
        payload = data[position:position + size]
        name = WASM_SECTIONS.get(section_id, "section-%d" % section_id)
        item = {"id": section_id, "name": name, "size": size}
        if section_id == 0:
            custom, _ = _wasm_name(payload, 0)
            item["custom_name"] = custom
        elif section_id == 2:
            count, cursor = _varuint(payload, 0)
            import_count = count or 0
        elif section_id == 7:
            count, cursor = _varuint(payload, 0)
            export_count = count or 0
        elif section_id == 3:
            # The function section declares the functions; the code section
            # holds their bodies. The declaration is the count.
            count, cursor = _varuint(payload, 0)
            function_count = count or 0
        elif section_id == 10:
            count, cursor = _varuint(payload, 0)
            if not function_count:
                function_count = count or 0
        elif section_id == 5:
            count, cursor = _varuint(payload, 0)
            if count:
                flags = payload[cursor] if cursor < len(payload) else 0
                cursor += 1
                minimum, cursor = _varuint(payload, cursor)
                memory_pages = minimum
                _ = flags
        sections.append(item)
        position += size
        if len(sections) > MAX_ITEMS:
            break
    facts["section_count"] = len(sections)
    facts["sections"], facts["sections_truncated"] = _capped(list(sections))
    facts["import_count"] = import_count
    facts["export_count"] = export_count
    facts["function_count"] = function_count
    if memory_pages is not None:
        facts["memory_pages"] = memory_pages
    details: Dict[str, Any] = {"sections": sections}
    return {"facts": facts, "details": details}


# ---------------------------------------------------------------------------
# EVM
# ---------------------------------------------------------------------------


def _evm_selectors(code: bytes) -> List[Dict[str, Any]]:
    """Find the 4-byte selectors a dispatcher compares.

    The shape is the classic one: a PUSH4 of the selector, then an EQ. The
    code is walked as instructions, so a byte that only looks like a PUSH4
    because it sits inside the data of another instruction is not mistaken
    for one.
    """
    selectors: List[Dict[str, Any]] = []
    seen = set()
    position = 0
    total = len(code)
    pending: Optional[Tuple[int, int]] = None
    age = 0
    while position < total:
        opcode = code[position]
        if 0x60 <= opcode <= 0x7F:  # PUSH1 .. PUSH32
            width = opcode - 0x5F
            chunk = code[position + 1:position + 1 + width]
            if opcode == 0x63 and len(chunk) == 4:
                pending = (position, int.from_bytes(chunk, "big"))
                age = 0
            else:
                pending = None
            position += 1 + width
            continue
        if opcode == 0x14:  # EQ
            if pending is not None and age <= 4:
                key = (pending[0], pending[1])
                if key not in seen:
                    seen.add(key)
                    selectors.append({
                        "selector": "0x%08x" % pending[1],
                        "offset": _hex(pending[0]),
                    })
            pending = None
            age = 0
        else:
            age += 1
            if age > 4:
                pending = None
        position += 1
        if len(selectors) >= MAX_ITEMS:
            break
    return selectors


def _analyze_evm(f: _File) -> Dict[str, Any]:
    """Read an EVM contract: the size, the kind of bytecode and the selectors."""
    code = f.read_at(0, min(f.size, 32 * 1024 * 1024))
    facts: Dict[str, Any] = {"code_size": len(code)}
    facts["is_creation"] = code[:5] == b"\x60\x80\x60\x40\x52"
    selectors = _evm_selectors(code)
    if selectors:
        facts["dispatcher_offset"] = selectors[0]["offset"]
        facts["selector_count"] = len(selectors)
    return {
        "facts": facts,
        "details": {"selectors": selectors},
    }


# ---------------------------------------------------------------------------
# plist, HAR and text
# ---------------------------------------------------------------------------


def _analyze_plist(f: _File) -> Dict[str, Any]:
    """Read a property list, in either its XML or its binary form."""
    head = f.read_at(0, 16)
    binary = head[:6] == b"bplist"
    facts: Dict[str, Any] = {"plist_format": "binary" if binary else "xml"}
    try:
        with open(f.path, "rb") as handle:
            data = plistlib.load(handle)
    except (OSError, ValueError, plistlib.InvalidFileException,
            struct.error, EOFError):
        return {"facts": facts, "details": {}}
    if isinstance(data, dict):
        facts["keys"] = sorted(str(key) for key in data.keys())[:MAX_ITEMS]
        facts["entry_count"] = len(data)
    elif isinstance(data, list):
        facts["entry_count"] = len(data)
    else:
        facts["entry_count"] = 1
    return {"facts": facts, "details": {}}


def _analyze_har(data: bytes) -> Optional[Dict[str, Any]]:
    """Read a HAR capture: the pages, the creator and the entries."""
    try:
        document = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(document, dict):
        return None
    log = document.get("log")
    if not isinstance(log, dict):
        return None
    entries = log.get("entries")
    if not isinstance(entries, list):
        return None

    facts: Dict[str, Any] = {"entry_count": len(entries)}
    pages = log.get("pages")
    if isinstance(pages, list) and pages:
        first = pages[0]
        if isinstance(first, dict) and first.get("title"):
            facts["page_title"] = first["title"]
    creator = log.get("creator")
    if isinstance(creator, dict):
        if creator.get("name"):
            facts["creator"] = creator["name"]
        if creator.get("version"):
            facts["creator_version"] = creator["version"]

    total_transferred = 0
    total_body = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        response = entry.get("response")
        if not isinstance(response, dict):
            continue
        body = response.get("bodySize")
        transfer = response.get("_transferSize")
        if isinstance(body, int):
            total_body += body
        if isinstance(transfer, int):
            total_transferred += transfer
        elif isinstance(body, int):
            total_transferred += body
    facts["total_transferred_bytes"] = total_transferred
    facts["total_body_bytes"] = total_body

    details_entries: List[Dict[str, Any]] = []
    for entry in entries[:MAX_ITEMS]:
        if not isinstance(entry, dict):
            continue
        request = entry.get("request") if isinstance(entry.get("request"), dict) else {}
        response = entry.get("response") if isinstance(entry.get("response"), dict) else {}
        content = response.get("content") if isinstance(
            response.get("content"), dict) else {}
        headers = request.get("headers") if isinstance(
            request.get("headers"), list) else []
        header_names = []
        for header in headers[:32]:
            if isinstance(header, dict) and header.get("name"):
                header_names.append(header["name"])
        details_entries.append({
            "method": request.get("method"),
            "url": request.get("url"),
            "status": response.get("status"),
            "mime_type": content.get("mimeType"),
            "response_size": response.get("content", {}).get("size")
            if isinstance(response.get("content"), dict) else None,
            "time_ms": entry.get("time"),
            "request_headers": header_names,
        })
    details: Dict[str, Any] = {"entries": details_entries}
    if len(entries) > MAX_ITEMS:
        details["entries_truncated"] = True
    return {"facts": facts, "details": details}


def _analyze_json_or_text(f: _File) -> Dict[str, Any]:
    """Read a text file, or a HAR capture when the JSON turns out to be one."""
    head = f.read_at(0, 4096)
    if head[:1] in (b"{", b"["):
        if f.size <= MAX_JSON_BYTES:
            data = f.read_at(0, int(f.size))
            har = _analyze_har(data)
            if har is not None:
                har["format"] = "har"
                return har
    facts: Dict[str, Any] = {}
    details: Dict[str, Any] = {}
    if f.size > MAX_TEXT_BYTES:
        facts["truncated"] = True
    sample = f.read_at(0, MAX_TEXT_BYTES)
    facts["printable_ratio"] = round(_printable_ratio(sample), 4)
    facts["lines"] = _count_lines(f)
    facts["characters"] = min(f.size, MAX_TEXT_BYTES)
    if head[:1] in (b"{", b"["):
        facts["encoding"] = "json"
    return {"facts": facts, "details": details}


def _count_lines(f: _File) -> int:
    """Count the lines of a file without holding it in memory."""
    lines = 0
    last = b"\n"
    try:
        with open(f.path, "rb") as handle:
            while True:
                chunk = handle.read(CHUNK_SIZE)
                if not chunk:
                    break
                lines += chunk.count(b"\n")
                last = chunk[-1:]
    except OSError:
        return lines
    if last != b"\n":
        lines += 1
    return lines


# ---------------------------------------------------------------------------
# Java class files
# ---------------------------------------------------------------------------

CLASS_ACCESS_FLAGS = {
    0x0001: "public",
    0x0002: "private",
    0x0004: "protected",
    0x0008: "static",
    0x0010: "final",
    0x0020: "super",
    0x0040: "volatile",
    0x0100: "native",
    0x0200: "interface",
    0x0400: "abstract",
    0x0800: "strict",
    0x1000: "synthetic",
    0x2000: "annotation",
    0x4000: "enum",
}


def _class_constant_pool_size(f: _File, count: int) -> Optional[int]:
    """The offset of the access flags, which follow the constant pool.

    The constant pool has to be walked to get there: every entry says how
    long it is, and the long ones (long and double) take two slots.
    """
    if count <= 0:
        return None
    position = 10
    index = 1
    while index < count:
        entry = f.read_at(position, 10)
        if not entry:
            return None
        tag = entry[0]
        if tag == 1:  # Utf8
            length = _u16(entry, 1, ">")
            if length is None:
                return None
            position += 3 + length
        elif tag in (3, 4):  # Integer, Float
            position += 5
        elif tag in (5, 6):  # Long, Double: two slots
            position += 9
            index += 1
        elif tag in (7, 8, 16, 19, 20):  # Class, String, MethodType, Module, Package
            position += 3
        elif tag in (9, 10, 11, 12, 17, 18):  # references and NameAndType
            position += 5
        elif tag == 15:  # MethodHandle
            position += 4
        else:
            return None
        index += 1
    return position


def _analyze_class(f: _File) -> Dict[str, Any]:
    """Read a Java class file: the version, the constant pool and the flags."""
    head = f.read_at(0, 24)
    if len(head) < 10:
        return {"facts": {}, "details": {}}
    facts: Dict[str, Any] = {
        "minor_version": struct.unpack_from(">H", head, 4)[0],
        "major_version": struct.unpack_from(">H", head, 6)[0],
        "constant_pool_count": struct.unpack_from(">H", head, 8)[0],
    }
    # The access flags come after the constant pool, so the pool is walked
    # to find them; a class file that cannot be walked keeps what was read.
    flags_offset = _class_constant_pool_size(f, facts["constant_pool_count"])
    if flags_offset is None:
        return {"facts": facts, "details": {}}
    tail = f.read_at(flags_offset, 12)
    if len(tail) < 12:
        return {"facts": facts, "details": {}}
    access = struct.unpack_from(">H", tail, 0)[0]
    facts["access_flags"] = access
    facts["access_flags_names"] = _flag_names(access, CLASS_ACCESS_FLAGS)
    facts["interfaces_count"] = struct.unpack_from(">H", tail, 6)[0]
    facts["fields_count"] = struct.unpack_from(">H", tail, 8)[0]
    facts["methods_count"] = struct.unpack_from(">H", tail, 10)[0]
    return {"facts": facts, "details": {}}


# ---------------------------------------------------------------------------
# PDF, gzip and SQLite
# ---------------------------------------------------------------------------


def _analyze_pdf(f: _File) -> Dict[str, Any]:
    """Read a PDF: the version, the page count and whether it is encrypted."""
    head = f.read_at(0, 32)
    facts: Dict[str, Any] = {}
    if len(head) >= 8:
        facts["version"] = head[5:8].decode("ascii", "replace")
    data = f.read_at(0, min(f.size, 16 * 1024 * 1024))
    facts["page_count"] = data.count(b"/Type") and _pdf_page_count(data)
    facts["encrypted"] = b"/Encrypt" in data
    facts["linearized"] = b"/Linearized" in data
    return {"facts": facts, "details": {}}


def _pdf_page_count(data: bytes) -> int:
    """Count the pages of a PDF from its page objects."""
    count = 0
    position = 0
    while True:
        position = data.find(b"/Type", position)
        if position == -1:
            break
        tail = data[position + 5:position + 40]
        stripped = tail.lstrip()
        if stripped.startswith(b"/Page") and not stripped.startswith(b"/Pages"):
            count += 1
        position += 5
    return count


def _analyze_gzip(f: _File) -> Dict[str, Any]:
    """Read a gzip stream: the method, the timestamp and the original name."""
    head = f.read_at(0, 512)
    facts: Dict[str, Any] = {}
    if len(head) < 10:
        return {"facts": facts, "details": {}}
    facts["compression"] = head[2]
    flags = head[3]
    facts["flags"] = flags
    facts["timestamp"] = _iso(struct.unpack_from("<I", head, 4)[0])
    facts["os"] = head[9]
    if flags & 0x04:  # FEXTRA
        extra_length = struct.unpack_from("<H", head, 10)[0]
        facts["extra_length"] = extra_length
    if flags & 0x08:  # FNAME
        name = _cstr(head, 12)
        facts["original_filename"] = name
    tail = f.read_at(max(0, f.size - 4), 4)
    if len(tail) == 4:
        facts["uncompressed_size"] = struct.unpack("<I", tail)[0]
    return {"facts": facts, "details": {}}


def _analyze_sqlite(f: _File) -> Dict[str, Any]:
    """Read a SQLite database: the page size, the encoding and the page count."""
    head = f.read_at(0, 100)
    if len(head) < 100:
        return {"facts": {}, "details": {}}
    page_size = struct.unpack_from(">H", head, 16)[0]
    if page_size == 1:
        page_size = 65536
    facts: Dict[str, Any] = {
        "page_size": page_size,
        "write_version": head[18],
        "read_version": head[19],
        "text_encoding": {1: "utf-8", 2: "utf-16le", 3: "utf-16be"}.get(
            struct.unpack_from(">I", head, 56)[0], "unknown"),
        "user_version": struct.unpack_from(">I", head, 60)[0],
        "application_id": struct.unpack_from(">I", head, 68)[0],
        "schema_version": struct.unpack_from(">I", head, 40)[0],
    }
    page_count = struct.unpack_from(">I", head, 28)[0]
    if page_count and page_size:
        facts["page_count"] = page_count
    return {"facts": facts, "details": {}}


# ---------------------------------------------------------------------------
# Firmware
# ---------------------------------------------------------------------------

UIMAGE_OS = {
    0: "invalid", 1: "openbsd", 2: "netbsd", 3: "freebsd", 4: "bsd",
    5: "linux", 6: "svr4", 7: "esix", 8: "solaris", 9: "Irix", 10: "sco",
    11: "dell", 12: "nt", 13: "openbsd", 14: "openbsd", 15: "openbsd",
    16: "openbsd",
}

UIMAGE_ARCH = {
    0: "invalid", 1: "alpha", 2: "arm", 3: "i386", 4: "ia64", 5: "mips",
    6: "mips64", 7: "powerpc", 8: "s390", 9: "sh", 10: "sparc", 11: "sparc64",
    12: "m68k", 13: "mips64", 14: "superh", 15: "sparc", 16: "superh",
    17: "mips64", 18: "arm", 19: "sh", 20: "sh", 21: "sh4", 22: "sh4",
    23: "sh4", 24: "itanium", 25: "mips", 26: "mips64", 27: "mips64",
    28: "mips64", 29: "mips64", 30: "mips64", 31: "arm", 32: "arm", 33: "arm",
    34: "arm", 35: "arm", 36: "arm", 37: "arm",
}

UIMAGE_TYPE = {
    0: "invalid", 1: "standalone", 2: "kernel", 3: "ramdisk", 4: "multi",
    5: "firmware", 6: "script", 7: "filesystem", 8: "flatdt", 9: "kwbimage",
    10: "imximage",
}

UIMAGE_COMPRESSION = {
    0: "none", 1: "gzip", 2: "bzip2", 3: "lzma", 4: "lzo", 5: "lz4",
    6: "zstd",
}

SQUASHFS_COMPRESSION = {
    1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd",
}


def _analyze_uimage(f: _File) -> Dict[str, Any]:
    """Read a uImage header: the size, the timestamp, the name and the target."""
    head = f.read_at(0, 64)
    if len(head) < 64:
        return {"facts": {}, "details": {}}
    # The header is 64 bytes: seven words, four bytes of target, and the name.
    (_magic, hcrc, timestamp, size, load, entry, dcrc) = struct.unpack_from(
        ">IIIIIII", head, 0)
    os_type, arch, image_type, compression = struct.unpack_from(">BBBB", head, 28)
    name = head[32:64].split(b"\x00")[0].decode("utf-8", "replace")
    facts: Dict[str, Any] = {
        "firmware_format": "uimage",
        "payload_size": size,
        "timestamp": _iso(timestamp),
        "name": name,
        "load_address": _hex(load),
        "entry_point": _hex(entry),
        "header_checksum": hcrc,
        "data_checksum": dcrc,
        "os": UIMAGE_OS.get(os_type, "0x%x" % os_type),
        "architecture": UIMAGE_ARCH.get(arch, "0x%x" % arch),
        "type": UIMAGE_TYPE.get(image_type, "0x%x" % image_type),
        "compression": UIMAGE_COMPRESSION.get(compression, "0x%x" % compression),
    }
    return {"facts": facts, "details": {}}


def _analyze_squashfs(f: _File) -> Dict[str, Any]:
    """Read a squashfs superblock: the version and the block size."""
    head = f.read_at(0, 96)
    if len(head) < 34:
        return {"facts": {}, "details": {}}
    (magic, inodes, mkfs_time, block_size, fragments) = struct.unpack_from(
        "<IIIII", head, 0)
    compression, _block_log = struct.unpack_from("<HH", head, 20)
    (_flags,) = struct.unpack_from("<I", head, 24)
    _no_ids, major, minor = struct.unpack_from("<HHH", head, 28)
    facts: Dict[str, Any] = {
        "firmware_format": "squashfs",
        "version": "%d.%d" % (major, minor),
        "block_size": block_size,
        "inode_count": inodes,
        "fragment_count": fragments,
        "timestamp": _iso(mkfs_time),
        "compression": SQUASHFS_COMPRESSION.get(compression, "0x%x" % compression),
    }
    _ = magic
    return {"facts": facts, "details": {}}


def _analyze_jffs2(f: _File) -> Dict[str, Any]:
    """Read the magic of a JFFS2 node."""
    facts: Dict[str, Any] = {"firmware_format": "jffs2"}
    head = f.read_at(0, 12)
    if len(head) >= 4:
        # The node header: the magic, the type of the node, its length.
        facts["node_type"] = struct.unpack_from("<H", head, 2)[0]
    return {"facts": facts, "details": {}}


def _analyze_cramfs(f: _File) -> Dict[str, Any]:
    """Read the superblock of a cramfs image."""
    facts: Dict[str, Any] = {"firmware_format": "cramfs"}
    head = f.read_at(0, 20)
    if len(head) >= 16:
        facts["size"] = struct.unpack_from("<I", head, 4)[0]
    if len(head) >= 20:
        facts["signature"] = head[16:20].decode("ascii", "replace")
    return {"facts": facts, "details": {}}


def _analyze_firmware(f: _File) -> Dict[str, Any]:
    """Read a firmware image: uImage, squashfs, JFFS2 or cramfs."""
    head = f.read_at(0, 16)
    if head[:4] == b"\x27\x05\x19\x56":
        return _analyze_uimage(f)
    if head[:4] == b"hsqs":
        return _analyze_squashfs(f)
    if head[:2] == b"\x85\x19":
        return _analyze_jffs2(f)
    if head[:4] == b"\x45\x3d\xcd\x28":
        return _analyze_cramfs(f)
    return {"facts": {"firmware_format": "unknown"}, "details": {}}


# ---------------------------------------------------------------------------
# JavaScript and Electron
# ---------------------------------------------------------------------------

# The markers that say a text file is JavaScript.
JS_MARKERS = ("require(", "module.exports", "exports.", "import ", "=>", "function ")

# The marker of a webpack bundle.
WEBPACK_MARKER = "webpackBootstrap"


def _asar_header(path: str) -> Optional[Dict[str, Any]]:
    """Read the header of an asar archive.

    An asar is a Chromium pickle: a size pickle that says how big the
    header pickle is, then the header pickle, which holds a JSON header.
    The files follow the header.
    """
    try:
        with open(path, "rb") as handle:
            head = handle.read(16)
            if len(head) < 16:
                return None
            header_size = struct.unpack_from("<I", head, 4)[0]
            json_length = struct.unpack_from("<I", head, 12)[0]
            if header_size <= 0 or json_length <= 0 or json_length > 64 * 1024 * 1024:
                return None
            handle.seek(16)
            raw = handle.read(json_length)
        header = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError, struct.error):
        return None
    if not isinstance(header, dict):
        return None
    # The file data follows the header pickle. The header may say where it
    # starts, either in absolute terms or relative to the end of the header.
    data_base = 8 + header_size
    top_offset = header.get("offset")
    if isinstance(top_offset, str) and top_offset.isdigit():
        value = int(top_offset)
        data_base = value if value >= data_base else data_base + value
    return {"header": header, "data_base": data_base}


def _asar_files(header: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flatten the file tree of an asar header."""
    files: List[Dict[str, Any]] = []

    def walk(node: Any, prefix: str) -> None:
        if len(files) >= MAX_ITEMS or not isinstance(node, dict):
            return
        for name in sorted(node.keys()):
            entry = node[name]
            if not isinstance(entry, dict):
                continue
            path = "%s/%s" % (prefix, name) if prefix else name
            if "files" in entry:
                walk(entry["files"], path)
            else:
                offset = entry.get("offset")
                files.append({
                    "name": path,
                    "size": entry.get("size"),
                    "offset": offset if isinstance(offset, str) else None,
                    "executable": bool(entry.get("executable")),
                    "unpacked": bool(entry.get("unpacked")),
                })

    walk(header.get("files"), "")
    return files


def _js_markers(text: str) -> List[str]:
    """Which JavaScript markers a text carries."""
    return [marker for marker in JS_MARKERS if marker in text]


def _analyze_javascript_file(f: _File) -> Dict[str, Any]:
    """Read a JavaScript file: the markers, the bundle and the source map."""
    facts: Dict[str, Any] = {"kind": "javascript-file"}
    details: Dict[str, Any] = {}
    text = f.read_at(0, MAX_TEXT_BYTES).decode("utf-8", "replace")
    markers = _js_markers(text)
    facts["markers"] = markers
    details["webpack"] = WEBPACK_MARKER in text
    source_map = f.path + ".map"
    details["source_map"] = os.path.isfile(source_map)
    details["source_maps"] = [source_map] if details["source_map"] else []
    facts["size"] = f.size
    return {"facts": facts, "details": details}


def _analyze_javascript_project(path: str) -> Dict[str, Any]:
    """Read a JavaScript project: its package.json, its entries and its bundles."""
    package_path = os.path.join(path, "package.json")
    facts: Dict[str, Any] = {"kind": "javascript-project"}
    details: Dict[str, Any] = {}
    package: Dict[str, Any] = {}
    try:
        with open(package_path, "rb") as handle:
            loaded = json.loads(handle.read().decode("utf-8"))
        if isinstance(loaded, dict):
            package = loaded
    except (OSError, ValueError, UnicodeDecodeError):
        package = {}

    if package:
        for key in ("name", "version", "main", "type"):
            value = package.get(key)
            if isinstance(value, (str, int)):
                facts[key] = value
        scripts = package.get("scripts")
        if isinstance(scripts, dict):
            facts["scripts"] = {str(key): str(value)
                                for key, value in list(scripts.items())[:MAX_ITEMS]}
        dependencies = package.get("dependencies")
        dev_dependencies = package.get("devDependencies")
        electron = False
        for group in (dependencies, dev_dependencies):
            if isinstance(group, dict) and "electron" in group:
                electron = True
        facts["electron"] = electron

    entries: List[str] = []
    source_maps: List[str] = []
    webpack = False
    try:
        names = sorted(os.listdir(path))
    except OSError:
        names = []
    for name in names:
        full = os.path.join(path, name)
        if not os.path.isfile(full):
            continue
        if name.endswith(".map"):
            source_maps.append(name)
        if name.endswith((".js", ".mjs", ".cjs")):
            entries.append(name)
            try:
                with open(full, "rb") as handle:
                    text = handle.read(MAX_TEXT_BYTES).decode("utf-8", "replace")
            except (OSError, UnicodeDecodeError):
                continue
            if WEBPACK_MARKER in text:
                webpack = True
            if os.path.isfile(full + ".map"):
                source_maps.append(name + ".map")
    if isinstance(package.get("main"), str) and package["main"] not in entries:
        entries.insert(0, package["main"])

    details["entry_points"] = entries[:MAX_ITEMS]
    details["source_maps"] = source_maps[:MAX_ITEMS]
    details["webpack"] = webpack
    details["electron"] = bool(facts.get("electron"))
    asar_files = [name for name in names if name.endswith(".asar")]
    if asar_files:
        details["asar"] = asar_files
        details["electron"] = True
    return {"facts": facts, "details": details}


def _analyze_asar(path: str) -> Dict[str, Any]:
    """Read an asar archive: the file tree it holds."""
    parsed = _asar_header(path)
    if parsed is None:
        return {
            "facts": {"kind": "asar", "parsed": False},
            "details": {},
        }
    header = parsed["header"]
    files = _asar_files(header)
    facts: Dict[str, Any] = {
        "kind": "asar",
        "parsed": True,
        "file_count": len(files),
        "electron": True,
    }
    details: Dict[str, Any] = {"files": files}
    return {"facts": facts, "details": details}


# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------


def _directory_size(path: str) -> int:
    """The total size of the files in a directory."""
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                continue
    return total


def _analyze_directory(path: str) -> Dict[str, Any]:
    """Read a directory: an Electron app, a JavaScript project, an APK or a firmware."""
    try:
        names = sorted(os.listdir(path))
    except OSError as exc:
        raise TriageError("cannot list %s: %s" % (path, exc),
                          "TRIAGE_UNREADABLE") from exc

    facts: Dict[str, Any] = {"entry_count": len(names)}
    visible, truncated = _capped(names)
    facts["top_level"] = visible
    facts["top_level_truncated"] = truncated
    size = _directory_size(path)

    if os.path.isfile(os.path.join(path, "package.json")):
        result = _analyze_javascript_project(path)
        result["format"] = "javascript"
        result["size"] = size
        return result

    asar_files = [name for name in names if name.endswith(".asar")]
    if asar_files:
        result = _analyze_asar(os.path.join(path, asar_files[0]))
        result["format"] = "javascript"
        result["size"] = size
        return result

    if "AndroidManifest.xml" in names:
        result = _analyze_apk_directory(path)
        result["format"] = "apk"
        result["size"] = size
        return result

    if any(name.endswith((".js", ".mjs", ".cjs")) for name in names):
        result = _analyze_javascript_project(path)
        result["format"] = "javascript"
        result["size"] = size
        return result

    firmware = [name for name in names if name.endswith(
        (".img", ".bin", ".sqsh", ".jffs2", ".cramfs")) or name in FIRMWARE_MARKERS]
    if firmware:
        facts["firmware_format"] = "directory"
        facts["firmware_files"] = firmware[:MAX_ITEMS]
        details = {"firmware_files": firmware[:MAX_ITEMS]}
        return {"format": "firmware", "size": size, "facts": facts,
                "details": details}

    facts["entropy"] = entropy(b"".join(
        name.encode("utf-8", "replace") for name in names[:MAX_ITEMS]))
    return {
        "format": "unknown",
        "size": size,
        "facts": facts,
        "details": {"top_level": visible},
    }


def _analyze_apk_directory(path: str) -> Dict[str, Any]:
    """Read an unpacked Android package."""
    facts: Dict[str, Any] = {"entry_count": len(os.listdir(path))}
    details: Dict[str, Any] = {}
    manifest_path = os.path.join(path, "AndroidManifest.xml")
    manifest: Dict[str, Any] = {}
    try:
        with open(manifest_path, "rb") as handle:
            manifest = _parse_android_manifest(handle.read())
    except OSError:
        manifest = {}
    for key in ("package", "version_name", "version_code", "min_sdk",
                "target_sdk", "compile_sdk"):
        if key in manifest:
            facts[key] = manifest[key]
    facts["manifest_parsed"] = bool(manifest.get("parsed"))
    if "permissions" in manifest:
        facts["permissions_extracted"] = manifest["permissions"]
        facts["permissions_note"] = (
            "extracted from the binary manifest, not fully parsed")

    native_libraries: List[str] = []
    dex_files: List[str] = []
    lib_root = os.path.join(path, "lib")
    if os.path.isdir(lib_root):
        try:
            for architecture in sorted(os.listdir(lib_root)):
                architecture_dir = os.path.join(lib_root, architecture)
                if not os.path.isdir(architecture_dir):
                    continue
                for name in sorted(os.listdir(architecture_dir)):
                    if name.endswith(".so"):
                        native_libraries.append("lib/%s/%s" % (architecture, name))
        except OSError:
            pass
    for root, _dirs, files in os.walk(path):
        for name in files:
            if name.endswith(".dex"):
                dex_files.append(os.path.relpath(os.path.join(root, name), path))
    facts["native_libraries"] = native_libraries[:MAX_ITEMS]
    facts["dex_files"] = sorted(dex_files)[:MAX_ITEMS]
    details["native_libraries"] = native_libraries[:MAX_ITEMS]
    return {"facts": facts, "details": details}


# ---------------------------------------------------------------------------
# The dispatcher
# ---------------------------------------------------------------------------


def _analyze_unknown(f: _File) -> Dict[str, Any]:
    """Report a file whose format is not known: its entropy and its first bytes."""
    head = f.read_at(0, 4096)
    facts: Dict[str, Any] = {
        "entropy": entropy(head),
        "first_bytes": head[:16].hex(),
    }
    if facts["entropy"] >= PACKED_ENTROPY:
        facts["probably_packed"] = True
    return {"facts": facts, "details": {}}


def _analyze(path: str) -> Dict[str, Any]:
    """Triage a path and return everything that was read out of it."""
    if not os.path.exists(path):
        raise TriageError("no such path: %s" % path, "TRIAGE_NO_FILE")
    if os.path.isdir(path):
        result = _analyze_directory(path)
        fmt = result.get("format", "unknown")
        facts = result.get("facts") or {}
        details = result.get("details") or {}
        result["recommendations"] = _recommendations(fmt, facts, details, path)
        return result

    with _File(path) as handle:
        head = handle.read_at(0, 8192)
        fmt = _detect_format(head, path)
        if fmt == _ZIP_CONTAINER:
            result = _analyze_zip_container(path, handle)
            fmt = result.pop("format", "zip")
        else:
            analyzer = _ANALYZERS.get(fmt, _analyze_unknown)
            try:
                result = analyzer(handle)
            except TriageError:
                raise
            except Exception as exc:  # a malformed file is not an error
                result = {"facts": {"parse_error": str(exc)}, "details": {}}
            # An analyzer may know better than the magic bytes: a JSON file
            # that turns out to be an HTTP archive is an archive.
            fmt = result.pop("format", fmt)

    facts = result.get("facts") or {}
    details = result.get("details") or {}
    # An ELF core dump is a core dump, not an ELF: the format says what the
    # file is, and that is what the tools have to be pointed at.
    if fmt == "elf" and facts.get("is_core_dump"):
        fmt = "core"
    recommendations = _recommendations(fmt, facts, details, path)
    return {
        "format": fmt,
        "size": handle.size,
        "facts": facts,
        "details": details,
        "recommendations": recommendations,
    }


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------


def _recommendations(fmt: str, facts: Dict[str, Any], details: Dict[str, Any],
                     path: str) -> List[str]:
    """Say what can be done with a target, in one short line per idea."""
    out: List[str] = []
    if fmt == "pe":
        if facts.get("is_dotnet"):
            out.append("managed .NET assembly: a .NET decompiler will read it "
                       "better than a native one")
            out.append("the native header holds the loader stubs; the logic is "
                       "in the IL, so extract the assembly first")
        else:
            out.append("native %s PE: run 'ghydra report build %s'"
                       % (facts.get("machine_name", "unknown"), path))
            if facts.get("is_dll"):
                out.append("DLL: the exports are the entry points")
        if facts.get("data_directories", {}).get("debug"):
            out.append("a debug directory is present: it may carry the PDB and "
                       "the original paths")
    elif fmt == "elf":
        if facts.get("is_core_dump"):
            out.append("core dump: the crash is already in the file; load it in "
                       "Ghidra as a core program")
            if facts.get("signal_name"):
                out.append("the process died with %s" % facts["signal_name"])
        else:
            out.append("native ELF (%s): run 'ghydra report build %s'"
                       % (facts.get("machine_name", "unknown"), path))
            if facts.get("type") == "ET_DYN":
                out.append("position-independent: the addresses move at load time")
    elif fmt == "core":
        if facts.get("core_kind") == "minidump":
            out.append("Windows minidump: the threads and the modules are in "
                       "the stream directory")
        else:
            out.append("core dump: load it in Ghidra as a core program")
    elif fmt == "mach-o":
        out.append("Mach-O image: Ghidra reads it, and the segments tell where "
                   "the code sits")
    elif fmt == "dex":
        out.append("DEX file: the classes are in the type and the method tables; "
                   "a DEX-aware decompiler reads it better")
    elif fmt == "apk":
        out.append("Android package: the code is in the DEX files, not in the "
                   "APK; decompile the .dex")
        if facts.get("native_libraries"):
            out.append("the package carries native libraries: those are the "
                       "ones for a native analysis")
    elif fmt == "wasm":
        out.append("WASM module: import the .wasm into Ghidra and analyse the "
                   "functions")
    elif fmt == "evm":
        out.append("EVM contract: the 4-byte selectors are in the dispatcher")
        if facts.get("is_creation"):
            out.append("this is creation bytecode: the constructor is what runs "
                       "on deployment")
    elif fmt == "javascript":
        if facts.get("electron"):
            out.append("Electron app: the JavaScript is the target; a native "
                       "decompiler only sees the Electron stubs")
        else:
            out.append("JavaScript: the code runs in a JavaScript engine, not in "
                       "a native one")
        if details.get("webpack"):
            out.append("a webpack bundle was found: the source map next to it "
                       "gives the original sources")
    elif fmt == "firmware":
        out.append("firmware image: carve the partitions before analysing them")
    elif fmt == "class":
        out.append("Java class file: use a Java decompiler; the bytecode is not "
                   "native code")
    elif fmt == "plist":
        out.append("property list: configuration, not code")
    elif fmt == "har":
        out.append("HAR capture: the traffic, not a binary; the URLs are the "
                   "interesting part")
    elif fmt == "zip":
        out.append("ZIP archive: unpack it and triage what is inside")
    elif fmt == "gzip":
        out.append("gzip stream: decompress it and triage the result")
    elif fmt == "sqlite":
        out.append("SQLite database: the schema and the rows, not code")
    elif fmt == "pdf":
        out.append("PDF: a document; look at the objects, not at code")
    elif fmt == "text":
        out.append("text: source or data, not a binary")
    else:
        if facts.get("entropy", 0) >= PACKED_ENTROPY:
            out.append("the entropy is high: the content is packed or "
                       "encrypted, so the headers will not tell much")
        else:
            out.append("unknown format: no magic number was recognised")
    return out


_ANALYZERS = {
    "pe": _analyze_pe,
    "elf": _analyze_elf,
    "mach-o": _analyze_macho,
    "dex": _analyze_dex,
    "wasm": _analyze_wasm,
    "evm": _analyze_evm,
    "core": _analyze_minidump,
    "plist": _analyze_plist,
    "javascript": _analyze_javascript_file,
    "firmware": _analyze_firmware,
    "class": _analyze_class,
    "pdf": _analyze_pdf,
    "gzip": _analyze_gzip,
    "sqlite": _analyze_sqlite,
    "text": _analyze_json_or_text,
    "unknown": _analyze_unknown,
}
