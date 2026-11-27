"""Validated, typed options for Ghidra's native raw binary importer."""

from __future__ import annotations


def normalize_raw_import(raw: bool = False, language_id: str | None = None,
                         image_base: str | None = None,
                         compiler_spec: str | None = None) -> dict:
    """Return canonical raw options, or an empty mapping for automatic import.

    Image bases accept unsigned decimal or explicitly prefixed hexadecimal.
    IDs are native Ghidra IDs, not command fragments; internal spaces are valid.
    """
    if type(raw) is not bool:
        raise ValueError("raw must be a boolean")
    if not raw:
        if any(value is not None for value in (language_id, image_base, compiler_spec)):
            raise ValueError("language_id, image_base and compiler_spec require raw=True")
        return {}
    for name, value in (("language_id", language_id), ("compiler_spec", compiler_spec)):
        if name == "compiler_spec" and value in (None, ""):
            continue
        if (not isinstance(value, str) or not value.strip() or value != value.strip()
                or value.startswith("-")
                or any(ord(char) < 32 or 127 <= ord(char) <= 159
                       or (char.isspace() and char != " ") for char in value)):
            raise ValueError(f"{name} must be a nonblank native ID without controls or leading options")
    if not isinstance(language_id, str):
        raise ValueError("language_id must be a full native language ID")
    parts = language_id.split(":")
    if (len(parts) != 4 or not all(part.strip() for part in parts)
            or not parts[2].isascii() or not parts[2].isdigit() or int(parts[2]) < 1):
        raise ValueError("language_id must be a full native processor:endian:bits:variant ID")
    if not isinstance(image_base, str) or not image_base:
        raise ValueError("raw import requires an unsigned image_base")
    hexadecimal = image_base.startswith(("0x", "0X"))
    digits = image_base[2:] if hexadecimal else image_base
    allowed = "0123456789abcdefABCDEF" if hexadecimal else "0123456789"
    if not digits or any(char not in allowed for char in digits):
        raise ValueError("image_base must be unsigned decimal or 0x-prefixed hexadecimal")
    base = int(digits, 16 if hexadecimal else 10)
    if base > 0xffffffffffffffff:
        raise ValueError("image_base must fit in an unsigned 64-bit address")
    return {"raw": True, "language_id": language_id,
            "image_base": hex(base), "compiler_spec": compiler_spec or ""}


def raw_import_arguments(options: dict) -> list:
    """Build native BinaryLoader arguments and the fixed mapping validator.

    Ghidra 12.1.2 support/analyzeHeadlessREADME.md, example 18 documents
    BinaryLoader and -loader-baseAddr; -processor and -cspec use native IDs.
    The trusted pre-analysis script validates native address width and mapping
    without changing memory or the program image base.
    """
    options = normalize_raw_import(**options)
    if not options:
        return []
    arguments = ["-loader", "BinaryLoader", "-processor", options["language_id"],
                 "-loader-baseAddr", options["image_base"]]
    if options["compiler_spec"]:
        arguments += ["-cspec", options["compiler_spec"]]
    arguments += ["-preScript", "GhydraRawImport.java", options["image_base"]]
    return arguments
