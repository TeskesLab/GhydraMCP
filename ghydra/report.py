"""The report: Ghidra and Kuna on one binary, in one document.

The report answers three questions at once, about a binary nobody has opened
yet:

* what is in it - the program, its functions, its imports, its strings, as
  Ghidra sees them;
* what does the code look like - the recovered C and the disassembly, as
  Kuna recovers them;
* where should a human start in the debugger - the annotations for x64dbg.

The two tools see the same binary at the same addresses, so they are put side
by side: the functions Ghidra found, the functions Kuna found, and what is
missing from each.

The Ghidra side needs an instance that serves the API. When there is none,
a headless run is started for the report and stopped at the end of it - the
analysis is saved, so the project holds it and the program can be opened in
Ghidra later.

Three files come out:

* ``<name>-report.md`` - the report a human reads;
* ``<name>-report.json`` - the same, machine-readable;
* ``<name>-x64dbg.json`` - the annotations, for the debugger.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import kuna
from .client import GhidraHTTPClient
from .client.exceptions import GhidraError
from .headless import HeadlessError, HeadlessRunner, api_answers, binary_name


def is_local_host(host: str) -> bool:
    """Whether the host is this machine.

    A headless run is started here, so it serves this machine and no other:
    a remote target has to be up already.
    """
    name = str(host or "").strip().lower()
    return name in ("", "localhost", "127.0.0.1", "::1", "0.0.0.0")


class ReportError(Exception):
    """A failure with a machine-readable code."""

    def __init__(self, message: str, code: str = "REPORT_ERROR") -> None:
        super().__init__(message)
        self.code = code


@dataclass
class ReportRequest:
    """What to report on, and how much of it."""

    binary: str
    output: Optional[str] = None
    port: int = 8192
    host: str = "127.0.0.1"
    ghidra_home: Optional[str] = None
    java_home: Optional[str] = None
    timeout: int = 900
    with_kuna: bool = True
    with_headless: bool = True
    keep: bool = False
    max_functions: int = 400
    max_strings: int = 300
    max_decompile: int = 12
    max_annotations: int = 60


# ---------------------------------------------------------------- Ghidra


def _result(response: Dict[str, Any]) -> Any:
    return response.get("result") if isinstance(response, dict) else None


def _meta(response: Dict[str, Any]) -> Dict[str, Any]:
    meta = response.get("meta") if isinstance(response, dict) else None
    return meta if isinstance(meta, dict) else {}


def collect_ghidra(client: GhidraHTTPClient, request: ReportRequest) -> Dict[str, Any]:
    """What Ghidra knows about the program.

    Every call is optional: an endpoint that fails does not take the report
    down with it, because a report that is missing a section is worth more
    than no report at all.
    """
    out: Dict[str, Any] = {"errors": []}

    def safe(name: str, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Any:
        try:
            return client.get(endpoint, params)
        except GhidraError as exc:
            out["errors"].append(f"{name}: {exc}")
            return None

    program = safe("program", "program")
    out["program"] = _result(program) if program else {}

    functions = safe("functions", "functions", {"limit": request.max_functions})
    out["functions"] = _result(functions) if functions else []
    out["function_total"] = _meta(functions).get("total", len(out["functions"]))

    strings = safe("strings", "strings", {"limit": request.max_strings})
    out["strings"] = _result(strings) if strings else []
    out["string_total"] = _meta(strings).get("total", len(out["strings"]))

    imports = safe("imports", "symbols/imports", {"limit": request.max_functions})
    out["imports"] = _result(imports) if imports else []

    exports = safe("exports", "symbols/exports", {"limit": request.max_functions})
    out["exports"] = _result(exports) if exports else []

    segments = safe("segments", "segments")
    out["segments"] = _result(segments) if segments else []

    return out


def decompile_top(client: GhidraHTTPClient, addresses: List[str],
                  limit: int) -> List[Dict[str, Any]]:
    """The decompilation of the functions that matter most.

    The order comes from the caller, because the size of a function is
    something only the other tool knows.
    """
    out: List[Dict[str, Any]] = []
    for address in addresses[:limit]:
        # The address goes with its "0x": Ghidra reads a plain number as
        # decimal, and a wrong address decompiles the wrong function.
        try:
            response = client.get(f"functions/0x{address}/decompile")
        except GhidraError:
            continue
        result = _result(response)
        if not isinstance(result, dict):
            continue
        code = result.get("decompilation") or ""
        if not code:
            continue
        out.append({
            "address": address,
            "name": result.get("functionName", ""),
            "code": str(code),
        })
    return out


# ------------------------------------------------------------------ Kuna


def collect_kuna(binary: str, request: ReportRequest) -> Dict[str, Any]:
    """What Kuna recovered: the export, its index and the C of the functions.

    The export is reused when it is already there: Kuna loads and analyses
    the whole image on every invocation, so a second export of the same
    binary is the most expensive no-op there is.
    """
    out: Dict[str, Any] = {"enabled": False, "errors": []}
    try:
        report = kuna.export(binary, config=kuna.config_section())
    except kuna.KunaError as exc:
        out["errors"].append(f"kuna: {exc}")
        return out

    directory = report.get("dir", "")
    out["enabled"] = True
    out["directory"] = directory
    out["functions"] = report.get("functions", 0)
    out["failed"] = report.get("failed", 0)
    out["reused"] = report.get("reused", False)

    records = kuna.index_records(directory) if directory else []
    out["index"] = records
    return out


def collect_kuna_code(kuna_data: Dict[str, Any], chosen: List[Dict[str, Any]],
                       limit: int) -> List[Dict[str, Any]]:
    """The C that Kuna recovered, for the functions that were chosen.

    The report puts the two decompilers side by side, so it needs what each
    of them says - not only what Ghidra says. The C is read out of the
    export on disk, the same way the index was.
    """
    directory = kuna_data.get("directory", "")
    if not directory or not kuna_data.get("enabled"):
        return []
    records = kuna_functions_by_address(kuna_data.get("index") or [])
    out: List[Dict[str, Any]] = []
    for item in chosen[:limit]:
        address = _hex(item.get("address"))
        record = records.get(address)
        if not record:
            continue
        try:
            code = kuna.extract_c(directory, record, 8192)
        except Exception:
            code = None
        if not code:
            continue
        out.append({
            "address": address,
            "name": record.get("name", ""),
            "code": str(code),
        })
    return out


def kuna_functions_by_address(records: List[dict]) -> Dict[str, dict]:
    """The Kuna index, keyed by the address it gives.

    The address is the one in the file, the same one Ghidra gives, so the two
    tools are put side by side without any conversion.
    """
    out: Dict[str, dict] = {}
    for record in records:
        address = str(record.get("addr") or "").lower()
        if address.startswith("0x"):
            address = address[2:]
        if address:
            out[address] = record
    return out


# ------------------------------------------------------------- the report


def _hex(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    try:
        return format(int(text, 16), "x")
    except (TypeError, ValueError):
        return text


def interesting_functions(ghidra: Dict[str, Any], kuna_data: Dict[str, Any],
                          limit: int) -> List[Dict[str, Any]]:
    """The functions worth a human's attention.

    Two groups: the ones Kuna found big, and the ones Ghidra found with a
    name of their own. A function that both tools found is more interesting
    than one that only one of them found.

    A stripped binary read without Kuna leaves both groups empty - every
    name is one Ghidra made up, and nothing was measured. A report with
    nothing in it is worse than one with the code in it, so there is a third
    group for that case: the functions that are really in the program, the
    ones that take arguments first.
    """
    by_address = kuna_functions_by_address(kuna_data.get("index") or [])
    functions = ghidra.get("functions") or []

    def address_of(function: Dict[str, Any]) -> str:
        return _hex(function.get("address"))

    scored: List[Dict[str, Any]] = []
    for function in functions:
        address = address_of(function)
        record = by_address.get(address)
        size = int(record.get("size") or 0) if record else 0
        name = str(function.get("name") or "")
        named = not name.startswith("FUN_") and not name.startswith("LAB_")
        scored.append({
            "address": address,
            "name": name,
            "signature": function.get("signature", ""),
            "comment": function.get("comment") or "",
            "kuna_name": record.get("name") if record else None,
            "kuna_size": size,
            "named": named,
            "external": bool(function.get("isExternal")),
            "thunk": bool(function.get("isThunk")),
            "parameters": int(function.get("parameterCount") or 0),
        })

    scored.sort(key=lambda item: (item["kuna_size"], item["named"]), reverse=True)

    chosen: List[Dict[str, Any]] = []
    seen = set()

    def take(item: Dict[str, Any]) -> None:
        if item["address"] in seen:
            return
        seen.add(item["address"])
        chosen.append(item)

    for item in scored:
        if item["kuna_size"] > 0:
            take(item)
        if len(chosen) >= limit:
            break
    for item in scored:
        if item["named"] and not item["external"]:
            take(item)
        if len(chosen) >= limit:
            break

    if not chosen:
        # Nothing ranked anything. The fallback is the code itself: the real
        # functions - not the thunks, not the ones outside the program - with
        # the ones that take arguments first, and the rest in the order they
        # come in the program.
        fallback = [item for item in scored
                    if not item["external"] and not item["thunk"]]
        fallback.sort(key=lambda item: (-item["parameters"], item["address"]))
        for item in fallback:
            take(item)
            if len(chosen) >= limit:
                break

    return chosen[:limit]


def build_annotations(binary: str, program: Dict[str, Any],
                      chosen: List[Dict[str, Any]]) -> Dict[str, Any]:
    """The annotations for x64dbg.

    The addresses are the ones in the file. The debugger works on the live
    process, where the module was loaded wherever the loader put it, so the
    conversion is left to the moment the annotations are applied - it needs
    the module base, and only the debugger knows it.
    """
    image_base = program.get("imageBase", "")
    annotations = []
    for item in chosen:
        comments = []
        if item.get("signature"):
            comments.append(str(item["signature"]))
        if item.get("kuna_size"):
            comments.append(f"{item['kuna_size']} bytes")
        if item.get("kuna_name") and item["kuna_name"] != item["name"]:
            comments.append(f"kuna: {item['kuna_name']}")
        if item.get("comment"):
            comments.append(str(item["comment"]))
        annotations.append({
            "address": item["address"],
            "name": item["name"],
            "comment": " - ".join(comments),
        })
    return {
        "binary": binary,
        "image_base": image_base,
        "note": ("The addresses are the ones in the file. The runtime address "
                 "is static - image_base + module_base."),
        "annotations": annotations,
    }


def _instance_binary(client: GhidraHTTPClient) -> str:
    """The binary the instance has open, as the instance reports it.

    An empty answer means the instance did not say, and the caller treats
    that as "no reason to refuse it".
    """
    try:
        response = client.get("/program")
    except GhidraError:
        return ""
    result = response.get("result") if isinstance(response, dict) else None
    if not isinstance(result, dict):
        return ""
    return str(result.get("path") or result.get("name") or "")


def _serves_binary(client: GhidraHTTPClient, binary: str) -> bool:
    """Whether the instance has the binary that was asked for.

    The report labels its files with the binary that was asked for and
    carries the addresses of the program the instance has - so an instance
    with another file open would produce a report that says one thing and
    shows another.
    """
    actual = _instance_binary(client)
    if not actual:
        return True
    wanted = binary_name(binary).lower()
    if not wanted:
        return True
    return binary_name(actual).lower() == wanted


def build_report(request: ReportRequest) -> Dict[str, Any]:
    """Collect everything and put it together."""
    binary = os.path.abspath(os.path.expanduser(request.binary))
    if not os.path.isfile(binary):
        raise ReportError(f"no such binary: {request.binary}", code="REPORT_NO_FILE")

    runner: Optional[HeadlessRunner] = None
    started = False

    if not api_answers(request.host, request.port):
        if not request.with_headless:
            raise ReportError(
                f"no Ghidra instance is serving on {request.host}:{request.port}",
                code="REPORT_NO_INSTANCE",
            )
        if not is_local_host(request.host):
            # A headless run is started here, on this machine, and it serves
            # this machine. A remote target has to be up already - starting
            # a run for it would wait for an answer that cannot come, and
            # leave the analyzer behind.
            raise ReportError(
                f"no Ghidra instance is serving on {request.host}:{request.port}, and "
                "a headless run only serves this machine. Start the instance there, "
                "or point the report at this machine.",
                code="REPORT_NO_INSTANCE",
            )
        try:
            runner = HeadlessRunner(
                binary=binary,
                port=request.port,
                ghidra_home=request.ghidra_home,
                java_home=request.java_home,
                host=request.host,
            )
            runner.start(timeout=request.timeout)
        except HeadlessError as exc:
            # The run that was started is not left behind: it would keep the
            # port and the project busy, with nothing serving on it.
            if runner is not None:
                runner.stop()
            raise ReportError(str(exc), code=exc.code) from None
        started = True
    else:
        # An instance is already serving. It has to be serving THIS binary.
        client = GhidraHTTPClient(host=request.host, port=request.port, timeout=request.timeout)
        if not _serves_binary(client, binary):
            raise ReportError(
                f"the instance on {request.host}:{request.port} has another binary "
                f"open, not {os.path.basename(binary)}",
                code="REPORT_WRONG_BINARY",
            )

    try:
        client = GhidraHTTPClient(host=request.host, port=request.port, timeout=request.timeout)
        ghidra = collect_ghidra(client, request)

        kuna_data: Dict[str, Any] = {"enabled": False, "errors": [], "index": []}
        if request.with_kuna:
            kuna_data = collect_kuna(binary, request)

        chosen = interesting_functions(ghidra, kuna_data, request.max_annotations)
        addresses = [item["address"] for item in chosen]
        decompiled = decompile_top(client, addresses, request.max_decompile)
        kuna_code = collect_kuna_code(kuna_data, chosen, request.max_decompile)

        report = {
            "generated_at": time.time(),
            "binary": binary,
            "ghidra": ghidra,
            "kuna": {key: value for key, value in kuna_data.items() if key != "index"},
            "functions": chosen,
            "decompiled": decompiled,
            "kuna_code": kuna_code,
            "annotations": build_annotations(binary, ghidra.get("program") or {}, chosen),
        }
        return report
    finally:
        if started and runner is not None and not request.keep:
            runner.stop()


# ------------------------------------------------------------- rendering


def _table(headers: List[str], rows: List[List[Any]]) -> str:
    if not rows:
        return "_nothing_\n"
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(str(cell)))
    out = ["| " + " | ".join(str(h).ljust(widths[i]) for i, h in enumerate(headers)) + " |"]
    out.append("|" + "|".join("-" * (widths[i] + 2) for i in range(len(headers))) + "|")
    for row in rows:
        out.append("| " + " | ".join(str(c).ljust(widths[i]) for i, c in enumerate(row)) + " |")
    return "\n".join(out) + "\n"


def _permissions(segment: Dict[str, Any]) -> str:
    """The access of a segment, the way it is written."""
    flags = ""
    if segment.get("isRead"):
        flags += "r"
    if segment.get("isWrite"):
        flags += "w"
    if segment.get("isExecute"):
        flags += "x"
    return flags or "-"


def render_markdown(report: Dict[str, Any]) -> str:
    """The report a human reads."""
    ghidra = report.get("ghidra", {})
    program = ghidra.get("program", {}) or {}
    kuna_data = report.get("kuna", {}) or {}
    chosen = report.get("functions", []) or []

    out: List[str] = []
    out.append(f"# {os.path.basename(report.get('binary', ''))} - analysis report\n")
    out.append(f"- Binary: `{report.get('binary', '')}`")
    out.append(f"- Generated: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(report.get('generated_at', 0)))}")
    if program.get("language"):
        out.append(f"- Language: {program.get('language')} ({program.get('compiler', '')})")
    if program.get("imageBase"):
        out.append(f"- Image base: `{program.get('imageBase')}`")
    if program.get("path"):
        out.append(f"- Path in the program: `{program.get('path')}`")
    out.append("")

    statistics = program.get("statistics", {}) or {}
    out.append("## What Ghidra found\n")
    out.append(_table(
        ["What", "How many"],
        [
            ["Functions", statistics.get("functionCount", ghidra.get("function_total", 0))],
            ["Symbols", statistics.get("symbolCount", "-")],
            ["Memory blocks", statistics.get("memoryBlockCount", "-")],
            ["Strings", ghidra.get("string_total", 0)],
            ["Imports", len(ghidra.get("imports") or [])],
            ["Exports", len(ghidra.get("exports") or [])],
        ],
    ))

    if ghidra.get("errors"):
        out.append("### What could not be read\n")
        for error in ghidra["errors"]:
            out.append(f"- {error}")
        out.append("")

    segments = ghidra.get("segments") or []
    if segments:
        out.append("## Segments\n")
        rows = []
        for segment in segments:
            rows.append([
                segment.get("name", ""),
                segment.get("start", segment.get("address", "")),
                segment.get("size", ""),
                _permissions(segment),
            ])
        out.append(_table(["Name", "Start", "Size", "Access"], rows))

    imports = ghidra.get("imports") or []
    if imports:
        out.append("## Imports\n")
        rows = []
        for entry in imports[:60]:
            if isinstance(entry, dict):
                rows.append([entry.get("name", ""), entry.get("address", ""),
                             entry.get("library", entry.get("namespace", ""))])
            else:
                rows.append([str(entry), "", ""])
        out.append(_table(["Name", "Address", "Library"], rows))
        if len(imports) > 60:
            out.append(f"\n_and {len(imports) - 60} more_\n")

    out.append("## What Kuna found\n")
    if kuna_data.get("enabled"):
        out.append(_table(
            ["What", "How many"],
            [
                ["Functions recovered", kuna_data.get("functions", 0)],
                ["Failed", kuna_data.get("failed", 0)],
                ["Export reused", "yes" if kuna_data.get("reused") else "no"],
                ["Directory", kuna_data.get("directory", "")],
            ],
        ))
    else:
        out.append("_Kuna was not run._\n")
        for error in (kuna_data.get("errors") or []):
            out.append(f"- {error}")
        out.append("")

    out.append("## The functions worth a look\n")
    rows = []
    for item in chosen[:60]:
        rows.append([
            item.get("address", ""),
            item.get("name", ""),
            item.get("kuna_size", ""),
            (item.get("signature") or "")[:70],
        ])
    out.append(_table(["Address", "Name", "Bytes", "Signature"], rows))

    strings = ghidra.get("strings") or []
    if strings:
        out.append("## Strings\n")
        rows = []
        for entry in strings[:40]:
            if isinstance(entry, dict):
                rows.append([entry.get("address", ""), (entry.get("value", "") or "")[:80]])
            else:
                rows.append(["", str(entry)[:80]])
        out.append(_table(["Address", "Value"], rows))
        if len(strings) > 40:
            out.append(f"\n_and {len(strings) - 40} more in the JSON report_\n")

    decompiled = report.get("decompiled") or []
    kuna_code = report.get("kuna_code") or []
    if decompiled or kuna_code:
        out.append("## Decompilation\n")
        by_address = {item["address"]: item for item in chosen}
        ghidra_by_address = {item["address"]: item for item in decompiled}
        kuna_by_address = {item["address"]: item for item in kuna_code}
        addresses: List[str] = []
        for item in decompiled:
            if item["address"] not in addresses:
                addresses.append(item["address"])
        for item in kuna_code:
            if item["address"] not in addresses:
                addresses.append(item["address"])
        for address in addresses:
            name = by_address.get(address, {}).get("name", address)
            out.append(f"### {name} (`{address}`)\n")
            ghidra_item = ghidra_by_address.get(address)
            if ghidra_item:
                out.append("_Ghidra_\n")
                out.append("```c")
                out.append(ghidra_item["code"].rstrip())
                out.append("```\n")
            kuna_item = kuna_by_address.get(address)
            if kuna_item:
                out.append("_Kuna_\n")
                out.append("```c")
                out.append(kuna_item["code"].rstrip())
                out.append("```\n")

    annotations = (report.get("annotations") or {}).get("annotations") or []
    if annotations:
        out.append("## For the debugger\n")
        out.append(f"{len(annotations)} annotations are ready for x64dbg, in the "
                   f"`<name>-x64dbg.json` file next to this one. The addresses "
                   f"are the ones in the file; the debugger adds the module base.\n")

    return "\n".join(out)


def write_report(report: Dict[str, Any], output: Optional[str] = None) -> Dict[str, str]:
    """Write the three files and say where they are."""
    binary = report.get("binary", "")
    stem = os.path.splitext(os.path.basename(binary))[0] or "binary"
    directory = os.path.abspath(os.path.expanduser(output)) if output else os.getcwd()
    os.makedirs(directory, exist_ok=True)

    paths = {
        "markdown": os.path.join(directory, f"{stem}-report.md"),
        "json": os.path.join(directory, f"{stem}-report.json"),
        "annotations": os.path.join(directory, f"{stem}-x64dbg.json"),
    }

    with open(paths["markdown"], "w", encoding="utf-8") as handle:
        handle.write(render_markdown(report))
    with open(paths["json"], "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
    with open(paths["annotations"], "w", encoding="utf-8") as handle:
        json.dump(report.get("annotations", {}), handle, indent=2, ensure_ascii=False)

    return paths
