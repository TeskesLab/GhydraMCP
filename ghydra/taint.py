"""Source-to-sink hypotheses from the pcode the API already provides (R5).

`analysis_taint(source, sink)` answers a *question*, not a verdict: does data
that enters through `source` (a `recv`, a `ReadFile`) plausibly reach `sink`
(a `system`, a `WinExec`)? It composes what the plugin already returns - the
references to a name, the pcode of a function, the call graph - and reports
candidate paths **with their evidence and a confidence**, never "this binary is
vulnerable".

Three rules keep it honest:

* **A hypothesis needs an order.** Two calls in the same function only form a
  flow when the sink runs *after* the source; a `system` above the `recv` is
  not fed by it. Branches are not modelled, so this is a linear reading of the
  function and the answer says so.
* **Evidence is an address, not a sentence.** Every path carries the source
  call site, the sink call site and the hops between them, so a human (or an
  agent) can open them.
* **Absence is not safety.** "No path found" says how many functions were
  examined and why the search stopped; it never reads as "clean".

The false-positive rate of this approach is the reason the roadmap marks it
`experimental`: it is a lead generator.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .core import taint as core_taint

#: All of these are defined once, in the core (I1).
PROGRAM_FIELDS = core_taint.PROGRAM_FIELDS
PAGE_LIMIT = core_taint.PAGE_LIMIT
MAX_PAGES = core_taint.MAX_PAGES
CALL_OPCODES = core_taint.CALL_OPCODES
CONFIDENCE_DIRECT = core_taint.CONFIDENCE_DIRECT
CONFIDENCE_REACHABLE = core_taint.CONFIDENCE_REACHABLE
DISCLAIMER = core_taint.DISCLAIMER


def _get(client, endpoint: str, params: dict | None = None) -> Any:
    try:
        return client.get(endpoint, params=params)
    except Exception:
        return {"success": False, "error": {"code": "TAINT_READ_FAILED"}}


def _result(envelope: Any) -> Any:
    """Delegates to the core (I1)."""
    return core_taint.result_of(envelope)


def _quote(value: str) -> str:
    from urllib.parse import quote
    return quote(value, safe="")


def resolve_name(client, name: str) -> Dict[str, Any]:
    """The addresses a name is known by, and the functions that reference it.

    Uses the same two endpoints a human would: the function table for the name
    itself, and the xrefs to it for the call sites.
    """
    addresses: List[str] = []
    references: List[Dict[str, Any]] = []

    function = _result(_get(client, f"functions/by-name/{_quote(name)}"))
    if isinstance(function, dict) and function.get("address"):
        addresses.append(str(function["address"]))

    xrefs = _result(_get(client, f"xrefs/to-name/{_quote(name)}",
                         {"limit": PAGE_LIMIT}))
    if isinstance(xrefs, list):
        for item in xrefs:
            if not isinstance(item, dict):
                continue
            reference = {
                "from_address": item.get("from_address") or item.get("fromAddress"),
                "to_address": item.get("to_address") or item.get("toAddress"),
                "type": item.get("type") or item.get("ref_type"),
                "function": item.get("function") or item.get("from_function"),
            }
            references.append(reference)
            if reference["to_address"]:
                addresses.append(str(reference["to_address"]))

    return {"name": name, "addresses": list(dict.fromkeys(addresses)),
            "references": references}


def calls_in_function(client, function_address: str) -> List[Dict[str, Any]]:
    """Every CALL pcode operation of a function, with its target when known."""
    payload = _result(_get(client, f"functions/{function_address}/pcode"))
    if not isinstance(payload, dict):
        return []
    operations = payload.get("operations")
    if not isinstance(operations, list):
        return []
    calls = []
    for op in operations:
        if not isinstance(op, dict):
            continue
        opcode = op.get("opcode")
        if opcode not in CALL_OPCODES:
            continue
        inputs = op.get("inputs") or []
        calls.append({
            "at": str(op.get("address") or ""),
            "target": str(inputs[0]) if inputs else "",
            "inputs": [str(value) for value in inputs],
        })
    return calls


def _site_for(calls: List[Dict[str, Any]], wanted: str,
              wanted_name: str) -> Optional[str]:
    """Delegates to the core (I1)."""
    return core_taint.site_for(calls, wanted, wanted_name)


def _function_of(client, address: str) -> Dict[str, Any]:
    payload = _result(_get(client, f"functions/containing/{_quote(address)}"))
    if isinstance(payload, dict):
        return payload
    return {}


def _call_path(client, source_function: str, sink_function: str,
               max_depth: int = 8) -> Dict[str, Any]:
    payload = _result(_get(client, "analysis/call-path",
                           {"from": source_function, "to": sink_function,
                            "max_depth": max_depth}))
    return payload if isinstance(payload, dict) else {}


def _address_key(address: str) -> tuple:
    """Delegates to the core (I1)."""
    return core_taint.address_key(address)


def find_hypotheses(client, source: str, sink: str,
                    max_depth: int = 8) -> Dict[str, Any]:
    """Compose every endpoint this needs into source-to-sink hypotheses."""
    source_info = resolve_name(client, source)
    sink_info = resolve_name(client, sink)

    examined: List[str] = []
    hypotheses: List[Dict[str, Any]] = []
    source_functions = _functions_referencing(client, source_info, examined)
    sink_functions = _functions_referencing(client, sink_info, examined)

    # ---- the same function calls both ------------------------------------
    for function_address in sorted(set(source_functions) & set(sink_functions)):
        calls = calls_in_function(client, function_address)
        source_at = _site_for(calls, (source_info["addresses"] or [""])[0], source)
        sink_at = _site_for(calls, (sink_info["addresses"] or [""])[0], sink)
        if not source_at or not sink_at:
            continue
        # A sink that runs before the source cannot be fed by it.
        if _address_key(sink_at) <= _address_key(source_at):
            hypotheses.append({
                "confidence": "weak",
                "reason": "the sink call precedes the source call in this function",
                "source_call": source_at, "sink_call": sink_at,
                "hops": [function_address],
            })
            continue
        hypotheses.append({
            "confidence": CONFIDENCE_DIRECT,
            "reason": "source and sink are called in the same function, sink after source",
            "source_call": source_at, "sink_call": sink_at,
            "hops": [function_address],
        })

    # ---- the source function reaches the sink function -------------------
    for source_function in sorted(set(source_functions) - set(sink_functions)):
        for sink_function in sorted(sink_functions):
            path = _call_path(client, source_function, sink_function, max_depth)
            hops = path.get("path") or []
            if not hops:
                continue
            if path.get("truncated"):
                hypotheses.append({
                    "confidence": "weak",
                    "reason": "the call-path search hit its cap; a path was not proven",
                    "source_call": None, "sink_call": None,
                    "hops": [str(hop) for hop in hops],
                })
                continue
            hypotheses.append({
                "confidence": CONFIDENCE_REACHABLE,
                "reason": f"a call path connects the source's function to the sink's "
                          f"({len(hops)} hop(s))",
                "source_call": None, "sink_call": None,
                "hops": [str(hop) for hop in hops],
            })

    return {
        "source": {"name": source, "addresses": source_info["addresses"],
                   "sites": len(source_info["references"])},
        "sink": {"name": sink, "addresses": sink_info["addresses"],
                 "sites": len(sink_info["references"])},
        "hypotheses": hypotheses,
        "functions_examined": len(set(examined)),
        "max_depth": max_depth,
        "disclaimer": DISCLAIMER,
    }


def _functions_referencing(client, info: Dict[str, Any],
                           examined: List[str]) -> Dict[str, str]:
    """The function each call site belongs to, keyed by address."""
    found: Dict[str, str] = {}
    for reference in info.get("references") or []:
        address = reference.get("from_address")
        if not address:
            continue
        function = reference.get("function")
        if isinstance(function, dict):
            function_address = (function.get("address")
                                or function.get("entry"))
        else:
            function_address = function
        if not function_address:
            containing = _function_of(client, str(address))
            function_address = containing.get("address") or containing.get("entry")
        if function_address:
            found[str(function_address)] = info["name"]
    for address in info.get("addresses") or []:
        if not address:
            continue
        if str(address) in found:
            continue
        containing = _function_of(client, str(address))
        function_address = containing.get("address") or containing.get("entry")
        if function_address:
            found[str(function_address)] = info["name"]
    examined.extend(found.keys())
    return found


def summarize(report: Dict[str, Any]) -> Dict[str, Any]:
    """Delegates to the core (I1): one count, two surfaces."""
    return core_taint.summarize(report)


def to_text(report: Dict[str, Any]) -> str:
    """A text rendering shared by the CLI and the bridge."""
    if not isinstance(report, dict):
        return str(report)
    source = report.get("source") or {}
    sink = report.get("sink") or {}
    counts = summarize(report)
    lines = [f"Taint hypotheses: {source.get('name', '?')} -> {sink.get('name', '?')}",
             f"  source sites: {source.get('sites', 0)}  "
             f"sink sites: {sink.get('sites', 0)}  "
             f"functions examined: {report.get('functions_examined', 0)}"]
    if not counts["found"]:
        lines.append("  no source-to-sink path was found — this is not proof of "
                     "safety (the search is linear and bounded)")
    for item in (report.get("hypotheses") or [])[:20]:
        lines.append(f"  [{item.get('confidence')}] {item.get('reason')}")
        if item.get("source_call"):
            lines.append(f"      source call at {item['source_call']}")
        if item.get("sink_call"):
            lines.append(f"      sink call at {item['sink_call']}")
        hops = item.get("hops") or []
        if hops:
            lines.append("      hops: " + " -> ".join(str(hop) for hop in hops))
    if report.get("disclaimer"):
        lines.append("")
        lines.append(report["disclaimer"])
    return "\n".join(lines)