"""Identity-bound, non-mutating BSim comparison of native snapshot DTOs.

The direction is always current target -> inspected reference.  Type identifiers
are snapshot-local: equality follows their graphs, not their spelling.  Missing
evidence is unknown, never equality, and every preview is merely a proposal.
"""
from __future__ import annotations

from copy import deepcopy
from difflib import unified_diff
import re
import json
from typing import Any, Dict, List, NoReturn, Tuple


class BSimComparisonError(ValueError):
    """A malformed comparison or a broken selected-match identity binding."""

    def __init__(self, message: str, code: str = "BSIM_COMPARISON_INVALID"):
        super().__init__(message)
        self.code = code


def _bsim_identity_error() -> NoReturn:
    raise BSimComparisonError("Selected BSim match identity does not match the snapshots",
                              "BSIM_IDENTITY_MISMATCH")


def _bsim_address(value: Any) -> Tuple[str, int]:
    if not isinstance(value, str):
        _bsim_identity_error()
    match = re.fullmatch(r"(?:(.+)::)?(?:0[xX])?([0-9a-fA-F]+)", value)
    if not match:
        _bsim_identity_error()
    return match.group(1) or "", int(match.group(2), 16)


def _bsim_same_address(first: Any, second: Any) -> bool:
    space_a, offset_a = _bsim_address(first)
    space_b, offset_b = _bsim_address(second)
    return offset_a == offset_b and (not space_a or not space_b or space_a == space_b)


def _bsim_md5(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{32}", value):
        _bsim_identity_error()
    return value.lower()


def _bsim_status(complete: bool, different: bool) -> Dict[str, Any]:
    return {"complete": complete, "status": ("incomplete" if not complete else
            "different" if different else "equal"),
            "equal": not different if complete else None,
            "observed_differences": different}


def _bsim_change(field: str, before: Any, after: Any) -> Dict[str, Any]:
    return {"field": field, "before": deepcopy(before), "after": deepcopy(after)}


def _bsim_value_changes(before: Any, after: Any, path: str) -> List[Dict[str, Any]]:
    if isinstance(before, dict) and isinstance(after, dict):
        changes = []
        for key in sorted(set(before) | set(after)):
            child = path + "." + str(key)
            if key not in before or key not in after:
                change = _bsim_change(child, before.get(key), after.get(key))
                change["kind"] = "added" if key not in before else "removed"
                changes.append(change)
            else:
                changes.extend(_bsim_value_changes(before[key], after[key], child))
        return changes
    if isinstance(before, list) and isinstance(after, list):
        changes = []
        for index in range(max(len(before), len(after))):
            child = f"{path}[{index}]"
            if index >= len(before) or index >= len(after):
                change = _bsim_change(child, before[index] if index < len(before) else None,
                                      after[index] if index < len(after) else None)
                change["kind"] = "added" if index >= len(before) else "removed"
                changes.append(change)
            else:
                changes.extend(_bsim_value_changes(before[index], after[index], child))
        return changes
    if before != after or type(before) is not type(after):
        return [dict(_bsim_change(path, before, after), kind="changed")]
    return []


def _bsim_type_parts(descriptor: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Separate type edges from attributes without exposing local IDs as changes."""
    shape = deepcopy(descriptor)
    edges = {}
    kind = descriptor.get("kind")
    if not isinstance(kind, str):
        kind = ""
    for field in ({"pointer": ("target",), "array": ("element",),
                   "typedef": ("base",), "bitfield": ("base",),
                   "function_definition": ("return_type",)}
                  .get(kind, ())):
        edges[field] = shape.pop(field, None)
    collection = ("components" if kind in ("struct", "union") else
                  "parameters" if kind == "function_definition" else None)
    if collection and isinstance(shape.get(collection), list):
        for index, item in enumerate(shape[collection]):
            if isinstance(item, dict):
                edges[f"{collection}[{index}].type"] = item.pop("type", None)
    return shape, edges


def _bsim_type_label(types: Dict[str, Any], type_id: Any) -> Any:
    descriptor = types.get(type_id) if isinstance(type_id, str) else None
    if not isinstance(descriptor, dict):
        return None
    return {field: deepcopy(descriptor.get(field)) for field in ("kind", "name", "path", "length")}


def _bsim_type_evidence(types: Dict[str, Any], type_id: Any) -> Any:
    if _bsim_type_label(types, type_id) is None:
        return None
    reachable, pending = {}, [type_id]
    while pending and len(reachable) < 256:
        current = pending.pop()
        if not isinstance(current, str) or current in reachable:
            continue
        descriptor = types.get(current)
        if isinstance(descriptor, dict):
            reachable[current] = deepcopy(descriptor)
            pending.extend(_bsim_type_parts(descriptor)[1].values())
    return {"root": type_id, "types": reachable}


def _bsim_type_roots(function: Dict[str, Any]) -> Dict[str, Any]:
    roots = {}
    if "return_type" in function:
        roots["return_type"] = function["return_type"]
    parameters = function.get("parameters")
    if isinstance(parameters, list):
        for index, parameter in enumerate(parameters):
            if isinstance(parameter, dict) and "type" in parameter:
                roots[f"parameters[{index}].type"] = parameter["type"]
    return roots


def _bsim_type_inventory(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    types = snapshot.get("types")
    types = types if isinstance(types, dict) else {}
    missing, cycles, visited, active = [], [], set(), {}

    def visit(type_id: Any, path: str, depth: int) -> None:
        if not isinstance(type_id, str) or not isinstance(types.get(type_id), dict):
            missing.append({"field": path, "reason": "missing_type"})
            return
        if type_id in active:
            cycles.append({"field": path, "type_id": type_id, "ancestor": active[type_id]})
            return
        if type_id in visited:
            return
        if len(visited) >= 256 or depth > 16:
            missing.append({"field": path, "reason": "type_graph_limit"})
            return
        visited.add(type_id)
        descriptor = types[type_id]
        if any(field not in descriptor for field in ("kind", "name", "path", "length")):
            missing.append({"field": path, "reason": "incomplete_type_descriptor"})
        kind = descriptor.get("kind")
        required = {"array": ("count",), "enum": ("values",),
                    "struct": ("components",), "union": ("components",),
                    "bitfield": ("bit_offset", "bit_size"),
                    "function_definition": ("parameters", "varargs", "calling_convention")}
        if any(field not in descriptor for field in required.get(kind, ())):
            missing.append({"field": path, "reason": "incomplete_type_descriptor"})
        collection = "components" if kind in ("struct", "union") else "parameters"
        if kind in ("struct", "union", "function_definition"):
            members = descriptor.get(collection)
            fields = (("name", "offset", "length", "type", "bitfield")
                      if collection == "components" else ("ordinal", "name", "type"))
            if not isinstance(members, list) or any(
                    not isinstance(member, dict) or any(key not in member for key in fields)
                    for member in members):
                missing.append({"field": path, "reason": "incomplete_type_members"})
        active[type_id] = path
        for field, child in _bsim_type_parts(descriptor)[1].items():
            visit(child, path + "." + field, depth + 1)
        del active[type_id]

    function = snapshot["function"]
    if "return_type" not in function:
        missing.append({"field": "return_type", "reason": "missing_type_root"})
    parameters = function.get("parameters")
    if not isinstance(parameters, list):
        missing.append({"field": "parameters", "reason": "missing_type_roots"})
    else:
        for index, parameter in enumerate(parameters):
            if not isinstance(parameter, dict) or "type" not in parameter:
                missing.append({"field": f"parameters[{index}].type", "reason": "missing_type_root"})
    for field, type_id in _bsim_type_roots(function).items():
        visit(type_id, field, 0)
    return {"complete": snapshot.get("types_complete") is True and not missing,
            "missing": missing, "cycles": cycles, "reachable_count": len(visited),
            "reachable_ids": sorted(visited)}


def _bsim_compare_type(types_a: Dict[str, Any], types_b: Dict[str, Any],
                       id_a: Any, id_b: Any, path: str) -> List[Dict[str, Any]]:
    active, seen = set(), set()

    def compare(a: Any, b: Any, field: str, depth: int) -> List[Dict[str, Any]]:
        if not isinstance(a, str) or not isinstance(b, str):
            return []  # Unavailable evidence is recorded by the inventory, not a deletion.
        pair = (a, b)
        if pair in active or pair in seen or depth > 16 or len(seen) >= 65536:
            return []
        first, second = types_a.get(a), types_b.get(b)
        if not isinstance(first, dict) or not isinstance(second, dict):
            return []
        if any(key not in node for node in (first, second)
               for key in ("kind", "name", "path", "length")):
            return []
        active.add(pair)
        seen.add(pair)
        shape_a, edges_a = _bsim_type_parts(first)
        shape_b, edges_b = _bsim_type_parts(second)
        changes = _bsim_value_changes(shape_a, shape_b, field)
        for edge in sorted(set(edges_a) | set(edges_b)):
            child = field + "." + edge
            if edge in edges_a and edge in edges_b:
                changes.extend(compare(edges_a[edge], edges_b[edge], child, depth + 1))
            elif edge in edges_b and _bsim_type_label(types_b, edges_b[edge]) is not None:
                changes.append(dict(_bsim_change(child, None, _bsim_type_label(types_b, edges_b[edge])),
                                    kind="added"))
            elif edge in edges_a and _bsim_type_label(types_a, edges_a[edge]) is not None:
                changes.append(dict(_bsim_change(child, _bsim_type_label(types_a, edges_a[edge]), None),
                                    kind="removed"))
        active.remove(pair)
        return changes

    return compare(id_a, id_b, path, 0)


def _bsim_code(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    code = snapshot.get("code")
    if not isinstance(code, dict):
        return {"text": None, "complete": False, "reason": "missing_code"}
    text = code.get("text")
    available = isinstance(text, str) and bool(text.strip())
    complete = available and code.get("complete") is True and code.get("error") is None
    return {"text": text if isinstance(text, str) else None, "complete": complete,
            "reason": None if complete else "code_unavailable" if not available else
            "decompilation_error" if code.get("error") is not None else "truncated_code"}


def _bsim_unified_diff(before: str, after: str) -> str:
    lines = unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                         fromfile="target.c", tofile="reference.c")
    return "".join(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n"
                   for line in lines)


def compare_match(selection: object, target: object,
                  reference: object) -> Dict[str, Any]:
    """Compare selected native evidence; never read, apply, import, or mutate it.

    Raises BSimComparisonError with code BSIM_COMPARISON_INVALID for malformed
    envelopes, or BSIM_IDENTITY_MISMATCH for any broken identity/stamp binding.
    A successful identity check does not imply complete or interchangeable code.
    """
    if not isinstance(selection, dict) or not isinstance(target, dict) or not isinstance(reference, dict):
        raise BSimComparisonError("Comparison requires selection and snapshot objects")
    selected = selection.get("match")
    binding = selection.get("target")
    inspected = reference.get("snapshot")
    if not isinstance(selected, dict) or not isinstance(binding, dict) or not isinstance(inspected, dict):
        raise BSimComparisonError("Comparison requires selected match and reference snapshot")
    if not all(isinstance(snapshot.get(field), dict) for snapshot in (target, inspected)
               for field in ("program", "function")):
        raise BSimComparisonError("Comparison requires program and function identities")
    match_id = selection.get("match_id")
    if (not isinstance(match_id, str) or not match_id or reference.get("match_id") != match_id
            or selected.get("match_id") != match_id
            or reference.get("identity_verified") is not True):
        _bsim_identity_error()
    if (_bsim_md5(selected.get("executable_md5")) != _bsim_md5(inspected["program"].get("md5"))
            or _bsim_md5(binding.get("md5")) != _bsim_md5(target["program"].get("md5"))
            or not _bsim_same_address(binding.get("address"), target["function"].get("address"))
            or not _bsim_same_address(selected.get("address", selected.get("function_address")),
                                      inspected["function"].get("address"))
            or not isinstance(binding.get("modification"), int)
            or isinstance(binding.get("modification"), bool)
            or type(target.get("modification")) is not int
            or binding["modification"] != target["modification"]):
        _bsim_identity_error()

    warnings = []
    for field, message in (("language", "Architecture/language differs between target and reference"),
                           ("compiler", "Compiler differs between target and reference"),
                           ("pointer_size", "Pointer size differs between target and reference")):
        before, after = target["program"].get(field), inspected["program"].get(field)
        if before is None or after is None:
            warnings.append(f"Cannot compare program {field}: metadata unavailable")
        elif before != after:
            warnings.append(message)
    indexed_name = selected.get("function", selected.get("function_name", selected.get("name")))
    if isinstance(indexed_name, str) and indexed_name != inspected["function"].get("name"):
        warnings.append("Indexed match name differs from the current reference function name")

    code_a, code_b = _bsim_code(target), _bsim_code(inspected)
    code_complete = code_a["complete"] and code_b["complete"]
    code_different = (code_a["text"] is not None and code_b["text"] is not None
                      and code_a["text"] != code_b["text"])
    code = dict(_bsim_status(code_complete, code_different), kind="textual_unified_c",
                source_complete=code_a["complete"], reference_complete=code_b["complete"],
                unified_diff=(_bsim_unified_diff(code_a["text"], code_b["text"])
                              if code_a["text"] is not None and code_b["text"] is not None else None))

    function_a, function_b = target["function"], inspected["function"]
    types_a = target.get("types")
    if not isinstance(types_a, dict):
        types_a = {}
    types_b = inspected.get("types")
    if not isinstance(types_b, dict):
        types_b = {}
    inventory_a, inventory_b = _bsim_type_inventory(target), _bsim_type_inventory(inspected)
    signature_changes, type_differences, conflicts = [], [], []
    missing_signature = {"source": [], "reference": []}
    required = ("name", "prototype", "calling_convention", "varargs", "return_type", "parameters", "comment")
    for side, function in (("source", function_a), ("reference", function_b)):
        missing_signature[side].extend(field for field in required if field not in function)
        if not isinstance(function.get("name"), str):
            missing_signature[side].append("name")
        parameters = function.get("parameters")
        if not isinstance(parameters, list):
            missing_signature[side].append("parameters")
        else:
            for index, parameter in enumerate(parameters):
                for field in ("ordinal", "name", "type"):
                    if not isinstance(parameter, dict) or field not in parameter:
                        missing_signature[side].append(f"parameters[{index}].{field}")

    def add_signature(field: str, before: Any, after: Any) -> None:
        if before != after:
            signature_changes.append(_bsim_change(field, before, after))

    for field in ("prototype", "calling_convention", "varargs", "comment"):
        if field in function_a and field in function_b:
            add_signature(field, function_a[field], function_b[field])
    if isinstance(function_a.get("name"), str) and isinstance(function_b.get("name"), str):
        for field, index in (("namespace", 0), ("name", 2)):
            first, second = function_a["name"].rpartition("::"), function_b["name"].rpartition("::")
            add_signature(field, first[index], second[index])

    roots_a, roots_b = _bsim_type_roots(function_a), _bsim_type_roots(function_b)
    for field in sorted(set(roots_a) | set(roots_b)):
        if field in roots_a and field in roots_b:
            changes = _bsim_compare_type(types_a, types_b, roots_a[field], roots_b[field], field)
            type_differences.extend(changes)
            if changes:
                signature_changes.append(_bsim_change(
                    field, _bsim_type_evidence(types_a, roots_a[field]),
                    _bsim_type_evidence(types_b, roots_b[field])))
        elif (field.startswith("parameters[") and field in roots_b
              and isinstance(function_a.get("parameters"), list)
              and int(field.split("[", 1)[1].split("]", 1)[0]) >= len(function_a["parameters"])):
            label = _bsim_type_label(types_b, roots_b[field])
            if label is not None:
                type_differences.append(dict(_bsim_change(field, None, label), kind="added"))
        elif (field.startswith("parameters[") and field in roots_a
              and isinstance(function_b.get("parameters"), list)
              and int(field.split("[", 1)[1].split("]", 1)[0]) >= len(function_b["parameters"])):
            label = _bsim_type_label(types_a, roots_a[field])
            if label is not None:
                type_differences.append(dict(_bsim_change(field, label, None), kind="removed"))

    # Same repository type path, incompatible description: report a conflict even
    # when its use moved to another parameter.  Never resolve it automatically.
    by_path_a, by_path_b = {}, {}
    for types, by_path, inventory in ((types_a, by_path_a, inventory_a),
                                      (types_b, by_path_b, inventory_b)):
        for type_id in inventory["reachable_ids"]:
            descriptor = types[type_id]
            if isinstance(descriptor, dict) and isinstance(descriptor.get("path"), str):
                by_path.setdefault(descriptor["path"], []).append(type_id)
    for path in sorted(set(by_path_a) & set(by_path_b)):
        for id_a in sorted(by_path_a[path]):
            for id_b in sorted(by_path_b[path]):
                changes = _bsim_compare_type(types_a, types_b, id_a, id_b, "type")
                if changes:
                    conflicts.append({"path": path, "source_id": id_a, "reference_id": id_b,
                                      "differences": changes})

    parameters_a, parameters_b = function_a.get("parameters"), function_b.get("parameters")
    if isinstance(parameters_a, list) and isinstance(parameters_b, list):
        add_signature("parameter_count", len(parameters_a), len(parameters_b))
        names_a = [name for parameter in parameters_a if isinstance(parameter, dict)
                   and isinstance(name := parameter.get("name"), str)]
        names_b = [name for parameter in parameters_b if isinstance(parameter, dict)
                   and isinstance(name := parameter.get("name"), str)]
        if (len(names_a) == len(parameters_a) == len(names_b) == len(parameters_b)
                and len(set(names_a)) == len(names_a) and sorted(names_a) == sorted(names_b)):
            add_signature("parameter_order", names_a, names_b)
        for index in range(max(len(parameters_a), len(parameters_b))):
            first = parameters_a[index] if index < len(parameters_a) else None
            second = parameters_b[index] if index < len(parameters_b) else None
            if index >= len(parameters_a) or index >= len(parameters_b):
                # A parameter proposal includes the type's description, not a
                # meaningless reference-worker-local datatype identifier.
                def describe(parameter: Any, types: Dict[str, Any]) -> Any:
                    if not isinstance(parameter, dict):
                        return None
                    return dict(deepcopy(parameter), type=_bsim_type_evidence(types, parameter.get("type")))
                signature_changes.append(_bsim_change(f"parameters[{index}]",
                                                      describe(first, types_a), describe(second, types_b)))
            elif isinstance(first, dict) and isinstance(second, dict):
                for field in ("ordinal", "name"):
                    if field in first and field in second:
                        add_signature(f"parameters[{index}].{field}", first[field], second[field])

    types_complete = inventory_a["complete"] and inventory_b["complete"]
    signature_complete = types_complete and not any(missing_signature.values())
    signature = dict(_bsim_status(signature_complete, bool(signature_changes)), changes=signature_changes)
    type_comparison = dict(_bsim_status(types_complete, bool(type_differences or conflicts)),
                           differences=type_differences, conflicts=conflicts,
                           cycles={"source": inventory_a["cycles"], "reference": inventory_b["cycles"]})
    evidence = {"source": {"code": {key: value for key, value in code_a.items() if key != "text"},
                            "types": inventory_a, "missing_signature": sorted(set(missing_signature["source"]))},
                "reference": {"code": {key: value for key, value in code_b.items() if key != "text"},
                               "types": inventory_b, "missing_signature": sorted(set(missing_signature["reference"]))}}
    complete = code_complete and signature_complete and types_complete
    if not complete:
        warnings.append("Comparison evidence is incomplete; absence of differences is not equality")
    warnings.append("Preview only: no changes were applied; textual C diff is not native CodeDiffPlugin analysis")
    preview = [dict(change, kind="signature", complete=signature_complete) for change in signature_changes]
    preview.extend(dict(change, kind="type", change_kind=change["kind"], complete=types_complete)
                   for change in type_differences)

    def identity(snapshot: Dict[str, Any]) -> Dict[str, Any]:
        return {"program": deepcopy(snapshot["program"]),
                "function": {key: deepcopy(snapshot["function"].get(key)) for key in ("name", "address")},
                "modification": snapshot.get("modification")}

    reference_identity = identity(inspected)
    reference_identity.update({key: deepcopy(reference.get(key)) for key in ("profile", "path", "version")})
    return {"match_id": match_id, "selected_match": deepcopy(selected), "identity_verified": True,
            "complete": complete, "source": identity(target), "target_reference": reference_identity,
            "comparison": {"code": code, "signature": signature, "types": type_comparison, "evidence": evidence},
            "preview": preview, "warnings": warnings, "applied": False}


def render_comparison(result: Dict[str, Any]) -> str:
    """Render the shared human surface without I/O or snapshot duplication."""
    comparison = result["comparison"]
    lines = [
        f"BSim selected match: {result['match_id']}",
        "Identity verified: " + ("yes" if result.get("identity_verified") is True else "NO"),
        "Evidence: " + ("COMPLETE" if result.get("complete") is True else
                        "INCOMPLETE - absence of differences is not equality"),
        "No changes applied. Proposed changes only; no claim of safe applicability.",
    ]
    for label, section in (("Code (textual unified C)", "code"),
                           ("Signature", "signature"), ("Referenced types", "types")):
        lines.append(f"{label}: {comparison[section]['status']}")
    reference = result.get("target_reference", {})
    lines.append("Reference: " + json.dumps(
        {field: reference.get(field) for field in ("profile", "path", "version")},
        sort_keys=True, ensure_ascii=False))
    lines.append("Proposed changes (current target -> reference):")
    if not result.get("preview"):
        lines.append("  None observed" + ("" if result.get("complete") else " in available evidence"))
    for change in result.get("preview", []):
        suffix = "" if change.get("complete") is True else " [INCOMPLETE evidence]"
        lines.append(f"  [{change['kind']}] {change['field']}{suffix}")
        for field in ("before", "after"):
            lines.append(f"    {field}: " + json.dumps(change.get(field), sort_keys=True, ensure_ascii=False))
    conflicts = comparison["types"].get("conflicts", [])
    if conflicts:
        lines.append("Unresolved type conflicts:")
        lines.extend("  " + json.dumps(conflict, sort_keys=True, ensure_ascii=False)
                     for conflict in conflicts)
    lines.append("Warnings:")
    lines.extend("  - " + warning for warning in result.get("warnings", []))
    lines.append("Textual unified C diff (not native CodeDiffPlugin analysis):")
    diff = comparison["code"].get("unified_diff")
    if diff:
        lines.append(diff.rstrip("\n"))
    elif diff is None:
        lines.append("  Unavailable: code evidence missing")
    else:
        lines.append("  No textual differences observed" +
                     ("" if comparison["code"].get("complete") else " in incomplete code evidence"))
    return "\n".join(lines) + "\n"
