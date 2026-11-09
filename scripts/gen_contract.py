"""Generate the machine-readable half of the unification contract.

The plan (`docs/UNIFICATION-PLAN.md` §3) says the two projects can only share a
**specification**, because they share no runtime. A specification that nobody
regenerates is a document that is wrong after the first tool is renamed, so the
part of the contract that can be derived from this repository is **generated**:

    contract/tools.json        every tool, its namespace, its group and whether it
                               has a formatter — the vocabulary rule, applied
    contract/error-codes.json  every error code with its side, status and origin,
                               plus the envelope rule that makes a code usable

    python scripts/gen_contract.py            # write both
    python scripts/gen_contract.py --check    # fail when either is stale

The hand-written half (`contract/README.md`, the TargetDescriptor schema and the
vocabulary document) states the rules and the other side's status; it is reviewed,
not generated.
"""

from __future__ import annotations

import argparse
import importlib.util
import io
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTRACT = os.path.join(ROOT, "contract")
TOOLS_DOCUMENT = os.path.join(CONTRACT, "tools.json")
ERRORS_DOCUMENT = os.path.join(CONTRACT, "error-codes.json")

CONTRACT_VERSION = 1

#: The vocabulary rule from §3.1: namespace-qualified, snake_case, `domain_verb`.
NAME_PATTERN = "^[a-z][a-z0-9]*(_[a-z0-9]+)+$"

#: Parameters the MCP protocol reserves on a tool (see AGENTS.md).
RESERVED_PARAMETERS = ("arguments",)


def _load(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def collect_tools() -> list:
    """Every tool the bridge registers, with the contract's fields."""
    sys.path.insert(0, ROOT)
    os.environ.setdefault("GHYDRA_MCP_OUTPUT", "json")
    import bridge_mcp_hydra as bridge

    manager = bridge.mcp._tool_manager._tools
    tools = []
    for name in sorted(manager):
        tool = manager[name]
        schema = getattr(tool, "parameters", {}) or {}
        properties = schema.get("properties") or {}
        tools.append({
            "name": name,
            "namespace": name.split("_")[0],
            "group": bridge._tool_group(name),
            "parameters": sorted(properties),
            "reserved_parameters": sorted(
                parameter for parameter in properties
                if parameter in RESERVED_PARAMETERS),
            "takes_instance": "port" in properties,
            "has_formatter": name in bridge.FORMATTERS,
        })
    return tools


def collect_errors() -> dict:
    """Every error code, from the two sides that produce them."""
    module = _load("gen_errors_doc", os.path.join(ROOT, "scripts", "gen_errors_doc.py"))
    java = module.collect_java()
    python = module.collect_python()
    codes = []
    for code in sorted(set(java) | set(python)):
        entry = java.get(code) or python[code]
        codes.append({
            "code": code,
            "side": entry["side"],
            "http_status": entry["status"] or None,
            "message": entry["message"] or None,
            "origin": entry["where"],
        })
    return {
        "contract_version": CONTRACT_VERSION,
        "generated_by": "scripts/gen_contract.py",
        "envelope": {
            "rule": "an error carries a stable machine-readable code next to its "
                    "human text; a client branches on the code, never on the prose",
            "code_pattern": "^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$",
            "required_on_failure": ["success", "error.code", "error.message"],
            "success_field": "success",
        },
        "counts": {
            "codes": len(codes),
            "families": len({code["code"].split("_")[0] for code in codes}),
        },
        "codes": codes,
    }


def render_tools(tools: list) -> str:
    document = {
        "contract_version": CONTRACT_VERSION,
        "generated_by": "scripts/gen_contract.py",
        "vocabulary": {
            "rule": "namespace-qualified, snake_case, domain_verb: the prefix is "
                    "what keeps two tools that mean different things apart "
                    "(memory_read reads the static image; x64dbg_read_memory would "
                    "read the live process)",
            "name_pattern": NAME_PATTERN,
            "namespace": "the first token of the name",
            "reserved_parameters": list(RESERVED_PARAMETERS),
            "takes_instance": "the tool names a Ghidra instance through its port",
        },
        "counts": {
            "tools": len(tools),
            "namespaces": len({tool["namespace"] for tool in tools}),
            "with_formatter": sum(1 for tool in tools if tool["has_formatter"]),
            "with_reserved_parameter": sum(
                1 for tool in tools if tool["reserved_parameters"]),
        },
        "tools": tools,
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def render_errors(document: dict) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="fail when a generated contract file is stale")
    arguments = parser.parse_args(argv)

    os.makedirs(CONTRACT, exist_ok=True)
    expected = {
        TOOLS_DOCUMENT: render_tools(collect_tools()),
        ERRORS_DOCUMENT: render_errors(collect_errors()),
    }

    stale = []
    for path, rendered in expected.items():
        current = ""
        if os.path.exists(path):
            with io.open(path, encoding="utf-8") as handle:
                current = handle.read()
        if arguments.check:
            if rendered != current:
                stale.append(os.path.basename(path))
            continue
        if rendered != current:
            with io.open(path, "w", encoding="utf-8", newline="") as handle:
                handle.write(rendered)
            print(f"wrote {path}")
        else:
            print(f"ok: {os.path.basename(path)} is current")

    if arguments.check:
        if stale:
            print("stale contract file(s): " + ", ".join(stale)
                  + ". Run: python scripts/gen_contract.py", file=sys.stderr)
            return 1
        print("ok: the contract files are current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())