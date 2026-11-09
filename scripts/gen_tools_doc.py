"""Generate `GHYDRA_TOOLS.md` from the bridge, and check it has not drifted.

The tool surface is the widest part of this project (134 tools in 36
namespaces, three surfaces), and a hand-written catalogue is a document that is
wrong the first time somebody adds a tool. So the catalogue is **generated**:

    python scripts/gen_tools_doc.py            # write the document
    python scripts/gen_tools_doc.py --check    # fail when it is stale

What is read, and from where:

* the tool function's **decorators** (`@mcp.tool()`), so only real tools appear;
* its **docstring's first paragraph**, which is the promise the answer makes;
* its **signature**, so the parameters are the ones the schema publishes (`port`
  is left out: it is the instance selector, documented once);
* its **endpoint** when the body names one literally (a tool that composes
  several calls says so);
* its **group** from `_tool_group`, the same function the tool profiles use;
* its **CLI path**, matched against the real click tree, not guessed.
"""

from __future__ import annotations

import argparse
import ast
import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BRIDGE = os.path.join(ROOT, "bridge_mcp_hydra.py")
DOCUMENT = os.path.join(ROOT, "GHYDRA_TOOLS.md")

REQUEST_VERBS = ("safe_get", "safe_post", "safe_patch", "safe_put", "safe_delete")


def _decorator_name(node: ast.AST) -> str:
    """`mcp.tool()` -> "tool", `text_output` -> "text_output"."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    return ""


def _render_endpoint(node: ast.AST) -> str | None:
    """The endpoint a call names, as a template (`functions/{address}`)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(str(value.value))
            elif isinstance(value, ast.FormattedValue):
                rendered = ast.unparse(value.value)
                # `{quote(resolved)}` reads as noise in a route template.
                for wrapper in ("quote", "unquote", "int", "str", "float"):
                    prefix = wrapper + "("
                    if rendered.startswith(prefix) and rendered.endswith(")"):
                        rendered = rendered[len(prefix):-1]
                parts.append("{" + rendered + "}")
        return "".join(parts)
    return None


def _function_index(tree: ast.Module) -> dict:
    """Every module-level function: its request count and the functions it calls."""
    index = {}
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        requests = 0
        called = set()
        for call in ast.walk(node):
            if not isinstance(call, ast.Call):
                continue
            if isinstance(call.func, ast.Name):
                if call.func.id in REQUEST_VERBS:
                    requests += 1
                else:
                    called.add(call.func.id)
            elif isinstance(call.func, ast.Attribute):
                # `self.helper()` / `obj.helper()`: the method name is the key.
                called.add(call.func.attr)
        index[node.name] = {"requests": requests, "called": called}
    return index


def _reachable_requests(name: str, index: dict, depth: int = 4,
                        seen=None) -> int:
    """How many requests a tool reaches, following the helpers it calls."""
    seen = set() if seen is None else seen
    if name in seen or depth < 0 or name not in index:
        return 0
    seen.add(name)
    entry = index[name]
    total = entry["requests"]
    for helper in entry["called"]:
        if helper in index:
            total += _reachable_requests(helper, index, depth - 1, seen)
    return total


def _endpoint_of(function: ast.FunctionDef) -> tuple:
    """(method, endpoint, requests) of the first named request the body makes.

    `requests` counts every request verb the tool calls, so a tool with none is
    local (it reads a file or drives a subprocess) and a tool with several is
    composed — which is a different statement from "the endpoint is dynamic".
    """
    found = None
    for call in ast.walk(function):
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
            continue
        if call.func.id not in REQUEST_VERBS:
            continue
        if found is None and len(call.args) >= 2:
            endpoint = _render_endpoint(call.args[1])
            if endpoint is not None:
                method = {"safe_get": "GET", "safe_post": "POST",
                          "safe_patch": "PATCH", "safe_put": "PUT",
                          "safe_delete": "DELETE"}[call.func.id]
                found = (method, endpoint)
    if found is None:
        return None, None, 0
    return found[0], found[1], 0


def _summary_of(function: ast.FunctionDef) -> str:
    """The first paragraph of the docstring: the tool's one-line promise."""
    docstring = ast.get_docstring(function) or ""
    paragraph = []
    for line in docstring.splitlines():
        if not line.strip():
            if paragraph:
                break
            continue
        paragraph.append(line.strip())
    text = " ".join(paragraph)
    return text or "(no summary)"


def _parameters_of(function: ast.FunctionDef) -> str:
    """The parameters the schema publishes, `*` marking a required one."""
    arguments = function.args
    defaults = [None] * (len(arguments.args) - len(arguments.defaults)) \
        + list(arguments.defaults)
    names = []
    for argument, default in zip(arguments.args, defaults):
        if argument.arg in ("self", "port"):
            continue
        annotation = ast.unparse(argument.annotation) if argument.annotation else ""
        annotation = annotation.replace(" | None", "").replace("Optional[", "")\
            .replace("]", "").replace("str", "text").replace("bool", "flag")\
            .replace("int", "int").replace("float", "float").replace("dict", "object")\
            .replace("list", "list")
        marker = "" if default is not None else "*"
        names.append(f"`{argument.arg}`{marker}"
                     + (f" {annotation}" if annotation else ""))
    for argument in arguments.kwonlyargs:
        if argument.arg == "port":
            continue
        names.append(f"`{argument.arg}`")
    return ", ".join(names) or "—"


def _cli_paths() -> dict:
    """The real click tree, as {tool-ish name: 'ghydra <group> <command>'}."""
    sys.path.insert(0, ROOT)
    try:
        from ghydra.cli.main import cli
    except Exception as failure:  # noqa: BLE001 - the catalogue must say why
        raise SystemExit(f"cannot read the CLI tree: {failure}")
    paths = {}
    for group_name, group in cli.commands.items():
        subcommands = getattr(group, "commands", None)
        if not subcommands:
            paths[group_name] = f"ghydra {group_name}"
            continue
        for sub_name, command in subcommands.items():
            paths[f"{group_name}_{sub_name}"] = f"ghydra {group_name} {sub_name}"
            aliases = getattr(command, "name", None)
            if aliases and aliases != sub_name:
                paths[f"{group_name}_{aliases}"] = f"ghydra {group_name} {aliases}"
    return paths


def _cli_for(tool: str, paths: dict) -> str:
    """The command for a tool, matched against the tree (dashes tried too)."""
    namespace, _, rest = tool.partition("_")
    for candidate in (tool, f"{namespace}_{rest.replace('_', '-')}"):
        if candidate in paths:
            return paths[candidate]
    return "—"


def collect() -> list:
    """Every tool, in the order the document groups them."""
    with io.open(BRIDGE, encoding="utf-8") as handle:
        tree = ast.parse(handle.read())
    index = _function_index(tree)
    paths = _cli_paths()
    metadata = _groups()
    tools = []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        decorations = {_decorator_name(item) for item in node.decorator_list}
        if "tool" not in decorations:
            continue
        method, endpoint, _unused = _endpoint_of(node)
        requests = _reachable_requests(node.name, index)
        tools.append({
            "name": node.name,
            "namespace": node.name.split("_")[0],
            "group": metadata.get(node.name, "?"),
            "summary": _summary_of(node),
            "parameters": _parameters_of(node),
            "method": method,
            "endpoint": endpoint,
            "requests": requests,
            "cli": _cli_for(node.name, paths),
        })
    return tools


def _groups() -> dict:
    """tool -> workflow group, from the bridge itself."""
    sys.path.insert(0, ROOT)
    os.environ.setdefault("GHYDRA_MCP_OUTPUT", "json")
    import bridge_mcp_hydra as bridge  # noqa: E402 - the document is about it
    return {name: bridge._tool_group(name)
            for name in bridge.mcp._tool_manager._tools}


GROUP_ORDER = ("core", "functions", "data", "types", "scripts", "headless",
               "kuna", "x64dbg", "runbook", "fleet")
GROUP_TITLE = {
    "core": "Core — instance, project, program, evidence, sessions, tasks, tools",
    "functions": "Functions, analysis and signatures",
    "data": "Data, strings, structs and scalars",
    "types": "Data types",
    "scripts": "Scripts (gated)",
    "headless": "Headless runs",
    "kuna": "Kuna (local)",
    "x64dbg": "x64dbg (local)",
    "runbook": "Runbooks",
    "fleet": "Fleet",
}


def render(tools: list) -> str:
    """The Markdown document."""
    by_group: dict = {}
    for tool in tools:
        by_group.setdefault(tool["group"], []).append(tool)
    lines = [
        "# The tool catalogue",
        "",
        "Every MCP tool, what it answers and where it lives. **Generated** from",
        "`bridge_mcp_hydra.py` by `scripts/gen_tools_doc.py`; do not edit this file by",
        "hand — a test fails when it drifts from the code.",
        "",
        f"**{len(tools)} tools** in {len(by_group)} workflow groups. The `port` parameter",
        "every tool accepts is left out of the tables: it names the Ghidra instance,",
        "and it is documented once in [GHYDRA_CLI.md](GHYDRA_CLI.md).",
        "",
        "A tool marked `composed` does not map to one endpoint: it gathers several",
        "answers into one. The local integrations (`kuna_*`, `x64dbg_*`) have no HTTP",
        "route at all.",
        "",
    ]
    for group in GROUP_ORDER + tuple(name for name in by_group
                                     if name not in GROUP_ORDER):
        members = by_group.get(group) or []
        if not members:
            continue
        lines.append(f"## {GROUP_TITLE.get(group, group)}")
        lines.append("")
        lines.append(f"`{len(members)}` tools.")
        lines.append("")
        lines.append("| Tool | REST | What it answers | Parameters | CLI |")
        lines.append("| --- | --- | --- | --- | --- |")
        for tool in sorted(members, key=lambda item: item["name"]):
            if tool["endpoint"] and tool["requests"] <= 1:
                route = f"`{tool['method']} /{tool['endpoint']}`"
            elif tool["requests"] > 1:
                route = f"composed ({tool['requests']} calls)"
            elif tool["requests"] == 0:
                # No HTTP call at all: a file, a subprocess, the local state.
                route = "local"
            elif tool["requests"] == 1:
                # One call through a helper (the endpoint is built for it).
                route = "route by argument"
            else:
                route = f"composed ({tool['requests']} calls)"
            summary = tool["summary"].replace("|", "\\|")
            lines.append(f"| `{tool['name']}` | {route} | {summary} | "
                         f"{tool['parameters']} | {tool['cli']} |")
        lines.append("")
    lines.append("## Regenerating")
    lines.append("")
    lines.append("```bash")
    lines.append("python scripts/gen_tools_doc.py           # rewrite this document")
    lines.append("python scripts/gen_tools_doc.py --check   # fail when it is stale")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="fail when the document is stale")
    arguments = parser.parse_args(argv)
    rendered = render(collect())
    current = ""
    if os.path.exists(DOCUMENT):
        with io.open(DOCUMENT, encoding="utf-8") as handle:
            current = handle.read()
    if arguments.check:
        if rendered != current:
            print("stale: GHYDRA_TOOLS.md does not match the bridge. "
                  "Run: python scripts/gen_tools_doc.py", file=sys.stderr)
            return 1
        print("ok: the tool catalogue is current")
        return 0
    if rendered == current:
        print("ok: nothing to update")
        return 0
    with io.open(DOCUMENT, "w", encoding="utf-8", newline="") as handle:
        handle.write(rendered)
    print(f"wrote {DOCUMENT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())