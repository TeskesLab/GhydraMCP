"""The combined MCP client configuration — Phase 2 of the unification plan.

The plan's Phase 2 is "one agent surface": a single client configuration that
registers both servers, with the two sides separately toggleable and the tool
groups opt-in rather than all-or-nothing. This module builds that configuration; the
`ghydra mcp-config` command writes it.

Two entries, because the two servers are reached differently:

* **ghydra** — a stdio MCP server (`bridge_mcp_hydra.py`, run through `uv`), with the
  tool groups and the instance address in its environment;
* **x64dbg** — an HTTP MCP server inside the debugger, reached by URL with a bearer
  token.

The token is a secret and this module treats it as one: it is written into a file
when the caller asks for a file, and it is **masked** in anything printed. A CLI
that echoes a bearer token into a terminal is a CLI that puts it in a shell history
file.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from typing import Any, Dict, List, Optional, Tuple

from . import x64dbg as debugger

#: The workflow groups the bridge can register (`GHYDRA_TOOL_GROUPS`).
#:
#: Checked against `contract/tools.json` by the `--mcp-config` suite, so a group
#: that is added to the bridge and not here fails the build instead of producing a
#: configuration that silently drops tools.
TOOL_GROUPS = ("core", "functions", "data", "types", "scripts", "headless",
               "kuna", "x64dbg", "runbook", "fleet")

#: The bridge, next to the package.
BRIDGE_NAME = "bridge_mcp_hydra.py"

#: What a masked token looks like in text output.
MASK = "***"


def bridge_path() -> str:
    """The bridge script: next to the package in a checkout, one level up."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(os.path.dirname(here), BRIDGE_NAME)


def parse_groups(groups: Optional[str]) -> List[str]:
    """A comma-separated group list, validated against the bridge's groups."""
    if groups is None:
        return []
    names = [name.strip() for name in str(groups).split(",") if name.strip()]
    unknown = [name for name in names if name not in TOOL_GROUPS]
    if unknown:
        raise ValueError(
            f"unknown tool group(s): {', '.join(unknown)}; "
            f"the groups are: {', '.join(TOOL_GROUPS)}")
    return names


def bridge_entry(groups: Optional[List[str]] = None,
                 host: Optional[str] = None,
                 state_dir: Optional[str] = None) -> Dict[str, Any]:
    """The stdio entry: the bridge, run through `uv` when it is there.

    Only variables the bridge actually reads are set. There is no port variable:
    the bridge discovers the instances by scanning, and a configuration that named
    one would be describing a mechanism that does not exist.
    """
    script = bridge_path()
    environment: Dict[str, str] = {}
    if groups:
        environment["GHYDRA_TOOL_GROUPS"] = ",".join(groups)
    if host:
        environment["GHIDRA_HYDRA_HOST"] = str(host)
    if state_dir:
        environment["GHYDRA_STATE_DIR"] = str(state_dir)

    if shutil.which("uv"):
        entry: Dict[str, Any] = {"command": "uv",
                                 "args": ["run", "--script", script]}
    else:
        # A machine without uv can still run the bridge: it is one Python file
        # with inline dependencies, and pip installs them.
        entry = {"command": sys.executable or "python3", "args": [script]}
    if environment:
        entry["env"] = environment
    return entry


def debugger_entry(settings: Optional[dict] = None) -> Tuple[Optional[Dict[str, Any]],
                                                            Optional[str]]:
    """The HTTP entry for the debugger's own MCP server, or the reason there is none.

    The debugger has no stdio: its server lives inside the plugin and answers HTTP
    with a bearer token. Without a token there is no way to talk to it (the client
    would only get `401`), so the entry is left out and the reason is returned —
    a configuration that names a server nobody can authenticate against is worse
    than one that says what is missing.
    """
    resolved = debugger.resolve_config(settings)
    token = resolved.get("token") or ""
    if not token:
        return None, ("the x64dbg token is unknown: point at the installation with "
                      "`\"x64dbg\": {\"path\": ...}` in ~/.ghydra/config.json, or set "
                      f"{debugger.ENV_TOKEN}")
    url = f"http://{resolved['host']}:{int(resolved['port'])}/"
    return {"type": "http", "url": url,
            "headers": {"Authorization": f"Bearer {token}"}}, None


#: The console script the gateway is served by. It is its own entry point on
#: purpose: an MCP server on stdio must own stdout, and the CLI's root command
#: discovers instances and prints.
GATEWAY_SCRIPT = "ghydra-gateway"


def gateway_entry(groups: Optional[List[str]] = None,
                  host: Optional[str] = None) -> Dict[str, Any]:
    """The single entry: the gateway server, which fronts both plugins."""
    environment: Dict[str, str] = {}
    if groups:
        environment["GHYDRA_TOOL_GROUPS"] = ",".join(groups)
    if host:
        environment["GHIDRA_HYDRA_HOST"] = str(host)
    entry: Dict[str, Any] = {"command": GATEWAY_SCRIPT, "args": []}
    if environment:
        entry["env"] = environment
    return entry


def build(groups: Optional[List[str]] = None,
          settings: Optional[dict] = None,
          include_debugger: bool = True,
          gateway: bool = False,
          host: Optional[str] = None,
          state_dir: Optional[str] = None) -> Dict[str, Any]:
    """The combined configuration, in the shape clients already understand.

    `mcpServers` is the de-facto standard (Claude Desktop, Cursor, Cline, 5ire);
    the two entries use the transports each server actually speaks.
    """
    if gateway:
        # One server, both sides: the tools are `target_*`, and the workflows that
        # need both plugins are a single call.
        return {"mcpServers": {"ghydra-gateway": gateway_entry(
            groups=groups, host=host)}}
    document: Dict[str, Any] = {"mcpServers": {"ghydra": bridge_entry(
        groups=groups, host=host, state_dir=state_dir)}}
    notes: List[str] = []
    if include_debugger:
        entry, reason = debugger_entry(settings)
        if entry is not None:
            document["mcpServers"]["x64dbg"] = entry
        elif reason:
            notes.append(reason)
    if notes:
        # A note is not part of the client's schema; it travels beside it, and the
        # human-facing summary prints it.
        document["_notes"] = notes
    return document


def summary(document: Dict[str, Any], include_secrets: bool = False) -> List[str]:
    """The lines a terminal gets: what is registered, and why something is not."""
    lines = []
    servers = document.get("mcpServers") or {}
    for name in sorted(servers):
        entry = servers[name]
        if entry.get("url"):
            url = entry["url"]
            token = (entry.get("headers") or {}).get("Authorization", "")
            shown = token if include_secrets else (
                token.split(" ", 1)[0] + " " + MASK if token else "")
            lines.append(f"{name}: http {url}"
                         + (f" ({shown})" if shown else ""))
        else:
            command = entry.get("command", "")
            arguments = " ".join(entry.get("args") or [])
            groups = (entry.get("env") or {}).get("GHYDRA_TOOL_GROUPS")
            lines.append(f"{name}: stdio {command} {arguments}".rstrip()
                         + (f"  [groups: {groups}]" if groups else ""))
    for note in document.get("_notes") or []:
        lines.append(f"note: {note}")
    return lines


def mask(document: Dict[str, Any]) -> Dict[str, Any]:
    """The same document with every bearer token replaced by the mask."""
    masked = json.loads(json.dumps(document))
    for entry in (masked.get("mcpServers") or {}).values():
        headers = entry.get("headers")
        if isinstance(headers, dict) and "Authorization" in headers:
            scheme = str(headers["Authorization"]).split(" ", 1)[0]
            headers["Authorization"] = f"{scheme} {MASK}"
    return masked


def write(document: Dict[str, Any], path: str) -> str:
    """Write the configuration, and say where it went.

    The `_notes` are for the human, not for the client: a strict client may refuse
    a key it does not know, so they stay out of the file (the command prints them).
    """
    payload = {key: value for key, value in document.items()
               if not key.startswith("_")}
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    # The file holds a bearer token with debugger control: on POSIX, make it
    # readable by its owner only. On Windows the ACL is inherited, and chmod is a
    # no-op there, which is why this is not an error when it fails.
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path