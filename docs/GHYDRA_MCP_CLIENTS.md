# MCP client setup

The bridge (`bridge_mcp_hydra.py`) is a **stdio MCP server**: the client starts
it and owns its input/output streams. The CLI (`ghydra`) is the recommended
terminal and scripting interface; the bridge remains available for MCP clients
and MCP resources. Install and enable the Ghidra extension first using
[the installation guide](GHYDRA_INSTALLATION.md).

## Generic configuration

Any client supporting stdio MCP servers can launch the bridge. With uv, the
script's inline dependency metadata supplies its pinned dependencies:

```json
{
  "mcpServers": {
    "ghydra": {
      "command": "uv",
      "args": ["run", "--script", "/ABSOLUTE_PATH_TO/GhydraMCP/bridge_mcp_hydra.py"],
      "env": {"GHIDRA_HYDRA_HOST": "localhost"}
    }
  }
}
```

Replace the path with the actual absolute path, for example
`/home/username/GhydraMCP/bridge_mcp_hydra.py` on Linux/macOS or
`C:\\Users\\username\\GhydraMCP\\bridge_mcp_hydra.py` in Windows JSON.
A GUI client may also need an absolute path to `uv` if it is not on its `PATH`.

`GHIDRA_HYDRA_HOST` is the bridge's host variable; the formerly documented
`GHYDRA_HYDRA_HOST` spelling is not read by the bridge. The CLI's host variable
is `GHYDRA_HOST`.

For a smaller tool list, add `GHYDRA_TOOL_GROUPS=core,functions` to the server's
`env`. [Concepts](GHYDRA_CONCEPTS.md#7-tools-are-grouped-and-the-group-is-a-profile)
explains profiles and runtime loading; the generated
[tool catalogue](GHYDRA_TOOLS.md) is the complete reference.

### Using Python directly

Install the dependencies into a project environment with `uv sync` or the
[editable-install instructions](GHYDRA_INSTALLATION.md#cli-tool-and-python-dependencies).
Then use that environment's interpreter:

```json
{
  "mcpServers": {
    "ghydra": {
      "command": "/ABSOLUTE_PATH_TO/GhydraMCP/.venv/bin/python",
      "args": ["/ABSOLUTE_PATH_TO/GhydraMCP/bridge_mcp_hydra.py"],
      "env": {"GHIDRA_HYDRA_HOST": "localhost"}
    }
  }
}
```

On Windows, use `.venv\\Scripts\\python.exe` in JSON. A GUI client does not
inherit your shell's activated virtualenv: a bare `python` usually lacks `mcp`
and `requests`. Keep the environment's dependency pins from this repository.

## Claude Desktop configuration

Add the generic `mcpServers` entry above to `claude_desktop_config.json`.
If you prefer running from the repository's directory, the equivalent uv
argument list is:

```json
["run", "--directory", "/ABSOLUTE_PATH_TO/GhydraMCP", "--script", "bridge_mcp_hydra.py"]
```

The absolute-interpreter alternative above also works.

## Claude Code configuration

Register the bridge with the client:

```bash
claude mcp add ghydra -- uv run --script /ABSOLUTE_PATH_TO/GhydraMCP/bridge_mcp_hydra.py
```

Alternatively, put the generic `mcpServers` configuration in the project's
`.mcp.json`. Set the bridge's host in `env` when it is not localhost.

## Cline configuration

1. Open Cline and click its MCP Servers icon.
2. Choose **Configure MCP Servers** to edit `cline_mcp_settings.json`.
3. Add the generic `mcpServers` entry, with the actual absolute path. Cline also
   accepts `"disabled": false` on the server entry.
4. Save and restart Cline to load GhydraMCP.

Use the absolute `.venv` interpreter from **Using Python directly** if you do
not want uv to launch the script.

## 5ire configuration

- Tool Key: `ghydra`
- Name: `GhydraMCP`
- Command: `uv run --script /ABSOLUTE_PATH_TO/GhydraMCP/bridge_mcp_hydra.py`

## Generated and combined configurations

The CLI can generate a configuration instead of copying one manually:

```bash
ghydra mcp-config --no-x64dbg
ghydra mcp-config --groups core,functions
ghydra mcp-config -o claude_desktop.json
ghydra mcp-config --gateway
```

See [the CLI configuration reference](GHYDRA_CLI.md#the-combined-mcp-client-configuration)
for the bridge plus debugger setup, token handling, and the separate five-tool
gateway. Printed debugger tokens are masked by default; a written configuration
may contain a real bearer token and must not be committed.

## Resources a client can read

Ghidra resources use the absolute `ghidra://` scheme, not an HTTP-relative URI:

| URI | Content |
| --- | --- |
| `ghidra://instance/{port}` | The instance and its program |
| `ghidra://instance/{port}/function/decompile/address/{address}` | Decompiled C |
| `ghidra://instance/{port}/function/decompile/name/{name}` | Decompiled C by fully-qualified name |
| `ghidra://instance/{port}/function/disassembly/address/{address}` | Disassembly |
| `ghidra://instance/{port}/function/disassembly/name/{name}` | Disassembly by fully-qualified name |
| `ghidra://instance/{port}/function/info/address/{address}` | Function information |
| `ghidra://instance/{port}/function/info/name/{name}` | Function information by fully-qualified name |

For recovered C and assembly from durable Kuna exports, follow
[the Kuna resources reference](GHYDRA_KUNA.md#the-mcp-resources): list
`kuna://exports`, read the digest's `index.jsonl`, then read the named artifact.
The digest survives bridge restarts, unlike an in-memory export job ID.

## Output and protocol

Tool results default to formatted **text**. Add `GHYDRA_MCP_OUTPUT=json` to the
server environment when a program needs the raw response envelope as one JSON
document. See [Output formats](GHYDRA_OUTPUT.md#the-mcp-bridge) for the contract.

Between the bridge/CLI and the Java plugin, communication is JSON over the
HATEOAS REST API. The canonical
[HTTP API reference](GHIDRA_HTTP_API.md#general-concepts) describes HTTP methods,
API version checks, success/error envelopes, pagination, and navigational links.
The local Kuna and x64dbg integrations do not add Ghidra REST endpoints; their
transport and error details live in [Kuna](GHYDRA_KUNA.md) and
[x64dbg](GHYDRA_X64DBG.md).
