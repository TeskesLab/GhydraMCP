# GhydraMCP — x64dbg integration

GhydraMCP can drive the [x64dbg MCP server](https://github.com/duty1g/x64dbg-mcp-server), the Zig
plugin that lives inside the debugger. The point is to have both halves of a reverse-engineering
job in the same place: Ghidra for the static image, x64dbg for the live process, with the
addresses of one side usable on the other.

Nothing about the Ghidra plugin changes for this. The x64dbg server is a separate program with
its own HTTP contract, so it touches neither `API_VERSION` nor the Java side — the same way the
[Kuna integration](GHYDRA_KUNA.md) is local.

## How it works

The plugin answers JSON-RPC 2.0 over HTTP:

```
POST / HTTP/1.1
Content-Type: application/json
Authorization: Bearer <token>

{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
 "params": {"name": "ListModules", "arguments": {}}}
```

The answer is plain `application/json` — no SSE framing — and the server keeps no state, so
every request stands alone. There is no handshake to maintain; `initialize` is a courtesy.

It binds `127.0.0.1:9094` for a 64-bit debuggee and `127.0.0.1:9095` for a 32-bit one, and it
wants a bearer token. The token cannot be guessed: the plugin writes it to its own
`mcp_config.json`, next to `x64dbg.exe` — it asks the OS for the process path, not the DLL's.

The released plugin binds exactly those two ports and stops serving when one of them is taken.
The fixed build (PR #13 upstream) walks up to the next free port instead and logs the one it
bound, so the port is looked for rather than assumed, and the scan reaches as far as that build
can go.

## Configure it

The token is the one thing that has to be found somewhere. Point at the installation and the
plugin's own file is enough:

```json
{
  "x64dbg": {
    "path": "C:/tools/x64dbg"
  }
}
```

The `mcp_config.json` in that directory (or in one of its plugin folders) carries `IpAddress`,
`Port` and `AuthToken`, and all three are picked up. To set the token outright:

```json
{
  "x64dbg": {
    "host": "127.0.0.1",
    "port": 9094,
    "token": "the-token"
  }
}
```

The environment carries the same, and the path too: `GHYDRA_X64DBG_HOST`, `GHYDRA_X64DBG_PORT`,
`GHYDRA_X64DBG_TOKEN` and `GHYDRA_X64DBG_PATH`. The config file wins over the environment, as
everywhere else. The path is worth having in the environment because the token is the one thing
that cannot be guessed: `GHYDRA_X64DBG_PATH` is enough to make the integration work without
editing a configuration file at all.

## Verified against the real plugin

The integration was exercised against the real x64dbg plugin — the one built from
`x64dbg-mcp-server` — with `cmd.exe` loaded under the debugger:

- The plugin wrote its `mcp_config.json` next to `x64dbg.exe`, and the token, the port (9094) and
  the bind address were read from there.
- `x64dbg_status` reported the server, its **80 tools**, and the five loaded modules with their
  runtime bases.
- The address model was checked against the running debugger: the static entry point of
  `cmd.exe` (`0x140027B90`, at the image base `0x140000000`) translated to the runtime address of
  the module as the loader had placed it, and that address disassembled to the real entry stub.
  The static address on its own is not mapped in the live process and does not disassemble — which
  is the point of the translation.
- The breakpoint was then set at that translated address, and the debugger listed it as
  `cmd.exe!entry breakpoint`: it resolved the address to the entry point by name.

## The address model

Ghidra and x64dbg do not agree on where a function is. Ghidra works on the image as it sits in
the file, at the image base; the loader puts the module somewhere else in the process, and that
is where x64dbg works.

```
runtime = static − image_base + module_base
```

The `image_base` comes from the Ghidra instance (`GET /program`), the `module_base` from the
plugin's `ListModules`. The two binaries are matched by full path first and by file name second,
because the two sides can disagree about the directory without disagreeing about the file. When
nothing matches, the call fails with `X64DBG_NO_MATCH` rather than guessing.

The tools that take an address take the **static** one — the address as Ghidra shows it — and
translate it.

## The MCP tools

The plugin carries eighty tools. They are not exposed one by one: an agent with a hundred and
sixty tools picks badly, so the catalogue and a generic pass-through are exposed instead.

| Tool | What it does |
| --- | --- |
| `x64dbg_status` | Whether the server answered, where it is, how many tools it has and which modules are loaded |
| `x64dbg_tools` | The plugin's catalogue: name, description, input schema and whether the tool is read-only |
| `x64dbg_call` | Call any plugin tool by name, with its arguments |
| `x64dbg_target` | How the Ghidra program and the x64dbg session line up: both bases and the distance between them |
| `x64dbg_breakpoint_at` | Set a breakpoint on a Ghidra address, translated into the runtime address |
| `x64dbg_go_to` | Move the instruction pointer to a Ghidra address, translated the same way |

`x64dbg_call` takes a `timeout`, in seconds (30 by default), and the plugin's own arguments in
`tool_arguments`. The tools that block — `run`, `WaitForEvent`, `WaitForPause` — need more:

```python
client.use_tool("ghydra", "x64dbg_call",
                {"tool": "WaitForEvent", "tool_arguments": '{"timeoutMs": 60000}', "timeout": 90})
```

The arguments go as **one piece of JSON text**, and that is what the schema asks for. A client that
re-encodes the container the MCP protocol uses for a tool's parameters flattens what is nested in it:
every value of a nested object arrives as a string. Measured on this desktop, where an integer
`count` arrived as `"3"` — and the plugin, which ignores a parameter it cannot read, answered with
its default count instead of the one that was asked for. The text is the form nothing gets in the
way of, and it is parsed here.

An object is still accepted, for the clients that deliver one, and its types are put back from the
plugin's own schema before the call:

```python
client.use_tool("ghydra", "x64dbg_call",
                {"tool": "WaitForEvent", "tool_arguments": {"timeoutMs": 60000}, "timeout": 90})
```

The parameter is not called `arguments` because that is the name of the container the MCP protocol
itself uses for a tool's parameters, and the two get confused easily.

The debugger is local, so these tools take no `port` for it. The workflow tools take one, and it
is the **Ghidra** instance, as everywhere else in the bridge.

## The CLI commands

```bash
# is the debugger there, and what is it looking at
ghydra x64dbg status

# the plugin's catalogue
ghydra x64dbg tools

# any plugin tool, by name
ghydra x64dbg call GetAllRegisters
ghydra x64dbg call SetBreakpoint --arg target=0x7FF7A1234000
ghydra x64dbg call ReadMemory --json-args '{"address": "0x7FF7A1234000", "size": 64}'

# the two bases, and the distance between them
ghydra x64dbg target

# a breakpoint on a Ghidra address
ghydra x64dbg breakpoint 0x140001234

# move the instruction pointer there
ghydra x64dbg go-to 0x140001234
```

`ghydra --json x64dbg status` prints the same thing as JSON.

## Failures carry a code

The bridge and the CLI carry the same ten codes, so an agent can branch on the reason instead
of reading prose:

| Code | What it means |
| --- | --- |
| `X64DBG_ERROR` | The generic fallback |
| `X64DBG_DISABLED` | No token, so no way to talk to the server |
| `X64DBG_MISSING` | Nothing answered on the port, and the request never left |
| `X64DBG_TIMEOUT` | The server did not answer in time |
| `X64DBG_UNCERTAIN` | The request was sent but the answer was lost: the debugger may already have acted |
| `X64DBG_UNAUTHORIZED` | The bearer token did not match |
| `X64DBG_NO_SESSION` | No debug session in x64dbg |
| `X64DBG_NO_TOOL` | The plugin has no tool with that name |
| `X64DBG_BAD_ARGS` | The tool rejected the arguments |
| `X64DBG_NO_MATCH` | The binary does not match any loaded module |

## The network, on this machine

Two facts about the local network stack shape the client, and both were measured rather than
guessed:

- **The plugin hangs up after every response.** A pooled connection would be reused after the
  server had already closed it, which arrives as a `ConnectionResetError` and not as a missing
  server. The client opens a fresh connection per call.
- **A local TCP connection is reset every now and then.** Measured at 7% of the connections on
  this machine — with curl and with plain sockets alike, so it is the Windows network stack and
  not this client. The client retries a connection error, up to three attempts, each on a fresh
  connection.

A timeout is only retried when the request is safe to repeat, and so is a connection that died
while the answer was coming: the plugin marks every tool with `annotations.readOnlyHint`, so a
read-only tool may be called again; a tool that changes the debuggee is not repeated, because
the first attempt may already have reached it. A connection that never came up is the one
exception: the request was never sent, so it is always safe to try again.

That last distinction is the one an agent has to be told about, because the two failures look the
same from the outside and mean opposite things. `X64DBG_MISSING` means "nothing was sent, nothing
happened, the debugger is not listening". `X64DBG_UNCERTAIN` means "the debugger took the request
and the answer was lost on the way back" — the connection died after the request was handed over,
which is what the local network stack does to about one connection in fourteen. The request was
not repeated, because the debugger may already have acted on it: a breakpoint may be set, and the
state of the debuggee is unknown. A read-only tool never ends in `X64DBG_UNCERTAIN`, because it
is always safe to send it again.

The connect timeout and the read timeout are separate for the same reason: a closed local port
does not refuse straight away on Windows — the SYN hangs and is only refused about two seconds
later — so the port scan uses a short connect timeout (0.35 s) and probes the ports
concurrently, while a tool that blocks gets the read timeout it asked for.

A connection that is reset *and* whose reset is lost behaves the same way from the outside: the
client waits for an answer that is never coming, and the call ends with the read timeout rather
than with an error. The retry then succeeds on a fresh connection, but the wait was the read
timeout — thirty seconds by default, which is the price of a call the network stack swallowed.

## Limits and gotchas

- The plugin has to be loaded and the debugger has to be running. A server that answers `401` is
  still a server: it means the token is wrong, which is worth saying.
- **The tools that block need a timeout of their own.** `run`, `WaitForEvent` and `WaitForPause`
  block for minutes by default, and the default read timeout is 30 seconds, so a call to one of
  them without a `timeout` always times out. Give it more than the tool's own `timeoutMs`.
- An address is read as hexadecimal whatever it looks like: `"0x140001234"`, `"140001234"` and
  `"140001234"` are the same number, and so is `"4096"` — which is `0x4096`, not 4096. That is
  what Ghidra's `imageBase` needs too.
- `x64dbg_go_to` moves the instruction pointer, so the debuggee has to be paused.
- The tool catalogue is fetched once and kept: the plugin's tool set does not change while the
  debugger runs.
- The `x64dbg_*` tools carry no `port` for the debugger. On the workflow tools, `port` is the
  Ghidra instance.

## Tests

```bash
python run_tests.py --x64dbg
```

`test_x64dbg.py` needs neither Ghidra nor x64dbg: it starts a fake plugin that answers like the
real one — JSON-RPC over HTTP, a bearer token, the catalogue with `annotations.readOnlyHint` — and
covers the client, the config precedence, the address model, the bridge tools and the error
taxonomy.
