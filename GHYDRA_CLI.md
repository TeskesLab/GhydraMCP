# Ghydra CLI

A command-line interface for GhydraMCP that provides access to Ghidra's reverse engineering capabilities via a standalone tool.

## `ghydra stats` — what the session actually did

The bridge records one JSON object per MCP tool call under
`~/.ghydra/telemetry.jsonl` (local only — nothing is sent anywhere; disable
with `GHYDRA_TELEMETRY=0`). The log is capped at about 1 MB.

```bash
ghydra stats                    # calls, failures, latency, tokens per tool
ghydra stats --days 30          # a wider window
ghydra stats --reset            # delete the local log, then report
ghydra --json stats             # the raw report
```

When the log shows a pattern a composed tool replaces, the report names it:
4+ inspection calls point at `analysis_context_pack`, 4+ listings at
`programs_overview`, 4+ decompiles at `functions_batch_decompile`, and a slow
tool at `async_mode`.

## Overview

Ghydra CLI is a standalone command-line tool that exposes all the functionality of the GhydraMCP bridge in a terminal-friendly format. It supports both human-readable formatted output (with tables, syntax highlighting, and colors) and JSON output for scripting.

## `ghydra stats` — what the session actually did

The bridge records one JSON object per MCP tool call under
`~/.ghydra/telemetry.jsonl` (local only — nothing is sent anywhere; disable
with `GHYDRA_TELEMETRY=0`). The log is capped at about 1 MB.

```bash
ghydra stats                    # calls, failures, latency, tokens per tool
ghydra stats --days 30          # a wider window
ghydra stats --reset            # delete the local log, then report
ghydra --json stats             # the raw report
```

When the log shows a pattern a composed tool replaces, the report names it:
4+ inspection calls point at `analysis_context_pack`, 4+ listings at
`programs_overview`, 4+ decompiles at `functions_batch_decompile`, and a slow
tool at `async_mode`.

## Installation

```bash
# Install in development mode
cd /path/to/GhydraMCP
pip install -e .

# After installation, reshim if using asdf
asdf reshim
```

## `ghydra stats` — what the session actually did

The bridge records one JSON object per MCP tool call under
`~/.ghydra/telemetry.jsonl` (local only — nothing is sent anywhere; disable
with `GHYDRA_TELEMETRY=0`). The log is capped at about 1 MB.

```bash
ghydra stats                    # calls, failures, latency, tokens per tool
ghydra stats --days 30          # a wider window
ghydra stats --reset            # delete the local log, then report
ghydra --json stats             # the raw report
```

When the log shows a pattern a composed tool replaces, the report names it:
4+ inspection calls point at `analysis_context_pack`, 4+ listings at
`programs_overview`, 4+ decompiles at `functions_batch_decompile`, and a slow
tool at `async_mode`.

## Quick Start

```bash
# List all Ghidra instances
ghydra instances list

# Decompile a function
ghydra functions decompile --name main

# Read memory as hex dump
ghydra memory read --address 0x401000 --length 64

# Get JSON output for scripting
ghydra --json functions list
```

## `ghydra stats` — what the session actually did

The bridge records one JSON object per MCP tool call under
`~/.ghydra/telemetry.jsonl` (local only — nothing is sent anywhere; disable
with `GHYDRA_TELEMETRY=0`). The log is capped at about 1 MB.

```bash
ghydra stats                    # calls, failures, latency, tokens per tool
ghydra stats --days 30          # a wider window
ghydra stats --reset            # delete the local log, then report
ghydra --json stats             # the raw report
```

When the log shows a pattern a composed tool replaces, the report names it:
4+ inspection calls point at `analysis_context_pack`, 4+ listings at
`programs_overview`, 4+ decompiles at `functions_batch_decompile`, and a slow
tool at `async_mode`.

## Global Options

These are options on the **root** command, so they must come **before** the subcommand —
`ghydra --json functions list`, not `ghydra functions list --json` (the latter errors with a
usage error, since no subcommand redefines them):

- `--host, -h TEXT`: Ghidra host (default: from config or localhost)
- `--port, -p INTEGER`: Ghidra port (default: from config or 8192)
- `--json`: Output raw JSON instead of formatted text
- `--no-color`: Disable colored output (also honored via the `NO_COLOR` environment variable)
- `--verbose, -v`: Enable verbose output
- `--version`: Show version and exit
- `--help`: Show help message

## `ghydra stats` — what the session actually did

The bridge records one JSON object per MCP tool call under
`~/.ghydra/telemetry.jsonl` (local only — nothing is sent anywhere; disable
with `GHYDRA_TELEMETRY=0`). The log is capped at about 1 MB.

```bash
ghydra stats                    # calls, failures, latency, tokens per tool
ghydra stats --days 30          # a wider window
ghydra stats --reset            # delete the local log, then report
ghydra --json stats             # the raw report
```

When the log shows a pattern a composed tool replaces, the report names it:
4+ inspection calls point at `analysis_context_pack`, 4+ listings at
`programs_overview`, 4+ decompiles at `functions_batch_decompile`, and a slow
tool at `async_mode`.

## Agent / programmatic use

For scripts and AI agents, prefer one of these so output is parse-clean:

- `--json` is the recommended programmatic path: structured output you can pipe to `jq`, e.g. `ghydra --json functions list | jq '.result[].name'`.
- Colored (ANSI) output is auto-disabled whenever stdout is not a terminal (a pipe, a file, or a subprocess capture), so the default table output is already clean when captured by an agent. Color appears only in an interactive terminal.
- `--no-color` (or `NO_COLOR=1`) forces plain output even in a terminal, if you want tables without ANSI styling.

Earlier versions forced ANSI color codes on regardless of the output target, which corrupted hex-address parsing when an agent captured the output; that is fixed.

## `ghydra stats` — what the session actually did

The bridge records one JSON object per MCP tool call under
`~/.ghydra/telemetry.jsonl` (local only — nothing is sent anywhere; disable
with `GHYDRA_TELEMETRY=0`). The log is capped at about 1 MB.

```bash
ghydra stats                    # calls, failures, latency, tokens per tool
ghydra stats --days 30          # a wider window
ghydra stats --reset            # delete the local log, then report
ghydra --json stats             # the raw report
```

When the log shows a pattern a composed tool replaces, the report names it:
4+ inspection calls point at `analysis_context_pack`, 4+ listings at
`programs_overview`, 4+ decompiles at `functions_batch_decompile`, and a slow
tool at `async_mode`.

## Configuration

Configuration file: `~/.ghydra/config.json`

Example configuration:
```json
{
  "default_host": "localhost",
  "default_port": 8192,
  "timeout": 10,
  "use_colors": true,
  "page_output": true,
  "max_pagination": 100,
  "kuna": {
    "enabled": false,
    "path": ""
  }
}
```

Environment variables:
- `GHYDRA_HOST`: Override default Ghidra host
- `GHYDRA_PORT`: Override default Ghidra port
- `GHYDRA_KUNA`: Enable the Kuna decompiler integration (`1`, `true`, `yes`, `on`)
- `GHYDRA_KUNA_PATH`: Path to the `kuna` executable
- `GHYDRA_KUNA_TIMEOUT`: Timeout in seconds for a Kuna call (default: 900)

The `kuna` section of the config file wins over the environment: `"enabled": false` keeps the
Kuna integration off even when `GHYDRA_KUNA=1` is set, and `kuna.path` overrides
`GHYDRA_KUNA_PATH`. A config file without an `enabled` value leaves the decision to the
environment.

## `ghydra stats` — what the session actually did

The bridge records one JSON object per MCP tool call under
`~/.ghydra/telemetry.jsonl` (local only — nothing is sent anywhere; disable
with `GHYDRA_TELEMETRY=0`). The log is capped at about 1 MB.

```bash
ghydra stats                    # calls, failures, latency, tokens per tool
ghydra stats --days 30          # a wider window
ghydra stats --reset            # delete the local log, then report
ghydra --json stats             # the raw report
```

When the log shows a pattern a composed tool replaces, the report names it:
4+ inspection calls point at `analysis_context_pack`, 4+ listings at
`programs_overview`, 4+ decompiles at `functions_batch_decompile`, and a slow
tool at `async_mode`.

## Implemented Command Groups

### Instances Commands

Manage multiple Ghidra instances:

```bash
# List all instances (auto-discovers on ports 8192-8201)
ghydra instances list

# Discover instances on custom range
ghydra instances discover --start-port 8192 --end-port 8220

# Discover on different host
ghydra instances discover --host 192.168.1.100

# Register an instance manually
ghydra instances register --port 8195

# Set current working instance
ghydra instances use --port 8195

# Get current instance info
ghydra instances current

# Unregister an instance
ghydra instances unregister --port 8195
```

### Scripts Commands

Run Java GhidraScript or Python 3 (PyGhidra) scripts. Disabled server-side by
default: start Ghidra with `-Dghydra.dev.allowScripts=true` (or
`GHYDRA_ALLOW_SCRIPTS=1`). Running a script is arbitrary code execution.

```bash
ghydra scripts list
ghydra scripts run --name FixupNoReturnFunctionsScript.java
ghydra scripts run --file ./MassRename.java --arg prefix_
ghydra scripts run --file ./probe.py                     # .py selects Python 3
ghydra scripts run --filename probe.py --language python --code "println('hi')"
```

`--language` accepts `java` (default) or `python`. A `.py` `--file`/`--filename`
also selects Python 3 and is forwarded so the server preserves the extension —
sending only the source text used to lose it and produce a `.java` file. Python
3 requires Ghidra launched through `pyghidraRun`; installing the extension alone
does not initialize the Python runtime.

### Functions Commands

Analyze and manipulate functions:

```bash
# List all functions
ghydra functions list

# List with filtering
ghydra functions list --name-contains main
ghydra functions list --name-matches "^sub_.*"
ghydra functions list --limit 50

# Get function details
ghydra functions get --name main
ghydra functions get --address 0x401000

# Decompile function
ghydra functions decompile --name main
ghydra functions decompile --address 0x401000
ghydra functions decompile --name main --start-line 10 --end-line 20
ghydra functions decompile --name main --max-lines 50

# Disassemble function
ghydra functions disassemble --name main
ghydra functions disassemble --address 0x401000

# Create function
ghydra functions create --address 0x401500

# Rename function
ghydra functions rename --old-name sub_401000 --new-name main
ghydra functions rename --address 0x401000 --new-name main

# Set function signature
ghydra functions set-signature --name main --signature "int main(int argc, char **argv)"

# Get function variables
ghydra functions get-variables --name main

# Rename or retype a local variable (by function name or address)
ghydra functions set-variable --name main --variable size --data-type "uint32_t"
ghydra functions set-variable --address 0x401000 --variable i --new-name index

# Get the control-flow graph (basic blocks and edges)
ghydra functions get-cfg --name main
ghydra functions get-cfg --address 0x401000

# Get decompiled p-code operations (runs a real decompilation)
ghydra functions get-pcode --name main
ghydra functions get-pcode --address 0x401000

# Set function comment
ghydra functions set-comment --address 0x401000 --comment "Main entry point"
```

> `set-variable` is the single command for renaming or retyping a local variable. (The older
> `update-variable`, which required `--address` and used `--variable-name`/`--new-data-type`,
> was removed in 3.0.0 — use `set-variable`, which also accepts `--name`.)

### The four composed commands

Four commands that answer a question in one call, where the pieces were all there and the agent
paid a call for each. They close the four native gaps against the REA — the comparison is in
[REA_PARITY.md](REA_PARITY.md).

```bash
# Decompile a list of functions in one call
ghydra functions decompile-batch --targets '["main","0x401000"]'
ghydra functions decompile-batch --targets main,strcmp

# The references to a name, resolved and collected
ghydra xrefs find-by-name strlen
ghydra xrefs find-by-name "FOM::Read"

# What is at this address: the symbol, the function, the data, the code,
# the comments and the references on both sides
ghydra inspect-address 0x140001008

# How does A reach B
ghydra analysis trace-call-path --from main --to strcmp
ghydra analysis trace-call-path --from 0x401000 --to 0x402000 --max-depth 12
```

| Command | Endpoint | Notes |
| --- | --- | --- |
| `ghydra functions decompile-batch --targets` | `POST /functions/decompile-batch` | the targets are JSON text, a comma-separated list or one name; a target that resolves to nothing is reported as a failed entry and the rest are still decompiled |
| `ghydra xrefs find-by-name NAME` | `GET /xrefs/to-name/{name}` | a bare name matches every namespace, a qualified one matches that namespace; a name that resolves to nothing is a 404 |
| `ghydra inspect-address ADDRESS` | `GET /inspect/address/{address}` | one traversal, one answer |
| `ghydra analysis trace-call-path --from --to` | `GET /analysis/call-path` | the shortest path Ghidra knows about; `--max-depth` is at most 16 |

And four more that came out of the same comparison with the REA — the composed calls:

```bash
# Who calls this function, and what does it call?
ghydra analysis callers 0x140001008
ghydra analysis callees 0x1400373f0

# A page of them, when there are more than the page holds
ghydra analysis callers 0x140027bc0 --offset 0 --limit 50

# Everything about one function: the decompilation, the callers, the callees, the references
ghydra functions analyze --address 0x140001008
ghydra functions analyze --name main

# What is this binary: what it is, how it is laid out, how much is in it, what it imports
ghydra analysis overview
```

| Command | Endpoint | Notes |
| --- | --- | --- |
| `ghydra analysis callers ADDR` | `GET /analysis/callers/{address}` | the functions that reach this one; `--offset` and `--limit` take a page, and the answer says how many there are in total when the page holds fewer |
| `ghydra analysis callees ADDR` | `GET /analysis/callees/{address}` | the functions this one calls; `--offset` and `--limit` take a page |
| `ghydra functions analyze --name/--address` | several | one call that gathers the function, its decompilation, its callers, its callees and its references |
| `ghydra analysis overview` | several | the program, its segments, its counts and its imports |

### Raw Image Commands

Define raw image data so a captured framebuffer renders inline in the Listing view. Added in 3.0.0.

```bash
# Define a raw image at an address
ghydra raw-image define --address 0x401000 --width 128 --height 64 --format RGB565

# 320x240 ARGB8888, big-endian byte order
ghydra raw-image define -a 0x402000 --width 320 --height 240 --format ARGB8888 --endian big

# Always pair with --json for scripting
ghydra --json raw-image define -a 0x401000 --width 64 --height 64 --format RGB565
```

Options:

- `--address` / `-a` (**required**): where the image data starts.
- `--width` / `--height` (**required**): dimensions in pixels, both positive.
- `--format`: `RGB565` (default), `RGB888`, `ARGB8888`, `RGB332`, `ARGB4444`,
  `1bpp`, `2bpp`, `4bpp`, `8bpp`, and the descriptive aliases `1bpp_Monochrome`,
  `2bpp_Grayscale`, `4bpp_Grayscale`, `8bpp_Grayscale`.
- `--endian`: `little` (default) or `big`.

Backs `POST /raw-image/define`. The command clears any code units overlapping the target
range and creates the data in a single transaction.

```bash
# Remove the raw image at one address
ghydra raw-image cleanup --address 0x401000

# Sweep every RawImage in the program
ghydra raw-image cleanup --all

# Machine-readable
ghydra --json raw-image cleanup --all
```

Options:

- `--address` / `-a`: the raw image to clear. Required unless `--all`.
- `--all`: clear every RawImage data item in the program.

Backs `POST /raw-image/cleanup`. Clearing a code unit leaves the bytes **undefined** — nothing is
deleted. Collection and clearing run in one transaction, so a failure part-way through `--all`
rolls the whole sweep back. Cleaning up when nothing is defined reports `removed: 0` rather than
failing. `addresses` is capped at 100 in the response (`addressesTruncated` flags when the cap
bites), but `removed` and `bytes` always reflect the full sweep.

Passing `--address` where something other than a RawImage is defined is an error — the CLI will
not clear an unrelated data item.

### Kuna Commands

Drive the [Kuna](https://github.com/Noelo-Lab/kuna) decompiler CLI directly. These commands run on
this machine and need **no Ghidra instance** — useful for a file that is not open in Ghidra, a
packed sample, or a second opinion on a function.

The integration is opt-in, because it lets the CLI run a program on the host:

```bash
export GHYDRA_KUNA=1
```

or in `~/.ghydra/config.json`:

```json
{ "kuna": { "enabled": true, "path": "/usr/local/bin/kuna" } }
```

The config file wins when both are set. `ghydra kuna status` reports which one decided.

```bash
# Is the integration enabled, and which binary did it resolve?
ghydra kuna status

# Size up a binary: function count, entry point, reachability
ghydra kuna summary ./challenge.exe

# List the recovered functions
ghydra kuna functions ./challenge.exe --limit 20
ghydra kuna functions ./challenge.exe --name main

# Decompile one function
ghydra kuna decompile ./challenge.exe main
ghydra kuna decompile ./challenge.exe 0x401000 --addr

# Disassemble and read bytes
ghydra kuna disassemble ./challenge.exe main
ghydra kuna read ./challenge.exe 0x401000 --bytes 32

# Search strings (the pattern is required: an unfiltered scan is huge)
ghydra kuna strings ./challenge.exe '(?i)password|flag'

# Find crypto constants and the functions that use them
ghydra kuna crypto ./challenge.exe --algorithm AES

# Cross-references of a symbol
ghydra kuna xrefs ./challenge.exe main --direction to

# Unpack a UPX image
ghydra kuna unpack ./packed.exe -o ./unpacked.exe

# Machine-readable
ghydra --json kuna summary ./challenge.exe
```

Kuna loads and analyses the whole image on every invocation, so a large binary costs seconds per
call. Export it once and read the result from disk instead:

```bash
# Analyse once, write the recovered C, the disassembly and an index to disk
ghydra kuna export ./challenge.exe -o ./challenge.kuna

# Then read from the export
ghydra kuna export-read ./challenge.kuna main
ghydra kuna export-read ./challenge.kuna main --artifact asm
ghydra kuna export-read ./challenge.kuna --artifact index
```

Without `-o`, the export goes to `~/.ghydra/kuna/<digest of path and mtime>/`, so re-analysing the
same file reuses the same directory — and, in fact, reuses the export that is already there
instead of analysing the binary again. The digest is 12 hex characters and it is enough to read
the export:

```bash
ghydra kuna status                    # lists the exports on this machine with their digests
ghydra kuna export-read 9f2c1a4b7e03 main
```

## `ghydra stats` — what the session actually did

The bridge records one JSON object per MCP tool call under
`~/.ghydra/telemetry.jsonl` (local only — nothing is sent anywhere; disable
with `GHYDRA_TELEMETRY=0`). The log is capped at about 1 MB.

```bash
ghydra stats                    # calls, failures, latency, tokens per tool
ghydra stats --days 30          # a wider window
ghydra stats --reset            # delete the local log, then report
ghydra --json stats             # the raw report
```

When the log shows a pattern a composed tool replaces, the report names it:
4+ inspection calls point at `analysis_context_pack`, 4+ listings at
`programs_overview`, 4+ decompiles at `functions_batch_decompile`, and a slow
tool at `async_mode`.

## x64dbg Commands

The `x64dbg` group drives the [x64dbg MCP server](https://github.com/duty1g/x64dbg-mcp-server), the
plugin that lives inside the debugger. It is local: no Ghidra instance is involved for the
debugger itself, but the workflow commands read the image base from Ghidra.

```bash
# Is the debugger there, and what is it looking at
ghydra x64dbg status

# The plugin's catalogue: eighty tools, with their schemas
ghydra x64dbg tools

# Call any of them by name
ghydra x64dbg call GetAllRegisters
ghydra x64dbg call SetBreakpoint --arg target=0x7FF7A1234000
ghydra x64dbg call ReadMemory --json-args '{"address": "0x7FF7A1234000", "size": 64}'

# The tools that block need more time than the default 30 seconds
ghydra x64dbg call WaitForEvent --json-args '{"timeoutMs": 60000}' --timeout 90

# How the Ghidra program and the x64dbg session line up
ghydra x64dbg target

# A breakpoint on a Ghidra address, translated into the runtime address
ghydra x64dbg breakpoint 0x140001234

# Move the instruction pointer there
ghydra x64dbg go-to 0x140001234

# Machine-readable
ghydra --json x64dbg target
```

The addresses are the **static** ones — the addresses Ghidra shows. The translation is
`runtime = static − image_base + module_base`, and the two binaries are matched by full path
first and by file name second.

An address is read as hexadecimal however it is written, so `0x140001234` and `140001234` are
the same number. `--arg` sends strings only: a parameter the plugin wants as a number needs
`--json-args`.

The plugin wants a bearer token, and it writes it to its own `mcp_config.json`. Pointing at the
installation is enough:

```json
{
  "x64dbg": {
    "path": "C:/tools/x64dbg"
  }
}
```

`"host"`, `"port"` and `"token"` set it outright, and `GHYDRA_X64DBG_HOST`, `GHYDRA_X64DBG_PORT`
and `GHYDRA_X64DBG_TOKEN` do the same from the environment. The config file wins.

**[GHYDRA_X64DBG.md](GHYDRA_X64DBG.md)** is the full reference.

### Doctor, Inspect, Evidence and Session Commands

```bash
# Is everything in place on this machine, and what is not?
ghydra doctor

# What is this target, and what does it need?
ghydra inspect C:\bin\cmd.exe

# Record a finding, and give it an ID
ghydra evidence add --kind function --address 0x140001000 \
    --name decrypt_blob --note "the key comes from the serial" --tags crypto

# What was found
ghydra evidence list --tag crypto

# Take the findings with you
ghydra evidence export --output out

# Open a binary and keep it available under a name
ghydra session open C:\bin\cmd.exe --name cmd

# What is open
ghydra session list

# End it; the analysis is saved first
ghydra session close s-3f9a21c4
```

| Command | What it does |
| --- | --- |
| `ghydra doctor` | checks the installation, the JDK it needs, the extension, the port, the project directory, the API, Kuna and the x64dbg plugin; every problem carries the command that solves it |
| `ghydra inspect <target>` | identifies a file from its bytes - a PE, an ELF, a Mach-O, a DEX, an APK, a WASM module, an EVM contract, a firmware image, a JavaScript or Electron application, a core dump, a plist, a HAR capture - and says what each one needs |
| `ghydra evidence add` | records a finding and gives it an ID (`EV-0001`) that never changes and is never given out twice |
| `ghydra evidence list` | filters the findings by kind, tag, address or text |
| `ghydra evidence export` | writes the ledger as a bundle: a Markdown document to read and a JSON one to read with a program |
| `ghydra session open` | analyses a binary and keeps it available under a name; the session outlives the shell that opened it |
| `ghydra session list` | the sessions, and what state they are in |
| `ghydra session close` | ends a session, saving the analysis on the way out |

The `doctor` exits with a non-zero status when something is wrong, so it can be used as a gate.

## `ghydra stats` — what the session actually did

The bridge records one JSON object per MCP tool call under
`~/.ghydra/telemetry.jsonl` (local only — nothing is sent anywhere; disable
with `GHYDRA_TELEMETRY=0`). The log is capped at about 1 MB.

```bash
ghydra stats                    # calls, failures, latency, tokens per tool
ghydra stats --days 30          # a wider window
ghydra stats --reset            # delete the local log, then report
ghydra --json stats             # the raw report
```

When the log shows a pattern a composed tool replaces, the report names it:
4+ inspection calls point at `analysis_context_pack`, 4+ listings at
`programs_overview`, 4+ decompiles at `functions_batch_decompile`, and a slow
tool at `async_mode`.

## The other command groups

The following command groups follow the same pattern as `instances` and `functions`.

### Headless Commands

Run the GhidraMCP API without a window. A headless Ghidra run imports and analyses the binary and
then serves the same REST API the CodeBrowser plugin serves. See
[GHYDRA_HEADLESS.md](GHYDRA_HEADLESS.md) for the full reference.

```bash
# Analyse a binary and serve the API on 8192
ghydra headless start C:\bin\cmd.exe --port 8192

# What is running
ghydra headless status

# End it; the analysis is saved first
ghydra headless stop
```

| Option | What it is |
| --- | --- |
| `--port`, `-p` | the port to serve on (default: 8192) |
| `--project-dir` | where the Ghidra project lives (default: `~/ghidra_projects`) |
| `--project-name` | the name of the project (default: the name of the binary, with a mark of its path) |
| `--ghidra-home` | the Ghidra installation (default: `GHIDRA_HOME`) |
| `--java-home` | the JDK (default: `JAVA_HOME`) |
| `--timeout` | how long to wait for the API, in seconds (default: 900) |

The project goes to `ghidra_projects` in your home directory: Ghidra refuses a project path with an
element that starts with a dot, so `~/.ghidra` is not a place a project can live.

### Report Commands

Build a report on a binary: Ghidra and Kuna side by side, and the annotations for the debugger.

```bash
# The whole report: the document, the data and the annotations
ghydra report build C:\bin\cmd.exe --output out

# Without Kuna
ghydra report build C:\bin\cmd.exe --no-kuna
```

| Option | What it is |
| --- | --- |
| `--output`, `-o` | where the files go (default: the current directory) |
| `--port`, `-p` | the port of the Ghidra instance (default: 8192) |
| `--ghidra-home` | the Ghidra installation (default: `GHIDRA_HOME`) |
| `--java-home` | the JDK (default: `JAVA_HOME`) |
| `--timeout` | how long to wait for the analysis and the API (default: 900) |
| `--no-kuna` | do not run Kuna; the report carries Ghidra alone |
| `--no-headless` | do not start a headless run; use the instance that is already there |
| `--keep` | leave the headless run running when the report is done |
| `--max-functions` | how many functions to read (default: 400) |
| `--max-strings` | how many strings to read (default: 300) |
| `--max-decompile` | how many functions to decompile (default: 12) |
| `--max-annotations` | how many annotations to prepare (default: 60) |

The three files are `<name>-report.md`, `<name>-report.json` and `<name>-x64dbg.json`.

### x64dbg Report and Annotations

Take down what the debugger is doing, and put the annotations of a report into it.

```bash
# The snapshot: state, registers, modules, breakpoints, disassembly, stack, memory map
ghydra x64dbg report --output out

# Put the annotations of a report into the debugger
ghydra x64dbg annotate out\cmd-x64dbg.json --bookmarks
```

| Option | What it is |
| --- | --- |
| `--output`, `-o` | where the files go (default: the current directory) |
| `--name` | the name of the files (default: `x64dbg-report`) |
| `--instructions` | how many instructions to disassemble (default: 16) |

The annotations take the addresses in the file — the ones in the binary — and translate them into
the addresses of the live process. `--mode Label` sets labels instead of comments, and `--limit`
says how many of them to apply.

### Headless Commands

Run the GhidraMCP API without a window. A headless Ghidra run imports and analyses the binary and
then serves the same REST API the CodeBrowser plugin serves. See
[GHYDRA_HEADLESS.md](GHYDRA_HEADLESS.md) for the full reference.

```bash
# Analyse a binary and serve the API on 8192
ghydra headless start C:\bin\cmd.exe --port 8192

# What is running
ghydra headless status

# End it; the analysis is saved first
ghydra headless stop
```

| Option | What it is |
| --- | --- |
| `--port`, `-p` | the port to serve on (default: 8192) |
| `--project-dir` | where the Ghidra project lives (default: `~/ghidra_projects`) |
| `--project-name` | the name of the project (default: the name of the binary, with a mark of its path) |
| `--ghidra-home` | the Ghidra installation (default: `GHIDRA_HOME`) |
| `--java-home` | the JDK (default: `JAVA_HOME`) |
| `--timeout` | how long to wait for the API, in seconds (default: 900) |

The project goes to `ghidra_projects` in your home directory: Ghidra refuses a project path with an
element that starts with a dot, so `~/.ghidra` is not a place a project can live.

### Report Commands

Build a report on a binary: Ghidra and Kuna side by side, and the annotations for the debugger.

```bash
# The whole report: the document, the data and the annotations
ghydra report build C:\bin\cmd.exe --output out

# Without Kuna
ghydra report build C:\bin\cmd.exe --no-kuna
```

| Option | What it is |
| --- | --- |
| `--output`, `-o` | where the files go (default: the current directory) |
| `--port`, `-p` | the port of the Ghidra instance (default: 8192) |
| `--ghidra-home` | the Ghidra installation (default: `GHIDRA_HOME`) |
| `--java-home` | the JDK (default: `JAVA_HOME`) |
| `--timeout` | how long to wait for the analysis and the API (default: 900) |
| `--no-kuna` | do not run Kuna; the report carries Ghidra alone |
| `--no-headless` | do not start a headless run; use the instance that is already there |
| `--keep` | leave the headless run running when the report is done |
| `--max-functions` | how many functions to read (default: 400) |
| `--max-strings` | how many strings to read (default: 300) |
| `--max-decompile` | how many functions to decompile (default: 12) |
| `--max-annotations` | how many annotations to prepare (default: 60) |

The three files are `<name>-report.md`, `<name>-report.json` and `<name>-x64dbg.json`.

### x64dbg Report and Annotations

Take down what the debugger is doing, and put the annotations of a report into it.

```bash
# The snapshot: state, registers, modules, breakpoints, disassembly, stack, memory map
ghydra x64dbg report --output out

# Put the annotations of a report into the debugger
ghydra x64dbg annotate out\cmd-x64dbg.json --bookmarks
```

| Option | What it is |
| --- | --- |
| `--output`, `-o` | where the files go (default: the current directory) |
| `--name` | the name of the files (default: `x64dbg-report`) |
| `--instructions` | how many instructions to disassemble (default: 16) |

The annotations take the addresses in the file — the ones in the binary — and translate them into
the addresses of the live process. `--mode Label` sets labels instead of comments, and `--limit`
says how many of them to apply.

### 1. Memory Commands (`ghydra/cli/memory.py`)

```python
"""Memory operations commands."""

import click
from ..client.exceptions import GhidraError
from ..utils import should_page, page_output


@click.group('memory')
def memory():
    """Memory read/write commands."""
    pass


@memory.command('read')
@click.option('--address', '-a', required=True, help='Memory address (hex)')
@click.option('--length', type=int, default=16, help='Number of bytes to read')
@click.option('--format', type=click.Choice(['hex', 'base64', 'string']), default='hex', help='Output format')
@click.pass_context
def read_memory(ctx, address, length, format):
    """Read bytes from memory.

    Examples:
        ghydra memory read --address 0x401000
        ghydra memory read --address 0x401000 --length 64
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {
            'length': length,
            'format': format
        }

        response = client.get(f'memory/{address.lstrip("0x")}', params=params)
        output = formatter.format_memory(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        click.echo(error_output, err=True)
        ctx.exit(1)


@memory.command('write')
@click.option('--address', '-a', required=True, help='Memory address (hex)')
@click.option('--bytes-data', required=True, help='Data to write')
@click.option('--format', type=click.Choice(['hex', 'base64', 'string']), default='hex', help='Input format')
@click.pass_context
def write_memory(ctx, address, bytes_data, format):
    """Write bytes to memory (use with caution).

    Examples:
        ghydra memory write --address 0x401000 --bytes-data "4883EC10"
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        data = {
            'bytes': bytes_data,
            'format': format
        }

        response = client.post(f'memory/{address.lstrip("0x")}', json_data=data)
        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        click.echo(error_output, err=True)
        ctx.exit(1)
```

Then add to `main.py`:
```python
from . import instances, functions, memory

cli.add_command(memory.memory)
```

### 2. Data Commands (`ghydra/cli/data.py`)

```python
@click.group('data')
def data():
    """Data item management commands."""
    pass

@data.command('list')
# Add options: --offset, --limit, --addr, --name, --name-contains, --type
# Endpoint: GET /data with params

@data.command('list-strings')
# Options: --offset, --limit, --filter
# Endpoint: GET /data/strings

@data.command('create')
# Options: --address, --data-type, --size
# Endpoint: POST /data/{address}

@data.command('rename')
# Options: --address, --name
# Endpoint: PATCH /data/{address}

@data.command('delete')
# Options: --address
# Endpoint: DELETE /data/{address}

@data.command('set-type')
# Options: --address, --data-type
# Endpoint: PATCH /data/{address}/type
```

### 3. Structs Commands (`ghydra/cli/structs.py`)

```python
@click.group('structs')
def structs():
    """Struct data type management commands."""
    pass

@structs.command('list')
# Options: --offset, --limit, --category
# Endpoint: GET /structs

@structs.command('get')
# Options: --name
# Endpoint: GET /structs/{name}

@structs.command('create')
# Options: --name, --category, --description
# Endpoint: POST /structs

@structs.command('add-field')
# Options: --struct-name, --field-name, --field-type, --offset, --comment
# Endpoint: POST /structs/{struct_name}/fields

@structs.command('update-field')
# Options: --struct-name, --field-name OR --field-offset, --new-name, --new-type, --new-comment
# Endpoint: PATCH /structs/{struct_name}/fields/{field_name_or_offset}

@structs.command('delete')
# Options: --name
# Endpoint: DELETE /structs/{name}
```

### 4. Xrefs Commands (`ghydra/cli/xrefs.py`)

```python
@click.group('xrefs')
def xrefs():
    """Cross-reference analysis commands."""
    pass

@xrefs.command('list')
# Options: --to-addr, --from-addr, --type, --offset, --limit
# Endpoint: GET /xrefs with params
# Note: At least one of --to-addr or --from-addr required
```

### 5. Analysis Commands (`ghydra/cli/analysis.py`)

```python
@click.group('analysis')
def analysis():
    """Program analysis commands."""
    pass

@analysis.command('run')
# Options: --analysis-options (JSON dict)
# Endpoint: POST /analysis

@analysis.command('get-callgraph')
# Options: --name, --address, --max-depth
# Endpoint: GET /analysis/callgraph/{name_or_address}

@analysis.command('get-dataflow')
# Options: --address, --direction (forward/backward), --max-steps
# Endpoint: GET /analysis/dataflow/{address}

@analysis.command('status')
# Endpoint: GET /analysis/status
```

### 6. UI Commands (`ghydra/cli/ui.py`)

```python
@click.group('ui')
def ui():
    """UI integration commands."""
    pass

@ui.command('get-current-address')
# Endpoint: GET /ui/current-address

@ui.command('get-current-function')
# Endpoint: GET /ui/current-function
```

### 7. Comments Commands (`ghydra/cli/comments.py`)

```python
@click.group('comments')
def comments():
    """Comment management commands."""
    pass

@comments.command('set')
# Options: --address, --comment, --comment-type (plate/pre/post/eol/repeatable)
# Endpoint: POST /comments/{address}
```

### 8. Project Commands (`ghydra/cli/project.py`)

```python
@click.group('project')
def project():
    """Project management commands."""
    pass

@project.command('info')
# Endpoint: GET /project

@project.command('list-files')
# Options: --folder, --recursive, --offset, --limit
# Endpoint: GET /project/files

@project.command('open-file')
# Options: --path
# Endpoint: POST /project/open
```

## `ghydra stats` — what the session actually did

The bridge records one JSON object per MCP tool call under
`~/.ghydra/telemetry.jsonl` (local only — nothing is sent anywhere; disable
with `GHYDRA_TELEMETRY=0`). The log is capped at about 1 MB.

```bash
ghydra stats                    # calls, failures, latency, tokens per tool
ghydra stats --days 30          # a wider window
ghydra stats --reset            # delete the local log, then report
ghydra --json stats             # the raw report
```

When the log shows a pattern a composed tool replaces, the report names it:
4+ inspection calls point at `analysis_context_pack`, 4+ listings at
`programs_overview`, 4+ decompiles at `functions_batch_decompile`, and a slow
tool at `async_mode`.

## Implementation Pattern

All command groups follow the same pattern:

1. **Create command group file** in `ghydra/cli/`
2. **Define Click group** with `@click.group('name')`
3. **Add commands** with `@group.command('command-name')`
4. **Use context** with `@click.pass_context` to access client and formatter
5. **Handle errors** with try/except and `GhidraError`
6. **Format output** using `formatter.format_*()` methods
7. **Page long output** using `should_page()` and `page_output()`
8. **Import and register** in `main.py`

## `ghydra stats` — what the session actually did

The bridge records one JSON object per MCP tool call under
`~/.ghydra/telemetry.jsonl` (local only — nothing is sent anywhere; disable
with `GHYDRA_TELEMETRY=0`). The log is capped at about 1 MB.

```bash
ghydra stats                    # calls, failures, latency, tokens per tool
ghydra stats --days 30          # a wider window
ghydra stats --reset            # delete the local log, then report
ghydra --json stats             # the raw report
```

When the log shows a pattern a composed tool replaces, the report names it:
4+ inspection calls point at `analysis_context_pack`, 4+ listings at
`programs_overview`, 4+ decompiles at `functions_batch_decompile`, and a slow
tool at `async_mode`.

## Output Formatting

The CLI supports two output modes:

### Default Mode (Rich Terminal Output)

- Tables with colored columns
- Syntax-highlighted code (C and assembly)
- Panels for detailed info
- Tree views for structured data
- Hex dumps for memory
- Auto-paging for long output

### JSON Mode (`--json` flag)

- Raw JSON output from API
- Pretty-printed by default
- Suitable for scripting and automation
- Can be piped to `jq` for processing

## `ghydra stats` — what the session actually did

The bridge records one JSON object per MCP tool call under
`~/.ghydra/telemetry.jsonl` (local only — nothing is sent anywhere; disable
with `GHYDRA_TELEMETRY=0`). The log is capped at about 1 MB.

```bash
ghydra stats                    # calls, failures, latency, tokens per tool
ghydra stats --days 30          # a wider window
ghydra stats --reset            # delete the local log, then report
ghydra --json stats             # the raw report
```

When the log shows a pattern a composed tool replaces, the report names it:
4+ inspection calls point at `analysis_context_pack`, 4+ listings at
`programs_overview`, 4+ decompiles at `functions_batch_decompile`, and a slow
tool at `async_mode`.

## Testing Against Running Ghidra

To test the CLI against a running Ghidra instance:

1. **Start Ghidra** with GhydraMCP plugin loaded
2. **Open a binary** in CodeBrowser
3. **Test basic commands**:
   ```bash
   ghydra instances list
   ghydra functions list --limit 10
   ghydra functions decompile --address <some_address>
   ```

4. **Test JSON output**:
   ```bash
   ghydra --json functions list | jq '.result[0]'
   ```

5. **Test error handling**:
   ```bash
   ghydra --port 9999 instances current  # Should fail gracefully
   ghydra functions get --name nonexistent  # Should show error
   ```

## `ghydra stats` — what the session actually did

The bridge records one JSON object per MCP tool call under
`~/.ghydra/telemetry.jsonl` (local only — nothing is sent anywhere; disable
with `GHYDRA_TELEMETRY=0`). The log is capped at about 1 MB.

```bash
ghydra stats                    # calls, failures, latency, tokens per tool
ghydra stats --days 30          # a wider window
ghydra stats --reset            # delete the local log, then report
ghydra --json stats             # the raw report
```

When the log shows a pattern a composed tool replaces, the report names it:
4+ inspection calls point at `analysis_context_pack`, 4+ listings at
`programs_overview`, 4+ decompiles at `functions_batch_decompile`, and a slow
tool at `async_mode`.

## API Endpoint Reference

Reference `bridge_mcp_hydra.py` for the exact endpoint patterns:

- **Functions**: `/functions`, `/functions/{address}`, `/functions/by-name/{name}`
- **Memory**: `/memory/{address}`
- **Data**: `/data`, `/data/strings`, `/data/{address}`
- **Structs**: `/structs`, `/structs/{name}`, `/structs/{name}/fields`
- **Xrefs**: `/xrefs`
- **Analysis**: `/analysis`, `/analysis/callgraph/{address}`, `/analysis/dataflow/{address}`
- **UI**: `/ui/current-address`, `/ui/current-function`
- **Comments**: `/comments/{address}`
- **Project**: `/project`, `/project/files`, `/project/open`
- **Instances**: `/plugin-version`, `/program`

## `ghydra stats` — what the session actually did

The bridge records one JSON object per MCP tool call under
`~/.ghydra/telemetry.jsonl` (local only — nothing is sent anywhere; disable
with `GHYDRA_TELEMETRY=0`). The log is capped at about 1 MB.

```bash
ghydra stats                    # calls, failures, latency, tokens per tool
ghydra stats --days 30          # a wider window
ghydra stats --reset            # delete the local log, then report
ghydra --json stats             # the raw report
```

When the log shows a pattern a composed tool replaces, the report names it:
4+ inspection calls point at `analysis_context_pack`, 4+ listings at
`programs_overview`, 4+ decompiles at `functions_batch_decompile`, and a slow
tool at `async_mode`.

## Tips for Implementation

1. **Copy existing patterns**: Use `instances.py` or `functions.py` as templates
2. **Check MCP bridge**: Reference `bridge_mcp_hydra.py` for exact parameter names and endpoint paths
3. **Test incrementally**: Implement one command at a time and test
4. **Handle mutual exclusivity**: Use Click's validation for mutually exclusive options (like `--name` vs `--address`)
5. **Use formatters**: Ensure `TableFormatter` has appropriate `format_*()` methods for each response type
6. **Page output**: Long listings should use paging for better UX
7. **Error messages**: Provide helpful error messages for common mistakes

## `ghydra stats` — what the session actually did

The bridge records one JSON object per MCP tool call under
`~/.ghydra/telemetry.jsonl` (local only — nothing is sent anywhere; disable
with `GHYDRA_TELEMETRY=0`). The log is capped at about 1 MB.

```bash
ghydra stats                    # calls, failures, latency, tokens per tool
ghydra stats --days 30          # a wider window
ghydra stats --reset            # delete the local log, then report
ghydra --json stats             # the raw report
```

When the log shows a pattern a composed tool replaces, the report names it:
4+ inspection calls point at `analysis_context_pack`, 4+ listings at
`programs_overview`, 4+ decompiles at `functions_batch_decompile`, and a slow
tool at `async_mode`.

## Development Workflow

```bash
# Make changes to code
# Reinstall in development mode
pip install -e .
asdf reshim  # If using asdf

# Test immediately
ghydra <command>

# Check help text
ghydra <group> <command> --help
```

## `ghydra stats` — what the session actually did

The bridge records one JSON object per MCP tool call under
`~/.ghydra/telemetry.jsonl` (local only — nothing is sent anywhere; disable
with `GHYDRA_TELEMETRY=0`). The log is capped at about 1 MB.

```bash
ghydra stats                    # calls, failures, latency, tokens per tool
ghydra stats --days 30          # a wider window
ghydra stats --reset            # delete the local log, then report
ghydra --json stats             # the raw report
```

When the log shows a pattern a composed tool replaces, the report names it:
4+ inspection calls point at `analysis_context_pack`, 4+ listings at
`programs_overview`, 4+ decompiles at `functions_batch_decompile`, and a slow
tool at `async_mode`.

## Architecture

```
ghydra/
├── __init__.py
├── cli/
│   ├── __init__.py
│   ├── main.py          # Main CLI group with global options
│   ├── instances.py     # ✅ Implemented (6 commands)
│   ├── functions.py     # ✅ Implemented (8 commands)
│   ├── memory.py        # ⏳ TODO (2 commands)
│   ├── data.py          # ⏳ TODO (6 commands)
│   ├── structs.py       # ⏳ TODO (6 commands)
│   ├── xrefs.py         # ⏳ TODO (1 command)
│   ├── analysis.py      # ⏳ TODO (4 commands)
│   ├── ui.py            # ⏳ TODO (2 commands)
│   ├── comments.py      # ⏳ TODO (2 commands)
│   └── project.py       # ⏳ TODO (3 commands)
├── client/
│   ├── __init__.py
│   ├── http_client.py   # ✅ HTTP client with connection pooling
│   ├── exceptions.py    # ✅ Custom exceptions
│   └── models.py        # ✅ Data models
├── formatters/
│   ├── __init__.py
│   ├── base.py          # ✅ Base formatter interface
│   ├── json_formatter.py    # ✅ JSON formatter
│   └── table_formatter.py   # ✅ Table formatter with rich
├── config/
│   ├── __init__.py
│   ├── config_manager.py    # ✅ Config file management
│   └── defaults.py      # ✅ Default configuration
└── utils/
    ├── __init__.py
    ├── pager.py         # ✅ Output paging
    └── validators.py    # ✅ Input validation
```

## `ghydra stats` — what the session actually did

The bridge records one JSON object per MCP tool call under
`~/.ghydra/telemetry.jsonl` (local only — nothing is sent anywhere; disable
with `GHYDRA_TELEMETRY=0`). The log is capped at about 1 MB.

```bash
ghydra stats                    # calls, failures, latency, tokens per tool
ghydra stats --days 30          # a wider window
ghydra stats --reset            # delete the local log, then report
ghydra --json stats             # the raw report
```

When the log shows a pattern a composed tool replaces, the report names it:
4+ inspection calls point at `analysis_context_pack`, 4+ listings at
`programs_overview`, 4+ decompiles at `functions_batch_decompile`, and a slow
tool at `async_mode`.

## Contributing

When implementing remaining command groups:

1. Follow the established patterns in `instances.py` and `functions.py`
2. Add appropriate formatters to `table_formatter.py` if needed
3. Update this README with usage examples
4. Test against running Ghidra instance
5. Ensure help text is clear and includes examples

## `ghydra stats` — what the session actually did

The bridge records one JSON object per MCP tool call under
`~/.ghydra/telemetry.jsonl` (local only — nothing is sent anywhere; disable
with `GHYDRA_TELEMETRY=0`). The log is capped at about 1 MB.

```bash
ghydra stats                    # calls, failures, latency, tokens per tool
ghydra stats --days 30          # a wider window
ghydra stats --reset            # delete the local log, then report
ghydra --json stats             # the raw report
```

When the log shows a pattern a composed tool replaces, the report names it:
4+ inspection calls point at `analysis_context_pack`, 4+ listings at
`programs_overview`, 4+ decompiles at `functions_batch_decompile`, and a slow
tool at `async_mode`.

## License

Same as GhydraMCP project.

## Reproducible runbooks and diffs (R6)

A runbook is a sequence of API calls with a digest of every answer: recording it
turns a session into a file that can be versioned, and replaying it says what
changed.

```bash
ghydra runbook record -s steps.json -o sample.ghydrarb.jsonl
ghydra runbook replay sample.ghydrarb.jsonl                  # what moved
ghydra runbook replay sample.ghydrarb.jsonl --fail-on-change # CI gate
ghydra runbook show sample.ghydrarb.jsonl                    # no calls made
ghydra analysis diff --a-port 8192 --b-port 8193
```

`steps.json` is a list (or `{"steps": [...]}`) of
`{"endpoint": "...", "method": "GET|POST|PATCH|PUT|DELETE", "params": {...}, "payload": {...}}`.

`ghydra analysis diff` compares two instances on the program fingerprint, the
functions (by address; a rename is reported as a rename), the imports and the
defined strings. `--no-strings` skips the last comparison, and `--a-host`/
`--b-host` reach instances on another machine. A listing that could not be read
to its end is reported as a floor, never as a removal.

## Source-to-sink hypotheses (R5)

```bash
ghydra analysis taint --source recv --sink system
ghydra analysis taint -s ReadFile -t WinExec --max-depth 4
```

Composes the references to both names, the pcode of the functions that call
them and the call graph, and reports candidate flows with a confidence —
`direct` (both calls in one function, sink after source), `reachable` (a call
path connects them) or `weak` (the sink precedes the source, or the bounded
search gave up). Every hypothesis carries its evidence addresses.

This is a **lead generator, not a verdict**: branches are not modelled and a
"nothing found" answer is not evidence of safety. The text answer says both
things.