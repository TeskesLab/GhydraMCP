# GhydraMCP — Kuna integration

[Kuna](https://github.com/Noelo-Lab/kuna) is a standalone decompiler CLI. GhydraMCP can drive it
directly, with no Ghidra instance involved: the `kuna_*` MCP tools and the `ghydra kuna` command
group shell out to the `kuna` binary on the machine where GhydraMCP runs.

That makes it useful for a file that is not open in Ghidra, a packed sample, a second opinion on
a function, or a quick triage of something someone just handed over. Because nothing here goes
through the plugin, it also works against any Ghidra version.

- [Enable it](#enable-it)
- [Two ways to use it](#two-ways-to-use-it)
- [The MCP tools](#the-mcp-tools)
- [The CLI commands](#the-cli-commands)
- [The export layout](#the-export-layout)
- [Performance](#performance)
- [Limits and gotchas](#limits-and-gotchas)
- [Troubleshooting](#troubleshooting)

## Enable it

The integration is **opt-in**, because it lets GhydraMCP run a program on the host. The bridge
normally only speaks HTTP to Ghidra; this lets it launch a decompiler.

Two ways to turn it on, and the config file wins when both are set:

```bash
# the environment variable
export GHYDRA_KUNA=1
```

```json
{
  "kuna": {
    "enabled": true,
    "path": "/usr/local/bin/kuna"
  }
}
```

The config file lives in `~/.ghydra/config.json` and is the same file the CLI uses. A config file
that carries no `enabled` value (or a null one) leaves the decision to the environment; an
explicit `true` or `false` in the file always wins.

| Source | Effect |
| --- | --- |
| `GHYDRA_KUNA=1` in the environment | Enables the integration |
| `"kuna": {"enabled": true}` in the config | Enables the integration |
| `"kuna": {"enabled": false}` in the config | Disables it, even with the env var set |
| `"kuna": {"path": "..."}` in the config | Points at a specific `kuna` binary |
| `GHYDRA_KUNA_PATH` in the environment | Same, lower precedence than the config |
| `GHYDRA_KUNA_TIMEOUT` in the environment | Timeout in seconds for a Kuna call (default: 900) |

Check what is in force at any time:

```bash
ghydra kuna status
```

```
Kuna integration: enabled (opt-in via $GHYDRA_KUNA)
Binary: /usr/local/bin/kuna  [kuna 1.785]
Config: /home/you/.ghydra/config.json
Work:   /home/you/.ghydra/kuna
```

The binary is resolved in this order: the configured path, `GHYDRA_KUNA_PATH`, `kuna` on `PATH`,
and finally the common Scoop install locations. If none of them has a `kuna` binary, the tools
report it instead of failing obscurely.

## Two ways to use it

**One shot.** Every command re-analyses the image. That is fine for a small file and for a
single question:

```bash
ghydra kuna summary ./challenge.exe
ghydra kuna decompile ./challenge.exe main
```

**Export once, then read.** Kuna loads and analyses the whole image on every invocation, so on a
large binary each one-shot call pays the full analysis cost. The export flow analyses the file
once, writes the result to disk, and every later read is a file read:

```bash
ghydra kuna export ./challenge.exe -o ./challenge.kuna
ghydra kuna export-read ./challenge.kuna main
```

This is the main path for anything but a small binary. The MCP bridge exposes the same flow as
`kuna_export_start`, `kuna_export_status` and `kuna_export_read`.

## The MCP tools

Thirteen tools, in the `kuna_*` namespace. They are **local**: none of them takes a `port`
parameter, and none of them needs a Ghidra instance.

| Tool | What it does | Parameters |
| --- | --- | --- |
| `kuna_status` | Whether the integration is on, which binary it resolved, which opt-in decided | — |
| `kuna_summary` | Function count, entry point, reachability, code size | `binary_path`, `mode` |
| `kuna_functions` | The functions Kuna recovered | `binary_path`, `name_filter`, `offset`, `limit` |
| `kuna_decompile` | One function, as C | `binary_path`, `function`, `addr`, `mode`, `max_lines` |
| `kuna_disassemble` | One function or an address range | `binary_path`, `target`, `count`, `bytes`, `addr`, `mode` |
| `kuna_read` | Raw bytes, as a hex dump | `binary_path`, `target`, `bytes`, `addr` |
| `kuna_strings` | Strings matching a regular expression | `binary_path`, `pattern`, `limit`, `min_length`, `encoding`, `section` |
| `kuna_crypto` | Crypto constants and the functions that use them | `binary_path`, `algorithm`, `section` |
| `kuna_xrefs` | Cross-references of a symbol or address | `binary_path`, `target`, `direction`, `kind` |
| `kuna_unpack` | Unpack a UPX image | `binary_path`, `output` |
| `kuna_export_start` | Export a binary in the background | `binary_path`, `functions`, `jobs`, `job_id` |
| `kuna_export_status` | Progress of an export job | `job_id` |
| `kuna_export_read` | Read a function out of an export | `job_id`, `function`, `artifact`, `max_bytes` |

Notes on the arguments:

- `target` is a function name, an address, or a `0xstart-0xend` range. Pass `addr` when the value
  is an address, so Kuna does not look it up as a name.
- `direction` is `from` (who references this) or `to` (what this references).
- `artifact` is `c` (recovered C), `asm` (disassembly), `index` (the function list) or `readme`
  (the export report). Without a `function`, the tool lists what the export holds.
- `mode` is one of Kuna's own presets: `auto`, `reliable`, `aggressive`, `fast`.
- `encoding` is `ascii`, `utf16` or `all`.

`kuna_strings` **requires** a pattern. An unfiltered scan of a large binary returns hundreds of
kilobytes of text, which is noise rather than an answer.

## The CLI commands

```bash
ghydra kuna status
ghydra kuna summary      <binary> [--mode MODE]
ghydra kuna functions    <binary> [--name TEXT] [--offset N] [--limit N]
ghydra kuna decompile    <binary> <function> [--addr] [--mode MODE]
ghydra kuna disassemble  <binary> <target> [--count N] [--bytes N] [--addr] [--mode MODE]
ghydra kuna read         <binary> <target> [--bytes N] [--addr]
ghydra kuna strings      <binary> <pattern> [--limit N] [--min-length N] [--encoding E] [--section S]
ghydra kuna crypto       <binary> [--algorithm A] [--section S]
ghydra kuna xrefs        <binary> <target> [--direction from|to] [--kind K]
ghydra kuna unpack       <binary> [--output PATH]
ghydra kuna export       <binary> [--output DIR] [--functions NAMES] [--jobs N|auto]
ghydra kuna export-read  <directory> [function] [--artifact c|asm|index|readme] [--max-bytes N]
```

`--json` works as everywhere else, and has to come **before** the subcommand:

```bash
ghydra --json kuna summary ./challenge.exe
```

A few examples:

```bash
# size up a binary
ghydra kuna summary ./challenge.exe

# find the function you are after
ghydra kuna functions ./challenge.exe --name main --limit 20

# decompile it
ghydra kuna decompile ./challenge.exe main

# the strings that mention the flag
ghydra kuna strings ./challenge.exe '(?i)password|flag'

# where the AES table is used
ghydra kuna crypto ./challenge.exe --algorithm AES

# what calls this function
ghydra kuna xrefs ./challenge.exe main --direction to

# analyse once, then read from disk
ghydra kuna export ./challenge.exe -o ./challenge.kuna
ghydra kuna export-read ./challenge.kuna main --artifact asm
```

## The export layout

`kuna decompile-project` writes a directory with the recovered C, the disassembly and an index:

| File | What it holds |
| --- | --- |
| `index.jsonl` | One JSON object per function, appended after that function's C block is complete |
| `<stem>.c` | The recovered C for every function |
| `<stem>.h` | Prototypes and the recompile prelude |
| `<stem>.asm` | The disassembly and the data bytes |
| `README.md` | Image details, progress and success/failure counts |
| `.streaming` | Live status, present only while the export runs |

An index record looks like this:

```json
{"seq": 0, "name": "sub_140027b90", "addr": "0x140027b90", "size": 48, "c_offset": 22, "c_len": 122, "error": null}
```

`c_offset` and `c_len` slice the `.c` file to exactly that function's block, so an index line is
also the proof that the block is complete. Only newline-terminated records are read: an
unfinished last record is deferred until the next read.

Without `-o`, the export goes to `~/.ghydra/kuna/<hash of path and mtime>/`, so re-analysing the
same file reuses the same directory and a rebuilt file gets a fresh one.

The MCP side uses the same layout. `kuna_export_start` returns a job id, `kuna_export_status`
reports the progress, and `kuna_export_read` serves the files. The job registry lives in the
bridge process: a job started by one bridge is invisible to another, and it does not survive a
restart. The CLI has no registry at all — `ghydra kuna export` runs synchronously and
`export-read` works off the directory.

## Performance

Measured on this machine, with Kuna 1.785:

| Binary | Size | `summary` | `crypto` | `decompile` |
| --- | --- | --- | --- | --- |
| `cmd.exe` | 332 KB | 691 ms | 43 ms | 492 ms |
| `kuna.exe` | 22 MB, 50 122 functions | 19 475 ms | 19 035 ms | 10 529 ms |

The cost is the analysis of the whole image, and it is paid on **every** invocation — Kuna keeps
no state between calls. A 22 MB binary costs about twenty seconds per question asked one-shot.
Exporting it once and reading the files afterwards turns every later question into a file read.

## Limits and gotchas

- **The recovered C is an estimate.** Verify the answer-critical branches, widths, signedness and
  indirect calls against the disassembly (`kuna_disassemble`, or `--artifact asm`) or against
  observed execution.
- **`kuna_strings` needs a filter**, for the reason above.
- **A single answer is capped at 8 MiB** of JSON. A wider request is refused rather than pushed
  into the agent's context; narrow it, or export and read the files.
- **The `kuna_*` tools take no `port`.** They are not part of the plugin API, so they take no
  Ghidra instance either.
- **Kuna's own options are the ones that matter.** `--mode reliable` is slower and more careful
  than `auto`; `--mode fast` is the opposite. The tools pass `mode` straight through.
- **The bridge must run on the machine that has the binary.** The path is a local filesystem path,
  not something to be fetched from a Ghidra instance.

## Troubleshooting

**"the Kuna integration is disabled"** — the opt-in did not reach this process. Set
`GHYDRA_KUNA=1` in the environment the bridge runs in, or add the `kuna` section to
`~/.ghydra/config.json`. `ghydra kuna status` shows which of the two decided.

**"the kuna binary was not found"** — the path is wrong, or Kuna is not installed. Check the
resolved path in `ghydra kuna status`, and set `"kuna": {"path": "..."}` in the config if it
lives somewhere unusual.

**"unknown job id"** — the job belongs to another bridge process, or the bridge restarted. The
registry is in memory. Export again, or use the directory directly with
`ghydra kuna export-read`.

**"the export has no index yet"** — the export is still running, or it failed. `kuna_export_status`
reports the phase and the live counters.

**A tool returns nothing for a function** — the name may be a generated one (`sub_<addr>`) rather
than a symbol. `kuna_functions` lists what Kuna actually recovered.

## Tests

```bash
python run_tests.py --kuna
```

The suite needs neither Ghidra nor the Kuna binary, so it always runs and always gives a signal.
It covers the opt-in precedence, the bridge/CLI contract and the export readers.
