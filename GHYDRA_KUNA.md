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
Binary: /usr/local/bin/kuna  [kuna 1.988]
Config: /home/you/.ghydra/config.json
Work:   /home/you/.ghydra/kuna

Exports on disk (1):
  9f2c1a4b7e03  818 functions  /home/you/challenge.exe
    kuna://export/9f2c1a4b7e03/index.jsonl
```

The version is whatever is installed - the numbers above are illustrative. The exports listing is
read from disk, so it is there after a restart and it is the same list the MCP resources expose.

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

Exporting the same binary again **reuses** the export that is already on disk instead of
analysing it again. The export is named after a digest of the path and the modification time, so
`ghydra kuna export-read 9f2c1a4b7e03 main` works without knowing where the directory is.

This is the main path for anything but a small binary. The MCP bridge exposes the same flow as
`kuna_export_start`, `kuna_export_status` and `kuna_export_read`, and the exports themselves as
the `kuna://export/` resources.

## The MCP tools

Thirteen tools, in the `kuna_*` namespace. They are **local**: none of them takes a `port`
parameter, and none of them needs a Ghidra instance.

| Tool | What it does | Parameters |
| --- | --- | --- |
| `kuna_status` | Whether the integration is on, which binary it resolved, which opt-in decided, the export jobs and the exports on disk | — |
| `kuna_summary` | Function count, entry point, reachability, code size | `binary_path`, `mode` |
| `kuna_functions` | The functions Kuna recovered | `binary_path`, `name_filter`, `offset`, `limit` |
| `kuna_decompile` | One function, as C | `binary_path`, `function`, `addr`, `mode`, `max_lines` |
| `kuna_disassemble` | One function or an address range | `binary_path`, `target`, `count`, `bytes`, `addr`, `mode` |
| `kuna_read` | Raw bytes, as a hex dump | `binary_path`, `target`, `bytes`, `addr` |
| `kuna_strings` | Strings matching a regular expression | `binary_path`, `pattern`, `limit`, `min_length`, `encoding`, `section` |
| `kuna_crypto` | Crypto constants and the functions that use them | `binary_path`, `algorithm`, `section` |
| `kuna_xrefs` | Cross-references of a symbol or address | `binary_path`, `target`, `direction`, `kind` |
| `kuna_unpack` | Unpack a UPX image | `binary_path`, `output` |
| `kuna_export_start` | Export a binary in the background, or reuse the export that is already there | `binary_path`, `functions`, `jobs`, `job_id` |
| `kuna_export_status` | Progress of an export job | `job_id` |
| `kuna_export_read` | Read a function out of an export | `job_id`, `function`, `artifact`, `max_bytes`, `directory` |

Notes on the arguments:

- `target` is a function name, an address, or a `0xstart-0xend` range. Pass `addr` when the value
  is an address, so Kuna does not look it up as a name.
- `direction` is `from` (who references this) or `to` (what this references).
- `artifact` is `c` (recovered C), `asm` (disassembly), `index` (the function list) or `readme`
  (the export report). Without a `function`, the tool lists what the export holds.
- `mode` is one of Kuna's own presets: `auto`, `reliable`, `aggressive`, `fast`.
- `encoding` is `ascii`, `utf16` or `all`.
- `job_id` addresses an export by the job that made it. `directory` addresses it by its path or by
  the 12-character digest it is named after, and **outlives the bridge process**: a job id does
  not, so an export written by the CLI is reachable only through `directory`. Give one of the two.

`kuna_strings` **requires** a pattern. An unfiltered scan of a large binary returns hundreds of
kilobytes of text, which is noise rather than an answer.

## The MCP resources

The export is the durable artifact: the analysis is expensive and the files on disk are the cheap
way to read it. The job registry is not durable - it lives in the bridge process - so the export
is also exposed as **MCP resources**, addressed by the digest it is named after.

| Resource | What it holds |
| --- | --- |
| `kuna://exports` | Every export on this machine, as a JSON manifest: digest, binary, function count |
| `kuna://export/{digest}/index.jsonl` | The function index of one export |
| `kuna://export/{digest}/{function}.c` | The recovered C of one function |
| `kuna://export/{digest}/{function}.asm` | The disassembly of one function |
| `kuna://export/{digest}/README.md` | The report Kuna wrote next to the export |

The retrieval loop is the RAG loop with **exact** addressing, not a similarity search:

1. read `kuna://exports` - which binaries have been exported
2. read `kuna://export/<digest>/index.jsonl` - the function list, one small read
3. read `kuna://export/<digest>/<function>.c` - that one function

Nothing is pulled into the agent's context that the agent did not ask for by name, and every step
is a file read rather than a fresh analysis. The decompiled program has an exact index, so an
embedding search would retrieve the *wrong* function more often than the right one.

A function name goes into the URI percent-encoded, because a name may hold a slash and the URI
may not. `sub_140027b90` needs no encoding; a name like `ns/fn` becomes `ns%2Ffn`.

The resources are served even when the export was made by the CLI, or by an earlier version of
the bridge: the digest is the only identifier that matters.

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

`<directory>` is a directory or the 12-character digest of one. `ghydra kuna status` lists the
exports on this machine with their digests.

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
| `.ghydra.json` | Which binary the export came from, written by the CLI and the bridge |

An index record looks like this:

```json
{"seq": 0, "name": "sub_140027b90", "addr": "0x140027b90", "size": 48, "c_offset": 22, "c_len": 122, "error": null}
```

`c_offset` and `c_len` slice the `.c` file to exactly that function's block, so an index line is
also the proof that the block is complete. Only newline-terminated records are read: an
unfinished last record is deferred until the next read.

## The digest, and why the export is reused

Without `-o`, the export goes to `~/.ghydra/kuna/<digest>/`, where the digest is a hash of the
path and the modification time: twelve hex characters. A rebuilt binary gets a fresh digest, and
the same file keeps its own.

That digest is the identity of the export. It is what `kuna_export_read(directory=...)` accepts,
what the `kuna://export/<digest>/` resources are addressed by, and what `ghydra kuna status`
lists. It outlives the bridge process, which a job id does not.

The digest also makes the export **reusable**. `kuna_export_start` and `ghydra kuna export` look
for a complete export under the digest first, and only run the analysis when there is none, or
when the one on disk does not hold the functions that were asked for. The report says which
happened with `"reused": true` or `false`.

This is the single most valuable thing in the integration. A 44 MB binary costs about twenty
seconds to analyse, and about two and a half minutes to export; reading an export that already
exists costs milliseconds.

An export is complete when it has an index and is not still being streamed: a streamed export
appends a record only after that function's C block is done, so an index without the `.streaming`
marker is a finished one.

The sidecar `.ghydra.json` records which binary the export came from, because the digest is a
hash and cannot be reversed. An export made before the sidecar existed still names its binary in
the `README.md` that Kuna writes, and that is where the listing falls back to.

## The MCP side

The MCP side uses the same layout. `kuna_export_start` returns a job id, `kuna_export_status`
reports the progress, and `kuna_export_read` serves the files - by job id, or by the directory or
digest. The job registry lives in the bridge process: a job started by one bridge is invisible to
another, and it does not survive a restart. The CLI has no registry at all - `ghydra kuna export`
runs synchronously and `export-read` works off the directory or the digest.

Because the digest survives, the two sides can read each other's exports. An export made by the
CLI is readable by the bridge, and the other way round.

## Performance

Measured with Kuna **1.988**, as the median of three runs, on the commands the integration
actually runs. The numbers are that version's; a newer Kuna may differ, so re-measure before
quoting them. `scripts/bench_kuna.py` is what produced them, and it is in the repository so the
numbers can be re-measured instead of quoted:

```bash
python scripts/bench_kuna.py --repeat 3 --with-export
```

| Binary | Size | `summary` | `crypto` | `decompile` |
| --- | --- | --- | --- | --- |
| `cmd.exe` | 332 KB, 1 118 functions | 501 ms | 21 ms | 369 ms |
| `kuna.exe` | 44 MB, 67 686 functions | 20 410 ms | 20 489 ms | 9 352 ms |

The cost is the analysis of the whole image, and it is paid on **every** invocation — Kuna keeps
no state between calls. A 44 MB binary costs about twenty seconds per question asked one-shot.

Exporting it once and reading the files afterwards turns every later question into a file read:

| Binary | Export (the analysis) | Re-read of that export |
| --- | --- | --- |
| `cmd.exe` | 2 750 ms | 21 ms |
| `kuna.exe` | 154 018 ms | 152 ms |

The export is the expensive half: it recovers the C of **every** function, and 67 686 of them take
about two and a half minutes. The re-read is the cheap half, and it is what the digest is for. It
costs about 21 ms for a small binary and about 152 ms for a 44 MB one — the index has 67 686
records to read, so it is not free either.

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
- **`max_lines` caps the answer, not the work.** It is applied to the text after the function has
  been fetched, so it saves context but no time. It is not passed to Kuna.
- **The bridge must run on the machine that has the binary.** The path is a local filesystem path,
  not something to be fetched from a Ghidra instance.
- **The timeout differs between the two sides.** On the bridge `GHYDRA_KUNA_TIMEOUT` falls back
  to `GHYDRA_TIMEOUT`; on the CLI it is a fixed 900 seconds and `ghydra config set timeout` does
  not change it.

## Troubleshooting

**"the Kuna integration is disabled"** — the opt-in did not reach this process. Set
`GHYDRA_KUNA=1` in the environment the bridge runs in, or add the `kuna` section to
`~/.ghydra/config.json`. `ghydra kuna status` shows which of the two decided, and says
"nothing (the integration is off)" when neither did.

**"the kuna binary was not found"** — the path is wrong, or Kuna is not installed. Check the
resolved path in `ghydra kuna status`, and set `"kuna": {"path": "..."}` in the config if it
lives somewhere unusual.

**"unknown job id"** — the job belongs to another bridge process, or the bridge restarted. The
registry is in memory. Address the export by its digest or its directory instead:
`kuna_export_read(directory="9f2c1a4b7e03")`, or `ghydra kuna export-read 9f2c1a4b7e03`.

**"the export has no index yet"** — the export is still running, or it failed. `kuna_export_status`
reports the phase and the live counters, and the exports listing in `kuna_status` marks a
streaming export.

**A tool returns nothing for a function** — the name may be a generated one (`sub_<addr>`) rather
than a symbol. `kuna_functions` lists what Kuna actually recovered.

## Failures carry a code

Every failure has a machine-readable code, the same on the bridge and on the CLI:

| Code | What it means |
| --- | --- |
| `KUNA_DISABLED` | The opt-in did not reach this process |
| `KUNA_MISSING` | The kuna binary is not installed |
| `KUNA_TIMEOUT` | Kuna ran past its timeout |
| `KUNA_LAUNCH` | Kuna could not be started at all |
| `KUNA_FAILED` | Kuna ran and failed |
| `KUNA_NO_JSON` | Kuna printed something that is not JSON |
| `KUNA_TOO_LARGE` | The answer is above the 8 MiB cap |
| `KUNA_NO_FILE` | A file the call named does not exist |
| `KUNA_IO` | Reading or writing a file failed |
| `KUNA_NO_DIR` | The export directory does not exist |
| `KUNA_NO_INDEX` | The export has no index yet |
| `KUNA_BAD_ARTIFACT` | The artifact name is not one of the four |
| `KUNA_NO_FUNCTION` | The function is not in the export index |

An agent can branch on the reason instead of reading prose.

## Tests

```bash
python run_tests.py --kuna
```

The suite needs neither Ghidra nor the Kuna binary, so it always runs and always gives a signal.
It covers the opt-in precedence, the bridge/CLI contract and the export readers.

The performance table above is not part of the suite — it needs the Kuna binary and minutes of
analysis. `scripts/bench_kuna.py` measures it on demand.
