# The cheat sheet

One line per command. **Generated** from the CLI itself by
`scripts/gen_cheatsheet.py`, so a command listed here exists — and `--check`
fails when it stops existing.

The summary of each line is the first line of its `--help`, which is the text the
CLI prints. Read [GHYDRA_CLI.md](GHYDRA_CLI.md) for the arguments of any one of
them, and [GHYDRA_RECIPES.md](GHYDRA_RECIPES.md) for the jobs that combine them.

## The ones you will actually use

| Command | What it does |
| --- | --- |
| `ghydra instances list` | List all known Ghidra instances with automatic discovery. |
| `ghydra functions decompile` | Decompile a function to C pseudocode. |
| `ghydra functions analyze` | Everything about one function, in one call. |
| `ghydra analysis overview` | An overview of the loaded binary. |
| `ghydra analysis context-pack` | Answer one question about the binary in a single budgeted dossier. |
| `ghydra analysis capabilities-summary` | Rank ATT&CK/MBC-style capability leads for the loaded binary. |
| `ghydra analysis taint` | Hypothesise whether data from SOURCE reaches SINK (R5). |
| `ghydra assert` | Assert facts about the binary and exit non-zero when one fails. |
| `ghydra mission start` | Run a mission from the beginning. |
| `ghydra runbook record` | Call each step once and write a replayable runbook. |
| `ghydra fleet overview` | What each instance has open, merged by file. |
| `ghydra bsim ingest` | Generate signatures for the open program and insert them (R1). |
| `ghydra bsim query` | Which stored functions look like this one (R1). |
| `ghydra twin build` | Take a snapshot of the instance's program. |
| `ghydra inspect` | Say what TARGET is, and what it needs. |
| `ghydra doctor` | Check that everything is in place, and say what is not. |
| `ghydra headless start` | Analyse BINARY and serve the API from it. |
| `ghydra headless stop` | Stop the headless run on the port. |
| `ghydra report build` | Build the report on BINARY. |
| `ghydra x64dbg status` | Show whether the x64dbg MCP server is reachable, and what it has. |
| `ghydra kuna status` | Show whether the Kuna integration is enabled and ready to use. |

## Every command

`172` commands in `42` groups.

| Command | What it does |
| --- | --- |
| `ghydra analysis callees` | Get the functions this function calls. |
| `ghydra analysis callers` | Get the functions that call this function. |
| `ghydra analysis capabilities-summary` | Rank ATT&CK/MBC-style capability leads for the loaded binary. |
| `ghydra analysis context-pack` | Answer one question about the binary in a single budgeted dossier. |
| `ghydra analysis diff` | Compare two instances and report what changed (R6). |
| `ghydra analysis get-callgraph` | Get function call graph visualization data. |
| `ghydra analysis get-dataflow` | Perform data flow analysis from an address. |
| `ghydra analysis overview` | An overview of the loaded binary. |
| `ghydra analysis run` | Run analysis on the current program. |
| `ghydra analysis status` | Get analysis status for the current program. |
| `ghydra analysis taint` | Hypothesise whether data from SOURCE reaches SINK (R5). |
| `ghydra analysis trace-call-path` | Trace how one function reaches another. |
| `ghydra assert` | Assert facts about the binary and exit non-zero when one fails. |
| `ghydra audit` | Show the mutations the plugin allowed, newest last. |
| `ghydra bsim apply-match` | Apply the exact prepared signature/types in one native transaction. |
| `ghydra bsim apply-names` | Name a function after the stored function it most resembles (R1). |
| `ghydra bsim batch-query` | Search only the explicitly selected source entries; never bulk apply. |
| `ghydra bsim compare-match` | Compare one selected match without applying names, signatures or types. |
| `ghydra bsim diff` | What changed between two versions, paired by signature (R1). |
| `ghydra bsim ingest` | Generate signatures for the open program and insert them (R1). |
| `ghydra bsim overview` | Rank BSim matches within one address-ordered page, never globally. |
| `ghydra bsim prepare-apply` | Preview one selected match's native signature/types without applying them. |
| `ghydra bsim query` | Which stored functions look like this one (R1). |
| `ghydra bsim status` | Is a BSim signature query possible, and against which database. |
| `ghydra cache clear` | Remove every cached answer. |
| `ghydra cache path` | Print the directory the cache lives in. |
| `ghydra cache stats` | Show how many answers are cached and how much space they take. |
| `ghydra classes list` | List classes and namespaces. |
| `ghydra comments get` | Get a comment at specified address. |
| `ghydra comments set` | Set a comment at specified address. |
| `ghydra connections create` | Create an approved endpoint and prompt for credentials without echo. |
| `ghydra connections inspect` | Inspect approved metadata; never print credential references or values. |
| `ghydra connections list` | List approved worker IDs remotely, or inspect an operator's explicit store. |
| `ghydra connections remove` | Remove an endpoint and its credentials without contacting its server. |
| `ghydra connections rotate` | Replace only credentials, preserving approved endpoint and grants. |
| `ghydra connections update` | Replace all metadata AND credentials (no old secret fields are retained). |
| `ghydra data create` | Define a new data item at specified address. |
| `ghydra data delete` | Delete data at specified address. |
| `ghydra data list` | List defined data items with optional filtering. |
| `ghydra data list-strings` | List all defined strings in the binary. |
| `ghydra data rename` | Rename a data item. |
| `ghydra data search` | Search for data items by name. |
| `ghydra data set-type` | Set the data type of a data item. |
| `ghydra datatypes create-enum` | Create an enum datatype. |
| `ghydra datatypes create-struct` | Create a struct datatype. |
| `ghydra datatypes create-union` | Create a union datatype. |
| `ghydra datatypes list` | List data types defined in the program. |
| `ghydra datatypes search` | Search for data types by name. |
| `ghydra doctor` | Check that everything is in place, and say what is not. |
| `ghydra evidence add` | Record a finding, and give it an ID. |
| `ghydra evidence export` | Export the ledger as a bundle. |
| `ghydra evidence ledgers` | Every ledger that exists. |
| `ghydra evidence list` | The findings of a ledger. |
| `ghydra fleet has-function` | Which of the fleet's binaries contain this function. |
| `ghydra fleet has-import` | Which of the fleet's binaries import this symbol. |
| `ghydra fleet has-string` | Which of the fleet's binaries contain this string. |
| `ghydra fleet overview` | What each instance has open, merged by file. |
| `ghydra fleet xrefs-to` | How many references to this name each binary has. |
| `ghydra functions analyze` | Everything about one function, in one call. |
| `ghydra functions create` | Create a new function at specified address. |
| `ghydra functions decompile` | Decompile a function to C pseudocode. |
| `ghydra functions decompile-batch` | Decompile a list of functions in one call. |
| `ghydra functions delete` | Delete a function. |
| `ghydra functions disassemble` | Get disassembly for a function. |
| `ghydra functions get` | Get detailed information about a function. |
| `ghydra functions get-cfg` | Get control flow graph (basic blocks and edges). |
| `ghydra functions get-containing` | Find the function containing the specified address. |
| `ghydra functions get-next` | Get the next function after the given address (by memory order). |
| `ghydra functions get-pcode` | Get pcode operations (low-level intermediate representation). |
| `ghydra functions get-prev` | Get the previous function before the given address (by memory order). |
| `ghydra functions get-variables` | Get variables for a function. |
| `ghydra functions list` | List all functions with optional filtering. |
| `ghydra functions rename` | Rename a function. |
| `ghydra functions search` | Search for functions by name. |
| `ghydra functions set-comment` | Set a decompiler-friendly comment at a function. |
| `ghydra functions set-signature` | Set function signature/prototype. |
| `ghydra functions set-variable` | Rename or change the type of a function variable. |
| `ghydra headless start` | Analyse BINARY and serve the API from it. |
| `ghydra headless status` | What is running on the port. |
| `ghydra headless stop` | Stop the headless run on the port. |
| `ghydra inspect` | Say what TARGET is, and what it needs. |
| `ghydra inspect-address` | Say what is at ADDRESS, in one call. |
| `ghydra instances capabilities` | Describe what this instance can do (capability negotiation). |
| `ghydra instances current` | Get information about the current working instance. |
| `ghydra instances discover` | Discover Ghidra instances on a specific host. |
| `ghydra instances list` | List all known Ghidra instances with automatic discovery. |
| `ghydra instances register` | Register a new Ghidra instance. |
| `ghydra instances unregister` | Unregister a Ghidra instance. |
| `ghydra instances use` | Set the current working Ghidra instance. |
| `ghydra kuna crypto` | Scan a binary for crypto constants with Kuna. |
| `ghydra kuna decompile` | Decompile one function with Kuna. |
| `ghydra kuna disassemble` | Disassemble a function or an address range with Kuna. |
| `ghydra kuna export` | Export a binary to disk with Kuna. |
| `ghydra kuna export-read` | Read a function out of a Kuna export. |
| `ghydra kuna functions` | List the functions Kuna recovered from a binary. |
| `ghydra kuna read` | Read raw bytes with Kuna, as a hex dump. |
| `ghydra kuna status` | Show whether the Kuna integration is enabled and ready to use. |
| `ghydra kuna strings` | Search the strings of a binary with Kuna. |
| `ghydra kuna summary` | Summarize a binary: function count, entry point, reachability, size. |
| `ghydra kuna unpack` | Unpack a UPX-packed executable with Kuna. |
| `ghydra kuna xrefs` | Find the cross-references of a symbol or address with Kuna. |
| `ghydra mcp-config` | Build the combined MCP client configuration. |
| `ghydra memory disassemble` | Disassemble instructions at an arbitrary address. |
| `ghydra memory read` | Read bytes from memory. |
| `ghydra memory write` | Write bytes to memory (use with caution). |
| `ghydra mission resume` | Continue a mission from its checkpoint. |
| `ghydra mission show` | Read a dossier from its checkpoint, without calling anything. |
| `ghydra mission start` | Run a mission from the beginning. |
| `ghydra namespaces list` | List namespaces in the program. |
| `ghydra project delete-program` | Delete/close program by ID or current. |
| `ghydra project get-program` | Get program details by ID or current. |
| `ghydra project get-project` | Get project details by name. |
| `ghydra project info` | Get information about the currently open Ghidra project. |
| `ghydra project list-files` | List files in the current Ghidra project. |
| `ghydra project list-programs` | List programs. |
| `ghydra project list-projects` | List projects visible to the plugin. |
| `ghydra project open-file` | Open a file from the project in CodeBrowser. |
| `ghydra project save-program` | Save the current program to the project (persists analysis). |
| `ghydra raw-image cleanup` | Remove RawImage data items created by 'raw-image define'. |
| `ghydra raw-image define` | Define a raw image at the specified address. |
| `ghydra report build` | Build the report on BINARY. |
| `ghydra repositories checkin` | Publish saved changes from an exclusive checkout; save alone does not publish. |
| `ghydra repositories checkout` | Create an explicit native local checkout; never force an existing checkout. |
| `ghydra repositories list-files` | List one folder; response explicitly reports truncation. |
| `ghydra repositories open` | Activate a native repository program without discarding unsaved changes. |
| `ghydra repositories status` | Connect and report safe repository status and grants. |
| `ghydra runbook record` | Call each step once and write a replayable runbook. |
| `ghydra runbook replay` | Re-run a runbook and report which answers moved. |
| `ghydra runbook show` | Show what a runbook records, without running anything. |
| `ghydra scalars search` | Search for occurrences of a scalar VALUE (hex 0x... or decimal) in instructions. |
| `ghydra scripts list` | List Ghidra scripts available to run. |
| `ghydra scripts run` | Run a Ghidra script by --name, or ad-hoc from --file / --code. |
| `ghydra segments list` | List memory segments/blocks. |
| `ghydra session close` | Close a session, saving the analysis on its way out. |
| `ghydra session list` | The sessions, and what state they are in. |
| `ghydra session open` | Analyse BINARY and keep it available. |
| `ghydra session reopen` | Restart a stopped session using current approved worker credentials. |
| `ghydra stats` | Summarize what this bridge has actually done, from the local log. |
| `ghydra structs add-field` | Add a field to an existing struct. |
| `ghydra structs create` | Create a new struct data type. |
| `ghydra structs delete` | Delete a struct data type. |
| `ghydra structs get` | Get detailed information about a specific struct. |
| `ghydra structs list` | List all struct data types in the program. |
| `ghydra structs update-field` | Update an existing field in a struct. |
| `ghydra symbols exports` | List exported symbols. |
| `ghydra symbols imports` | List imported symbols. |
| `ghydra symbols list` | List all symbols in the program. |
| `ghydra target breakpoint` | Set a breakpoint in the debugger on a function Ghidra knows. |
| `ghydra target decompile` | Decompile a function on the static side, named or addressed. |
| `ghydra target describe` | Show the target as both sides see it, and whether they may be correlated. |
| `ghydra target locate` | Find a function's static address by name or by address. |
| `ghydra target run-to` | Run the debuggee to a function, and report the registers at the stop. |
| `ghydra twin build` | Take a snapshot of the instance's program. |
| `ghydra twin diff` | What changed between two snapshots, with the shared comparison. |
| `ghydra twin query` | Answer a question from a snapshot, with no Ghidra running. |
| `ghydra ui get-current-address` | Get the address currently selected in Ghidra's UI. |
| `ghydra ui get-current-function` | Get the function currently selected in Ghidra's UI. |
| `ghydra variables list` | List variables in the program. |
| `ghydra version` | Show version information. |
| `ghydra x64dbg annotate` | Put the annotations of a report into the debugger. |
| `ghydra x64dbg breakpoint` | Set a breakpoint on a Ghidra address. |
| `ghydra x64dbg call` | Call one of the x64dbg plugin's tools by name. |
| `ghydra x64dbg go-to` | Move the instruction pointer to a Ghidra address. |
| `ghydra x64dbg report` | Take a snapshot of the debugger and write it down. |
| `ghydra x64dbg setup` | Find the x64dbg plugin's settings and write them down. |
| `ghydra x64dbg status` | Show whether the x64dbg MCP server is reachable, and what it has. |
| `ghydra x64dbg target` | Show how the Ghidra program and the x64dbg session line up. |
| `ghydra x64dbg tools` | List the x64dbg plugin's tools, with the schema of each. |
| `ghydra xrefs find-by-name` | Get the cross-references to a symbol, found by name. |
| `ghydra xrefs from` | Get cross-references FROM an address. |
| `ghydra xrefs list` | List cross-references with filtering and pagination. |
| `ghydra xrefs to` | Get cross-references TO an address. |

## Regenerating

```bash
python scripts/gen_cheatsheet.py           # rewrite this document
python scripts/gen_cheatsheet.py --check   # fail when it is stale
```
