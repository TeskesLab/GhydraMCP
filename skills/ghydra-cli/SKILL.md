# Ghydra CLI Skill

Use this skill only when operating Ghidra through the `ghydra` CLI. Generic reverse engineering and MCP-only work do not activate it; MCP-only work follows the mounted tool schemas. Analysis methodology belongs to the reverse-engineering skill.

## Prerequisites

- A Ghydra worker must be running: CodeBrowser with the plugin, or a headless worker. Program analysis needs a selected program; repository browsing can precede opening one.
- Install the current CLI into an owned environment. On Nix use Nix-provided Python; on SSHFS put `UV_PROJECT_ENVIRONMENT` on local storage and invoke `uv run --python python3 python -m ghydra.cli`. See [operator setup](../../docs/GHYDRA_CONNECTIONS.md#nix-and-sshfs-checkouts).
- Default HTTP port is 8192. Native Ghidra Server repository ports are separate.

## Workflow

### 1. Always start by discovering instances

Before any other command, check what Ghidra instances are available:

```bash
ghydra instances list
```

If none are found, check/start the intended GUI or headless worker. Do not assume a CodeBrowser is required.

### 2. Target the intended instance explicitly

```bash
ghydra --host HOST --port PORT --json functions list --limit 5
```

CLI `instances use` is in-process only; it does not persist selection across shell
commands. Use root `--host`/`--port` flags or `GHYDRA_HOST`/`GHYDRA_PORT`.

### 3. Use `--json` for structured data

When you need to parse or process output programmatically, use `--json`:

```bash
ghydra --json functions list | jq '.result[0]'
```

## Remote BSim and repository workflow

- Human operators provision credentials outside the agent session. Agents use
  `connections list` and approved profile IDs only. Never read credential files,
  put credentials in URLs/argv/environment, or enable scripts on credential workers.
  Separate worker UID/host and authenticated API transport are required for isolation.
- Query: `ghydra --port TARGET --json bsim query --profile CORPUS --name FUNCTION`.
  Status is configuration only; a real query must succeed. BSim requires a native
  signature-capable decompiler; ordinary C decompilation is not proof (the tested
  Nix Ghidra 12.1.2 decompiler lacked this module).
- Narrow large corpora with exact `--executable`, `--architecture`, `--compiler`
  and repeatable `--category NAME=VALUE` filters. Use `available_categories` from
  a query for legal category names. All predicates combine with AND before the
  match limit; invalid/unsupported filters fail closed. Retain `result.filters`
  when reporting no matches: a filtered absence is not a corpus-wide absence.
  MCP `bsim_query` takes categories as JSON text, not a nested object.
- Select the exact query row's `match_id`, then run
  `ghydra --port TARGET bsim compare-match MATCH_ID --profile CORPUS --reference-profile REPO --reference-port REFERENCE`.
  Both workers share the configured HTTP host; separate workers can keep separate
  credential stores. The temporary reference is read-only, URL/profile-bound and
  MD5/address-verified. Neither worker's active selection changes.
- Review the textual C diff, signature/type conflicts and exact annotation preview.
  Nothing is applied. Missing/truncated evidence is incomplete, not equality;
  raise `--max-code-lines` if necessary. IDs expire on restart/eviction and become
  stale after target edits or selection changes; query again rather than guessing.
- To apply a selected signature/types, explicitly call
  `ghydra --port TARGET bsim prepare-apply MATCH_ID --profile CORPUS --reference-profile REPO --reference-port REFERENCE`.
  Review its preview, then explicitly call
  `ghydra --port TARGET bsim apply-match MATCH_ID --profile CORPUS --apply-token TOKEN`.
  Never infer approval from a search or comparison. Stale/replayed tokens, ABI
  mismatch and incompatible existing types are refused; failures roll back.
- Read-only views support local minor-language compatibility adjustments without
  changing stored versions. `Program.isChangeable()` is not permission; mutations
  and analysis return `403 REPOSITORY_READ_ONLY`. Protection lasts until native close.
- BSim version diff is a function-matching summary; selected-match comparison is
  textual C plus structured signatures/types, not native CodeDiffPlugin alignment.
  `apply-names` re-queries a best match; it does not apply the selected preview.
  Signature/type transfer requires the separate explicit prepare/apply workflow;
  unsolicited changes, comment transfer and bulk acceptance are not supported.
  Similarity is a lead, not proof.
- Writes need explicit authorization. Repository writes require checkout grants,
  an exclusive checkout and a check-in comment; save alone does not publish.

References: [connections](../../docs/GHYDRA_CONNECTIONS.md),
[repositories](../../docs/GHYDRA_REPOSITORIES.md), [BSim](../../docs/GHYDRA_BSIM.md).

## Command Reference

### Instance Management

```bash
ghydra instances list                          # Discover and list all instances
ghydra instances use --port PORT               # Set working instance
ghydra instances current                       # Show current instance
ghydra instances discover --host IP            # Scan a different host
```

### Function Analysis

```bash
ghydra functions list                          # List all functions
ghydra functions list --name-contains PATTERN  # Filter by name substring
ghydra functions list --containing-address ADDR # Find function containing address
ghydra functions search NAME                   # Search by name
ghydra functions search --regex "^sub_.*"      # Search by regex
ghydra functions get --name NAME               # Function details
ghydra functions get --address ADDR            # Function details by address
ghydra functions get-containing --address ADDR  # Find function containing address
ghydra functions get-next --address ADDR       # Next function after address
ghydra functions get-prev --address ADDR       # Previous function before address
ghydra functions decompile --name NAME         # Decompile to C
ghydra functions decompile --address ADDR      # Decompile by address
ghydra functions decompile --name NAME --start-line 10 --end-line 20  # Partial decompile
ghydra functions disassemble --name NAME       # Get disassembly
ghydra functions get-variables --name NAME     # List local variables
ghydra functions get-cfg --name NAME           # Control flow graph (basic blocks + edges)
ghydra functions get-pcode --name NAME         # Pcode intermediate representation
ghydra functions rename --address ADDR --new-name NEW  # Rename function
ghydra functions set-signature --name NAME --signature "int foo(char *buf, int len)"  # Set prototype
ghydra functions set-comment --address ADDR --comment "..."  # Set comment
ghydra functions set-variable --name NAME --variable VAR --new-name NEW  # Rename variable
ghydra functions set-variable --name NAME --variable VAR --data-type "size_t"  # Retype variable
ghydra functions create --address ADDR         # Create function
```

### Data Items and Strings

```bash
ghydra data list                               # List data items
ghydra data list --type string                 # Filter by type
ghydra data search NAME                        # Search data by name
ghydra data list-strings                       # List all strings
ghydra data list-strings --filter "password"   # Search strings
ghydra data create --address ADDR --data-type TYPE  # Define data
ghydra data rename --address ADDR --name NEW   # Rename data
ghydra data set-type --address ADDR --data-type TYPE  # Change type
ghydra data delete --address ADDR              # Remove data
```

### Struct Management

```bash
ghydra structs list                            # List structs
ghydra structs get --name NAME                 # Struct details + fields
ghydra structs create --name NAME              # Create struct
ghydra structs add-field --struct-name S --field-name F --field-type T  # Add field
ghydra structs update-field --struct-name S --field-name F --new-type T  # Update field
ghydra structs delete --name NAME              # Delete struct
```

### Memory Operations

```bash
ghydra memory read --address ADDR --length 64  # Read bytes (hex dump)
ghydra memory read --address ADDR --format string  # Read as string
ghydra memory disassemble -a ADDR --limit 20   # Disassemble at address
ghydra memory write --address ADDR --bytes-data "4883EC10"  # Write bytes
```

### Cross-References

```bash
ghydra xrefs to ADDR                           # Who calls/refs this address
ghydra xrefs from ADDR                         # What does this address call/ref
ghydra xrefs list --to-addr ADDR --type CALL   # Filter by type
ghydra xrefs find-by-name NAME                 # Who refers to this name (resolved for you)
```

### Analysis

```bash
ghydra analysis status                         # Check analysis status
ghydra analysis run                            # Trigger analysis
ghydra analysis get-callgraph --name main --max-depth 5  # Call graph
ghydra analysis get-dataflow --address ADDR --direction backward  # Data flow
ghydra analysis trace-call-path --from main --to strcmp  # How A reaches B
```

### One answer per question

Eight commands that answer in one call what used to take several:

```bash
ghydra functions decompile-batch --targets '["main","0x401000"]'  # A list of functions
ghydra xrefs find-by-name NAME                 # The references to a name
ghydra inspect-address ADDR                    # What is at this address, all of it
ghydra analysis trace-call-path --from A --to B  # How A reaches B
ghydra analysis callers ADDR                   # Who calls this function
ghydra analysis callees ADDR                   # What this function calls
ghydra functions analyze --address ADDR        # Everything about one function
ghydra analysis overview                       # What this binary is
```

### Symbols, Segments, Namespaces

```bash
ghydra symbols list                            # All symbols
ghydra symbols imports                         # Imported functions
ghydra symbols exports                         # Exported functions
ghydra classes list                            # Classes
ghydra segments list                           # Memory segments (.text, .data, etc.)
ghydra namespaces list                         # Namespace hierarchy
ghydra variables list                          # All variables
ghydra variables list --global-only             # Global variables only
```

### Data Types

```bash
ghydra datatypes list                          # List all types
ghydra datatypes list --kind struct            # Filter by kind (struct/enum/union)
ghydra datatypes search NAME                   # Search types by name
ghydra datatypes create-struct --name NAME     # Create a struct
ghydra datatypes create-enum --name NAME --size 4  # Create an enum
ghydra datatypes create-union --name NAME      # Create a union
```

### Scalar Search

```bash
ghydra scalars search 0x1234                   # Find where constant 0x1234 appears
ghydra scalars search 0 --to-function memset    # Find zeros passed to memset
ghydra scalars search 0x80 --in-function main  # Find 0x80 in main's function
```

### Script Execution (Java GhidraScript or Python 3 via PyGhidra)

The old single-`script` command group and the `/script/execute` route were
removed in v3.0.0 — they are not valid commands. Use the `scripts` group below;
it stays disabled server-side unless Ghidra is started with
`-Dghidra.dev.allowScripts=true` (or `GHYDRA_ALLOW_SCRIPTS=1`).

```bash
ghydra scripts list                                     # Available scripts
ghydra scripts run --name FixupNoReturnFunctionsScript.java
ghydra scripts run --file ./MassRename.java --arg prefix_
ghydra scripts run --file ./probe.py                     # .py selects Python 3
ghydra scripts run --code "print(currentProgram.getName())" --language python
```

`--language python` (or a `.py` `--file` / `--filename`) runs a temporary
`.py` file with the PyGhidra provider explicitly selected; `--language java` is
the default and needs a `class <Name> extends GhidraScript`. Python 3 requires
Ghidra launched via `pyghidraRun`; installing the extension alone does not
initialize the Python runtime.

### Raw Image Data

```bash
ghydra raw-image define --address 0x401000 --width 128 --height 64 --format RGB565
ghydra raw-image define -a 0x402000 --width 320 --height 240 --format ARGB8888 --endian big
```

### Comments

```bash
ghydra comments set --address ADDR --comment "..."              # Plate comment
ghydra comments set --address ADDR --comment "..." --comment-type eol  # EOL comment
ghydra comments get --address ADDR              # Get comment at address
```

### Project Management

```bash
ghydra project info                            # Current project info
ghydra project list-files                      # List project files
ghydra project open-file --path "/file.exe"    # Open in new CodeBrowser
ghydra project list-projects                   # List all projects
ghydra project get-project --name NAME         # Get project details
ghydra project list-programs                   # List programs in project
ghydra project get-program --program-id "Proj:/file.exe"  # Get program details
```

### UI State

```bash
ghydra ui get-current-address                  # Selected address in Ghidra
ghydra ui get-current-function                 # Selected function in Ghidra
```

## Tips

- Addresses should be in hex: `0x401000` (with or without `0x` prefix both work)
- Use `--json` for scripting/piping, omit it for human-readable Rich output
- Use `--port PORT` or `--host HOST` to target a specific instance
- After `project open-file`, run `ghydra instances discover` to find the new instance
- Long output auto-pages; use `--no-color` when redirecting to files
