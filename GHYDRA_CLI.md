# Ghydra CLI v2.4.1

A standalone command-line interface for GhydraMCP — interact with Ghidra's reverse engineering capabilities directly from the terminal. No MCP client needed.

## Installation

```bash
cd /path/to/GhydraMCP
pip install -e .
```

## Quick Start

```bash
# List all Ghidra instances
ghydra instances list

# Decompile a function
ghydra functions decompile --name main

# Read memory as hex dump
ghydra memory read --address 0x401000 --length 64

# Get JSON output for scripting
ghydra --json functions list | jq '.result[0]'
```

## Global Options

All commands support these options:

| Flag | Short | Description |
|---|---|---|
| `--host` | `-h` | Ghidra host (default: from config or `localhost`) |
| `--port` | `-p` | Ghidra port (default: from config or `8192`) |
| `--json` | | Output raw JSON instead of formatted text |
| `--no-color` | | Disable colored output |
| `--verbose` | `-v` | Enable verbose output |
| `--version` | | Show version and exit |
| `--help` | | Show help message |

## Configuration

Config file: `~/.ghydra/config.json`

```json
{
  "default_host": "localhost",
  "default_port": 8192,
  "timeout": 10,
  "use_colors": true,
  "page_output": true,
  "max_pagination": 100
}
```

Environment variables:
- `GHYDRA_HOST`: Override default host
- `GHYDRA_PORT`: Override default port

## Command Reference

### `ghydra instances` — Instance Management

Manage multiple Ghidra instances running with the GhydraMCP plugin.

| Command | Description |
|---|---|
| `list` | List all instances with auto-discovery (scans ports 8192-8201) |
| `discover` | Discover instances on custom host/port range |
| `register` | Manually register an instance |
| `use` | Set current working instance |
| `current` | Show current instance info |
| `unregister` | Remove instance from known list |

```bash
ghydra instances list
ghydra instances discover --host 192.168.1.100 --start-port 8192 --end-port 8220
ghydra instances register --port 8195
ghydra instances use --port 8195
ghydra instances current
ghydra instances unregister --port 8195
```

### `ghydra functions` — Function Analysis

List, decompile, disassemble, and modify functions.

| Command | Description |
|---|---|
| `list` | List all functions with optional filtering |
| `search` | Search functions by name |
| `get` | Get detailed function info |
| `get-containing` | Find function containing an address |
| `get-next` | Get next function after an address |
| `get-prev` | Get previous function before an address |
| `decompile` | Decompile to C pseudocode |
| `disassemble` | Get disassembly |
| `create` | Create function at address |
| `rename` | Rename a function |
| `set-signature` | Update function prototype |
| `get-variables` | List function variables |
| `set-comment` | Set function comment |
| `get-cfg` | Get control flow graph |
| `get-pcode` | Get pcode operations |
| `set-variable` | Rename or retype a function variable |
| `update-variable` | Update a function variable (alternative) |

```bash
ghydra functions list
ghydra functions list --name-contains main
ghydra functions list --name-matches "^sub_.*"
ghydra functions list --containing-address 0x401234
ghydra functions list --limit 50
ghydra functions search ClassifyStar
ghydra functions search --regex "^sub_.*"
ghydra functions get --name main
ghydra functions get --address 0x401000
ghydra functions decompile --name main
ghydra functions decompile --address 0x401000
ghydra functions decompile --name main --start-line 10 --end-line 20
ghydra functions decompile --name main --max-lines 50
ghydra functions disassemble --name main
ghydra functions disassemble --name main --offset 50 --limit 100
ghydra functions create --address 0x401500
ghydra functions rename --old-name sub_401000 --new-name main
ghydra functions rename --address 0x401000 --new-name main
ghydra functions set-signature --name main --signature "int main(int argc, char **argv)"
ghydra functions get-variables --name main
ghydra functions set-comment --address 0x401000 --comment "Main entry point"
ghydra functions get-cfg --name main
ghydra functions get-cfg --address 0x401000
ghydra functions get-pcode --name main
ghydra functions set-variable --name main --variable buf --new-name buffer
ghydra functions set-variable --address 0x401000 --variable len --data-type "size_t"
ghydra functions get-containing --address 0x401500
ghydra functions get-next --address 0x401000
ghydra functions get-prev --address 0x401000
ghydra functions update-variable --address 0x401000 --variable-name buf --new-data-type "size_t"
```

### `ghydra data` — Data Items

Manage defined data items and strings.

| Command | Description |
|---|---|
| `list` | List data items with filtering |
| `search` | Search data items by name |
| `list-strings` | List all defined strings |
| `create` | Define new data item |
| `rename` | Rename a data item |
| `delete` | Delete a data item |
| `set-type` | Change data type |

```bash
ghydra data list
ghydra data list --type string
ghydra data list --name-contains "user"
ghydra data search user
ghydra data search "error_msg" --type string
ghydra data list-strings
ghydra data list-strings --filter "error"
ghydra data list-strings --limit 100
ghydra data create --address 0x401000 --data-type string
ghydra data create --address 0x401000 --data-type dword
ghydra data rename --address 0x401000 --name "user_string"
ghydra data delete --address 0x401000
ghydra data set-type --address 0x401000 --data-type "uint32_t"
```

### `ghydra structs` — Struct Types

Create and manage struct data types.

| Command | Description |
|---|---|
| `list` | List struct data types |
| `get` | Get detailed struct info |
| `create` | Create a new struct |
| `add-field` | Add field to struct |
| `update-field` | Update struct field |
| `delete` | Delete a struct |

```bash
ghydra structs list
ghydra structs list --category "/winapi"
ghydra structs get --name "MyStruct"
ghydra structs create --name "MyStruct" --category "/custom"
ghydra structs add-field --struct-name "MyStruct" --field-name "field1" --field-type "int"
ghydra structs add-field --struct-name "MyStruct" --field-name "field2" --field-type "char" --offset 4
ghydra structs update-field --struct-name "MyStruct" --field-name "field1" --new-type "uint32_t"
ghydra structs update-field --struct-name "MyStruct" --field-offset 0 --new-name "newField1"
ghydra structs delete --name "MyStruct"
```

### `ghydra memory` — Memory Operations

Read, write, and disassemble raw memory.

| Command | Description |
|---|---|
| `read` | Read bytes from memory |
| `disassemble` | Disassemble at arbitrary address (not tied to function) |
| `write` | Write bytes to memory |

```bash
ghydra memory read --address 0x401000
ghydra memory read --address 0x401000 --length 64
ghydra memory read --address 0x401000 --format string
ghydra memory disassemble --address 0x401000
ghydra memory disassemble -a 0x401000 --limit 20
ghydra memory disassemble -a 0x401000 --offset 10 --limit 30
ghydra memory write --address 0x401000 --bytes-data "4883EC10"
ghydra memory write --address 0x401000 --bytes-data "Hello" --format string
```

### `ghydra xrefs` — Cross-References

Analyze cross-references between code and data.

| Command | Description |
|---|---|
| `list` | List xrefs with filtering |
| `to` | Get xrefs TO an address |
| `from` | Get xrefs FROM an address |

```bash
ghydra xrefs list --to-addr 0x401000
ghydra xrefs list --from-addr 0x401000
ghydra xrefs list --to-addr 0x401000 --type CALL
ghydra xrefs to 0x401000
ghydra xrefs to 0x401000 --type CALL
ghydra xrefs from 0x401000
```

### `ghydra analysis` — Program Analysis

Run analysis and get structural information.

| Command | Description |
|---|---|
| `run` | Trigger program analysis |
| `status` | Check analysis status |
| `get-callgraph` | Get function call graph |
| `get-dataflow` | Perform data flow analysis |

```bash
ghydra analysis run
ghydra analysis run --analysis-options '{"functionRecovery": true}'
ghydra analysis status
ghydra analysis get-callgraph --name main
ghydra analysis get-callgraph --address 0x401000 --max-depth 5
ghydra analysis get-callgraph  # Uses entry point
ghydra analysis get-dataflow --address 0x401000
ghydra analysis get-dataflow --address 0x401000 --direction backward
```

### `ghydra symbols` — Symbol Table

List symbols, imports, and exports.

| Command | Description |
|---|---|
| `list` | List all symbols |
| `imports` | List imported symbols |
| `exports` | List exported symbols |

```bash
ghydra symbols list
ghydra symbols imports
ghydra symbols exports --limit 50
```

### `ghydra classes` — Classes

List classes and namespaces.

| Command | Description |
|---|---|
| `list` | List classes and namespaces |

```bash
ghydra classes list
ghydra classes list --limit 50
```

### `ghydra segments` — Memory Segments

List memory segments/blocks and their permissions.

| Command | Description |
|---|---|
| `list` | List memory segments |

```bash
ghydra segments list
ghydra segments list --name .text
```

### `ghydra namespaces` — Namespaces

List the namespace hierarchy.

| Command | Description |
|---|---|
| `list` | List namespaces |

```bash
ghydra namespaces list
```

### `ghydra variables` — Variables

List global and local variables.

| Command | Description |
|---|---|
| `list` | List variables with optional filtering |

```bash
ghydra variables list
ghydra variables list --global-only
ghydra variables list --search counter
```

### `ghydra datatypes` — Data Types

List and search data types.

| Command | Description |
|---|---|
| `list` | List data types with filtering |
| `search` | Search data types by name |
| `create-struct` | Create a new struct datatype |
| `create-enum` | Create a new enum datatype |
| `create-union` | Create a new union datatype |

```bash
ghydra datatypes list
ghydra datatypes list --kind struct
ghydra datatypes list --category /MyCategory
ghydra datatypes search MyStruct
ghydra datatypes create-struct --name MyStruct --category /custom
ghydra datatypes create-enum --name MyEnum --size 4
ghydra datatypes create-union --name MyUnion --category /custom
```

### `ghydra comments` — Comments

Set comments at addresses.

| Command | Description |
|---|---|
| `set` | Set comment (plate, pre, post, eol, repeatable) |
| `get` | Get comment at address |

```bash
ghydra comments set --address 0x401000 --comment "This is the entry point"
ghydra comments set --address 0x401000 --comment "Loop counter" --comment-type eol
ghydra comments set --address 0x401000 --comment ""  # Remove comment
ghydra comments get --address 0x401000
```

### `ghydra project` — Project Management

Manage Ghidra projects and files.

| Command | Description |
|---|---|
| `info` | Get current project info |
| `list-files` | List files in project |
| `open-file` | Open file in new CodeBrowser |
| `list-projects` | List Ghidra projects |
| `get-project` | Get project details by name |
| `list-programs` | List programs in a project |
| `get-program` | Get program details by ID |

```bash
ghydra project info
ghydra project list-files
ghydra project list-files --folder "/malware"
ghydra project list-files --no-recursive
ghydra project open-file --path "/malware.exe"
ghydra project list-projects
ghydra project get-project --name MyProject
ghydra project list-programs
ghydra project get-program --program-id "MyProject:/malware.exe"
```

### `ghydra scalars` — Scalar Search

Find where constant values appear in instructions.

| Command | Description |
|---|---|
| `search` | Search for scalar value in instructions |

```bash
ghydra scalars search 0x1234
ghydra scalars search 256
ghydra scalars search 0 --to-function memset
ghydra scalars search 0x80 --in-function main
```

### `ghydra script` — Script Execution

Run Python 3 scripts inside Ghidra via PyGhidra.

| Command | Description |
|---|---|
| `execute` | Execute a Python 3 script |
| `capabilities` | Check available script runtimes |

```bash
ghydra script execute --code "print(currentProgram.getName())"
ghydra script capabilities
```

### `ghydra raw-image` — Raw Image Data

Define raw image data that renders inline in Ghidra's Listing view.

| Command | Description |
|---|---|
| `define` | Define raw image at address with pixel format |

```bash
ghydra raw-image define --address 0x401000 --width 128 --height 64 --format RGB565
ghydra raw-image define -a 0x402000 --width 320 --height 240 --format ARGB8888 --endian big
```

### `ghydra ui` — UI State

Interact with Ghidra's UI state.

| Command | Description |
|---|---|
| `get-current-address` | Get currently selected address |
| `get-current-function` | Get currently selected function |

```bash
ghydra ui get-current-address
ghydra ui get-current-function
```

## Architecture

```
ghydra/
├── __init__.py
├── cli/
│   ├── __init__.py
│   ├── main.py           # CLI entry point, global options
│   ├── instances.py      # Instance management (6 commands)
│   ├── functions.py      # Function analysis (16 commands)
│   ├── data.py           # Data items (7 commands)
│   ├── structs.py        # Struct types (6 commands)
│   ├── memory.py         # Memory operations (3 commands)
│   ├── xrefs.py          # Cross-references (3 commands)
│   ├── analysis.py       # Program analysis (4 commands)
│   ├── symbols.py        # Symbols, imports, exports (3 commands)
│   ├── classes.py        # Classes and namespaces (1 command)
│   ├── segments.py       # Memory segments (1 command)
│   ├── namespaces.py     # Namespace hierarchy (1 command)
│   ├── variables.py      # Global and local variables (1 command)
│   ├── datatypes.py      # Data type listing (5 commands)
│   ├── scalars.py        # Scalar search (1 command)
│   ├── script.py         # Script execution (2 commands)
│   ├── raw_image.py      # Raw image definition (1 command)
│   ├── comments.py       # Comment management (2 commands)
│   ├── project.py        # Project management (7 commands)
│   └── ui.py             # UI state (2 commands)
├── client/
│   ├── __init__.py
│   ├── http_client.py    # HTTP client with connection pooling
│   ├── exceptions.py     # Custom exceptions
│   └── models.py         # Data models
├── formatters/
│   ├── __init__.py
│   ├── base.py           # Base formatter interface
│   ├── json_formatter.py # JSON formatter
│   └── table_formatter.py # Rich table formatter
├── config/
│   ├── __init__.py
│   ├── config_manager.py # Config file management
│   └── defaults.py       # Default configuration
└── utils/
    ├── __init__.py
    ├── pager.py          # Output paging
    └── validators.py     # Input validation
```

## Output Modes

### Default (Rich Terminal)

- Tables with colored columns
- Syntax-highlighted C and assembly
- Panels for detailed info
- Tree views for structured data
- Hex dumps for memory
- Auto-paging for long output

### JSON (`--json`)

- Raw JSON from the API
- Pretty-printed by default
- Pipe to `jq` for processing:
  ```bash
  ghydra --json functions list | jq '.result[0]'
  ```

## License

Same as GhydraMCP project.
