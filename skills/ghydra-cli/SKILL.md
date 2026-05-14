# Ghydra CLI Skill

Use this skill when the user asks to interact with Ghidra, reverse engineer a binary, analyze disassembly/decompilation, or work with functions, data types, structs, memory, cross-references, or any other Ghidra reverse engineering task via the `ghydra` CLI tool.

Keywords: ghidra, reverse engineering, binary analysis, decompile, disassemble, ghydra, RE, firmware, malware, binary, disassembly, decompilation, cross-references, xrefs, callgraph, data flow, CFG, pcode, struct, data type, memory dump

## Prerequisites

- Ghidra must be running with the GhydraMCP plugin loaded and a binary open in CodeBrowser
- The `ghydra` CLI must be installed (`pip install -e .` from the GhydraMCP repo)
- A Ghidra instance must be listening (default port 8192)

## Workflow

### 1. Always start by discovering instances

Before any other command, check what Ghidra instances are available:

```bash
ghydra instances list
```

If no instances are found, the user needs to open a binary in Ghidra's CodeBrowser first.

### 2. Set the working instance (if multiple)

```bash
ghydra instances use --port 8193
```

### 3. Use `--json` for structured data

When you need to parse or process output programmatically, use `--json`:

```bash
ghydra --json functions list | jq '.result[0]'
```

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
```

### Analysis

```bash
ghydra analysis status                         # Check analysis status
ghydra analysis run                            # Trigger analysis
ghydra analysis get-callgraph --name main --max-depth 5  # Call graph
ghydra analysis get-dataflow --address ADDR --direction backward  # Data flow
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
```

### Scalar Search

```bash
ghydra scalars search 0x1234                   # Find where constant 0x1234 appears
ghydra scalars search 0 --to-function memset    # Find zeros passed to memset
ghydra scalars search 0x80 --in-function main  # Find 0x80 in main's function
```

### Script Execution (PyGhidra)

```bash
ghydra script execute --code "print(currentProgram.getName())"  # Run Python 3 in Ghidra
ghydra script capabilities                   # Check available runtimes
```

### Raw Image Data

```bash
ghydra raw-image define --address 0x401000 --width 128 --height 64 --format RGB565
ghydra raw-image define -a 0x402000 --width 320 --height 240 --format ARGB8888 --endian big
```

### Comments

```bash
ghydra comments set --address ADDR --comment "..."              # Plate comment
ghydra comments set --address ADDR --comment "..." --comment-type eol  # EOL comment
```

### Project Management

```bash
ghydra project info                            # Current project info
ghydra project list-files                      # List project files
ghydra project open-file --path "/file.exe"    # Open in new CodeBrowser
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
