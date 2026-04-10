# GhydraMCP — AI-Assisted Reverse Engineering via MCP

## Goal

GhydraMCP is a bridge between [Ghidra](https://ghidra-sre.org/) and AI assistants (Claude, Cline, etc.) using the Model Context Protocol (MCP). It exposes Ghidra's reverse engineering capabilities through a HATEOAS-driven REST API, enabling AI-driven binary analysis, decompilation, annotation, and data manipulation.

## Architecture

**3-tier**: LLM (MCP client) → `bridge_mcp_hydra.py` (Python MCP via FastMCP, stdio transport) → HTTP REST → `GhydraMCPPlugin.java` (Ghidra plugin HttpServer)

- Each open CodeBrowser gets its own HTTP server instance on ports 8192-8447 (256 port range)
- First CodeBrowser gets port 8192, second 8193, etc.
- The Python bridge auto-discovers running instances on startup
- ~53 MCP tools organized into namespaces: `instances_*`, `functions_*`, `data_*`, `structs_*`, `memory_*`, `xrefs_*`, `analysis_*`, `classes_*`, `symbols_*`, `segments_*`, `namespaces_*`, `variables_*`, `datatypes_*`, `scalars_*`, `project_*`, `comments_*`
- CLI tool (`ghydra/`) provides standalone terminal access — human-readable tables + `--json` mode for scripting

## Code Layout

```
GhydraMCP/
├── bridge_mcp_hydra.py          # Python MCP bridge (~3650 lines), all MCP tools defined here
├── ghydra/                       # CLI tool (Python package)
│   ├── cli/                      # Click-based CLI commands
│   ├── client/                   # HTTP client for Ghidra API
│   ├── config/                   # Configuration management
│   ├── formatters/               # Output formatters
│   └── utils/                    # Utility functions
├── src/main/java/eu/starsong/ghidra/
│   ├── GhydraMCPPlugin.java      # Main plugin class, endpoint registration, HTTP server
│   ├── api/
│   │   ├── ApiConstants.java     # Version constants (PLUGIN_VERSION, API_VERSION)
│   │   ├── GhidraJsonEndpoint.java # Base JSON endpoint handler
│   │   └── ResponseBuilder.java  # HATEOAS response construction
│   ├── endpoints/                # REST API endpoint handlers (17 files)
│   │   ├── AbstractEndpoint.java  # Base class for all endpoints
│   │   ├── FunctionEndpoints.java # Function CRUD, decompile, disassemble, CFG, pcode
│   │   ├── AnalysisEndpoints.java # Analysis status, callgraph
│   │   ├── ProgramEndpoints.java  # Dataflow, callgraph handlers
│   │   ├── DataEndpoints.java      # Data items, strings
│   │   ├── StructEndpoints.java    # Struct CRUD
│   │   ├── XrefsEndpoints.java     # Cross-references
│   │   ├── MemoryEndpoints.java    # Memory read/write
│   │   ├── InstanceEndpoints.java  # Multi-instance management
│   │   └── ... (Class, DataType, Namespace, Scalar, Segment, Symbol, Variable, ProjectManagement)
│   ├── model/                     # Data models (FunctionInfo, JsonResponse, ProgramInfo, etc.)
│   └── util/                      # Utilities (GhidraUtil, HttpUtil, TransactionHelper, DecompilerCache)
├── pom.xml                        # Maven build (Ghidra 12.0.1, Java 21)
├── pyproject.toml                 # Python package config
├── .github/workflows/build.yml    # GitHub Actions CI/CD
└── .gitea/workflows/build.yml     # Gitea Actions CI/CD
```

## Build Commands

### Java Plugin (Maven)
```bash
mvn clean package                  # Build plugin zip + complete package zip
mvn clean package -P plugin-only   # Build only the Ghidra extension zip
mvn clean package -P complete-only # Build only the complete package
```

Artifacts in `target/`:
- `GhydraMCP-<version>.zip` — Ghidra plugin only
- `GhydraMCP-Complete-<version>.zip` — Plugin + Python bridge combined

### Python CLI
```bash
pip install -e .                   # Install CLI tool (`ghydra` command)
```

## Code Conventions

### Adding a New Java Endpoint
1. Create handler method in the appropriate `*Endpoints.java` (extend `AbstractEndpoint`)
2. Use `ResponseBuilder` for HATEOAS-compliant JSON responses
3. Use `TransactionHelper` for any program modifications
4. Use `GhidraUtil` for common operations (type resolution, address parsing, etc.)
5. New top-level routes: register in `registerProgramDependentEndpoints()` in `GhydraMCPPlugin.java`
6. New sub-resource routes (e.g., `/functions/{addr}/cfg`): handled by existing dispatchers, no registration needed

### Adding a New MCP Tool
1. Add function in `bridge_mcp_hydra.py` with `@mcp.tool()` decorator
2. Add `@text_output` decorator if the tool returns structured data that needs formatting
3. Use `resource_verb` naming pattern: `functions_get_cfg`, `data_create`, etc.
4. Add a formatter function and register it in the `FORMATTERS` dict
5. The tool calls the Java HTTP endpoint via `make_ghidra_request()`

### Versioning
- Update both `ApiConstants.PLUGIN_VERSION` and `BRIDGE_VERSION` in `bridge_mcp_hydra.py` for any change
- Only bump `ApiConstants.API_VERSION` / `REQUIRED_API_VERSION` for breaking API changes
- Follow SemVer: patch for fixes, minor for features, major for breaking changes

### Style
- Java: standard Java conventions, comprehensive JavaDoc for public methods, proper null checks
- Python: PEP 8, type hints, docstrings
- Commit messages: conventional commits format (`feat:`, `fix:`, `docs:`, `refactor:`, etc.)

## Testing

```bash
python run_tests.py     # Run all tests (requires live Ghidra instance)
python run_tests.py --http  # HTTP API tests only
python run_tests.py --mcp   # MCP bridge tests only
```

Tests require Ghidra running with the plugin loaded. See `TESTING.md` for details.

## CI/CD

- **GitHub Actions** (`.github/workflows/build.yml`): Builds on push to main/feature branches, auto-creates GitHub releases on `v*` tags
- **Gitea Actions** (`.gitea/workflows/build.yml`): Auto-replicates from GitHub, uses `tea` CLI for Gitea releases
- Gitea runner image (`gitea/runner-images:ubuntu-latest`) does NOT include Maven — must install via apt
- Gitea Actions only supports `upload-artifact@v3` (not `@v4`)
- Gitea Actions secrets CANNOT start with `GITEA_` or `GITHUB_` prefix — the release token is named `RELEASE_TOKEN`
- Tags with releases on Gitea cannot be deleted — must bump tag version instead
- `tea` CLI download URL must be versioned: `https://dl.gitea.io/tea/0.13.0/tea-0.13.0-linux-amd64`
- `tea releases create` requires explicit `--asset` flags for file attachments

## Ghidra 12.0.1 API Notes

When writing Java code against the Ghidra API, be aware of these non-obvious patterns:

- `CodeBlock.getCodeBlocksContaining()` returns `CodeBlockIterator` (not `CodeBlock[]`)
- `CodeBlock` uses `getFirstStartAddress()` / `getMaxAddress()` (not `getStart()` / `getEnd()`)
- `CodeBlock.getDestinations()` returns `CodeBlockReferenceIterator` (not array)
- `CodeBlockReference.getDestinationBlock()` (not `getDestination()`)
- Use `GhidraUtil.findDataType()` / `GhidraUtil.resolveDataType()` for type resolution — don't pass `null` DataType to `HighFunctionDBUtil.updateDBVariable()`
- When in doubt about API signatures, inspect actual classes in `lib/SoftwareModeling.jar` via `javap -p -c classname`
- `DecompileResults.getHighFunction().getPcodeOps()` returns `PcodeOp[]` per basic block
- Use `SimpleBlockModel` for basic block / CFG analysis

## Key Documentation

- `README.md` — Feature overview, installation, client setup, example sessions
- `GHIDRA_HTTP_API.md` — Full HTTP REST API reference (778 lines)
- `GHYDRA_CLI.md` — CLI tool reference
- `CONTRIBUTING.md` — Contribution guidelines, PR process, release process
- `TESTING.md` — Test suites and how to run them
- `CHANGELOG.md` — Release history
