# GhydraMCP — AI-Assisted Reverse Engineering via MCP

## Goal

GhydraMCP is a bridge between [Ghidra](https://ghidra-sre.org/) and AI assistants (Claude, Cline, etc.) using the Model Context Protocol (MCP). It exposes Ghidra's reverse engineering capabilities through a HATEOAS-driven REST API, enabling AI-driven binary analysis, decompilation, annotation, and data manipulation.

## Architecture

**3-tier**: LLM (MCP client) → `bridge_mcp_hydra.py` (Python MCP via FastMCP, stdio transport) → HTTP REST → `GhydraPlugin.java` (Ghidra plugin, Javalin web server)

- Each open CodeBrowser gets its own HTTP server instance on ports 8192-8447 (256 port range)
- First CodeBrowser gets port 8192, second 8193, etc.
- The Python bridge auto-discovers running instances on startup
- ~71 MCP tools organized into namespaces: `instances_*`, `functions_*`, `data_*`, `structs_*`, `memory_*`, `xrefs_*`, `analysis_*`, `classes_*`, `symbols_*`, `segments_*`, `namespaces_*`, `variables_*`, `datatypes_*`, `scalars_*`, `project_*`, `comments_*`, `scripts_*`
- CLI tool (`ghydra/`) provides standalone terminal access — human-readable tables + `--json` mode for scripting, 20 command groups
- **v3.0.0**: Migrated from raw `HttpServer` to **Javalin** with service/DTO/resource architecture. Targets **Ghidra 12.1.2**. **API_VERSION 3000** (breaking: fully-qualified names everywhere)

## Code Layout

```
GhydraMCP/
├── bridge_mcp_hydra.py          # Python MCP bridge, all MCP tools defined here
├── ghydra/                       # CLI tool (Python package)
│   ├── cli/                      # Click-based CLI commands
│   ├── client/                   # HTTP client for Ghidra API
│   ├── config/                   # Configuration management
│   ├── formatters/               # Output formatters
│   └── utils/                    # Utility functions
├── src/main/java/eu/starsong/ghidra/
│   ├── GhydraPlugin.java         # Main plugin class, server lifecycle, resource registration
│   ├── api/
│   │   └── ApiConstants.java     # Version constants (PLUGIN_VERSION, API_VERSION)
│   ├── server/                   # Javalin server, context, Gson mapper, Resource interface
│   ├── resource/                 # REST route handlers (Javalin resources)
│   ├── service/                  # Business logic services
│   ├── dto/                      # Data Transfer Objects
│   ├── hateoas/                  # HATEOAS response builders, pagination, links
│   ├── middleware/               # CORS, error handling
│   ├── datatype/                 # Custom data types (RawImage)
│   └── util/                     # Utilities (GhidraUtil, GhidraSwing, TransactionHelper, etc.)
├── pom.xml                        # Maven build (Ghidra 12.1.2, Java 21, Javalin 6.3.0)
├── pyproject.toml                 # Python package config
└── .github/workflows/build.yml   # GitHub Actions CI/CD
```

## Build Commands

### Java Plugin (Maven)
```bash
mvn clean package                  # Build plugin zip + complete package zip
mvn clean package -P plugin-only   # Build only the Ghidra extension zip
mvn clean package -P complete-only # Build only the complete package
```

Artifacts in `target/`:
- `GhydraMCP-v<version>.zip` — Ghidra plugin only
- `GhydraMCP-Complete-v<version>.zip` — Plugin + Python bridge combined

### Python CLI
```bash
pip install -e .                   # Install CLI tool (`ghydra` command)
```

## Code Conventions

### Adding a New Java Endpoint
1. Create a method in the appropriate `*Service.java` (business logic)
2. Create or add to a `*Resource.java` (Javalin route handler, implements `Resource`)
3. Use `Response.ok()` from `hateoas/` for HATEOAS-compliant JSON responses
4. Use `TransactionHelper` for any program modifications
5. Use `GhidraUtil` for common operations (type resolution, address parsing, etc.)
6. Register the resource in `GhydraPlugin.java` via `server.register(new MyResource())`
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
