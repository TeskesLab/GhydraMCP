# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **Kuna integration:** the bridge gains a `kuna_*` namespace and the CLI a `ghydra kuna` command group that drive the [Kuna](https://github.com/Noelo-Lab/kuna) decompiler CLI locally. No Ghidra instance is involved: these tools work on any binary, with any Ghidra version. The integration is opt-in, because it lets the bridge run a program on the host — enable it with `GHYDRA_KUNA=1` or with `"kuna": {"enabled": true}` in `~/.ghydra/config.json`, and the config file wins when both are set.
- **Kuna export flow:** Kuna loads and analyses the whole image on every invocation, so a large binary costs seconds per call. `kuna_export_start` / `kuna_export_status` / `kuna_export_read` (bridge) and `ghydra kuna export` / `ghydra kuna export-read` (CLI) analyse a binary once, write the recovered C, the disassembly and a function index to disk, and read the result from those files.
- **Kuna test suite:** `test_kuna.py` (`python run_tests.py --kuna`) covers the opt-in precedence, the bridge/CLI contract, the export readers and the reference document. It needs neither Ghidra nor the Kuna binary, so it is the one suite that always gives a signal.
- **Kuna documentation:** `GHYDRA_KUNA.md` is the full reference for the integration — the opt-in and its precedence, every tool and command, the export layout, the measured performance and the limits.

### Changed
- **CI:** the `verify` job now also compiles the Python sources (`bridge_mcp_hydra.py` and the `ghydra` package). A syntax error in either broke the release without failing the Java build.
- **Release credentials:** the GitHub workflows take the automatic job token from `github.token` instead of `secrets.GITHUB_TOKEN`, and the Gitea release workflow probes which secret authenticates against which API. On Gitea the `GITHUB_TOKEN` secret is the instance's own job token: it works against the Gitea API and is rejected by GitHub, so the public Ghidra release list is read unauthenticated.
- **Gitea release build:** the release workflow installs the JDK each Ghidra series needs (21 for 11.x, 25 for 12.2) instead of a fixed one, because a single job builds both series and `javac` cannot read a newer class file.

## [3.0.0] - 2026-10-23

Changes since the last published TeskesLab release, [`v2.4.1`](https://github.com/TeskesLab/GhydraMCP/releases/tag/v2.4.1), including the upstream 3.0.0 beta and release-candidate changes.

### Breaking changes
- **REST API 3000:** the plugin now uses Javalin/Jetty with service, DTO, and resource layers instead of the JDK HTTP server. Upgrade the plugin and Python bridge together; the bridge requires an exact API-version match.
- **Fully-qualified names:** function, symbol, data-label, variable, and xref responses use namespace-qualified names such as `FOM::SharedMemory::ReadUInt`. Function and symbol responses no longer include a separate `namespace` field. Lookups and filters use the full name; bare names resolve only in the global namespace. URL-encode names in REST paths. Renaming to `A::B::name` moves the symbol into that namespace; `::name` or `Global::name` moves it to the global namespace. Local variable names remain bare and reject `::`.
- **Script API replacement:** the former PyGhidra `/script/execute` and `/script/capabilities` routes and `script_execute` / `script_capabilities` MCP tools are replaced by `/scripts`, `/scripts/run`, and `scripts_list` / `scripts_run`. Use `ghydra scripts list` / `run` instead of the former `script` commands. Script endpoints are disabled by default; enable them with `-Dghydra.dev.allowScripts=true` or `GHYDRA_ALLOW_SCRIPTS=1`. This permits arbitrary code execution; enable it only in a trusted environment.
- **CLI variable editing:** the duplicate `ghydra functions update-variable` command is removed. Use `ghydra functions set-variable` with `--variable` and `--data-type`. The `functions_update_variable` MCP tool and variable PATCH endpoint remain available.

### Added
- **Raw image cleanup:** `POST /raw-image/cleanup`, the `raw_image_cleanup` MCP tool, and `ghydra raw-image cleanup` remove one RawImage by address or all RawImages in a program. Cleanup is atomic, is safe to repeat, and refuses to clear non-RawImage data.
- **Raw image rendering:** `POST /raw-image/define` (`raw_image_define` MCP tool, `ghydra raw-image define`) creates a `RawImage` data type at an address so captured framebuffers render inline in the Listing. Supports 9 pixel formats (RGB565, RGB888, ARGB8888, RGB332, ARGB4444, 1bpp, 2bpp, 4bpp, 8bpp) plus little/big endian. Backed by a new `RawImage` built-in DataType with width/height/format settings.
- **Program saving:** `POST /program/save`, `programs_save`, and `ghydra project save-program` persist analysis changes. `all=true` / `--all` saves every open program with unsaved changes.
- **Ghidra script execution:** list and run installed scripts, or run ad-hoc GhidraScript source with arguments and captured output, through the replacement script API.
- **Development shutdown:** `POST /dev/shutdown` supports automated restart workflows. It requires `-Dghydra.dev.allowShutdown=true` or `GHYDRA_DEV_SHUTDOWN=1` and refuses unsaved changes with HTTP 409 unless `save=true` or `force=true` is supplied.
- **Database-backed variable listing:** `variables_list` defaults to `source=database` for committed locals and parameters with exact pagination; `source=decompiler` includes inferred locals with approximate pagination.
- **Release tooling:** `scripts/prepare_release.py` updates all five version locations and dates the changelog section. Shared version and release-note checks reject inconsistent versions and missing or empty release notes.
- **Release assets:** GitHub and Forgejo release workflows attach `SHA256SUMS` and verify that the release and its assets exist after publication.
- **CFG and pcode introspection:** `GET /functions/{address}/cfg` and `/pcode` (plus the `by-name` equivalents) expose a function's control-flow graph (`blocks`, `edges`, `blockCount`, `edgeCount`) and its decompiled p-code operations (`operations`, `opCount`). Reachable as `functions_get_cfg` / `functions_get_pcode` MCP tools, `ghydra functions get-cfg` / `get-pcode`, and via new `cfg`/`pcode` HATEOAS links on function responses. `/pcode` accepts `?timeout=` (default 60s).
- **Agent skill:** `skills/ghydra-cli/SKILL.md`, an agent-facing skill for driving the `ghydra` CLI.

### Changed
- **Ghidra compatibility:** builds target the latest Ghidra 11.x and 12.x releases. GitHub Actions detects the JDK required by the selected Ghidra distribution, including JDK 25 for Ghidra 12.2, instead of always selecting JDK 21.
- **Packaging:** the plugin is shipped as a shaded `Ghydra.jar`; extension archives use `Ghydra-…zip` and `Ghydra-Complete-…zip` names instead of `GhydraMCP-…zip`.
- **Default build target:** a build without `GHIDRA_HOME` defaults to Ghidra 12.0.1, matching the committed dependency jars. Set `GHIDRA_HOME` and `-Dghidra.version` when building for another installation.
- **Python dependencies:** committed `uv.lock` makes bridge dependency resolution reproducible.
- **Release automation:** separate build and release workflows share version and changelog guards. Release tags must reach each hosting platform to trigger publication there; GitHub also supports reusable builds and manual runs.
- **Decompilation:** cached results are reused, and decompiler lifecycle and concurrent cache access are corrected.
- **Instance and program metadata:** instance snapshots include program, project, and tool details; program responses include program, language, and compiler-spec identifiers. `/program` advertises its analysis link.

### Fixed
- **Ghidra 12.2 builds and struct deletion:** data-type removal resolves the API overload available in the running Ghidra version, retaining compatibility with 11.x and earlier 12.x releases.
- **Concurrent database reads:** iterator traversal and DTO construction run on the Swing EDT to prevent `IOException: Locked buffer` failures during concurrent Ghidra activity. Label-resolution stack overflows are contained so requests fail without crashing the EDT.
- **Write errors:** transaction failures return HTTP `409 TRANSACTION_FAILED` instead of HTTP 500. Malformed addresses, JSON, and other invalid inputs return HTTP 400.
- **Raw image CLI:** `ghydra raw-image define` calls `/raw-image/define` directly instead of the nonexistent `script/execute` route and no longer requires PyGhidra. The endpoint accepts bare hexadecimal addresses.
- **Bridge startup:** pinned `pydantic<2.14` avoids the `mcp==1.6.0` import failure; the unsupported FastMCP `version` argument is removed. The documented launch command uses `uv run python /path/to/bridge_mcp_hydra.py` so project dependency pins apply.
- **HATEOAS and response compatibility:** templated links substitute addresses and names correctly; paginated and error responses carry envelope metadata. Bridge and CLI routes and formatters match the new server response fields, and integral JSON numbers remain integers.
- **Analysis and pagination:** callee discovery scans full function bodies, xref pagination works past the first page, and variable listing no longer over-reports `hasMore`. Disassembly output reports truncation and the next offset.
- **CLI output:** color is disabled when stdout is not a terminal and respects `NO_COLOR`, keeping captured output free of ANSI escapes.
- **Gitea artifacts:** upload and release patterns match the renamed `Ghydra-*.zip` archives.


## [3.0.0-rc.1] - 2026-06-18

### Changed
- **Breaking: fully-qualified symbol names.** Functions, symbols, data labels, variables, and xrefs now use the fully-qualified name (namespace path, e.g. `FOM::SharedMemory::ReadUInt`; global-namespace members are unprefixed) for lookup, filtering, and output. `GET /functions/by-name/{fqn}` takes a URL-encoded FQN; a bare name resolves in the global namespace only. Renaming a function, data label, or symbol to an `A::B::name` value moves it into that namespace (created if absent); a leading `::` or `Global::` moves it to the global namespace. The separate `namespace` field is removed from function and symbol responses (folded into the FQN `name`). Local variable names stay bare and reject `::`. `API_VERSION` bumped to 3000. Reimplemented from PR #18 against the Javalin layer. (#18)

### Added
- **`analysis` link on `/program`:** the program resource now advertises an `analysis` link (to `/analysis/status`) for HATEOAS discoverability.
- **Run Ghidra scripts via the API:** `GET /scripts` (list) and `POST /scripts/run` (run an existing script by `name`, or compile and run ad-hoc GhidraScript `source`, with `args`), plus `scripts_list`/`scripts_run` bridge tools and `ghydra scripts list`/`run`. Captures the script's output. Lets an agent do multi-stage/batch work (mass rename, signature transfer) in one call. Arbitrary code execution, so it is disabled unless the server is started with `-Dghydra.dev.allowScripts=true` (or `GHYDRA_ALLOW_SCRIPTS=1`). (#3)
- **Scalar search:** find constant values in instructions (`GET /scalars`, `scalars_search` bridge tool, `ghydra scalars search`), like Ghidra's "Search For Scalars". Filter by containing function (`in_function`) or by a nearby called function (`to_function`, e.g. the `0` passed to `memset`). The `in_function` filter scans only the matching functions; unfiltered scans on large programs are time-bounded and report `scanTruncated`. Reimplemented from PR #17 against the Javalin layer. (#17)
- **Save endpoint:** `POST /program/save` persists the current program to the project (`?all=true` saves every open program with unsaved changes).
- **Dev-only shutdown endpoint:** `POST /dev/shutdown` quits Ghidra so the build/deploy/restart loop can be automated. Off by default; enable with `-Dghydra.dev.allowShutdown=true` or `GHYDRA_DEV_SHUTDOWN=1`. With unsaved changes it refuses (409) unless `?save=true` (save, then exit) or `?force=true` (discard, then exit).

### Fixed
- **HATEOAS links:** templated links with a single string argument (an address or name) emitted a literal `{}` href with the value misplaced into a `method` field; they now substitute correctly across all endpoints. Action links use a new `linkWithMethod`.
- **Disassembly truncation:** the bridge text output now reports the total instruction count and the next offset when a function's disassembly is paginated, instead of silently showing the first 100. `functions_disassemble` no longer documents `limit=0` as "all".
- **Agent-clean CLI output:** color is auto-disabled when stdout is not a terminal (and honors `NO_COLOR`), so piped or captured `ghydra` output no longer carries ANSI codes that corrupted hex-address parsing.

## [3.0.0-beta] - 2026-06-16

### Changed
- **Ghidra 11.x + 12.x:** The plugin builds and runs against both Ghidra 11.x and 12.x; CI builds a matrix over the latest of each. Per-version extension artifacts are stamped with the matching `ghidraVersion` (which must equal the running Ghidra exactly).
- **Ghidra 12.x:** Migrated the plugin to build against Ghidra 12.x (tested on 12.1.2). Build with `GHIDRA_HOME` pointing at the install, or `-Dghidra.version=` to stamp the extension.
- **Javalin HTTP server:** The plugin now embeds a Javalin/Jetty server with a layered `resource`/`service`/`dto`/`hateoas`/`middleware`/`server` structure, replacing the previous JDK `HttpServer` + `endpoints/` implementation. Shaded into a single `Ghydra.jar`.

### Fixed
- **Locked buffer crashes:** DB-iterator traversals are marshalled onto the EDT (`GhidraSwing.runRead`), fixing `IOException: Locked buffer` crashes during concurrent analysis.
- **StackOverflow containment:** A self-referential pointer made Ghidra's own label resolution recurse without bound; reads now contain the resulting `Error` and fail the request cleanly instead of crashing the EDT.
- **Call graph callees:** Callee discovery scans the whole function body instead of just the entry address, so `/analysis/callgraph` and `/analysis/callees` return results.
- **Client errors return 400:** Malformed input (bad addresses, hex, JSON bodies, invalid params) maps to HTTP 400 instead of 500; `/xrefs` pagination no longer returns empty pages past the first.
- **Bridge/CLI field sync:** Bridge and CLI formatters match the server's response field names (decompilation, variables, xrefs, segments, memory), and integral JSON numbers are no longer rendered as floats.

## [2.0.0] - 2025-11-11

### Added
- **MCP Integration Refactor:** Refactored the Python bridge for improved MCP integration. (337f89e)
  - Introduced MCP resources for loading context (e.g., instances, functions, disassembly).
  - Added namespaced tools (e.g., `instance.*`, `function.*`, `data.*`) for better organization and discoverability.
  - Implemented a "current working instance" concept to simplify commands by implicitly targeting the active Ghidra instance.
- **Analysis Prompts:** Added pre-defined prompts for common analysis tasks, including `reverse_engineer_binary` for comprehensive analysis. (337f89e, 3134581)
- **String Data Listing:** Added a new endpoint to list string data in the binary, with pagination and filtering by content. Python bridge support via `list_strings()` function. (f71f4aa)
- **Comprehensive Data Manipulation:** Added tools/endpoints for creating (`create_data`), deleting (`delete_data`), renaming (`rename_data`), changing type (`set_data_type`), and combined updates (`update_data`) for data items. Supports common types (byte, word, dword, string, etc.). (6c28553, 5797fb3, 28870e9)
- **Enhanced Cross-Reference (Xrefs) Analysis:** Implemented accurate xref tools (`get_references_to`, `get_references_from`) using Ghidra's ReferenceManager. Features include detailed info, bi-directional search, type filtering, and simplified bridge output. (96788f3)
- **Memory Operations:** Added tools/endpoints for reading (`read_memory`) and writing (`write_memory`) to program memory. (454c739)
- **Function Addressing Flexibility:** MCP bridge now supports addressing functions by name or address. (4f3042f)
- **API Version Check:** Bridge script now verifies compatibility with the Java plugin (expects API v2). (fedd2d0)
- **Enhanced Decompiler Controls:** Added options for raw vs. clean pseudocode output and multiple simplification styles. (454c739)

### Changed
- **Bridge Refactor & Namespacing:** Reorganized bridge tools into namespaces (e.g., `instance.list_instances`, `function.get_function_details`) as part of the MCP integration refactor. (337f89e)
- **Breaking: HATEOAS API v2 & Bridge Update:** Migrated fully to a HATEOAS-driven API (v2). The Python bridge (`bridge_mcp_hydra.py`) now *exclusively* uses this API, removing legacy support. Responses are simplified for AI agents, including text representations for structured data (e.g., disassembly). All endpoints require HATEOAS compliance (e.g., `_links`). (4bc2267, 4f3042f)
- **Optimized Variable Listing:** Improved performance of the `/variables` endpoint with efficient pagination and a `globalOnly` filter. (6c865c4)
- **Standardized Responses:** Unified all endpoints to use structured JSON and standardized HATEOAS links. (454c739, 4bc2267)
- **Improved Error Handling:** Enhanced error reporting and parameter validation across the API and bridge. (454c739, 4f3042f, 3df129f)
- **API Documentation:** Updated documentation to reflect the HATEOAS v2 API and new features. (28870e9, 3fd0cf4)

### Fixed
- **Real Instruction Disassembly:** The `/disassembly` endpoint now provides actual instruction disassembly instead of placeholders. (3df129f)
- **Ghidra 11+ Compatibility:** Resolved various API compatibility issues, particularly for cross-references (`XrefsEndpoints`). (5dc59ce, 2b1fe6c, 0eaa19a, 9443101)
- **Data Operations:** Fixed issues with HTTP request body consumption, parameter naming (`type` vs `dataType`), and name preservation during type changes. (28870e9)
- **Function Commenting:** Corrected `set_decompiler_comment` to apply comments at the function level. (2a1607c)
- **Call Graph Parameter Handling:** Updated the CallGraph endpoint to properly accept both function name and address parameters for flexibility. (fa8cc64)
- **Endpoint Functionality:** Addressed various issues including endpoint registration, handling of program-dependent endpoints, URL encoding, transaction management, and inconsistent response formats. (various commits, e.g., 4bc2267)

## [1.4.0] - 2025-04-08

### Added
- Structured JSON communication between Python bridge and Java plugin
- Consistent response format with metadata (timestamp, port, instance type)
- Comprehensive test suites for HTTP API and MCP bridge
- Test runner script for easy test execution
- Detailed testing documentation in TESTING.md
- Origin checking for API requests
- Mutating tests for API functionality

### Changed
- Improved error handling in API responses
- Enhanced JSON parsing in the Java plugin
- Updated documentation with JSON communication details
- Standardized API responses across all endpoints
- Improved version handling in build system

### Fixed
- Build complete package in `package` phase
- Versioning and naming of JAR files
- GitHub Actions workflow permissions
- Extension ZIP inclusion in complete package
- ProgramManager requirement
- Git tag fetching functionality
- MCP bridge test failures

## [1.3.0] - 2025-04-02

### Added
- Added docstrings for all @mcp.tool functions
- Variable manipulation tools (rename/retype variables)
- New endpoints for function variable management
- Dynamic version output in API responses
- Enhanced function analysis capabilities
- Support for searching variables by name
- New tools for working with function variables:
  - get_function_by_address
  - get_current_address
  - get_current_function
  - decompile_function_by_address
  - disassemble_function
  - set_decompiler_comment
  - set_disassembly_comment
  - rename_local_variable
  - rename_function_by_address
  - set_function_prototype
  - set_local_variable_type

### Changed
- Improved version handling in build system
- Reorganized imports in bridge_mcp_hydra.py
- Updated MANIFEST.MF with more detailed description

## [1.2] - 2025-03-30

### Added
- Enhanced function analysis capabilities
- Additional variable manipulation tools
- Support for multiple Ghidra instances

### Changed
- Improved error handling in API calls
- Optimized performance for large binaries

## [1.1] - 2025-03-30

### Added
- Initial release of GhydraMCP bridge
- Basic Ghidra instance management tools
- Function analysis tools 
- Variable manipulation tools

## [1.0] - 2025-03-24

### Added
- Initial project setup
- Basic MCP bridge functionality

[unreleased]: https://github.com/TeskesLab/GhydraMCP/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/TeskesLab/GhydraMCP/compare/v2.4.1...v3.0.0
[3.0.0-rc.1]: https://github.com/starsong-consulting/GhydraMCP/compare/v3.0.0-beta...v3.0.0-rc.1
[2.0.0]: https://github.com/teal-bauer/GhydraMCP/compare/v1.4.0...v2.0.0
[1.4.0]: https://github.com/teal-bauer/GhydraMCP/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/teal-bauer/GhydraMCP/compare/v1.2...v1.3.0
[1.2]: https://github.com/teal-bauer/GhydraMCP/compare/v1.1...v1.2
[1.1]: https://github.com/teal-bauer/GhydraMCP/compare/1.0...v1.1
[1.0]: https://github.com/teal-bauer/GhydraMCP/releases/tag/1.0