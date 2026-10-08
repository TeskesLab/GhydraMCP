# GhydraMCP — AI-Assisted Reverse Engineering via MCP

## Goal

Bridge between [Ghidra](https://ghidra-sre.org/) and AI assistants (MCP clients). Exposes Ghidra's
reverse-engineering capabilities over a HATEOAS REST API so an LLM can drive binary analysis,
decompilation, annotation, and data manipulation.

## Architecture

**3-tier**: LLM (MCP client) → `bridge_mcp_hydra.py` (Python MCP over stdio) → HTTP REST →
`GhydraPlugin.java` (Ghidra plugin running a Javalin server).

- Each open CodeBrowser starts its own HTTP server; the first binds `DEFAULT_PORT` 8192 and
  subsequent instances walk up to `MAX_PORT_ATTEMPTS` = 256 ports (8192–8447).
- The bridge auto-discovers instances on startup and on a daemon timer, but `QUICK_DISCOVERY_RANGE`
  only scans **8192–8201**. Instances above 8202 need `instances_register` / the CLI.
- 72 MCP tools in 21 namespaces: `analysis_*`, `classes_*`, `comments_*`, `data_*`, `datatypes_*`,
  `functions_*`, `instances_*`, `memory_*`, `namespaces_*`, `programs_*`, `project_*`, `projects_*`,
  `raw_image_*`, `scalars_*`, `scripts_*`, `segments_*`, `structs_*`, `symbols_*`, `ui_*`,
  `variables_*`, `xrefs_*`.
- v3.0.0 migrated `HttpServer` → **Javalin** with service/DTO/resource layering. `API_VERSION` is
  **3000** (breaking: fully-qualified names everywhere).

## Layout

```
bridge_mcp_hydra.py              # ALL MCP tools + formatters live here (4400+ lines)
ghydra/                          # standalone Click CLI — does NOT import the bridge
  cli/ client/ config/ formatters/ utils/
src/main/java/eu/starsong/ghidra/
  GhydraPlugin.java              # server lifecycle + resource registration
  api/ApiConstants.java          # PLUGIN_VERSION, API_VERSION, ports
  server/                        # GhydraServer, GhidraContext, GsonMapper, Resource iface
  resource/  service/  dto/  hateoas/  middleware/  datatype/  util/
lib/*.jar                        # committed Ghidra jars used as system-scoped deps
src/assembly/*.xml               # zip layouts (ghidra-extension, complete-package)
```

`CLAUDE.md` is a **git symlink to this file** (`120000`). Edit here only; never write `CLAUDE.md`
directly.

## Build

The build needs Ghidra module jars: set `GHIDRA_HOME` (recommended) or rely on the committed `lib/*.jar`.

```bash
# Recommended. -Dghidra.version is stamped into extension.properties as `ghidraVersion`
# and MUST match the install or Ghidra refuses to load the extension.
GHIDRA_HOME=/path/to/ghidra_12.1.2_PUBLIC mvn clean package -Dghidra.version=12.1.2

mvn clean package -P plugin-only     # plugin zip only
mvn clean package -P complete-only   # plugin + bridge script
pip install -e .                     # installs `ghydra` CLI and `ghydramcp` bridge
```

Artifacts land in `target/` as `Ghydra-<git-describe>-<timestamp>.zip` and
`Ghydra-Complete-...zip` (CI renames them to `...-ghidra<version>.zip`). The deployable jar is
`lib/Ghydra.jar` inside the extension — for iteration you can swap that file in an installed
extension and restart Ghidra instead of reinstalling.

CI builds a **matrix over the latest Ghidra 11.x and 12.x**, so keep code compiling against both.
JDK 21, Javalin 6.3.0, Gson is `provided` (Ghidra supplies it).

## Threading: the EDT rule (most important Java convention)

Request handlers run on Javalin's default Jetty worker threads — never the Swing EDT. Ghidra's DB
is only safe to traverse under the EDT, so:

- **Wrap compound/iterating DB reads and DTO construction in `GhidraSwing.runRead(...)`** — the
  whole traversal *and* `XxxDto.from(...)` go inside one lambda, not just the iterator seed.
  Forget it and you get `IOException: Locked buffer` under concurrent EDT activity.
- **Never wrap decompiler work.** `DecompilerCache`, `getFunctionVariables`, `DomainFile.save`, and
  `GhidraScript.execute` must stay off the EDT — wrapping them freezes the Ghidra UI for their full
  duration (and `runRead` will then block up to its 900 s timeout). See `GhidraUtil` for the
  split pattern: DB half in `runRead`, `DecompInterface` work outside.

Read timeout is `-Dghidra.mcp.read.timeout` seconds (default 900).

## Transactions

Every program mutation goes through `TransactionHelper.executeInTransaction(program, name, supplier)`.
It rejects a null program, rejects `!program.isChangeable()`, and rolls back on exception. It
rethrows `IllegalArgumentException` unwrapped so bad input maps to 400 rather than 500. No raw
`startTransaction`/`endTransaction` exists outside this helper.

Canonical shape — **write inside the transaction, read the DTO after it, outside**:

```java
Symbol symbol = TransactionHelper.executeInTransaction(program, "Create Label", () ->
    program.getSymbolTable().createLabel(address, name, SourceType.USER_DEFINED));
return GhidraSwing.runRead(() -> SymbolDto.from(symbol));
```

Services own transactions; resources never call DB mutators directly. Reads use no transaction.

## Adding a Java endpoint

1. Business logic in a `*Service.java` (transactions + EDT live here).
2. Route in a `*Resource.java` — `implements Resource`, routes registered in its `register(Javalin, Function<Context,GhidraContext>)` via `app.get("/functions/{address}/cfg", ctx -> cfg(contextFactory.apply(ctx)))`.
3. Register the resource in `GhydraPlugin.java`'s `server.register(...)` list — **required for a new
   resource class**; adding a route to an already-registered resource needs no extra step.
4. Build responses with `hateoas/Response` (`Response.ok(ctx, port, data).self(...)`). Every
   response envelope carries `success`, `id`, `instance`, `result`, `_links` — `test_http_api.py`
   asserts this.
5. Use `GhidraUtil` for type resolution and address parsing.
6. For non-GET action links use `Response.linkWithMethod(rel, href, "POST", args)`. Do **not**
   reintroduce a `link(String,String,String)` overload — it previously won overload resolution and
   emitted literal `{}` hrefs.

## Adding an endpoint end-to-end

The bridge and the CLI duplicate all request logic, so one endpoint means **six** edits:

1. Java service + resource + `GhydraPlugin` registration.
2. Bridge tool in `bridge_mcp_hydra.py`: `@mcp.tool()` over `@text_output`, ending with
   `port = _get_instance_port(port)` and calling `safe_get`/`safe_post`/`safe_patch`/
   `safe_put`/`safe_delete` (there is **no** `make_ghidra_request` — that name is gone).
3. A `FORMATTERS` entry **keyed by the tool function's exact name** — a missing key silently
   degrades output to `"Done"`. Formatters are called as `formatter(response, **tool_kwargs)`, so
   every one must accept `**kwargs`.
4. CLI command in `ghydra/cli/` using the shared `ctx.obj['client']` / `ctx.obj['formatter']`.
5. The output method on `BaseFormatter` **and** on both `JSONFormatter` and `TableFormatter`.
6. Google-style `Args:`/`Returns:` docstrings — the bridge's surface verbatim to the LLM, and the
   text is duplicated into CLI `--help`.

Name tools `resource_verb` (`functions_get_cfg`, `data_create`).

Note `safe_put`/`safe_post`/`safe_patch` **mutate the payload you pass in** (`data.pop("headers", None)`).
The popped `headers` dict is the only way to satisfy the server's Origin check on state-changing
calls, so don't reuse a literal dict across calls.

## Versioning

Four places must move together:

| Location | Field |
| --- | --- |
| `api/ApiConstants.java` | `PLUGIN_VERSION` (`v3.0.0`), `API_VERSION` (`3000`) |
| `bridge_mcp_hydra.py` | `BRIDGE_VERSION` (`v3.0.0`), `REQUIRED_API_VERSION` (`3000`) |
| `pyproject.toml` + `ghydra/__init__.py` | `__version__` (`3.0.0`, no `v`) |
| `src/main/resources/extension.properties` | `version=` |

`API_VERSION` / `REQUIRED_API_VERSION` only move for breaking API changes. The bridge enforces it
in exactly one place — `register_instance`, by exact equality against `3000` — and never
per-request, so a mismatch surfaces later as a generic "No active Ghidra instance". The CLI never
checks it.

SemVer: patch for fixes, minor for features, major for breaking.

## Testing

```bash
python run_tests.py                      # all suites
python run_tests.py --http --mcp --data --comments --port   # or any subset
```

**Every suite skips itself when Ghidra isn't running** (`setUp` → `skipTest("Ghidra not running")`).
A green run against no Ghidra means nothing — confirm tests actually executed before trusting it.
Tests need Ghidra with a binary open, and a loaded binary with functions (`skipTest` otherwise).

Target selection is inconsistent and worth knowing:
- `test_javalin_port.py` honors `GHYDRAMCP_TEST_HOST` **and** `GHYDRAMCP_TEST_PORT`.
- `test_http_api.py` honors only `GHYDRAMCP_TEST_HOST`; its port is hardcoded to 8192.
- `TESTING.md` documents the flags and the headless Java integration tests.

`mvn test` (14 JUnit tests) covers only pure logic — anything needing a live `Program` can't
run there, because the plugin's Ghidra deps are system-scoped jars in `lib/` and Ghidra ships
no test framework. Service tests live in `src/test/ghidra/` as GhidraScripts run under
`analyzeHeadless` (see TESTING.md); they throw on first failure so they work as a CI gate.

## CI/CD

- **GitHub Actions** (`.github/workflows/build.yml`): builds the 11.x/12.x matrix; on a `v*` tag the
  `release` job creates a release. Tags containing `-` publish as pre-releases.
- **Release notes are extracted from `CHANGELOG.md`** by matching a `## [<tag-without-v>]` heading.
  A release tag with no matching section ships empty notes — add the section first.
- **Gitea Actions** (`.gitea/workflows/build.yml`) mirrors the GitHub flow via the `tea` CLI. Its
  quirks: the runner image has no Maven (install via apt); only `upload-artifact@v3` works; secrets
  cannot start with `GITEA_`/`GITHUB_` (the token is `RELEASE_TOKEN`); the `tea` download URL must be
  versioned (`https://dl.gitea.io/tea/0.13.0/tea-0.13.0-linux-amd64`); `tea releases create` needs an
  explicit `--asset` per file; a tag with a release cannot be deleted, so bump the version instead.
- **Branch names gate CI.** Workflows trigger on `main`, `api-*`, `feature/*`, `feat/*`, `bugfix/*`.
  `CONTRIBUTING.md` also suggests `fix/*` and `docs/*` — those will *not* run CI. Branches are
  `feature/*`, `feat/*`, `bugfix/*`, `api-*` (matches the commit history). PRs need one reviewer
  approval; commits use conventional-commit prefixes; add a CHANGELOG entry under `## [Unreleased]`.

## Feature flags (off by default)

Two endpoints refuse to work until explicitly enabled — start Ghidra with the flag or env var:

- `POST /scripts/run` (`scripts_run`, `ghydra scripts run`) — arbitrary code execution.
  Needs `-Dghidra.dev.allowScripts=true` or `GHYDRA_ALLOW_SCRIPTS=1`.
- `POST /dev/shutdown` — quits Ghidra for automated rebuild/restart. Needs
  `-Dghidra.dev.allowShutdown=true` or `GHYDRA_DEV_SHUTDOWN=1`. Refuses with unsaved changes (409)
  unless `?save=true` or `?force=true`.

## CLI notes

`--json` is defined once on the root group and injected as `ctx.obj['formatter']`; no subcommand
redefines it, so it must come **before** the subcommand (`ghydra --json functions list`) — after it
is a usage error. Paging auto-disables under `--json`. Config precedence is
**CLI flag > `GHYDRA_HOST`/`GHYDRA_PORT` > `~/.ghydra/config.json` > defaults** (`localhost:8192`,
timeout 900).

The bridge's env vars are a *different, asymmetric* set: `GHYDRA_HYDRA_HOST` > `GHYDRA_HOST`,
plus `GHYDRA_TIMEOUT`, `GHYDRA_DECOMP_TIMEOUT`, `GHYDRA_ALLOWED_ORIGINS`. **The bridge never reads
`GHYDRA_PORT`.**

CLI multi-instance selection is in-process only — `ghydra instances use -p` mutates the client, and
`instances unregister` is a documented no-op.

## Ghidra API gotchas

Signatures that do not match the obvious guess:

- `CodeBlock.getCodeBlocksContaining()` → `CodeBlockIterator`, not `CodeBlock[]`.
- `CodeBlock` bounds are `getFirstStartAddress()` / `getMaxAddress()`, not `getStart()`/`getEnd()`.
- `CodeBlock.getDestinations()` → `CodeBlockReferenceIterator`; `CodeBlockReference.getDestinationBlock()`.
- `HighFunction.getPcodeOps()` returns `PcodeOp[]` per basic block.
- Use `SimpleBlockModel` for basic-block/CFG analysis.
- Never pass a null `DataType` to `HighFunctionDBUtil.updateDBVariable()` — resolve first via
  `GhidraUtil.findDataType()` / `resolveDataType()`.
- Unsure of a signature? `javap -p -c <class>` against `lib/SoftwareModeling.jar`.

## Fully-qualified names (API 3000)

Names are FQNs (`FOM::SharedMemory::ReadUInt`; global-namespace members unprefixed). A bare name
resolves in the global namespace only, and FQNs must be URL-encoded in paths. Renaming to `A::B::name`
moves the symbol into that namespace, creating it if needed; a leading `::` or `Global::` targets the
global namespace. Local variable names stay bare and reject `::`. The separate `namespace` field is
gone from function and symbol responses.

## Known drift

Verified rough edges — check before trusting anything downstream:

- **Transaction failures return `409 TRANSACTION_FAILED`.** `TransactionHelper.TransactionException` has
  a handler in `GhydraServer`. It is deliberately **unchecked**: resources guard service calls with
  `catch (RuntimeException e) { throw e; }` then a broader `catch (Exception e) { throw new
  RuntimeException(...) }`, so a checked exception would be rewrapped and surface as 500. Keep it a
  `RuntimeException` or the 409 mapping breaks.
- **Committed `lib/*.jar` are Ghidra 12.0.1, and `pom.xml` defaults to `ghidra.version=12.0.1`** so a
  bare `mvn package` (no `GHIDRA_HOME`) builds and stamps honestly. Building against a real install needs
  both: `GHIDRA_HOME=/path/to/ghidra_12.1.2_PUBLIC mvn clean package -Dghidra.version=12.1.2`. GitHub
  Actions does exactly that per matrix leg. Refresh `lib/` and bump the pom default if you want the
  no-flag build to target a newer Ghidra.
- **`ghydra functions set-variable` is the only variable-editing CLI command.** The duplicate
  `update-variable` was removed in 3.0.0.
- The pom's Ghidra dependency `<version>` tags are hardcoded to `12.1.2`; `-Dghidra.version` only
  rewrites the `ghidraVersion` property in `extension.properties`, not those tags. They're
  system-scoped, so this is cosmetic — the `systemPath` jars are what matter.

## Key documentation

`README.md` (install, MCP client setup), `GHIDRA_HTTP_API.md` (REST reference, API_VERSION 3000),
`GHYDRA_CLI.md` (CLI reference), `CONTRIBUTING.md` (PR/release process),
`TESTING.md` (stale on flags), `CHANGELOG.md` (release history — also the release-notes source).