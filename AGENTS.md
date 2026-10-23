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
- 85 MCP tools in 22 namespaces: `analysis_*`, `classes_*`, `comments_*`, `data_*`, `datatypes_*`,
  `functions_*`, `instances_*`, `kuna_*`, `memory_*`, `namespaces_*`, `programs_*`, `project_*`,
  `projects_*`, `raw_image_*`, `scalars_*`, `scripts_*`, `segments_*`, `structs_*`, `symbols_*`,
  `ui_*`, `variables_*`, `xrefs_*`.
- v3.0.0 migrated `HttpServer` → **Javalin** with service/DTO/resource layering. `API_VERSION` is
  **3000** (breaking: fully-qualified names everywhere).
- The `kuna_*` namespace is **local**: it drives the Kuna decompiler CLI as a subprocess, so it
  touches neither the REST API nor `API_VERSION`, and it works with any Ghidra version.

## Layout

```
bridge_mcp_hydra.py              # ALL MCP tools + formatters live here (4400+ lines)
ghydra/                          # standalone Click CLI — does NOT import the bridge
  kuna.py                        # Kuna CLI driver (local, opt-in)
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

## Performance

The rules below are the measured ones. `src/test/ghidra/MeasurePerf.java` measures them
headlessly (`analyzeHeadless <proj> Perf -process <binary> -noanalysis -scriptPath
src/test/ghidra -postScript MeasurePerf`) and prints a `RESULT` line per measurement.

- **Never create a `DecompInterface` per request.** Opening the program in a fresh
  decompiler costs more than the decompile itself — measured at 3.2x on a median function
  (756 ms vs 235 ms for three rounds). Use `DecompilerCache.shared()`: it keeps one
  long-lived decompiler, caches up to 50 decompile results, and invalidates itself when
  the program changes. `/functions/{}/pcode`, the variable listing and the variable
  rename all used to pay the `openProgram` price on every call.
- **Page listings on the server.** A listing endpoint must not build a DTO for every
  entity in the program and paginate afterwards: on a binary with 29 587 symbols that
  was 400 ms of DTO work for a 100-item page, against 87 ms when only the page is
  converted (`util/PagedCollector.java`). The response contract is unchanged — `result`
  is the page, `meta.total` the count.
- **Only skip the counting scan where the native count matches.** `getNumDefinedData()`
  agrees with what `getDefinedData()` yields, so the data listing stops walking as soon
  as the page is full. `getNumSymbols()` (28 993) and `getFunctionCount()` (4 444) do
  *not* agree with their iterators (29 587 and 3 333), so the symbol and function
  listings walk the collection to count it — using the native number would change the
  `meta.total` the client sees. That walk is cached in `util/ProgramCache.java` and
  dropped whenever the program changes, so it happens once per program state instead
  of once per page.
- **Cache the control flow graph of a function.** Walking the blocks of a function
  and their edges is the whole cost of the CFG endpoint — 24 ms for a function with
  1 079 blocks — and the graph only changes when the program does. `ProgramCache`
  holds it, and the listener drops it on any change.
- **Format bytes with a table, not `String.format`.** `String.format("%02X", b)` parses
  its format string and allocates a `Formatter` per call: 121x slower than a hex-digit
  table over 1.6 MB.
- **Do not pretty-print the response.** Indentation made a 100-item page 38% bigger
  (33 954 bytes against 24 553); the client parses the body either way.
- **Attach the item links without a round trip.** `PaginatedResult` used to serialise
  and re-parse every item to flatten it into a map before adding `_links`;
  `toJsonTree()` does it in one pass.
- **Look a struct up through the data type index** before walking every data type of
  the program.
- **The bridge holds no lock across network I/O.** `instances_lock` used to be held while
  the discovery thread made HTTP calls, so every tool call queued behind the round trip.
  Snapshot the registry under the lock, do the I/O outside it, write back under the lock.
- **The bridge uses one HTTP session per thread** (`_http_session()`), so a run of tool
  calls reuses the connection: median 3.1 ms -> 1.6 ms per request, p95 12.3 ms -> 1.9 ms.
  `requests.Session` is not thread-safe, hence one per thread. The CLI shares one session
  across its port scan instead of building a pool per port.
- **The bridge scans ports concurrently.** A closed port costs the full timeout on hosts
  whose firewall drops the packets instead of refusing them, so the serial scan of the
  quick range took 4.5 s; probing in parallel takes 0.5 s (8.8x). The probe timeout is
  0.2 s — a live local instance answers in milliseconds — and a quick scan stays valid
  for a second, so a burst of `instances_list` calls shares one scan.
- **Do not lowercase a whole response to search it.** The decompiler advisory check used
  `code.lower()`, which copied the entire decompilation; a case-insensitive regex answers
  the same question without the copy.

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

Five places carry the release version and must move together:

| Location | Field |
| --- | --- |
| `api/ApiConstants.java` | `PLUGIN_VERSION` (`v3.0.0`), `API_VERSION` (`3000`) |
| `bridge_mcp_hydra.py` | `BRIDGE_VERSION` (`v3.0.0`), `REQUIRED_API_VERSION` (`3000`) |
| `pyproject.toml` + `ghydra/__init__.py` | `__version__` (`3.0.0`, no `v`) |
| `src/main/resources/extension.properties` | `version=` |

**Don't edit them by hand.** `scripts/version.py` is the single source of truth:
`--set X.Y.Z` writes all of them, `--check` proves they agree, and both CI
workflows run `--check` on every push. `scripts/prepare_release.py` does the
whole release preparation (CHANGELOG section + versions) in one step.

`API_VERSION` / `REQUIRED_API_VERSION` only move for breaking API changes and are
never touched by `--set`. The bridge enforces it
in exactly one place — `register_instance`, by exact equality against `3000` — and never
per-request, so a mismatch surfaces later as a generic "No active Ghidra instance". The CLI never
checks it.

SemVer: patch for fixes, minor for features, major for breaking.

## Testing

```bash
python run_tests.py                      # all suites
python run_tests.py --http --mcp --data --comments --port --kuna   # or any subset
```

**Every suite skips itself when Ghidra isn't running** (`setUp` → `skipTest("Ghidra not running")`).
A green run against no Ghidra means nothing — confirm tests actually executed before trusting it.
Tests need Ghidra with a binary open, and a loaded binary with functions (`skipTest` otherwise).

**The exception is `--kuna`**: `test_kuna.py` needs neither Ghidra nor the Kuna binary, so it always
runs and always gives a signal. It covers the Kuna opt-in precedence, the bridge/CLI contract
(every `kuna_*` tool has a `FORMATTERS` entry and is registered in MCP; none takes a `port`) and
the export readers.

Target selection is inconsistent and worth knowing:
- `test_javalin_port.py` honors `GHYDRAMCP_TEST_HOST` **and** `GHYDRAMCP_TEST_PORT`.
- `test_http_api.py` honors only `GHYDRAMCP_TEST_HOST`; its port is hardcoded to 8192.
- `TESTING.md` documents the flags and the headless Java integration tests.

`mvn test` (14 JUnit tests) covers only pure logic — anything needing a live `Program` can't
run there, because the plugin's Ghidra deps are system-scoped jars in `lib/` and Ghidra ships
no test framework. Service tests live in `src/test/ghidra/` as GhidraScripts run under
`analyzeHeadless` (see TESTING.md); they throw on first failure so they work as a CI gate.

## CI/CD

- **Two workflows, split by responsibility.** `build.yml` owns the build and is
  reusable (`workflow_call`); `release.yml` owns releases. Don't create releases
  in `build.yml` — a second release path is how the two platforms drift apart.
- **A release is one tag.** `vX.Y.Z` pushed to **both** remotes. The GitHub
  runner cannot reach the Forgejo instance on the LAN, so neither platform can
  publish for the other — the tag has to go to both.
- **GitHub Actions** (`.github/workflows/`):
  - `build.yml` — `verify` (version guard) → `build` (Ghidra 11.x/12.x matrix)
    → upload artifacts. Triggers on push, PR, `workflow_dispatch` and
    `workflow_call`. Checkout with `fetch-depth: 0` so the artifact name can
    embed the tag. The JDK is derived from the Ghidra distribution, not
    hardcoded — see the Ghidra 12.2 note under Known drift.
  - `release.yml` — `guard` → `build` (calls `build.yml`) → `publish` →
    `verify`. Triggers on a `v*` tag push and on `workflow_dispatch`
    (inputs: `version`, `ref`, `dry_run`). Tags containing `-` publish as
    pre-releases.
- **Gitea Actions** (`.gitea/workflows/`): `build.yml` is build-only;
  `release.yml` publishes the Forgejo Release via the `tea` CLI, building the
  same 11.x/12.x matrix. Its quirks: the runner image has no Maven (install via
  apt) and no JDK; only `upload-artifact@v3` works; the `tea` download URL
  must be versioned
  (`https://dl.gitea.io/tea/0.13.0/tea-0.13.0-linux-amd64`); `tea releases
  create` needs an explicit `--asset` per file; a tag with a release cannot be
  deleted, so bump the version instead.
- **The Gitea release builds both series in one job, so the JDK is per
  series.** A single `actions/setup-java` cannot serve both: Ghidra 11.x
  needs JDK 21 and 12.2 needs JDK 25, and javac cannot read a newer class
  file ("bad class file"). The build loop reads the class file major version
  out of the downloaded distribution (44 plus the JDK number), floors it at
  21 — the version the extension targets — and installs that exact Temurin
  JDK from the Adoptium API. The GitHub workflow derives the same number
  with `actions/setup-java` per matrix leg.
- **Find the Ghidra jar with `find`, not with a glob.** A glob inside double
  quotes is not expanded, and the shell hands the literal pattern to
  `unzip`, which then reads nothing: the symptom is `od: cannot skip past
  end of combined input`, not a clear "file not found".
- **The Gitea instance is 1.22.0, and its token rules are its own.** A user
  secret cannot start with `GITEA_`/`GITHUB_` (Gitea reserves those prefixes
  for the secrets it provides itself), and the reserved `GITEA_TOKEN` job
  token with the `permissions:` block only exists from 1.23 — so on this
  instance the token that creates the release has to be a user secret under
  another name. What Gitea *does* fill in 1.22 is `secrets.GITHUB_TOKEN`, with
  its own job token: sending that to `api.github.com` answers **401**, so the
  Ghidra release list has to be read unauthenticated (it is public). The
  release workflow therefore probes both secrets against both APIs and picks
  what works, rather than assuming.
- **Reading a Gitea Actions log on this instance.** The 1.22 API exposes only
  `GET /actions/tasks` and the dispatch endpoint — there is no run, job or log
  endpoint (the Swagger of the instance lists them all). The log lives in the
  database: `action_task.log_filename` (`danalec/GhydraMCP/<repo>/<task>.log.zst`,
  zstd) inside the `Forgejo` container, and the task status is
  `action_task.status` (1 = success, 2 = failure). Read it over SSH:
  `docker exec postgresql18 psql -U postgres -d postgres ...` for the metadata
  and `docker exec Forgejo cat <file>` for the bytes.
- **The guards are shared Python, not YAML.** `scripts/version.py`,
  `scripts/release_notes.py` and `scripts/prepare_release.py` hold the version
  and release-notes rules so both platforms enforce the same ones. Change the
  rules there, not in a workflow `run:` block.
- **Version constants live in five places** — `ApiConstants.PLUGIN_VERSION`,
  `bridge_mcp_hydra.py`'s `BRIDGE_VERSION`, `pyproject.toml`,
  `ghydra/__init__.py`, `extension.properties`. `scripts/version.py --set` is
  the only supported way to change them; `API_VERSION` is a separate axis and
  only moves on breaking API changes.
- **Release notes come from `CHANGELOG.md`** via `scripts/release_notes.py`,
  which fails when the `## [<version>]` section is missing or empty — a tag
  without a matching section no longer ships a release with an empty body.
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

## Kuna integration (local, opt-in)

[Kuna](https://github.com/Noelo-Lab/kuna) is a standalone decompiler CLI. The bridge and the CLI
drive it as a subprocess: no Ghidra instance, no REST API, no `API_VERSION` change, so the `kuna_*`
tools work with any Ghidra version.

- **The bridge is a standalone script** — it ships as one file and must not import the `ghydra`
  package. The Kuna helpers are therefore **duplicated**: `ghydra/kuna.py` for the CLI, and the
  `Kuna integration` section of `bridge_mcp_hydra.py` for the bridge. The same pattern the
  request logic already follows.
- **Opt-in, because it is an elevation of privilege**: the bridge normally only speaks HTTP, and
  this lets it run a program on the host. Enabled by `GHYDRA_KUNA=1` or by
  `"kuna": {"enabled": true}` in `~/.ghydra/config.json`. **The config file wins**: an explicit
  `enabled: false` keeps it off even with the env var set. A config file *without* an `enabled`
  value (or with a null one) leaves the decision to the env var — otherwise `ghydra config init`,
  which writes `"enabled": null`, would silently pin the integration off.
- **Kuna loads and analyses the whole image on every invocation** — measured: 19 s for a 22 MB
  binary, 0.7 s for a 332 KB one. The cost is the analysis, not the command, so the export flow is
  the main path: analyse once into `~/.ghydra/kuna/<hash of path+mtime>/`, then read the C, the
  disassembly and `index.jsonl` from disk. `kuna strings` requires a filter for the same reason
  (an unfiltered scan of `cmd.exe` returns 480 KB).
- **The bridge's export jobs live in the bridge process.** The job registry is in memory, so a job
  started by one bridge is invisible to another, and the registry does not survive a restart. The
  CLI has no registry: `ghydra kuna export` runs synchronously and `export-read` works off the
  directory.
- **The `kuna_*` tools take no `port`.** They are not part of the plugin API, so they take no
  instance either.

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

## Linux and NixOS

The plugin itself is OS-independent (the Java has no path or shell assumptions). The
Python side is where the platform shows:

- **The bridge is a single file with inline dependencies** (PEP 723), so `uv run
  bridge_mcp_hydra.py` installs what it needs. The header must carry the same
  `pydantic<2.14` ceiling as `pyproject.toml`: measured with uv 0.10.10, a fresh
  resolve picks pydantic 2.14.1 and `import mcp.server.fastmcp` dies with "cannot
  import name 'eval_type_backport'". The two places drift apart easily — check both
  when a dependency changes.
- **On NixOS, `uv` cannot install its own managed Python** inside a `nix-shell`: it
  downloads the interpreter and then reports "Python interpreter not found". Use the
  nix-provided one: `nix-shell -p uv python3 --run 'uv run --script --python python3
  bridge_mcp_hydra.py'`.
- **NixOS has no `/bin/sh`**, so nothing may shell out through `shell=True`. The pager
  splits `$PAGER` with `shlex` and runs it without a shell.
- **Never decode a subprocess with the locale.** Python 3.7+ enables UTF-8 mode for
  the C locale, but `PYTHONUTF8=0` (or any non-UTF-8 locale) makes the preferred
  encoding ASCII: measured, a config file with a non-ASCII path then fails to read
  with `'ascii' codec can't decode byte 0xc3`. Pass `encoding="utf-8"` explicitly.
- **`pip install -e .` needs an environment you own.** NixOS and the other
  centrally-managed distributions refuse it with `externally-managed-environment`
  (PEP 668); use `uv`, a venv, or a nix-shell. The README documents the paths.
- **A box without Python is normal** (the Forgejo host has no `python3`): the CLI and
  the suite run in a container, and the workflows install what they need.

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
- **Ghidra 12.2 (2026-10-22) needs JDK 25 and moved the data type removal API.** Two
  consequences, both handled:
  - `javac` cannot read a class file newer than itself, so building against 12.2 with
    JDK 21 fails with `bad class file` on every Ghidra class — for any source, not just
    the change that triggered it. The workflow derives the JDK from the distribution
    instead of hardcoding it: the class file major version is 44 plus the JDK number
    (65 = 21, 69 = 25), with a floor of 21 because the extension targets Java 21.
  - `remove(DataType, TaskMonitor)` is gone; 12.2 has `remove(DataType)` and
    `remove(List<DataType>, TaskMonitor)`. No overload exists in 11.x, 12.0-12.1 and
    12.2 at once, so `GhidraUtil.removeDataType` resolves the call by name.
- The pom's Ghidra dependency `<version>` tags are hardcoded to `12.1.2`; `-Dghidra.version` only
  rewrites the `ghidraVersion` property in `extension.properties`, not those tags. They're
  system-scoped, so this is cosmetic — the `systemPath` jars are what matter.
- **The rich tables break on a Windows pipe.** `TableFormatter` renders with rich's default
  `HEAVY_HEAD` box, whose frame characters are outside cp1252; piped on a Western Windows
  (`sys.stdout.encoding == 'cp1252'`) `click.echo` raises `UnicodeEncodeError`. This is
  pre-existing and affects every table in the CLI, not just the new ones. The Kuna tables pass
  `box=box.ASCII` to stay inside cp1252, and `ghydra kuna` additionally writes with
  `errors="replace"`. A real fix would reconfigure stdout to UTF-8, which changes the CLI
  globally — not done here.

## Key documentation

`README.md` (install, MCP client setup), `GHIDRA_HTTP_API.md` (REST reference, API_VERSION 3000),
`GHYDRA_CLI.md` (CLI reference), `GHYDRA_KUNA.md` (the Kuna integration: opt-in, tools, export
layout), `CONTRIBUTING.md` (PR/release process),
`TESTING.md` (stale on flags), `CHANGELOG.md` (release history — also the release-notes source).