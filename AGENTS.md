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
- 128 MCP tools in 34 namespaces: `analysis_*`, `classes_*`, `comments_*`, `data_*`, `cache_*`, `datatypes_*`,
  `doctor_*`, `evidence_*`, `functions_*`, `headless_*`, `inspect_*`, `instances_*`, `kuna_*`,
  `memory_*`, `mission_*`, `namespaces_*`, `programs_*`, `project_*`, `projects_*`, `raw_image_*`, `scalars_*`,
  `scripts_*`, `segments_*`, `session_*`, `structs_*`, `symbols_*`, `tasks_*`, `telemetry_*`, `tools_*`, `ui_*`,
  `variables_*`, `x64dbg_*`, `runbook_*`, `xrefs_*`.
- v3.0.0 migrated `HttpServer` → **Javalin** with service/DTO/resource layering. `API_VERSION` is
  **3000** (breaking: fully-qualified names everywhere).
- The `kuna_*` namespace is **local**: it drives the Kuna decompiler CLI as a subprocess, so it
  touches neither the REST API nor `API_VERSION`, and it works with any Ghidra version.

## Layout

```
bridge_mcp_hydra.py              # ALL MCP tools + formatters live here (9700+ lines)
ghydra/                          # standalone Click CLI — does NOT import the bridge
  launcher.py                    # the Ghidra installation, the JDK it needs, the command
  headless.py                    # the headless runner: start, stop, status
  report.py                      # Ghidra + Kuna on one binary, and the debugger annotations
  doctor.py                      # what is missing on this machine, and the fix for each
  evidence.py                    # the ledger: findings with IDs that never change
  sessions.py                    # a named working context that outlives the shell
  triage.py                      # what a target is, from its bytes
  kuna.py                        # Kuna CLI driver (local, opt-in)
  x64dbg.py                      # the x64dbg driver (local)
  progress.py                    # what a long step is doing, and how long it took
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
  is the page, `meta.total` the count. The references to a *name* are the same case: the
  count comes from the references themselves, and only the ones of the page become DTOs.
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

**Every text answer ends with a `Next:` line** (I8): `text_output` translates the envelope's
`_links` into the bridge call that follows them (`functions_decompile(address="0x…")`, the next
page for a paginated listing). The hrefs carry real values, so the suggestion is directly
callable; a link that does not map to a registered tool is left out rather than guessed.

**A tool parameter must not be called `arguments`.** That is the name of the container the MCP
protocol uses for a tool's parameters, so a client that re-encodes the container loses the value
— the call goes through with no arguments and the tool does something else instead of failing. It
happened to `x64dbg_call`, and the unit tests did not catch it because they called the function
instead of the protocol: `test_x64dbg.py` now drives a tool through `mcp.call_tool(...)`, and a
guard asserts that no bridge tool declares a parameter the protocol reserves.

**The tool list is groupable** (I15): 120 tools in one list degrade selection, so the bridge groups
them by workflow — `core` (always), `functions`, `data`, `types`, `scripts`, `headless`, `kuna`,
`x64dbg`. `GHYDRA_TOOL_GROUPS=core,functions` at startup keeps only those groups registered;
at runtime `tools_load_group` / `tools_unload_group` change it, and `tools_search` searches the
FULL catalogue (including hidden tools) and names the group to load. `tools_groups` shows what is
loaded. A client that caches the tool list must re-read it after a runtime change — the env var
gives a guaranteed profile.

**A tool parameter that takes a nested object should take it as one piece of text.** A client that
delivers a tool's parameters over stdio flattens what is nested in them: every value of a nested
object arrives as a string. Measured on this desktop with the official GitHub MCP server, whose
`labels` array arrived as something that was not an array, and with `x64dbg_call`, whose integer
`count` arrived as `"3"` — the plugin ignores a parameter it cannot read and answers with its
default instead of the one that was asked for.

So `x64dbg_call` declares `tool_arguments` as a **string** (the JSON text) and parses it itself;
an object is accepted as well, and its types are put back from the plugin's own input schema.
Two things make it work, and both are worth keeping: the schema asks for the form that survives
the client, and the types are restored from the schema the plugin publishes — not guessed.

The trap on the way: FastMCP's `pre_parse_json` (`func_metadata.py`) turns a JSON string into the
object it describes *before* the validation, so a parameter declared as `str` rejects the object it
just built. `Annotated[str, BeforeValidator(...)]` is what takes the object back as text.

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
in exactly one place — `register_instance` — by exact equality against `3000`, and never
per-request. It negotiates through `GET /capabilities` (falling back to `/plugin-version` on
older plugins), so a mismatch is reported immediately with both versions, the Ghidra/Java
runtime and the remedy. Optional features are discovered from that payload's `features` map;
they are additive and never require an `API_VERSION` bump. The CLI never checks the version.

SemVer: patch for fixes, minor for features, major for breaking.

## Testing

```bash
python run_tests.py                      # all suites
python run_tests.py --http --mcp --data --comments --port --kuna --x64dbg   # or any subset
python run_tests.py --rea                # the four gaps closed against the REA
```

**Every suite skips itself when Ghidra isn't running** (`setUp` → `skipTest("Ghidra not running")`).
A green run against no Ghidra means nothing — confirm tests actually executed before trusting it.
Tests need Ghidra with a binary open, and a loaded binary with functions (`skipTest` otherwise).

**The exception is `--kuna`**: `test_kuna.py` needs neither Ghidra nor the Kuna binary, so it always
runs and always gives a signal. It covers the Kuna opt-in precedence, the bridge/CLI contract
(every `kuna_*` tool has a `FORMATTERS` entry and is registered in MCP; none takes a `port`) and
the export readers.

**`--x64dbg` is the other one that always runs**: `test_x64dbg.py` needs neither Ghidra nor
x64dbg, because it starts a fake plugin that answers like the real one (JSON-RPC over HTTP, a
bearer token, the tool catalogue with `annotations.readOnlyHint`). It covers the client, the
config precedence, the address model, the bridge tools and the error taxonomy.

**`--rea` is half of each**: `test_rea_parity.py` splits the contract (the tools are registered, each
one has a formatter, the CLI has the command, the list of targets is read in every shape — none of
which needs a Ghidra) from the live half (the API and the bridge over the wire — which does). A skip
there is usually a stale premise rather than an absence: the suite looks for a caller/callee pair by
the `CALL` family of reference types, and Ghidra calls them `UNCONDITIONAL_CALL`,
`CALL_OVERRIDE` and `CALL_INDIRECT`.

**The x64dbg suite is not immune to the network stack.** A local TCP connection is reset every
now and then on this machine (measured: 7%), so a suite that opens dozens of connections will
see a failure every now and then unless the client retries — which it does, but only where
repeating is safe. When a test fails there, look at the transport before the logic: a
`ConnectionResetError` underneath is the machine, not the code. It reaches the test as
`X64DBG_UNCERTAIN` when the tool changes the debuggee (the request was delivered and its
answer was lost, so it was not repeated) and as `X64DBG_MISSING` when it did not leave.

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

`--json` is defined once on the root group and injected as `ctx.obj['formatter']`; no
subcommand redefines it. The root group class (`GhydraCLI`) lifts a `--json` found
**anywhere** in the arguments into `GHYDRA_JSON` before parsing, so both
`ghydra --json functions list` and `ghydra functions list --json` work (and so does
the environment variable alone). Paging auto-disables under `--json`. Config precedence
is **CLI flag > `GHYDRA_HOST`/`GHYDRA_PORT` > `~/.ghydra/config.json` > defaults**
(`localhost:8192`, timeout 900). The CLI also reconfigures stdout/stderr to UTF-8 with
`errors="replace"` at startup, so Rich tables survive a cp1252 Windows pipe.

The bridge's env vars are a *different, asymmetric* set: `GHIDRA_HYDRA_HOST` > `GHIDRA_HOST`,
plus `GHIDRA_TIMEOUT`, `GHIDRA_DECOMP_TIMEOUT`, `GHIDRA_ALLOWED_ORIGINS`. **The bridge never reads
`GHYDRA_PORT`.** The MCP-side switches keep the `GHYDRA_` prefix (`GHYDRA_MCP_OUTPUT`,
`GHYDRA_KUNA`, `GHYDRA_KUNA_TIMEOUT`, `GHYDRA_STATE_DIR`); the CLI's `GHYDRA_HOST`/`GHYDRA_PORT`
above are a separate set.

`GHYDRA_MCP_OUTPUT=json` is the exception to the rule that the bridge answers in **text**: it hands the
raw envelope as one JSON document instead of the formatted table. The default stays text — that is the
contract the agents are written against — and the mode exists for a machine that parses the answer
(the MCP test suite drives the bridge this way).

**The MCP resources carry the `ghidra://` scheme.** A relative URI is refused: the protocol types the
URI of a read as a URL, and the server validates it before the resource is looked up, so
`/instance/{port}/...` was a template no client could name and no client could read. The templates are
`ghidra://instance/{port}`, `ghidra://instance/{port}/function/{decompile,info,disassembly}/{address,name}/...`.

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
- **Kuna loads and analyses the whole image on every invocation** — measured with Kuna 1.988:
  20 s for a 44 MB binary, 0.5 s for a 332 KB one. The cost is the analysis, not the command, so
  the export flow is the main path: analyse once into `~/.ghydra/kuna/<digest of path+mtime>/`,
  then read the C, the disassembly and `index.jsonl` from disk. `kuna strings` requires a filter
  for the same reason (an unfiltered scan of `cmd.exe` returns 480 KB).
- **A complete export is reused, not re-analysed.** `kuna_export_start` and `ghydra kuna export`
  look under the digest first and only run Kuna when there is no complete export, or when the one
  on disk does not hold the functions that were asked for. The report says which happened
  (`"reused": true`). Measured: re-reading the export of a 332 KB binary takes 21 ms against the
  2 750 ms of the export itself; for a 44 MB binary it is 152 ms against the 154 s of the export.
  The re-read is not quite free either — it reads the index, which holds one record per function.
  The digest keys on the path *and* the mtime, so a rebuilt binary gets a fresh directory.
- **A subset is not the whole binary, and the digest does not know that.** The digest keys on the
  path and the mtime, *not* on the filter, so the same directory serves a filtered export and an
  unfiltered one. An export made with `--functions main` holds only that function; reusing it for
  an unfiltered request would answer with the subset and call it the whole binary. So the sidecar
  `.ghydra.json` records the filter, and an unfiltered request against a filtered export is
  analysed again.
- **A directory the caller named has no provenance of its own.** The digest directory carries the
  provenance in its name; a directory given with `-o` does not. The sidecar therefore records the
  mtime as well as the binary, and an export in a named directory is only reused when the sidecar
  says it came from this binary, with the mtime it has now — another binary, or the same path
  rebuilt, is analysed again instead of answered with stale artifacts.
- **The performance numbers are measured, not remembered.** `scripts/bench_kuna.py` produces the
  table in `GHYDRA_KUNA.md` and is committed with it. A Kuna upgrade changes the numbers, so they
  are re-measured rather than quoted.
- **The export is addressed by its digest, not by the job.** The digest is 12 hex characters,
  survives a restart of the bridge, and is what `kuna_export_read(directory=...)`, the
  `kuna://export/<digest>/` resources and `ghydra kuna status` all use. The job registry lives in
  the bridge process, so a job started by one bridge is invisible to another and does not survive
  a restart — which is why the digest exists. The CLI has no registry: `ghydra kuna export` runs
  synchronously and `export-read` works off the directory or the digest.
- **The exports are MCP resources.** `kuna://exports` is a JSON manifest of every export on disk;
  `kuna://export/{digest}/index.jsonl`, `kuna://export/{digest}/{function}.c`,
  `kuna://export/{digest}/{function}.asm` and `kuna://export/{digest}/README.md` serve the files.
  A function name goes into the URI percent-encoded. The resources are the RAG loop with *exact*
  addressing: list the exports, read the index, read one function. Embeddings would retrieve the
  wrong function more often than the right one — the corpus has an exact index.
- **One error taxonomy on both sides.** The bridge and the CLI carry the same 14 codes
  (`KUNA_DISABLED`, `KUNA_MISSING`, `KUNA_TIMEOUT`, `KUNA_LAUNCH`, `KUNA_FAILED`, `KUNA_NO_JSON`,
  `KUNA_TOO_LARGE`, `KUNA_NO_FILE`, `KUNA_IO`, `KUNA_NO_DIR`, `KUNA_NO_INDEX`, `KUNA_BAD_ARTIFACT`,
  `KUNA_NO_FUNCTION`, `KUNA_ERROR`). `test_kuna.py` asserts the two lists are identical, so adding
  a code to one side without the other fails the suite.
- **The `kuna_*` tools take no `port`.** They are not part of the plugin API, so they take no
  instance either.

## x64dbg integration (local, like the Kuna one)

The [x64dbg MCP server](https://github.com/duty1g/x64dbg-mcp-server) is a Zig plugin that lives
inside the debugger and answers JSON-RPC 2.0 POSTed to `/`. It is **not** part of the Ghidra
plugin API, so it changes neither `API_VERSION` nor the Java side.

- **The contract**: `POST /` with a JSON-RPC 2.0 body, `Authorization: Bearer <token>`, and the
  answer is `application/json` — no SSE framing. The server keeps no state, so every request
  stands alone and there is no handshake to maintain. `tools/call` answers
  `{"content": [{"type": "text", "text": ...}]}`; an error is `{"error": {...}}`.
- **The token cannot be guessed.** The plugin writes it to its own `mcp_config.json` next to
  `x64dbg.exe` (it asks the OS for the *process* path, not the DLL's), so
  `"x64dbg": {"path": "<installation>"}` is enough to find it; `"x64dbg": {"token": ...}`
  sets it outright. The plugin's `IpAddress`, `Port` and `AuthToken` keys are the ones in that file.
  The environment carries `GHYDRA_X64DBG_HOST`, `GHYDRA_X64DBG_PORT`, `GHYDRA_X64DBG_TOKEN` and
  `GHYDRA_X64DBG_PATH`; the config file wins over the environment, as everywhere else. The path in
  the environment is what makes the integration usable without editing a configuration file, since
  the token is the one thing that cannot be guessed.
- **The port**: 9094 for a 64-bit debuggee and 9095 for a 32-bit one. The released plugin binds
  exactly those two and stops serving if the port is taken; the fixed build (PR #13 upstream)
  walks up to 32 ports instead. The bridge and the CLI look for the port rather than assume it,
  and the scan reaches as far as the fixed plugin can go. The walk starts from the **configured**
  port as well as from the two defaults, because that is where the fixed build starts: a server
  on the configured port plus one has to be found too.
- **The likely ports are probed with more patience than the walk.** The scan asks for one
  attempt per port in the walk — a closed port stays closed, and every extra attempt costs the
  whole connect timeout again — but the configured port and the two defaults are probed three
  times and get five seconds to answer. The machine resets about one loopback connection in
  fourteen and a loaded machine can take a couple of seconds to answer, and a debugger that is
  running must never be written off because of it.
- **The port the plugin was found on is kept.** The plugin does not move while the debugger
  runs, and the scan opens ninety connections — so a scan per call is a lot of exposure for an
  answer that does not change (and the machine resets one connection in fourteen). The port is
  probed once before it is used, and a port that stops answering — or a token that is refused —
  sends the scan back out. The cache is keyed by the configuration it was found with, so a
  different host, port or token never reads another one's answer.
- **The plugin's file fills the blanks and only the blanks.** It says which address the plugin
  listens on, and that is used when nothing else says so — but a host or a port that came from
  the config file or from the environment is a decision the user made, and the plugin's file
  does not get to overrule it.
- **No token means `X64DBG_DISABLED`, before the scan.** There is no way to talk to the server
  without one, and probing the ports would only report a missing server or a rejected token:
  neither of them says what is actually wrong. The CLI and the bridge refuse the same way.
- **The plugin's text is escaped before it reaches Rich.** Every answer carries a `[state]` line,
  and Rich reads a bracketed word as a style: without the escape the marker is swallowed and the
  agent loses the line that says what the debugger is doing. `escape()` the raw text, never the
  markup around it.
- **The arguments' types are restored from the plugin's own schema.** A `--arg count=3` reaches
  the plugin as the string `"3"`, and the plugin ignores a parameter it cannot read and answers
  with its default: the call comes back with ten instructions when three were asked for. The
  schema says what every parameter is, so the type is put back from it — not guessed.
- **The address model**: `runtime = static − image_base + module_base`. The `image_base` comes
  from the Ghidra `/program` endpoint, the `module_base` from the plugin's `ListModules`. The two
  binaries are matched by full path first and by file name second, because the two sides can
  disagree about the directory.
- **The 80 plugin tools are not exposed one by one.** That would drown the agent's tool list
  (165 tools in one agent), so the catalogue (`x64dbg_tools`) and a generic pass-through
  (`x64dbg_call`) are exposed instead, plus four workflow tools that carry the address model.
- **The `x64dbg_*` tools take no `port` for the debugger.** They are local, like the Kuna ones;
  the `port` on the workflow tools is the **Ghidra** instance, as everywhere else in the bridge.
- **No session pooling.** The plugin closes the connection after every response, so a pooled
  connection is reused after the server has already hung up on it — that is a
  `ConnectionResetError`, not a missing server. Use a plain `requests.post` per call.
- **A local connection is reset every now and then on this machine**: measured at 7% of the
  connections, with curl and with plain sockets alike, so it is the Windows network stack and not
  the client. The client retries a connection error (up to three attempts, on a fresh connection).
- **A timeout is only retried when the request is safe to repeat**, and so is a connection that
  died while the answer was coming: the plugin marks every tool with `annotations.readOnlyHint`,
  so a read-only tool may be called again; a tool that changes the debuggee may not, because the
  first attempt may already have reached it. A connection that never came up is the one
  exception: the request was never sent, so that one is always safe to try again.
- **The connect timeout and the read timeout are separate.** A closed local port does not refuse
  straight away on Windows — the SYN hangs and is only refused about two seconds later — so the
  probe uses a short connect timeout (0.35 s) and the ports are probed concurrently. A tool that
  blocks (`run`, `WaitForEvent`) needs a read timeout of its own: `x64dbg_call` takes a `timeout`.
- **The logic is duplicated**, like the Kuna helpers: the bridge is a standalone script and must
  not import the `ghydra` package, so `ghydra/x64dbg.py` and the bridge's x64dbg section carry
  the same client, the same error taxonomy and the same retry rules.

## Headless mode (no window)

The same API, served by a headless Ghidra run: the binary is imported, analysed, and the API
answers for that analysis, with nobody watching. `ghydra headless start|status|stop`, and
`ghydra report build` for the report. See `GHYDRA_HEADLESS.md`.

- **The bootstrap lives in `server/GhydraServerFactory`**, not in the plugin. Both paths - the
  CodeBrowser plugin and the headless run - go through it, so the same twenty-one resources are
  registered in both. A resource added to one and not the other answers 404 in one instance and
  200 in the other; that is the bug this factory exists to prevent.
- **The headless context holds one fixed program and one fixed project**
  (`server/GhidraContext.java`). `ctx.program()` and `ctx.project()` prefer them. The endpoints
  that need the GUI's cursor - `/address` and `/function` - answer 503 `HEADLESS_LIMITATION`,
  because there is no cursor without a window. The HTTP test suites that exercise them need the
  CodeBrowser; every other endpoint behaves the same in both.
- **A Ghidra script has to import the class it extends**: `import ghidra.app.script.GhidraScript;`.
  Ghidra only adds that import to the template it writes for a *new* script; an existing one has
  to carry it. Without it the script does not compile, and the error says nothing about the import
  - "cannot find symbol" on the class and on everything the class brings with it
  (`currentProgram`, `state`, `getScriptArgs()`). Measured: the same failure happens for a script
  inside a Ghidra module and for one outside every module, so it is not about where the script
  lives.
- **A Ghidra project path may not hold an element that starts with a dot.** `analyzeHeadless`
  refuses it ("Path element starting with '.' is not permitted"), so the project cannot live under
  `~/.ghidra`. The launcher uses `ghidra_projects` in the home directory.
- **The run is stopped politely.** The launcher leaves `~/.ghidra/headless-<port>.stop` behind and
  the script returns when it sees it; the headless analyzer then saves the program and closes the
  project, and the project is left unlocked. Killing the process instead leaves the lock file
  behind, and the next run refuses to open the project.
- **The launcher builds the JVM invocation itself** (`ghydra/launcher.py`), and does not call
  Ghidra's launcher script. It is the same invocation the launcher makes - the installation's own VM
  arguments, from Ghidra's `LaunchSupport`, the headless heap and thread flags, and the analyzer
  class. Three things fall out of it: the log of the run is the log that was asked for; the Windows
  launcher no longer asks "press any key to continue" when it fails (it cannot tell a double-click
  from a shell, and a launcher started by another program is exactly that case); and the JDK is
  found by asking Ghidra which one it supports.
- **The JDK is versioned against the installation, not guessed.** `application.java.min` says which
  JDK the Ghidra needs (21 for the 11.x series, 25 for 12.2), and the installation's VM arguments
  carry flags that only the newer JVMs take - so a JDK that is too old dies with a message about a
  flag instead of about the JDK. The layers, in the order of how explicit the decision is: what the
  caller asked for, what `~/.ghydra/config.json` says, `JAVA_HOME`, the JDK Ghidra itself would use
  (`LaunchSupport -jdk_home -save`), and the places a JDK is usually installed. An explicit JDK that
  is too old is an error; an environment that points at one that is too old is only a place the
  search did not stop.
- **A headless run only signals its own process.** A run that crashed leaves its state file behind,
  and the operating system hands its PID to somebody else - so the command line is read before
  anything is killed, and a process that does not carry the marker of the headless script is left
  alone. The child that was started is polled rather than looked for: polling reaps it, and a child
  that was never reaped stays a zombie, which `kill(pid, 0)` still finds alive.
- **A port that is already served is refused.** Starting on it would make the wait accept the server
  that is already there, and the command would report a run that never bound the port.
- **A headless run has to stop the server it started.** The threads of a Jetty are not daemons, and
  a JVM with a live Jetty does not exit: the run stayed alive after the analyzer had saved the
  program, and the launcher had to kill it - the polite stop turned into the blunt one, and the
  analysis of a program that was being saved was lost. The script stops the server before it
  returns.
- **The save of a headless run is the analyzer's, not the API's.** The program is inside the
  transaction of the script that serves the API, so `POST /program/save` is refused with "Unable to
  lock due to active transaction"; the analyzer saves the program when the script returns. The
  answer is built from the project instead: Ghidra writes the content of the program under
  `<project>.rep/idata/` in a file whose name starts with `db.`, and that is the witness of the
  save.
- **A program that is already in the project is processed again; one that is not is imported.**
  Importing a program that is already there fails, and the run never reaches the script that
  starts the server. The index of the project (`<project>.rep/idata/~index.dat`) is plain text and
  says which files are in it.
- **Ghidra identifies a program by its file name.** Two binaries with the same name in different
  directories are two programs that cannot live in the same project, so the default project name
  carries a short digest of the absolute path (`cmd-3f2a1b9c`). Without it the second run reuses
  the project of the first and is served the analysis of a file nobody asked about.
- **`POST /dev/shutdown` guards the headless program too.** The unsaved-changes probe asks the
  ProgramManager, and a headless instance has none - so the program the instance serves is asked
  as well, and an exit cannot throw the analysis away.
- **The save is checked before it is reported.** `requests.post` does not raise on a 4xx, so the
  launcher looks at the answer before it says `saved: true`; the reason goes to the log of the run.
  `headless stop` reports the save it got, and a save that was refused is not reported as a save.
- **The lock of a run that died is cleaned up.** A crashed analyzer leaves `<project>.lock`
  behind and every later start refuses the project, so stopping a run that is gone removes the
  lock. The lock of a live process that is not ours is left alone - and the lock file of a
  project carries no owner that can be read, so the processes are asked instead: a CodeBrowser
  that has the project open holds the lock, and that lock is never removed.
- **The state of a run is erased only while it is that run's state.** A start that was refused
  before the child was launched has no PID of its own, and the state on disk belongs to a run
  that is still there - erasing it would leave that run untracked, and the next start would
  walk past the guard that remembers it.
- **The report goes to the instance the CLI chose.** The command takes the host and the port from
  the client the root command built - the configuration, the environment or `--host/--port` - and
  not from a request of its own.
- **The program is matched by its full path.** Ghidra identifies a program by its file name, so
  the report compares the full path of the executable and falls back to the name only when one
  of the two paths is not known - otherwise a CodeBrowser serving `/a/foo.exe` answers for
  `/b/foo.exe`, and the report combines the addresses of the first with the output of the
  second.
- **A headless run serves this machine.** The run is started here, so a report pointed at another
  machine that is not serving the API is refused (`REPORT_NO_INSTANCE`) instead of starting a run
  that cannot answer it - and a run that does not come up is stopped, not left behind.
- **An address of this machine is local even without the DNS.** The question is asked of the
  operating system and not of the name of the machine: a socket that binds to the address is
  accepted, and one that binds to an address of somebody else is refused. A secondary address of
  a LAN card and an IPv6 address that the hostname does not carry are both local.
- **The port is checked before anything is started.** The script falls back to 8192 for a port it
  cannot use, so a port of 0, a negative one or one above 65535 is refused with
  `HEADLESS_BAD_PORT` instead of waiting on a port that was never bound.
- **The backslash is a separator everywhere.** On POSIX, `os.path.basename()` takes the whole
  `C:\bin\cmd.exe` as the name - so the name of the file comes from `binary_name()`, which knows
  both separators, and the lookup in the index of the project finds the program that is already
  there instead of importing it again.
- **A project remembers the binary it was built from.** The size and the time of the file are
  written next to the project (`<project>.ghydra.json`), and a binary that changed is imported
  again with `-overwrite` - otherwise the run would analyse the stored copy of a file that is not
  there any more. The time keeps its sub-second part, because a rebuild inside the same second
  is a different file; and the sidecar is written when the run is serving, not before it - a run
  that failed left behind the sidecar of a binary that was never in the project.
- **A run that is still analysing keeps the port.** It has not bound the API yet, so the port
  looks free - but the PID that is remembered for the port is checked before anything is started,
  or a second run would take the state of the first and leave it untracked.
- **The port is claimed before the child is launched.** Two starts that arrive together both
  find the port free, and both launch an analyzer: the one that binds the API first answers
  both waits, and the state file ends up naming the loser - so one report can combine the
  Ghidra data of one binary with the Kuna data of another. The claim carries a token that says
  which runner made it, and a claim that nobody took up is given back after a minute.
- **The PID is matched to its port.** The PID of a run that crashed is reused by another run
  of the same script - on another port, with another project - and stopping that one would kill
  a live analysis. The command line has to carry `port=<n>` as well as the marker.
- **The stop flag is removed after a kill, and before a run starts.** A run that was killed before
  the script could see the flag leaves it behind, and the next run on that port would stop as soon
  as it started.
- **The extension's jar is shaded.** Javalin, Jetty, SLF4J and Kotlin are inside `Ghydra.jar`, so
  the script's bundle finds them; a jar with only the compiled classes fails at runtime with
  `NoClassDefFoundError: io/javalin/http/Handler`. `scripts/make_uberjar.py` does the merge
  without Maven.
- **The registry of the instances holds a snapshot, not a handle.** The `/instances` route knows
  two things: the plugin of a CodeBrowser, and a map that carries the snapshot of the program.
  A headless run has no plugin - so what it registers is the map, and the file, the project,
  the executable, the architecture and the image base are there for the clients that pick an
  instance.

## The doctor, the evidence ledger and the sessions

Three things that exist because the work outlives the moment it was done.

- **`ghydra doctor` looks at everything at once** (`ghydra/doctor.py`): the installation, the JDK it
  needs, the extension and the version it was built for, the port, the project directory, the API,
  Kuna and the x64dbg plugin. Every problem carries the command that solves it - a check that fails
  is never a dead end. The doctor resolves the installation *first* and asks about the JDK and the
  extension in terms of that installation: a JDK that is too old for the Ghidra that is actually
  installed is a failure, not a warning.
- **The evidence ledger gives every finding an ID** (`ghydra/evidence.py`). The IDs are `EV-0001`
  and they are never given out twice, even after the finding is removed - the counter is the highest
  ID ever issued, kept in the ledger itself. The ledger lives in `~/.ghidra/evidence/<name>.json`
  and is exported as a bundle: a Markdown document to read and a JSON one to read with a program.
- **A session is a named working context** (`ghydra/sessions.py`): the binary, the port that serves
  it, the state. It outlives the shell that opened it, and `close_session` stops the run the polite
  way, so the analysis is saved and the project is left unlocked.
- **The bridge does not import the `ghydra` package** - it ships as one file - so the headless,
  doctor, evidence and session helpers are written out in `bridge_mcp_hydra.py` too, the way the
  Kuna ones are. The two sides have to agree about the file formats: the ledger and the sessions
  are read and written by both.

## The four gaps closed against the REA

`REA_PARITY.md` compared this project with the REA (139 tools in `rea-agents` 6.0.0) and named four
gaps that were native and cheap. All four are closed, on the three surfaces at once, and
`test_rea_parity.py` is what proves they agree:

| REA | REST API | Bridge tool | CLI |
| --- | --- | --- | --- |
| `batch_decompile` | `POST /functions/decompile-batch` | `functions_batch_decompile` | `ghydra functions decompile-batch --targets '["main"]'` |
| `find_xrefs_to_name` | `GET /xrefs/to-name/{name}` | `xrefs_find_by_name` | `ghydra xrefs find-by-name strlen` |
| `inspect_address_context` | `GET /inspect/address/{address}` | `inspect_address` | `ghydra inspect-address 0x140001008` |
| `trace_call_path` | `GET /analysis/call-path?from=&to=` | `analysis_trace_call_path` | `ghydra analysis trace-call-path --from main --to strcmp` |

- **A batch reports each target separately.** A target that resolves to nothing comes back as a failed
  entry with the reason, and the other targets are still decompiled: a triage pass wants to know which
  ones were wrong, not lose the nine that were right. The server caps a batch at 200 targets.
- **The list of targets is text.** `functions_batch_decompile` declares `targets` as a `str` (JSON text),
  because a client that hands over a nested list flattens it - every value arrives as a string. The
  schema asks for the form that survives the client, and the parser reads a JSON array, a bare name or
  a comma-separated list.
- **The deadline of a batch covers the batch.** The server runs the targets one after the other and
  each of them may take the whole timeout, so the transport deadline is the timeout times the number
  of targets the server accepts (200). The timeout of a batch travels in the body and not in the
  query, so a deadline derived from the query alone is one function long - and the bridge answers
  `REQUEST_TIMEOUT` while the server is still decompiling the targets that are left.
- **A name is a name.** `xrefs_find_by_name` resolves the name to the symbols that carry it (a bare name
  matches every namespace, a qualified one matches that namespace) and returns the references to them.
  A name that resolves to nothing is a 404 with `SYMBOL_NOT_FOUND`, not an empty list. The page is cut
  before the DTOs are built: each reference resolves the functions on both of its sides, so a hot
  symbol would make every page pay for the references it does not return.
- **The address context is one traversal.** `inspect_address` gathers the symbol, the containing
  function, the data, the instruction, both comments and the references on both sides inside a single
  `GhidraSwing.runRead`, so the answer is consistent and the agent pays one round trip.
- **The call path is the shortest one.** `analysis_trace_call_path` is a breadth-first walk over the
  call edges, bounded by the depth limit (16 at most) and by a cap on the functions it visits. When
  there is no path it says how many functions it explored and why it gave up - it never says "not
  found" without saying what it looked at. The path is rebuilt from the last hop back to the source,
  and every link of it is a node of the path: the function in the middle is not dropped, and the
  source is not put in twice. When the cap of visited functions cut the search short, the reason
  says so - a path beyond the cap was not looked for, and "there is none" is not the same answer.

## The composed calls

Four more that the REA has and this project did not, closed the same way: one tool, one command,
one formatter each. None of them needed a new endpoint - they compose what was already there.

| REA | Bridge tool | CLI | What it composes |
| --- | --- | --- | --- |
| `procedure_callers` | `analysis_callers` | `ghydra analysis callers ADDR` | `GET /analysis/callers/{address}` |
| `procedure_callees` | `analysis_callees` | `ghydra analysis callees ADDR` | `GET /analysis/callees/{address}` |
| `analyze_function` | `functions_analyze` | `ghydra functions analyze --address ADDR` | the function, its decompilation, its callers, its callees and its references |
| `binary_overview` | `programs_overview` | `ghydra analysis overview` | the program, its segments, its counts and its imports |

**The callers and the callees existed in the API and in neither of the other two surfaces.** The
endpoints were there since v3.0.0; the bridge and the CLI simply never exposed them, which is the
kind of gap that only a real comparison finds.

**A page that is not the whole list says so.** The callers and the callees take an `offset` and a
`limit`, and the text of the answer says how many there are in total when the page holds fewer - a
list of 100 that reads as "there are 100" when there are 136 is a lie an agent cannot see.

**A composed answer must not hide a failure.** `functions_analyze` and `programs_overview` gather
several answers into one, and a part that failed is reported as empty rather than as the whole
thing having failed. The one part that decides the success is the one the caller asked for: the
function, and the program. The CLI follows the same rule: a caller, a callee or a reference that
fails does not throw away the function that was found and the decompilation that came with it.

## The target triage

`ghydra/triage.py` identifies a file from its bytes - never from its extension - and says what
each kind needs: a PE (with its sections, its imports, its resources and whether it is managed),
an ELF (with its sections, its segments and its shared libraries), a Mach-O, a DEX, an APK, a
WASM module, an EVM contract (with the 4-byte selectors its dispatcher compares), a firmware image,
a JavaScript or Electron application, a core dump, a plist, a HAR capture. It needs neither Ghidra
nor the network, and it is the answer to "which tool do I use for this?".

- **Never guess a fact.** Everything it reports comes from the bytes; what cannot be read is
  omitted, and a truncated or corrupt file yields the facts that could be read rather than an error.
- **The asar archive is not a ZIP.** It is a pickle header with the size of a JSON header, then the
  JSON header, then the files - and an Electron application is a directory of them.

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
- **A jar built against `lib/` runs against the installed Ghidra, and the two do not have the same
  signatures.** `DataTypeComponent.setFieldName(String)` returns `void` in 12.0.1 and
  `DataTypeComponent` in 12.2, and the return type is part of the JVM descriptor: a call site compiled
  against `lib/` asks for `setFieldName(Ljava/lang/String;)V` and the installed 12.2 only has
  `setFieldName(Ljava/lang/String;)Lghidra/program/model/data/DataTypeComponent;`. It fails at runtime
  with a `NoSuchMethodError`, and an `Error` is not an `Exception`: `TransactionHelper` catches
  `Exception`, so nothing is logged, the exception escapes Javalin, and the answer is a `500` with an
  **empty body**. The jar must be compiled against the Ghidra that will run it — the install's own
  jars first on the classpath, `lib/` last. The symptom to recognise: a `500` with no body and nothing
  in the log is a build that was compiled against the wrong series.

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
- **The rich tables used to break on a Windows pipe.** `TableFormatter` renders with rich's default
  `HEAVY_HEAD` box, whose frame characters are outside cp1252; piped on a Western Windows
  (`sys.stdout.encoding == 'cp1252'`) `click.echo` raised `UnicodeEncodeError`. Fixed: the CLI
  entrypoint now reconfigures stdout/stderr to UTF-8 with `errors="replace"` before any output
  (covered by `test_errors.py`, which runs the CLI under `PYTHONIOENCODING=cp1252`). The Kuna
  tables keep `box=box.ASCII` as defense in depth.

## Key documentation

`README.md` (install, MCP client setup), `GHIDRA_HTTP_API.md` (REST reference, API_VERSION 3000),
`GHYDRA_CLI.md` (CLI reference), `GHYDRA_KUNA.md` (the Kuna integration: opt-in, tools, export
layout), `GHYDRA_X64DBG.md` (the x64dbg integration: the contract, the address model, the tools),
`CONTRIBUTING.md` (PR/release process),
`TESTING.md` (stale on flags), `CHANGELOG.md` (release history — also the release-notes source).

## Read-only mode, audit trail and CI assertions

- **Read-only is one handler** (`middleware/ReadOnlyGuard`, I12): with
  `-Dghidra.mcp.readOnly=true` or `GHYDRA_READ_ONLY=1`, every `POST`/`PUT`/`PATCH`/`DELETE`
  is refused with `403 READ_ONLY_MODE` before the resource runs. It is registered in
  `GhydraServer` right after CORS, so a mutation added later cannot bypass it. Do not
  add a per-service check: that is how one endpoint ends up unfenced.
- **Every mutation is recorded** (`middleware/AuditTrail`, I12): one JSONL line per
  state-changing request (`ts`, `request_id`, `method`, `path`, `status`, `ms`, `port`)
  under `~/.ghydra/audit.jsonl`, bounded and local; the request body is deliberately
  not recorded. `/capabilities` carries `features.read_only` and `features.audit_log`.
- **`--dry-run` is client-side** (`GhydraHTTPClient._dry_run`, I12): a mutating method
  returns the plan as its result instead of sending it, so a dry run cannot change
  anything even if the server disagrees about the method. `ghydra audit` reads the trail.
- **`ghydra assert` (I16)** evaluates a JSON list of assertions and exits non-zero on a
  failure (`--format text|junit|sarif`). An absence claim against a truncated listing is
  `inconclusive`, never a pass: proving "no import X" needs the whole list.
- **`?count=false` (I10)** skips the counting walk. The page stays exact; `meta.total` is
  omitted and `meta.counted` is false, and `next` comes from a full page. `Pagination`
  carries `counted`, `PaginatedResult` honours it, and the two listing services take a
  `count` flag; the bridge exposes it as `count` on `functions_list`/`symbols_list`.