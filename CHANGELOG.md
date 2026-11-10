# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **The BSim query was written twice.** The executable filter has to travel
  inside the query — BSim applies it in its SQL layer, so the match limit is
  spent on the matches of the wanted executable and not on the whole corpus —
  and the query service was out of reach when the filter was built, so
  `BSimDiffService` grew its own copy of it: about 250 lines that would have to
  be fixed twice. The filter moved to `BSimQueryService`, which now builds it
  (`executableFilter`) and attaches it (`query(..., filter)`), and the diff
  asks for one. The duplicate import of `GhidraSwing` went with it.
- **The program fingerprint asked for names no endpoint sends.**
  `ProgramResource.getCurrentProgram()` answers `path` and `imageBase`; the
  diff, the runbook and the mission asked for `executable_path` and
  `image_base`, so a fingerprint carried only the name — and **two different
  binaries of the same name compared as "the same program fingerprint"**. The
  runbook's own docstring says the path is what tells "the same program" from
  "another one with the same name", and the mission's dossier printed
  "(no path)" because it read `path` but stored it under `path` while its own
  renderer read `executable_path`. One accessor in the core
  (`fingerprint_from_program`) now builds it, and the bridge and the CLI call
  the same one — they did not even agree with each other before (the CLI read
  four fields, the bridge two).
- **The server's own error code was read and thrown away.** The cross-tool
  workflow turned every failure into a `TARGET_*` code and dropped the code the
  server sent, so "the instance is down" and "the server refused this one"
  looked the same. The target taxonomy is still the contract; the original code
  travels in the message.
- **`ghydra target` had no test at the level the user runs it.** The helpers
  were tested and the commands were not, which is how a mistake in the
  command's own failure handling survived: the handler named a class it did not
  import, and nothing ever reached it. A new suite drives the five commands
  through the real root command and checks that a failure is **reported** with
  its code and a non-zero exit, rather than raised out of the command.
- **The cross-tool workflow read a program shape no instance sends.** The Ghidra
  API emits `imageBase` and serialises every address with `Address.toString()` —
  **unprefixed hexadecimal** (`00401000`, `140000000`). The target workflow read
  only `image_base` and parsed addresses with `int(text, 0)`, so the image base
  stayed `0` (and `correlatable()` refused it: every breakpoint and run-to
  failed with `TARGET_NOT_SAME_BINARY` even when both paths matched), while
  `140001234` was read as **decimal** 140001234 — the wrong address, silently.
  Both sides now read the wire format, an address space prefix keeps its
  meaning, and the fixtures use the producer's shape rather than a friendly one.
- **`--dry-run` reached only the Ghidra client.** The flag is attached to
  `GhidraHTTPClient`, and the x64dbg and target commands build a client of their
  own — so `ghydra --dry-run x64dbg call Run` **called the debugger's `Run`
  tool**: a user asking for a preview could resume or modify the debuggee. The
  flag now reaches every mutating path; a read-only tool (the plugin says so
  itself) may still run under a preview, and the preview names the tool and the
  address it would have used.
- **The taint pass read an envelope that was never sent.**
  `XrefResource.getRefsToName()` answers `{name, symbols, references, total}`,
  and the DTO's fields are `fromAddress`/`toAddress`/`refType`/`fromFunction` —
  the code tested `isinstance(xrefs, list)` and looked for snake_case names, so
  every real reference was skipped and the pass lost its source and sink call
  sites before it could read their pcode. Both surfaces now read the producer's
  shape.
- **The taint pass looked for the wrong pcode opcodes.** `PcodeOp.CALL` is
  **7** and `CALLIND` is **8** (read with `javap -p -constants` against the
  committed `SoftwareModeling.jar`); 57 and 58 are `FLOAT_CEIL` and
  `FLOAT_FLOOR`. The constant named the floating-point opcodes, so every real
  call was discarded and no source-to-sink pair could ever be found. The test
  fixture manufactured opcode 57 — reproducing the mistake instead of the wire
  contract — and now uses the real ones.
- **A diff claimed removals against a listing that was never read.** The
  collectors record `imports_complete` and `strings_complete`, and the
  comparison threw those flags away: a failed or capped listing on one side
  produced a definite "these imports were removed" — an absence claim against a
  list that was never read. Each section now carries its own verdict, what was
  only *not seen* is kept apart from what is known to be gone, and the overall
  answer says which sections were incomplete.
- **A twin could not be queried with the address its own listing holds.** Ghidra
  writes an address zero-padded and unprefixed (`00401000`) and a caller writes
  `0x401000`; the comparison removed only the prefix, so `00401000 != 401000` and
  the function was "not found". The value is compared as the number it is, and an
  address space keeps its meaning. The twin's overall completeness also covers
  the strings and the imports, which the functions alone used to decide.
- **A runbook replayed a step differently from the way it was recorded.**
  `GhidraHTTPClient.post(data=...)` form-encodes a dictionary, so a recorded
  `POST /functions` went out as `application/x-www-form-urlencoded` while
  `FunctionResource.create()` parses a JSON `CreateRequest` — the CLI's
  record/replay of a mutation failed on a step the bridge sends correctly as
  JSON. The body goes as JSON now, and the step's query parameters travel with
  it on every method that can carry them (a POST BSim step was losing its
  address and its dry-run arguments).
- **`mcp-config --gateway --groups` is refused instead of ignored.** The gateway
  serves a fixed set of five tools and reads no group list, so the combination wrote
  a `GHYDRA_TOOL_GROUPS` that the server never looked at — a setting that does
  nothing is worse than an error that says which flag belongs where. The gateway
  entry also stops emitting that variable.
- **A generated setting the gateway ignored.** `ghydra mcp-config --gateway`
  writes `GHIDRA_HYDRA_HOST` into the client configuration, and
  `gateway.ghidra_client()` read only its argument and the config file — so the host
  in the generated file did nothing. It now follows the CLI precedence
  (`argument > environment > configuration > default`) with the bridge's variable
  names, and a test asserts the variable the generated file writes is one the
  gateway actually reads — the same guard that caught an invented port variable
  earlier. An unused import and a dead helper went with it.
- **A configuration file the newer commands ignored.** `GhidraConfig` keeps the
  x64dbg settings as flat `x64dbg_*` attributes and the file nests them under
  `"x64dbg"`; only the CLI's `_section` read them. So `ghydra-gateway` looked for an
  attribute named `x64dbg`, got `None`, and **ignored the documented
  `"x64dbg": {"path": ...}`** — working only from environment variables — and
  `ghydra mcp-config` passed no settings at all, so a config file pointing at an
  installation still answered "the x64dbg token is unknown". One accessor on the
  dataclass (`GhidraConfig.x64dbg_section()`) now feeds all three call sites, and
  the CLI test drives the real root command with a patched configuration.
- **The x64dbg plugin: four Phase-1 defects fixed and verified** on its own branch
  (`fix/thread-safety-and-honest-frames`, `81d4936`, pushed to the fork), with
  `zig build` and `zig build test` (50 unit tests) green on Zig 0.14.0:
  the **data race** (`.single_threaded = true` while threads came from Win32
  `CreateThread`; five structures written by callbacks and read by HTTP threads —
  now a mutex around the rings and the SSE table, an atomic `server_running`, and no
  slice into a ring escaping the lock), the **silent JSON truncation** (`JsonWriter`
  dropped bytes on overflow, so an oversized answer was malformed JSON that a client
  could not tell from a complete one — the writer now records it and the response
  paths answer a JSON-RPC error), the **CORS hole** (`Access-Control-Allow-Origin: *`
  plus a preflight answered before the token check), and a **tool that lied**
  (`ListCommandsByCategory` declared a category, ignored it, and listed the MCP
  tools). Docs corrected against the code: 80 tools, loopback bind, Zig 0.14.0, the
  two defaults.
- **The rename table no longer reports stale on an unrelated commit.** It compared
  the whole generated document, whose `source.commit` moves with every commit in the
  plugin repository — the four fixes above flagged 80 unchanged names as stale. The
  check now compares the **mapping** and reports a moved provenance as a note, while
  a real change (a tool added, renamed, or a flag flipped) still fails; the four
  states are pinned by tests.
- **The x64dbg rename table, generated from its own registry**
  ([`contract/x64dbg-vocabulary.json`](contract/x64dbg-vocabulary.json)):
  `contract/vocabulary.json` says the rule and that the x64dbg side does not follow
  it; this is what following it costs — **80 tools, all 80 renamed**, with the
  **36** read-only flags carried across and **zero collisions** with the tools this
  repository already has. Read from `danalec/x64dbg-mcp-server`'s
  `src/mcp/tools.zig` at `9d7a93e` (protocol `2024-11-05`), not from its README.
  The split is the only place the rule can go wrong, so the test fixes the cases:
  `GetSEHChain` → `x64dbg_get_seh_chain` (SEH + Chain, not S + EHChain), `GetPEB`,
  `DetectOEP`. The other repository is not a dependency of this one: the generator
  runs where it is checked out, the table is committed, and the guard **validates
  the committed table** when the repository is absent, which is what CI does — so
  the check is honest in both states instead of failing on a fresh clone.
- **The gateway: the cross-tool workflow as MCP tools** (`ghydra-gateway`): a
  separate MCP server on stdio — its own console script, not a subcommand, because a
  server on stdio must own stdout and the CLI's root command prints — exposing the
  five steps of the unification plan as tools: `target_open`, `target_locate`,
  `target_breakpoint`, `target_run_to`, `target_decompile`. The names follow the
  contract's vocabulary; the plan's workflow names are the steps, mapped in
  `ghydra/gateway.GATEWAY_STEPS`.
  Every tool answers **structurally** (`success`, plus `code` and `reason` on a
  failure): an MCP tool that raises turns a contract code into unstructured noise.
  The refusals are the same ones the CLI pins — `target_breakpoint` and
  `target_run_to` answer `TARGET_NOT_SAME_BINARY` and touch nothing over two
  different files — and `target_open` **reports** the mismatch instead of refusing,
  because `analyze_open` answering "these are a copy and a rebuild" is a successful
  analysis of a bad situation. Two of the fourteen tests exist because of that
  distinction, which the first version got wrong.
  `ghydra mcp-config --gateway` emits the one-entry client configuration for it.
  The plan put the gateway in a third repository; it turned out small enough to live
  next to the code it calls, and the contract's rules stay data that can move.
- **The cross-tool chain is complete** (`ghydra target run-to` and `… decompile`):
  with `describe`, `locate` and `breakpoint`, the five steps of the unification
  plan's Phase 3 exist as commands — `analyze_open`, `function_locate`,
  `breakpoint_set`, `run_to`, `decompile`.
  `run-to` carries the same identity refusal as `breakpoint` with a worse
  consequence if it were wrong — resuming a different build is not a breakpoint in
  the wrong place, it is a process running — and then reads the registers with a
  **read-only** tool, so the answer cannot change the debuggee. Its timeout defaults
  to **10 s**, below the client's 30 s read timeout on purpose: the debugger's own
  default is 30 s, and a run that takes the full time would lose its answer to the
  client giving up first.
  `decompile` addresses the static side through `locate`, so a name works as well as
  an address, and a decompiler that returns nothing is `TARGET_NO_CODE`, not an
  empty answer. `tests/test_target.py` is **19 tests** and pins both, including the
  two refusals that assert the fake debugger was never resumed or written.
- **The cross-tool target workflow (Phase 3 of the unification plan)**: three
  commands that make the static and the dynamic side work on one target —
  `ghydra target describe` (`analyze_open`: both sides, one `TargetDescriptor`, and
  the identity verdict), `ghydra target locate <name>` (`function_locate`: the
  static address) and `ghydra target breakpoint <name>` (`breakpoint_set`: locate,
  translate `runtime = static − image_base + module_base`, set it).
  The refusal is the point: `breakpoint` exits with `TARGET_NOT_SAME_BINARY`
  **before touching the debugger** when the descriptor says the two sides are not
  the same file, and `tests/test_target.py` (`--target`, 12 tests, in CI) asserts
  the fake debugger recorded no `SetBreakpoint` at all — a refusal that still writes
  is not a refusal. The same suite caught a dishonesty in the codes while it was
  being written: a connection failure reached the caller as `TARGET_NOT_FOUND`
  ("try another name") when the truth was `TARGET_NO_PROGRAM` ("start the
  instance"); the two are now split by the code the client carries.
  `run_to` and `decompile` — the last two steps of the chain — need no new address
  logic, and the gateway process itself stays where the plan puts it.
- **Phase 2 of the unification plan: one client configuration for both servers**
  (`ghydra mcp-config`): one file in the shape MCP clients already read, with the
  Ghidra bridge over **stdio** and the x64dbg MCP server over **HTTP + bearer token**
  as separate entries, so a client can enable one without the other — the plan's
  mitigation for "165 tools in one context degrades tool selection". The tool groups
  are opt-in (`--groups core,functions`), the debugger entry is **left out with the
  reason** when the token is unknown, and the token is treated as a secret: masked
  in everything printed (`--show-secrets` to see it), real only inside a written
  file, with the warning printed.
  Two defects were caught by the suite while writing it, and both are now guards:
  the configuration had set an **invented** `GHIDRA_HYDRA_PORT` (the bridge has no
  port variable — it discovers instances), and the printed JSON was wrapped by the
  terminal renderer, which broke `ghydra mcp-config | jq` on a long Windows path;
  the command now writes its JSON unwrapped. `tests/test_mcp_config.py` (19 tests,
  `--mcp-config`, in CI) checks the transports, the missing-token reason, the
  masking on both paths, and that **every environment variable written is one
  `bridge_mcp_hydra.py` actually reads**.
- **The unification contract, and the address model that can refuse** (Phase 1 of
  `docs/UNIFICATION-PLAN.md`): the plan's verdict is that these two projects cannot
  share code — a Java plugin in Ghidra and a Zig DLL in x64dbg — only a
  specification. That specification now exists in [`contract/`](contract/README.md),
  with the half that can be derived from this repository **generated**:
  [`tools.json`](contract/tools.json) (134 tools, 36 namespaces, every one matching
  `namespace_verb`, none declaring the reserved `arguments`, all with a formatter)
  and [`error-codes.json`](contract/error-codes.json) (112 codes with side, HTTP
  status and `file:line`), both checked by `scripts/gen_contract.py --check`.
  New [`ghydra/target.py`](ghydra/target.py) is the address model the plan asks for:
  `runtime = static − image_base + module_base`, plus the identity that makes the
  arithmetic safe — a descriptor built from two **different** files reports
  `correlatable: false` and says why, and the same file name in another directory is
  `name-only` (a copy, a symlink or a rebuild), not the same target. The shape is
  [`contract/target-descriptor.schema.json`](contract/target-descriptor.schema.json).
  The conformance suite `tests/test_contract.py` (`--contract`, and in CI) proves
  all of it: 24 tests, including a small validator that reads the schema and refuses
  a descriptor the schema refuses.
  Honest status, also recorded in the plan: the **x64dbg side is untouched**. Its
  nine Phase-1 defects — the data race, the GUI call from an HTTP worker thread, the
  silent JSON overflow, the static port — are the reason the plan puts them first,
  and they live in the other repository. The contract marks that side as
  `"conforms": false` rather than pretending.
- **The reference documents moved to `docs/`, and the guards follow them**: the
  root had 5 documents and 20 reference pages; the 20 are now in
  [`docs/`](docs/), next to the three design notes that were already there.
  What stayed is what a forge and a runtime expect to find at the top: `README.md`,
  `AGENTS.md` (and the `CLAUDE.md` symlink to it), `CHANGELOG.md`,
  `CONTRIBUTING.md` and `LICENSE`.
  Links were rewritten in both directions — a moved document that points at a root
  file goes up one level, a root file that points at a moved one names `docs/`, and
  neighbours keep bare names — and the tooling moved with them: the four generators
  write and index `docs/`, the command guard scans `docs/` as well, and the
  documentation index now has a **History and proposals** section that labels the
  three pre-existing notes by the status each declares (implemented, proposal, a
  design note) instead of listing them as reference.
  New guard: `check_docs.py` now resolves **every local link in every tracked
  document** from the file that holds it, so a future move fails the build instead
  of shipping a dead end. It found one real gap while being written (the index
  still resolved links from the repository root) and one honest boundary: the
  gitignored notes in `docs/` are not the repository's to check, so it reads
  `git ls-files`.
- **The test suites moved to `tests/`, with a guard against the clutter coming
  back**: the repository root held 67 files, **33 of them suites** — half of what a
  newcomer sees was test machinery. All 33 moved to [`tests/`](tests/), and the
  three things that depended on where a test file lives moved with them:
  `sys.path` now goes one level up (27 files), `ROOT` points at the repository (11
  files), and the runner builds every command through one `suite_script()` helper
  instead of 32 literal paths — plus the one suite it imports rather than spawns
  gets `tests/` on the path. Three files built a repository path **inline** rather
  than through `ROOT` (`tests/test_kuna.py` reading `GHYDRA_KUNA.md`,
  `tests/test_headless.py`, `tests/test_rea_parity.py`); the move broke each one,
  which is how they were found.
  `tests/test_runner.py` now fails if a suite appears at the root again, if the
  runner names a suite that does not exist, or if `tests/` stops holding them. Its
  flag-combination test runs two **cheap** suites rather than two heavy ones: it
  runs inside the runner, so the weight there measured the machine (one 120 s
  timeout observed under load), not the contract. The root is 34 files: 25
  documents, the bridge, the runner and the build files.
- **The four review findings that were left open, fixed — with the tests that pin
  them**: the independent review's remaining items are closed.
  **The property read is method-first** (`util/ReflectiveRead`): the BSim ingest read
  `DescriptionManager.numFunctions` as a field, and it is a method — that is what broke
  every ingest. The reader now tries the method, falls back to the field, and treats an
  absent property as absent; `ReflectiveReadTest` (7 cases) fails if it ever goes back,
  including a method that throws.
  **The ingest is capped at 5 000 functions by default** (was: all of them, up to
  200 000, with a decompilation per function — hours inside one request on a large
  binary, and the Jetty thread stays busy after the client gives up). `0` means
  everything when the caller asks, and the answer reports `functions_cap` and `capped`,
  because a partial ingest must not be read later as "not in the corpus";
  `BSimIngestServiceTest` pins the four cases.
  **An unsaved program explains itself**: `repository`/`path` used to be two nulls with
  no reason, and the answer now carries `location_reason`.
  **A twin name is one file, and a writable one**: `twin_path` adds a short digest of
  the original name (so `a/b` and `a_b` no longer share a snapshot), prefixes Windows
  device names (`CON`, `COM1`, …), and `resolve_path` still finds a snapshot made
  before the change. Six tests in `test_twin.py`.
  **`AGENTS.md` fits its budget**: 68 646 bytes was truncated to 65 143 when loaded as
  instructions, so the last sections were simply not read. "Known drift", "The four
  gaps closed against the REA" and "The composed calls" moved to
  [GHYDRA_INTERNALS.md](docs/GHYDRA_INTERNALS.md) — 60 120 bytes now, with headroom — and
  `AGENTS.md` points at it. `CLAUDE.md` is still the symlink.
- **Four examples, one of them runnable with nothing installed — and the suite that
  proves it**: `examples/` was one CI workflow and a JSON file; it is now an index
  of four jobs, each with what it needs and what to look for in the output.
  `examples/twin/` is the offline one: a snapshot and the queries it answers with
  **no Ghidra running**, and the snapshot says in its own README that it is
  synthetic — an example that pretends to be a real analysis teaches the wrong
  thing. `examples/mission/mission.sh` and `examples/fleet/fleet.sh` are complete
  scripts that start what they need, run the job, and stop it even when the job
  fails, with the traps called out where they happen.
  The suite (`test_examples.py`, wired as `--examples` and into CI) does the part
  that makes examples trustworthy: it **runs** the offline queries and compares
  the output, validates `asserts.json` against `ASSERTION_KINDS` (which caught
  three kinds the README had invented: `has_export`,
  `function_count_at_least`, `has_segment`), checks that every path the index
  names exists, and loads the snapshot through `ghydra/twin.py` — version, md5 and
  completeness. The command guard now reads the example **scripts** too, not just
  the Markdown fences, so a flag that stops existing in
  `examples/mission/mission.sh` fails the build.
- **A generated cheat sheet, and the guard that proves every documented command
  exists**: [GHYDRA_CHEATSHEET.md](docs/GHYDRA_CHEATSHEET.md) is one line per command —
  the 21 that get used most, then all of them, with the first line of each
  command's `--help` as the summary. It is generated by
  `scripts/gen_cheatsheet.py`, which fails if one of its hand-picked "most used"
  commands stops existing.
  The interesting part is the guard that came with it:
  `scripts/check_doc_commands.py` reads every `ghydra …` line inside a Markdown
  code fence — **326 commands across the documentation** — and resolves each group,
  subcommand and flag against the Click tree, stopping at a pipe so `jq -r` is not
  read as an option of ours and honouring `--dry-run/--apply` pairs. It found three
  real documentation bugs: `ghydra triage` (the command is `ghydra inspect`),
  `ghydra tools groups` (the `tools_*` group is MCP-only; the CLI has no such
  command) and `ghydra functions rename --name` (the options are `--old-name` and
  `--new-name`). All three would have been a usage error for a reader. Both checks
  run inside `scripts/check_docs.py`, so CI fails when a document names a command
  the CLI does not have.
- **A generated reference of every error code — and the damage a bad tamper test
  did**: [GHYDRA_ERRORS.md](docs/GHYDRA_ERRORS.md) lists **112 codes in 18 families**
  with the side that produces each, the HTTP status it answers with, the message it
  sends and the file:line that raises it. It is generated by
  `scripts/gen_errors_doc.py` from the Java `Response.error(...)` calls (literal
  codes and messages, a guard enforces both) and from the Python raises, and
  `check_docs.py` fails when it is stale. The grouping is by **domain** — a prefix
  with siblings is a subsystem (`BSIM`, `KUNA`, `X64DBG`); a lone prefix is a word
  (`BAD`, `NO`, `READ`) and goes to the generic section, where a reader looks for
  it. The eight medium guides also gained generated indexes (level 2), so every
  document over a few pages now opens with its shape.
  **The honest part:** proving the duplicate-heading guard worked, I appended a copy
  of section 1 of [GHYDRA_CONCEPTS.md](docs/GHYDRA_CONCEPTS.md) to the end of the file
  and "restored" it by removing the *first* match — which was the real section. The
  index caught it immediately (it listed 2…10 and then 1), and the guide was
  rebuilt from the commit that wrote it, with the section order asserted. A tamper
  test has to restore from a known-good source, not from a replacement that cannot
  tell the copy from the original; the restore script now does exactly that.
- **The two big references are navigable, and their indexes are generated**:
  `GHYDRA_CLI.md` (55 KB) and `GHIDRA_HTTP_API.md` (48 KB) now open with a table
  of contents, produced by `scripts/gen_toc.py` from the headings and checked by
  the docs guard — a renamed section cannot leave a dead index behind. Generating
  it exposed two real defects that no test had caught: the CLI reference carried
  the same 17-line section **eighteen times** (a copy/paste artifact, 12.5 KB of
  duplication) and three sections duplicated at the same depth. Both removed, and
  `check_docs.py` now fails a document that repeats a heading under the same
  parent. New guide: [GHYDRA_OUTPUT.md](docs/GHYDRA_OUTPUT.md) — the four shapes
  (text/JSON/table/report), the envelope, the `Next:` line, `GHYDRA_MCP_OUTPUT`,
  JUnit/SARIF, and the exit codes of `assert` (0/1/2) and of the CLI.
- **The documentation set, and the guards that keep it true**: the tool became
  wide enough that a reader could not find the answer, so the documentation is now
  a set with a map rather than a pile of files:
  [DOCUMENTATION.md](docs/DOCUMENTATION.md) is the index (what to read for which job,
  plus reading paths by audience), and five guides fill the gaps —
  [GHYDRA_GETTING_STARTED.md](docs/GHYDRA_GETTING_STARTED.md) (install to a first
  dossier, with real output), [GHYDRA_CONCEPTS.md](docs/GHYDRA_CONCEPTS.md) (the mental
  model: three surfaces, the envelope, absence vs incompleteness, evidence
  identity, budgets, tool profiles, what it is not),
  [GHYDRA_RECIPES.md](docs/GHYDRA_RECIPES.md) (twelve jobs with commands and the trap
  each one hides), [GHYDRA_TROUBLESHOOTING.md](docs/GHYDRA_TROUBLESHOOTING.md)
  (symptom → cause → fix, including the known drift) and
  [ARCHITECTURE.md](docs/ARCHITECTURE.md) (the tiers, the generated core, the rules).
  The **tool catalogue is generated**: `scripts/gen_tools_doc.py` reads the tool
  decorators, the docstring's first paragraph, the signature, the endpoint a body
  names (following the helpers it calls), the workflow group and the real CLI path,
  and writes [GHYDRA_TOOLS.md](docs/GHYDRA_TOOLS.md) — 134 tools, 61 named routes, 16
  composed, 15 routed by argument, 42 local. `scripts/check_docs.py` now also
  fails when that catalogue is stale and when a local link in the index points at
  nothing; both directions were verified by tampering.
- **The BSim surface after an independent review: five real bugs, one of them
  mine to own**: a fresh-context review of the BSim and twin code found twelve
  issues. Five mattered enough to fix before anything else.
  **The ingest was broken** — the refactor that introduced `BSimDatabase` replaced
  a `getMethod("numFunctions")` read with a `getField` read, and
  `DescriptionManager.numFunctions` is a *method*: every ingest answered
  `BSIM_SCAN_FAILED`, and my "94 functions in 3.1 s" claim had stopped being true
  because the last live run predated the refactor. It works again (94/94,
  re-measured live).
  **A failure was reported as a success** — the action routes wrapped every
  payload in `Response.ok`, so `success: true` sat on top of a failed ingest and
  the bridge and the CLI printed a table of zeros; a failure now carries
  `success: false`, its code, its reason and an honest status (400/409/503/500).
  **`?dry_run=yes` applied the rename** — `Boolean.parseBoolean` answers false for
  anything but "true", so the one parameter that protects the program was lenient
  in the dangerous direction; only `true`/`false` are accepted, and anything else
  is a 400 that changes nothing.
  **`ghydra bsim ingest` and `ghydra bsim apply-names` never ran** — the CLI called
  `client.post(..., params=...)`, which the client did not accept; `post` takes a
  query string now, and all four BSim commands were re-validated end to end.
  **The call-graph "trap" was our bug, not H2's** — the duplicate key came from
  unsorted call-graph records; with Ghidra's own sort in place,
  `track_call_graph=true` ingests 189 functions of `where.exe`, and both guides are
  corrected.
  Also fixed from the same review: the H2 handle leaked when the create or the
  initialize failed; the program database was traversed outside the EDT (the
  repo's rule); `apply-names` followed the first match instead of the most
  similar; `diff` reported `BSIM_NO_DATABASE` when the engine itself was missing;
  a pair whose address is unknown was called `moved`; `total_considered` counted
  the notes walked instead of what BSim considered; and the twin could crash on
  `--output twin.json`, recorded zero parameters for every function, called an
  unverifiable snapshot "complete", could not find a snapshot by name, and its
  `diff` presented phantom removals as fact. The mission dossier stopped claiming
  "nothing was left undetermined" for a mission that stopped, and no longer says
  "every conclusion holds" when nothing was re-read.
- **The x64dbg fixture listens with a 128-deep backlog, not 5**: the remaining
  local flake had a measurable cause. `ThreadingHTTPServer` listens with
  `request_queue_size = 5`; a burst of connections fills that queue, the OS drops
  the SYN, and the client sees a server that never answered — the same symptom as
  a dead debugger. It is **not** port exhaustion: this machine's dynamic range is
  16 384 ports and a full run leaves about 5 connections in TIME_WAIT, so the
  queue was the limit. The fixture now uses a 128-deep backlog with address reuse,
  waits until the port actually answers before a test uses it, and keeps its own
  side of a reset under `GHYDRA_X64DBG_TEST_LOG`. Measured after the change: 8
  clean runs in a row (13 in total) against 2 consecutive failures before it. The
  retry in the harness from the previous round stays: the two answer different
  halves of the problem.
- **The BSim surface is documented where people look for it**: a new
  `GHYDRA_BSIM.md` guide (setup, building a corpus, querying, applying a match,
  comparing two versions, the five measured traps, and the commands that
  reproduce every number), the five `/bsim/*` routes added to the HTTP reference
  (§13) — they had no documentation at all — and `--twin` added to `TESTING.md`'s
  suite list and its "runs without Ghidra" note. The features existed and were
  validated; this makes them findable.
- **The digital twin (R2), and the measurement that keeps it honest**:
  `ghydra twin build|query|diff` take a **snapshot** of a binary — program,
  functions, imports, exports, strings, counts, with the executable md5 and the
  source instance as provenance — and answer questions **with no Ghidra
  running**. Measured with `scripts/bench_twin.py` on two real binaries, which is
  the criterion R2 was accepted under: `where.exe` **715x** faster for a name
  search and **7993x** for one function by address (0.23 ms against 3.80 ms even
  when the file is read each time); `whoami.exe` **359x** and **8337x**. A
  snapshot is 47 KB for 104 functions and builds in 66 ms. The offline demo is
  the point: with the Ghidra process gone, `twin query` still answers the
  overview, a function by address, and imports by substring, and `twin diff`
  compares two builds using **the same comparison** as the live `analysis_diff`
  (`ghydra/core/diff.py`), so "what changed" has one definition on line and
  offline. Two facts the live runs forced: `/program` had no md5 (the one thing
  that says "same binary" across instances), now exposed additively; and a
  snapshot can be *shorter than the API's own count* (104 functions listed
  against 198 counted), so a twin records `functions_complete: false` in that
  case — otherwise a diff would report phantom removals. What a twin cannot do
  is stated next to the answer: it cannot decompile, read memory, or see a change
  made after it was taken.
- **BSim diff (R1, slice 4b), validated against a live Ghidra 12.2**:
  `GET /bsim/diff`, `bsim_diff_versions` and `ghydra bsim diff` compare the open
  program with another version **paired by signature** instead of by address —
  the complement of `analysis_diff`, and the thing a signature database is
  uniquely able to do: a function that moved address (or whose name was lost in
  the rebuild) is reported as the same function relocated, not as one removal
  plus one addition. Measured on `where.exe` against itself: 6 of 8 compared
  functions paired as `same` in 2.4 s; the two imported thunks came back
  `not_found`, which is honest — ingest stores only functions with a body.
  Against a name that is not in the database, every function answered
  `not_found` rather than an invented pair. The cost is one BSim query per
  function (0.2-0.8 s each), so the walk is bounded (`max_functions`, default 25,
  cap 500) and the answer reports how many functions were **not** compared. Two
  classes were added from what the live run showed: `no_signature` (a function
  with no body — a thunk, an external — cannot be in the database at all) is
  separate from `query_failures` (the query itself failed), because "not in the
  other version" would be a lie about the first.
- **The x64dbg suite stops failing on a dropped loopback connection**: measured
  in full local runs, a bridge-level x64dbg test failed every now and then —
  twice in a row, on two different tests — with a transport reset underneath.
  The fake plugin is stateless, so the *test* may repeat a call even where the
  product must not: one helper (`tool_result`) sends the nine bridge-tool call
  sites in `X64dbgBridgeTests` through the retry the suite already had, and the
  tests that prove the product *does not* repeat a mutating tool are untouched
  (`X64dbgRetryTests`). Three consecutive runs of the suite pass, one of them
  taking 126 s because the retries were doing the work.
- **BSim apply-names (R1, slice 4a), validated against a live Ghidra 12.2**:
  `POST /bsim/apply-names`, `bsim_apply_names` and `ghydra bsim apply-names` name
  a function after the stored function it most resembles. **The default is a dry
  run** — the answer says `would_rename` and the program is untouched — and the
  rename only happens with an explicit `dry_run=false`, through a
  `TransactionHelper` transaction so it is undoable in Ghidra. Nothing is applied
  below the similarity floor (default 0.8), a function already carrying the
  matched name is reported instead of rewritten, and the match's similarity and
  significance travel with the answer because the match is a heuristic.
  Validated end to end: a function renamed locally to `my_local_name` produced
  `would_rename` on the dry run (verified unchanged through `/functions/{addr}`)
  and `applied: true` on the real call, after which the API reported the matched
  name. Checks also found: `TransactionHelper` wraps refusals into a
  `RuntimeException` (so the catch is one clause, with the reason read from the
  cause), and its home is `eu.starsong.ghidra.util`, not the framework package.
- **BSim query (R1, slice 3), validated against a live Ghidra 12.2**:
  `GET /bsim/query`, `bsim_query` and `ghydra bsim query` ask the signature
  database which stored functions look like one function of the open program,
  and answer with BSim's own similarity and significance. Measured on the
  database ingest created a round earlier: `where.exe`'s `FUN_140001010`
  matched itself with **similarity 1.0 / significance 26.024 in 0.8 s** (0.2 s by
  name), and an unknown name answered `BSIM_NO_FUNCTION` with the reason.
  Reflective like the rest of BSim, and the shared half — opening a database,
  creating it, finding the program's project location, cleaning up — moved into
  `BSimDatabase` so ingest and query cannot drift. Three things only the live
  run could tell: the executable name comes from `getNameExec()` (`getName()`
  exists and answers null, which left every match without its binary), there is
  no `getFunction(String)` in this series (the name lookup is a walk), and
  `AddressFormatException` is checked — a malformed address is "not found", not
  a failed request.
- **BSim ingest (R1, slice 2), validated against a live Ghidra 12.2**:
  `POST /bsim/ingest`, `bsim_ingest` and `ghydra bsim ingest` generate signatures
  for the open program and insert them into the configured H2 database, creating
  the database when it is absent. Measured on `where.exe`: **94 functions
  inserted in 3.1 s**, a 120 KB `.mv.db`, and a second ingest answered as
  `already_present` with 0 inserted — because BSim deduplicates by executable
  fingerprint and a satisfied goal is not a failure.
  The implementation is **entirely reflective** (`H2FileFunctionDatabase`,
  `CreateDatabase`, `GenSignatures`, `InsertRequest` are internal API that has
  moved between series, and the extension builds against 11.x *and* 12.x), and it
  follows Ghidra's own script exactly — which the live run corrected twice: the
  `GenSignatures` boolean is `trackcallgraph`, not a cache flag, and a generator
  without `setVectorFactory(...)` dies on a database created in the same call.
  Three things the live run also found: `initialize()` on a missing H2 file
  answers "Database does not exist" (so ingest creates it with Ghidra's
  `CreateDatabase` command and the `medium_nosize` template); `database_exists`
  was checking the bare path while H2 writes `<path>.mv.db`, so a 120 KB
  database was reported as missing; and a database created with
  `trackcallgraph=true` rejects the insert with a duplicate
  `callgraphtable(src,dest)` key on ordinary recursion — so the call graph is
  **off by default** and turning it on is an explicit request.
- **I1 complete: eleven modules of pure logic in one core, generated into the
  bridge**: `digest`, `runbook`, `hints`, `cache`, `diff`, `fleet`,
  `capabilities`, `contextpack`, `telemetry`, `taint` and `mission` now have
  **one definition** under `ghydra/core/`, and the bridge carries a copy
  produced by `scripts/gen_core.py` (guarded by `--check` in both CI pipelines).
  What this buys is a single place to fix a rule: the digest, the cache key, the
  capability ranking, the token budget, the fleet merge, the taint confidence
  count and the mission dossier are no longer written twice.
  **It does not shrink the bridge**, and the tests say so honestly: the
  generated copy *is* the module's body plus one delegating wrapper, so each
  slice adds a few lines. The claims the suites enforce are the ones that
  matter — the region is byte-identical to a fresh generation, a core name has
  no definition outside its region, a wrapper with a public name must delegate,
  and every suite of the migrated module passes **unedited**.
  Found and fixed on the way: the generator stripped imports, so a core module
  calling an imported function left a bare name in the region (now refused, with
  the fix in the error); a splice anchored at "the next def" swallowed the
  runbook tools (caught immediately by `test_runbook.py`); and a
  `Measure-Object`-style line count hid 2 000 blank lines, which made an earlier
  "the bridge is smaller" claim wrong — the real numbers are in this entry.
- **The pure half of source-to-sink reasoning into the single core (I1,
  slice 9)**: `ghydra/core/taint.py` now owns what a *call site* is (the call
  whose target is the address, or whose target name contains the function), how
  an address sorts (numerically, with unparseable values last instead of an
  exception that loses the report), how hypotheses are counted by confidence,
  and the disclaimer that says a heuristic is not a verdict. The I/O — reading
  the source, the sink, the calls and the call graph — stays in the callers, so
  the extraction is deliberately partial; `test_taint.py` passes **unedited**,
  which is what proves the moved part behaves the same.
- **The telemetry report into the single core (I1, slice 8)**: the window
  filter, the per-tool aggregate and the advice moved into
  `ghydra/core/telemetry.py`, which is told the current time instead of reading
  the clock — so "the last 7 days" means the same thing on both surfaces and a
  test can pin it. The bridge's tool now reads the file and hands the rows
  over; the CLI does the same. The advice is unchanged in substance (a
  suggestion appears only when the log shows the pattern a composed tool
  replaces), but it is decided in one place.
- **The context pack into the single core (I1, slice 7)**: the question
  classifier, the token estimate and the budget composer moved whole —
  `ghydra/core/contextpack.py` is the definition, `ghydra/contextpack.py` is a
  re-export shim and the bridge delegates. The two decisions that matter are
  now made once: the section the question is about is **truncated, never
  dropped**, and every other section is dropped whole with its reason, so the
  "omitted and why" list is the same on both surfaces.
- **Telemetry now states what it records, in the text the user reads**: the
  `telemetry_summary` docstring and the module docstring list the six fields
  (tool name, timestamp, success, error code, duration, answer-size estimate),
  say explicitly that arguments, results, paths, symbols, addresses and binary
  content are never written, and give both controls (`GHYDRA_TELEMETRY=0`,
  deleting the file). "Local only" is a claim; the fields are what can be
  checked, so the fields are now in the text.
- **The capability rules into the single core (I1, slice 6)**: the ATT&CK/MBC
  triage module was pure by construction — envelopes in, report out — so the
  whole thing moved: `ghydra/core/capabilities.py` now owns the ten rules, the
  evidence helpers and the composer, `ghydra/capabilities.py` is a re-export
  shim (every existing import still works) and the bridge delegates to the
  generated copy. The step also showed the guard doing its job twice: a helper
  the generated region no longer owned was left referenced
  (`name '_cap_items' is not defined`), which the capability suite caught at
  once, and the "no second copy" invariant had to be refined — a *delegating*
  wrapper with the public name is exactly what this mechanism produces, so the
  test now accepts it only when its body calls the generated name.
- **The fleet merge into the single core (I1, slice 5)**: `ghydra/core/fleet.py`
  owns the two rules that make a fleet answer trustworthy — the merge is by
  **file identity** (two ports serving one program are one row, and their
  disagreement is reported rather than overwritten) and a port that did not
  answer is **carried** as unreachable ("not present" is not "not asked"). Both
  surfaces now collect the answers and hand them to the same merge, so the same
  fleet cannot group differently on the CLI and through the bridge. The step
  also replaced a brittle test — one that counted a field tuple by text, which
  became legitimately two once fleet owned its own tuple — with one that scales:
  **no core function may be defined twice in the bridge**.
- **The snapshot comparison into the single core (I1, slice 4)**:
  `ghydra/core/diff.py` owns what "what changed?" means — a function is
  identified by its address (a rename is not an add plus a remove), imports and
  strings are compared as sets of names (order, repeats and empty values are
  noise), and a section is only complete when *both* listings were read to their
  end. `analysis_diff` and the mission both use it through one function, and the
  bridge delegates to the generated copy. The step also cost a lesson worth
  recording: an anchor that ended at "the next `def`" swallowed the three
  runbook tools that live after the function, which the runbook suite caught at
  once (`runbook_record` no longer registered). The splice now ends at the next
  tool decorator, and the suites that assert tool registration are the guard
  against repeating it.
- **`examples/`: reverse engineering as a CI test**: the smallest useful
  example of the thing a pipeline can gate on — `examples/asserts.json` (eight
  assertions covering every kind, each with the `message` that explains *why* it
  exists) and `examples/ci/analyze.yml` (a GitHub Actions template that starts a
  headless instance, runs the assertions, uploads **SARIF** to code scanning and
  keeps the JUnit report, stopping the run with `if: always()`). Validated
  end-to-end against a live Ghidra 12.2 headless run: 8 assertions, 3 passed /
  5 failed, exit 1, and a SARIF 2.1.0 document with one result per failure.
  Writing the example found two real bugs: `reaches` and `has_xref_to` let a 404
  **escape** instead of producing a verdict (a missing name now fails the
  assertion, while a transport error still raises), and a `reaches` assertion
  printed `reaches None` because it has no single `name` (it is labelled
  `main -> strcmp` now). The scan evidence also stopped conflating distinct
  names with entries. `test_assertions.py` keeps the example valid so it cannot
  rot.
- **Single core, generated into the bridge (I1, slice 1)**: the bridge ships as
  one file and cannot import `ghydra`, so the pure helpers were duplicated — the
  canonical-JSON digest alone existed three times (runbook, cache, and the two
  that drifted apart). I1 replaces the copies with **one source and a
  generator**: `ghydra/core/digest.py` defines the canonical form, its SHA-256
  and the "stable view" of an answer, and `scripts/gen_core.py` writes them into
  the bridge between markers as `_core_*`. The named helpers
  (`_runbook_digest`, `_cache_digest`, …) are now one-line delegations, so a fix
  lands in one place. The mechanism is guarded where drift would appear: the
  generator has a `--check` mode, `test_core.py` asserts the region is current
  and byte-identical to a fresh generation **and** that a tampered region is
  detected, and **both CI pipelines run the check** before compiling. The rule
  for the core: pure functions only — a generated copy of a pure function is
  identical on both sides, which is what makes it safe.- **Fleet queries (R7)**: a question can now be asked of several instances at
  once. `ghydra fleet overview|has-function|has-import|has-string|xrefs-to
  --ports 8192,8193` and the bridge tool `fleet_query(kind, ports, target)`
  merge the answers **by file identity** — the program's `programId`, falling
  back to its path — so two ports serving the same binary are one row (with both
  ports listed, and a disagreement between them reported), while two binaries
  that merely share a name in different projects stay apart. A port that does
  not answer is reported as `unreachable`, never dropped: "not present" must not
  be confused with "not asked". An import/string absence is only claimed from a
  listing read to its end (`complete: false` otherwise). `test_fleet.py` covers
  the identity fallbacks, the merge, the disagreement, the unreachable member,
  the truncated listing, the CLI and the bridge — and asserts both sides produce
  the same report.- **Decompile cache on disk (I11)**: decompilation is the expensive call in
  this API, and a session that revisits a function paid for it again.
  `ghydra functions decompile --cache` (CLI) and
  `functions_decompile(use_cache=True)` (bridge) now serve an unchanged program
  from `~/.ghydra/cache`, keyed on the program's identity — `programId`,
  `path`, `language`, `imageBase`, `creationDate` and the reported statistics —
  so a different binary never reads another one's answer. The server exposes no
  modification counter, so the cache is **opt-in**, has a **max age** (24 h by
  default, `--max-age 0` forces a fresh answer), is **bounded** (50 MB, oldest
  evicted first) and can be inspected and cleared with `ghydra cache
  stats|path|clear` (`cache_stats` / `cache_clear` on the bridge). A cache
  failure is never a failed call: a full disk costs a re-decompile. The note
  that an answer came from the cache goes to **stderr**, so the answer itself
  stays parseable. `test_cache.py` covers the identity, the key, the age, the
  bound, eviction, the unwritable disk, the CLI and the bridge, and asserts the
  two sides compute the same key and read each other's entries.- **`mission_start` on the bridge**: mission mode now has a tool as well as a
  CLI, so the three surfaces agree. `mission_start(goal, max_calls, max_tokens,
  output, verify)` runs the same plan through the bridge's own primitives, writes
  the dossier to `~/.ghydra/missions/<id>.md` and answers with it. The bridge
  version is stateless (no checkpoint/resume — that is the CLI's), and the
  parity test asserts both sides produce the same hints, the same findings, the
  same skipped steps and the same stop on a spent budget. The `mission`
  namespace joins the `core` group, so it is always visible.- **The `--scripts` suite no longer flakes on its own fixture**: the fixture
  handed its port to a test before `serve_forever()` was accepting connections,
  and every immediate retry landed in that same closed window - which read as an
  unretryable `CONNECTION_ERROR` in roughly two runs out of five on this
  machine. It now waits until the port actually answers, listens with a backlog
  of 128 (the bridge opens a connection per call), and retries with exponential
  backoff on both the bridge and the CLI paths. Six consecutive suite runs and
  two full `--no-ghidra` runs are clean.- **Mission mode (R8)**: `ghydra mission start -g "<objective>"` runs a plan
  (program fingerprint, capability leads, source-to-sink hypotheses, address
  context) against a **hard budget** of calls, tokens and wall-clock, and writes
  an auditable dossier. It asks the user nothing: a doubt becomes an `unknown`
  finding with its reason. Before keeping a conclusion it **re-reads its own
  evidence** and compares the digests — a finding whose evidence moved is
  reported as `unverified` (and the command exits 1), never silently kept. The
  state is checkpointed after every step (`~/.ghydra/missions/<id>.json`), so
  `ghydra mission resume` continues without re-paying the calls already made and
  may raise the budget; `ghydra mission show` reads a dossier without calling
  anything. Hints (source, sink, address, function) are parsed from the goal
  text — nothing is inferred beyond the words. `test_mission.py` covers the hint
  parser, the budget stop, a plan with no source/sink (an unknown, not a clean
  bill), a moved-evidence `unverified`, checkpoint round-trip and resume, the
  dossier, and the CLI. The bridge keeps exposing the primitives the plan
  composes; a `mission_start` bridge tool is the remaining follow-up.- **Source-to-sink hypotheses (R5)**: `analysis_taint(source, sink)`
  (`ghydra analysis taint -s recv -t system`) composes the references to each
  name, the pcode of the functions that call them and the call graph into
  candidate data flows, each with its confidence (`direct` when the sink call
  follows the source call in one function, `reachable` when a call path
  connects the two functions, `weak` when the sink runs before the source or
  the bounded search gave up) and the evidence addresses. Three honesty rules
  are enforced by the tests: a sink that precedes the source is never a flow, a
  truncated search is `weak` rather than a proven path, and "nothing found" is
  never rendered as safety. The bridge duplicates the engine (single-file
  rule); `test_taint.py` asserts both sides produce the same report.- **Reproducible runbooks and `analysis_diff` (R6)**: `ghydra runbook
  record -s steps.json` turns a sequence of API calls into a versionable JSONL
  file (`<program>.ghydrarb.jsonl`) that records a digest of every answer;
  `ghydra runbook replay` re-runs it and says which answers are identical,
  which moved and which now fail (`--fail-on-change` makes it a CI gate), and
  `ghydra runbook show` reads one without calling anything. `analysis_diff`
  (CLI `ghydra analysis diff --a-port ... --b-port ...`, bridge
  `analysis_diff`) compares two instances on the facts the API already returns
  - program fingerprint, functions by address (a rename is not an add plus a
  remove), imports and defined strings - so a patch diff or a firmware
  regression becomes a report. A listing that could not be read to its end is
  reported as a floor, never as a removal. The bridge duplicates the logic
  (single-file rule); `test_runbook.py` asserts the two sides produce the same
  digest, the same comparison view and the same diff.- **Read-only mode, dry-run and a local audit trail (I12)**: a Ghidra started
  with `-Dghidra.mcp.readOnly=true` or `GHYDRA_READ_ONLY=1` refuses every
  `POST`/`PUT`/`PATCH`/`DELETE` with `403 READ_ONLY_MODE` - one `before`
  handler, so a mutation endpoint added later is covered without anyone
  remembering to ask - and every mutation is appended to a local JSONL trail
  (`~/.ghydra/audit.jsonl`, `GHYDRA_AUDIT_LOG`, disable with `GHYDRA_AUDIT=0`):
  timestamp, request id, method, path, status, duration and port, capped at
  ~1 MB and never carrying the request body. `/capabilities` advertises both
  (`features.read_only`, `features.audit_log`), the CLI answers `--dry-run`
  with the exact request it would send (client-side: the server never sees it)
  and `ghydra audit` reads the trail back. `test_read_only.py` covers the
  client, the CLI, the reader and the Java contract; `ReadOnlyGuardTest`
  covers the method set and the JSON escaping.
- **`ghydra assert`: CI assertions with JUnit and SARIF (I16)**: a JSON file
  of assertions (`has_import`, `no_import`, `has_string`, `no_string`,
  `has_function`, `no_function`, `has_xref_to`, `reaches`) is evaluated against
  the running instance and rendered as text, JUnit XML (`--format junit`) or
  SARIF 2.1.0 (`--format sarif`), exiting non-zero on a failure. A truncated
  listing is reported as *inconclusive*, never as a pass: proving the absence
  of an import requires reading the whole list. `test_assertions.py` covers
  the loader, the evaluator, both renderers and the command.
- **`?count=false` on the listings (I10)**: the symbol and function listings
  used to walk the whole program to compute `meta.total`. `?count=false`
  skips that walk: the page is still exact, `meta.total` is absent and
  `meta.counted` is `false`, and the `next` link comes from a full page
  instead of a total that was never computed. `functions_list` and
  `symbols_list` expose it as `count`, and `PaginatedResultTest` pins the
  counted/uncounted rules.
- **Local telemetry and `ghydra stats` (I14)**: the bridge records what it
  actually did — one JSON object per call (tool, ok, error code, latency,
  estimated tokens) under `~/.ghydra/telemetry.jsonl`, capped at ~1 MB, never
  sent anywhere and disabled with `GHYDRA_TELEMETRY=0`. The new
  `telemetry_summary` tool and `ghydra stats` aggregate it (calls, failures,
  latency and token volume per tool, the error codes seen) and **recommend the
  composed tool when the log shows the pattern one replaces** — 4+ inspection
  calls point at `analysis_context_pack`, 4+ listings at `programs_overview`,
  4+ decompiles at `functions_batch_decompile`, and a slow tool at
  `async_mode`. The recorder swallows every failure: telemetry never breaks a
  call. `test_telemetry.py` covers the recorder, the bound, the state dir, the
  disable switch, the summarizers' parity and the CLI/tool renderers;
  `--telemetry` joins `--no-ghidra`.
- **Progressive tool discovery (I15)**: 120 tools in one list degrade tool
  selection. The bridge now groups them by workflow (`core`, `functions`,
  `data`, `types`, `scripts`, `headless`, `kuna`, `x64dbg`) and loads only the
  groups a session asks for — with `GHYDRA_TOOL_GROUPS=core,functions` at
  startup, or at runtime. Four meta-tools are always loaded:
  `tools_groups` (the groups, their sizes and whether they are loaded),
  `tools_search` (searches the FULL catalogue, including hidden tools, and
  says which group to load), `tools_load_group` and `tools_unload_group`.
  `core` can never be unloaded, and the meta-tools survive every profile, so a
  hidden tool is always findable and recoverable. The catalogue is captured
  before any profile is applied; a client that caches the list must re-read it
  after a runtime change (a restart with the env var gives a guaranteed
  profile). `test_tool_groups.py` covers the map, the profile switch, the
  stash/restore and the four tools; `--tool-groups` joins `--no-ghidra`.
- **`context_pack`: one answered question within a token budget (R3)**: the
  `analysis_context_pack` tool and `ghydra analysis context-pack` compose the
  endpoints a question needs into ONE ranked dossier — three question models
  (what it does / where the data comes from / what changed, PT or EN) with
  exact-endpoint retrieval, graph expansion (callers/callees/xrefs), an
  approximate token budget, **citable addresses** for every section, and an
  explicit list of what was omitted and why. A section that fails is reported
  with its error code, never hidden. The builder lives in
  `ghydra/contextpack.py` with a copy in the bridge (parity asserted by
  `test_context_pack.py`).
- **Actionable HATEOAS (I8)**: every text answer now ends with a `Next:` line
  built from the envelope's `_links` — the hrefs carry real values, so the
  suggestion is the bridge call that follows (`functions_decompile(address="…")`),
  including the next page for paginated listings. A link that does not map to a
  registered tool is left out: a wrong suggestion is worse than none.
- **`--json` anywhere and UTF-8 output (I4)**: the CLI entrypoint reconfigures
  stdout/stderr to UTF-8 with `errors="replace"` before any output, so Rich tables
  no longer raise `UnicodeEncodeError` on a cp1252 Windows pipe, and a custom root
  group lifts a `--json` found in any position into `GHYDRA_JSON` — both
  `ghydra --json functions list` and `ghydra functions list --json` work now, and so
  does the environment variable alone. `test_errors.py` runs the CLI under
  `PYTHONIOENCODING=cp1252` to prove it.
- **Machine-readable error contract (I9)**: a static guard asserts every
  `Response.error(...)` call site in the Java sources passes a non-empty,
  code-shaped literal as its first string argument — no handler can ship an error an
  agent cannot branch on — and the bridge's `format_error` now keeps the envelope's
  request id in the text (`Error [CODE]: msg (request id: ...)`), so an agent that
  wants the server's log line for the exact failure has the handle to ask with.
- **Background tasks for long operations (I7)**: `functions_batch_decompile`
  and `headless_start` gain `async_mode=True` — a task handle (`T-0001`)
  comes back immediately, the blocking call runs in a background thread, and
  the new `tasks_get`/`tasks_list`/`tasks_cancel` tools poll and cancel it.
  The synchronous default is unchanged (a plain call behaves exactly as
  before). Cancelling is honest about what it stops: the waiting, not the
  server-side work — a batch keeps decompiling and a headless run keeps
  running (that is what `headless_stop` is for); the task's result is
  discarded. The registry generalizes the Kuna job pattern and lives in the
  bridge process, like the jobs. `test_tasks.py` covers the lifecycle, the
  cancel semantics, the fallback and the tool contract; `--tasks` joins
  `--no-ghidra`.
- **Capability triage (R4)**: `analysis_capabilities_summary` (bridge),
  `ghydra analysis capabilities-summary` (CLI) composes the program, imported
  symbols and defined strings into one ranked ATT&CK/MBC-style report — each
  technique with its confidence, score and the evidence (name + address) behind
  it, plus the explicit "a lead for an analyst, not a verdict" method line. A
  technique is only reported when an import or string actually matches one of
  the 10 rules; failures are listed, never hidden. The rule pack lives in
  `ghydra/capabilities.py` with a byte-identical copy in the bridge (parity
  asserted by `test_capabilities_summary.py`, the Kuna-taxonomy pattern);
  `--capability-summary` joins `--no-ghidra`. No new endpoint: it composes
  `/program` + `/symbols/imports` + `/strings`, so `API_VERSION` stays 3000.
- **Honest CI (I6)**: `run_tests.py` now accepts any number of suite flags in one
  invocation and reports each result separately, plus `--no-ghidra`, which expands
  to the suites that always execute. Both the GitHub Actions and Gitea Actions
  `build.yml` install the Python package and run exactly that set on every push/PR,
  so a green run is real evidence instead of a summary made of skipped suites.
  `test_runner.py` covers the new multi-flag behaviour and the `--no-ghidra`
  contract; `TESTING.md` documents it.
- **Documentation drift guard (I13)**: `scripts/check_docs.py` counts
  `@mcp.tool()`/`@mcp.prompt()`/`@mcp.resource()` and `FORMATTERS` entries from the
  AST, counts REST routes in the Java resources, and compares them with the
  "N tools in M namespaces" claims in `README.md` and `AGENTS.md`. It also runs
  `scripts/version.py --check` and verifies that `ghydra/x64dbg.py` uses
  `__version__` instead of a second hardcoded release number. Wired into CI as the
  `--docs` suite (part of `--no-ghidra`); `test_docs.py` covers the pure checks.
- **Sync with upstream v3.1.1**: incorporates the merged PyGhidra fix (PR #12)
  plus the maintainer's runtime-preservation and regression work.

## [3.1.1] - 2026-11-07

### Fixed
- **Ad-hoc Python 3 execution via PyGhidra**: the v3.0.0 merge that removed
  `/script/execute` left `ScriptService.runSource` writing only `.java` files and
  requiring `extends GhidraScript`, so Python 3 source answered `BAD_REQUEST`.
  `POST /scripts/run`, `scripts_run` and `ghydra scripts run` now accept an explicit
  `language` (`java`/`python`) and `filename`; a `.py` name (or `language=python`)
  runs a temporary `.py` file with the PyGhidra provider explicitly selected,
  independent of Jython defaults or script metadata. Unique temporary directories
  keep existing user scripts and concurrent requests with the same filename intact;
  a missing provider names the `pyghidraRun` remedy. Java support and the existing
  execution opt-in are unchanged. `skills/ghydra-cli/SKILL.md` no longer teaches the
  removed `script execute` / `script capabilities` commands.
- **Python script failures on Ghidra 12+:** capture the script error writer as well
  as stdout. PyGhidra versions that print uncaught exceptions instead of throwing
  them now return a failed result with the traceback and keep partial output.
  Ghidra 11 retains its legacy execution API and console-only capture limitations.
- **The script tools lost their output**: `scripts_list` and `scripts_run` had no
  `@text_output` and no `FORMATTERS` entry, so the script catalogue and the captured
  `output` degraded to a bare `"Done"`. Both are formatted now, and `scripts_run`'s
  `args` is one piece of text instead of a list that some MCP clients flatten.
- **Java ad-hoc compatibility:** Java sources remain at the script root because
  Ghidra interprets a subdirectory as a package. Existing Java sources are refused
  atomically rather than overwritten or deleted; Python uses isolated directories.

Automated by MisterMal

## [3.1.0] - 2026-11-06

### Added
- **Version 3.1.0**: all five version locations moved together via `scripts/version.py --set`;
  `API_VERSION` stays `3000`.
- **Live Python regression coverage**: `src/test/ghidra/TestPyGhidraScript.java` runs a `.py`
  probe under `analyzeHeadless` (skips cleanly without PyGhidra), `ScriptServiceTest` and
  `CompatibilityServiceTest` cover the pure Java logic, and `test_scripts.py` /
  `test_compatibility.py` cover the three-surface contracts without Ghidra.
- **Capability negotiation (`GET /capabilities`)**: the plugin now describes its versions
  (plugin/API/Ghidra/Java), whether it is headless, which feature flags are actually enabled
  and its limits. The bridge prefers it at `register_instance`, falls back to
  `/plugin-version` on older plugins (the endpoint is additive, `API_VERSION` stays 3000), and
  reports an API mismatch with both versions, the runtime and the remedy instead of a generic
  "No active Ghidra instance". Exposed on all three surfaces: `instances_capabilities`,
  `ghydra instances capabilities`, and `format_capabilities` on all three formatters.
  `test_capabilities.py` (`python run_tests.py --capabilities`) proves the contract without Ghidra.
- **`--require-live`**: `python run_tests.py --require-live` probes `/plugin-version` and
  refuses to run when no Ghidra is serving, so a green summary cannot be made of skips.
- **The doctor:** `ghydra doctor` checks the Ghidra installation, the JDK it needs, the extension and the version it was built for, the port, the project directory, the API, Kuna and the x64dbg plugin — and every problem comes with the command that solves it. The JDK is the part that bites: Ghidra 11.x wants a JDK 21 and Ghidra 12.2 wants a JDK 25, and the installation's own VM arguments carry flags that only the newer JVMs take, so a run with the wrong one dies with a message about a flag instead of about the JDK.
- **A launcher that builds the JVM invocation itself:** the headless runner no longer calls Ghidra's launcher script — it builds the same JVM invocation the launcher makes, reading the VM arguments from Ghidra's own `LaunchSupport`. Three things fall out of it. The log of the run is the log that was asked for, and not the one the Ghidra application log happens to hold. The Windows launcher no longer asks "press any key to continue" when it fails: it cannot tell a double-click from a shell, and a launcher that was started by another program is exactly that case. And the JDK is found by asking Ghidra which one it supports, instead of trusting `JAVA_HOME`.
- **The evidence ledger:** `ghydra evidence add` records a finding and gives it an ID (`EV-0001`) that never changes and is never given out twice, even after the finding is removed. `ghydra evidence list` filters by kind, tag, address or text, and `ghydra evidence export` writes the ledger as a bundle — a Markdown document to read and a JSON one to read with a program. A finding can be referred to from anywhere, for as long as the ledger exists.
- **The sessions:** `ghydra session open` analyses a binary and keeps it available under a name; the session survives the shell that opened it, `ghydra session list` says what is running, and `ghydra session close` ends it with the analysis saved. The bridge gains the same three tools.
- **The bridge gains ten tools:** `headless_start`, `headless_stop` and `headless_status` (the API without a window), `doctor_check`, `evidence_add`, `evidence_list`, `evidence_export`, `session_open`, `session_list` and `session_close`. The headless tools start the run themselves, wait for the API to come up and register the instance, so an agent can go from a file to a decompilation without a window and without a human.
- **The instances say whether they are headless:** `/instances` and `/program` carry a `headless` flag, so a client knows that the endpoints that need a window are not there instead of finding out from a 503.
- **The report says what one tool saw and the other did not:** Ghidra and Kuna read the same binary at the same addresses, so their functions line up — and a function only one of them found is a difference between the two decompilers rather than a fact about the binary. The report carries that comparison, and it carries the C that Kuna recovered next to the C that Ghidra recovered.
- **The report can mark the debugger in the same command:** `ghydra report build <binary> --annotate` puts the annotations into the live debugger when the report is done, and `--bookmarks` sets a bookmark at every address.
- **The CLI says what it is doing while it does it:** an analysis of a big binary takes minutes, and a decompiler that loads the whole image takes more. Every long step says what it is and how long it took, and the report says whether the Kuna export was reused or the analysis ran again.
- **`ghydra x64dbg setup`:** finds the `mcp_config.json` that the x64dbg plugin writes next to `x64dbg.exe` — the one thing about the debugger side that cannot be guessed — and writes the token, the host and the port into `~/.ghydra/config.json`.
- **The configuration holds the paths:** `ghidra_home` and `java_home` in `~/.ghydra/config.json` say where the installation and the JDK are, so they do not have to be found on every run. The doctor says when they are missing.
- **The target triage:** `ghydra inspect <target>` identifies a file from its bytes — a PE, an ELF, a Mach-O, a DEX, an APK, a WASM module, an EVM contract, a firmware image, a JavaScript or Electron application, a core dump, a plist, a HAR capture — and says what each one needs. It needs neither Ghidra nor the network, and it is the answer to "which tool do I use for this?".
- **The four gaps against the REA are closed.** `REA_PARITY.md` compared this project with the REA (`rea-agents`, 139 tools in version 6.0.0) and named four gaps that were native and cheap. All four now exist on the three surfaces at once — the REST API, the MCP bridge and the CLI — and `test_rea_parity.py` proves they agree.
  - **`batch_decompile`** — `POST /functions/decompile-batch`, `functions_batch_decompile`, `ghydra functions decompile-batch --targets '["main","0x401000"]'`. A list of functions decompiled in one call, which is what a triage pass needs. A target that resolves to nothing comes back as a failed entry with the reason: the other targets are still decompiled.
  - **`find_xrefs_to_name`** — `GET /xrefs/to-name/{name}`, `xrefs_find_by_name`, `ghydra xrefs find-by-name strlen`. The references were addressed by address, so a name had to be resolved first and then asked about again; now the name is enough. A bare name matches every namespace and a qualified one (`NS::foo`) matches that namespace. A name that resolves to nothing is a 404 with `SYMBOL_NOT_FOUND`, not an empty list.
  - **`inspect_address_context`** — `GET /inspect/address/{address}`, `inspect_address`, `ghydra inspect-address 0x140001008`. One call that says what an address is: the symbol, the containing function, the data, the instruction, both comments and the references on both sides. The pieces were all there; the agent paid four calls for them.
  - **`trace_call_path`** — `GET /analysis/call-path?from=&to=`, `analysis_trace_call_path`, `ghydra analysis trace-call-path --from main --to strcmp`. The call graph says who calls whom; this says which chain of calls goes from one function to another. The path is the shortest one Ghidra knows about, and when there is none the answer says how many functions it explored.
- **The four composed calls the catalogue comparison found:** comparing the two catalogues tool by tool — not by area — found four that the REA has and this project did not. Two of them (`/analysis/callers/{address}` and `/analysis/callees/{address}`) were in the REST API since 3.0.0 and were never exposed on the bridge or the CLI; the other two are compositions of what was already there. All four are now on the three surfaces: `analysis_callers` and `analysis_callees`, `functions_analyze` (the function, its decompilation, its callers, its callees and its references, in one call) and `programs_overview` (the program, its segments, its counts and its imports).
- **The headless GhidraMCP:** the same REST API, with nobody watching. `ghydra headless start <binary>` starts a headless Ghidra run that imports and analyses the binary and then serves the API for that analysis — the same resources, the same decompiler service, the same middleware as the CodeBrowser plugin, and only what is behind them differs: one fixed program and one fixed project, instead of a ProgramManager and a UI. The run outlives the command that started it, `ghydra headless status` says what is running and `ghydra headless stop` ends it. The endpoints that need the UI answer 503 rather than pretending to work.
- **The headless runner:** the launcher finds the Ghidra installation through `GHIDRA_HOME` or in the places Ghidra is usually installed, and runs `support/analyzeHeadless` on POSIX or `support/analyzeHeadless.bat` on Windows. The state is kept under `~/.ghydra`, so a run survives the shell that started it. A program that is already in the project is processed again and one that is not is imported — importing a program that is already there fails, and the run never reaches the script that starts the server.
- **The report:** `ghydra report build <binary>` writes three files: a Markdown document to read, a JSON one to read with a program, and the annotations for the debugger. The report puts Ghidra and Kuna side by side — the program, its functions, its imports, its strings and its segments, next to the C that Kuna recovered — and the two are matched by address, because both tools read the same binary at the same addresses. The functions worth a human's attention are the ones Kuna found big and the ones Ghidra found with a name of their own.
- **The debugger annotations:** the report writes them with the image base, so `ghydra x64dbg annotate <file>` can translate them into the addresses of the live process and set them as comments (or labels) and bookmarks. A human opens the debugger and finds the interesting functions already marked.
- **The x64dbg snapshot:** `ghydra x64dbg report` writes down what the debugger is doing right now — the state, the registers, the modules with their bases, the breakpoints, the disassembly at the instruction pointer, the call stack and the memory map — as a Markdown document and a JSON file. It is the dynamic half of the report, and it needs no Ghidra.
- **The headless test suite:** `test_headless.py` (`python run_tests.py --headless`) covers the launcher, the report and the annotations. It needs neither Ghidra nor x64dbg.
- **A build without Maven:** `scripts/make_uberjar.py` merges the compiled classes and the runtime dependencies into one jar, the way the Maven build shades them, for the machines that have a JDK and no Maven.
- **x64dbg integration:** the bridge gains an `x64dbg_*` namespace and the CLI a `ghydra x64dbg` command group that drive the [x64dbg MCP server](https://github.com/duty1g/x64dbg-mcp-server), the Zig plugin that lives inside the debugger. Like the Kuna integration, it is local and touches neither the REST API nor `API_VERSION`: the plugin is a separate program with its own HTTP contract, so the point of the unification is the client, not the source.
- **The x64dbg address model:** `runtime = static − image_base + module_base`. The image base comes from the Ghidra `/program` endpoint and the module base from the plugin's `ListModules`; the two binaries are matched by full path first and by file name second, because the two sides can disagree about the directory without disagreeing about the file. `x64dbg_breakpoint_at` and `x64dbg_go_to` take the **static** address — the one Ghidra shows — and translate it.
- **The x64dbg tool surface:** the plugin carries eighty tools, and exposing them one by one would drown the agent's tool list (165 tools in one agent), so the catalogue (`x64dbg_tools`) and a generic pass-through (`x64dbg_call`) are exposed instead, plus four workflow tools that carry the address model: `x64dbg_status`, `x64dbg_target`, `x64dbg_breakpoint_at` and `x64dbg_go_to`. `x64dbg_call` takes a `timeout`, because the tools that block (`run`, `WaitForEvent`, `WaitForPause`) need more than the default 30 seconds.
- **The x64dbg configuration:** a `x64dbg` section in `~/.ghydra/config.json` with `host`, `port`, `token` and `path`. The token is the one thing that cannot be guessed — the plugin writes it to its own `mcp_config.json` — so pointing `path` at the x64dbg installation is enough to find it, and the plugin's `IpAddress`, `Port` and `AuthToken` are picked up from there. `GHYDRA_X64DBG_HOST`, `GHYDRA_X64DBG_PORT`, `GHYDRA_X64DBG_TOKEN` and `GHYDRA_X64DBG_PATH` do the same from the environment, and the config file wins.
- **The x64dbg retry rule:** a request is only sent again when it is safe to send again. A connection that never came up means the request was never sent, so that is always safe to try again; a connection that died while the answer was coming, or a timeout, means the server may already have acted, so only a request that is safe to repeat may be retried — and the plugin marks every tool with `annotations.readOnlyHint`, so a read-only tool may be called again and one that changes the debuggee may not.
- **The x64dbg error codes:** the bridge and the CLI carry the same ten machine-readable codes (`X64DBG_ERROR`, `X64DBG_DISABLED`, `X64DBG_MISSING`, `X64DBG_TIMEOUT`, `X64DBG_UNCERTAIN`, `X64DBG_UNAUTHORIZED`, `X64DBG_NO_SESSION`, `X64DBG_NO_TOOL`, `X64DBG_BAD_ARGS`, `X64DBG_NO_MATCH`), so an agent can branch on the reason instead of reading prose. A test asserts the two lists are identical.
- **The x64dbg test suite:** `test_x64dbg.py` (`python run_tests.py --x64dbg`) covers the client, the config precedence, the address model, the bridge tools and the error taxonomy. It needs neither Ghidra nor x64dbg, because it starts a fake plugin that answers like the real one — JSON-RPC over HTTP, a bearer token, the catalogue with `annotations.readOnlyHint`.
- **The x64dbg documentation:** `GHYDRA_X64DBG.md` is the full reference — the contract, the configuration, the address model, every tool and command, the failure codes and the limits.
- **Kuna exports as MCP resources:** the export is now exposed as `kuna://exports` (a manifest of every export on disk) and as `kuna://export/{digest}/index.jsonl`, `kuna://export/{digest}/{function}.c`, `kuna://export/{digest}/{function}.asm` and `kuna://export/{digest}/README.md`. The retrieval loop is the RAG loop with exact addressing — list the exports, read the index, read one function — instead of pushing the whole binary into the agent's context. A function name goes into the URI percent-encoded, because a name may hold a slash.
- **Kuna export reuse:** `kuna_export_start` and `ghydra kuna export` look for a complete export under the digest first and only run the analysis when there is none, or when the one on disk does not hold the functions that were asked for. The report says which happened with `"reused": true`. Measured with Kuna 1.988: re-reading the export of a 332 KB binary takes 21 ms against the 2 750 ms of the export itself, and a 44 MB binary goes from about 154 s to 152 ms. The `_kuna_work_dir` docstring promised this reuse; the code now does it.
- **Kuna exports addressed by digest:** `kuna_export_read` takes a `directory` (a path or the 12-character digest the export is named after) next to the `job_id`, and `ghydra kuna export-read` takes a digest too. The digest outlives the bridge process, which a job id does not, so an export written by the CLI is now readable by the agent — the asymmetry that kept the two sides apart.
- **Kuna export listing:** `kuna_status` and `ghydra kuna status` list the exports on disk with their digests, the binary they came from and their function count. The listing is read from disk, so it is there after a restart.
- **Kuna export sidecar:** an export records which binary it came from in `.ghydra.json` next to it, because the digest is a hash and cannot be reversed. An export made before the sidecar existed still names its binary in the `README.md` that Kuna writes, and the listing falls back to that.
- **Kuna error codes:** the bridge carries the same 14 machine-readable codes as the CLI (`KUNA_DISABLED`, `KUNA_MISSING`, `KUNA_TIMEOUT`, `KUNA_LAUNCH`, `KUNA_FAILED`, `KUNA_NO_JSON`, `KUNA_TOO_LARGE`, `KUNA_NO_FILE`, `KUNA_IO`, `KUNA_NO_DIR`, `KUNA_NO_INDEX`, `KUNA_BAD_ARTIFACT`, `KUNA_NO_FUNCTION`, `KUNA_ERROR`), so an agent can branch on the reason instead of reading prose. The bridge used to collapse a missing binary, a timeout and a launch failure into one generic code. A test asserts the two sides carry the same list.
- **Unification plan:** `docs/UNIFICATION-PLAN.md` sets out how GhydraMCP and `x64dbg-mcp-server` can be brought under one agent-facing contract — a shared tool vocabulary, a target/address model that reconciles Ghidra's static image base with x64dbg's ASLR-relocated runtime addresses, a common error envelope, and a conformance suite. The two codebases stay separate: one is Java + Python inside a JVM application, the other a Zig DLL inside a native debugger, so the unification point is the client, not the source.
- **Kuna MCP analysis:** `docs/KUNA-MCP-ANALYSIS.md` reviews whether Kuna's parameters belong in MCP directly and whether RAG is the right pattern. The 13 `kuna_*` tools already cover the curated surface; the gap is not flags but addressing — exports are reachable only through an in-memory job id that dies with the bridge. The recommendation is MCP resources over the export directory, keyed by the existing `sha256(path+mtime)` digest, with exact retrieval rather than embeddings.
- **Kuna integration:** the bridge gains a `kuna_*` namespace and the CLI a `ghydra kuna` command group that drive the [Kuna](https://github.com/Noelo-Lab/kuna) decompiler CLI locally. No Ghidra instance is involved: these tools work on any binary, with any Ghidra version. The integration is opt-in, because it lets the bridge run a program on the host — enable it with `GHYDRA_KUNA=1` or with `"kuna": {"enabled": true}` in `~/.ghydra/config.json`, and the config file wins when both are set.
- **Kuna export flow:** Kuna loads and analyses the whole image on every invocation, so a large binary costs seconds per call. `kuna_export_start` / `kuna_export_status` / `kuna_export_read` (bridge) and `ghydra kuna export` / `ghydra kuna export-read` (CLI) analyse a binary once, write the recovered C, the disassembly and a function index to disk, and read the result from those files.
- **Kuna test suite:** `test_kuna.py` (`python run_tests.py --kuna`) covers the opt-in precedence, the bridge/CLI contract, the export readers and the reference document. It needs neither Ghidra nor the Kuna binary, so it is the one suite that always gives a signal.
- **Kuna documentation:** `GHYDRA_KUNA.md` is the full reference for the integration — the opt-in and its precedence, every tool and command, the export layout, the measured performance and the limits.
- **A measured Kuna benchmark:** `scripts/bench_kuna.py` measures the commands the integration actually runs and prints the table that `GHYDRA_KUNA.md` quotes, so the numbers can be re-measured instead of remembered. It resolves the real Kuna binary behind the Scoop shim — the shim is a 133 KB launcher, and quoting its size and function count would be quoting the wrong file — and it measures the export flow in process, through the integration itself, so the numbers are the cost of the work and not the cost of starting Python. The table was measured with Kuna 1.988: the Kuna binary is now 44 MB with 67 686 functions, and the old figures were from 1.785, when it was 22 MB with 50 122.
- **New logo:** a hand-inked three-headed dragon — two vermilion serpents and one black one — whose bodies twist into a Ghidra-style infinity loop, with a red seal in the corner carrying a real QR code to the project GitHub and the project kamon at its centre. The 1024 and 2K artwork plus a standalone scannable seal live in `images/logo/`.
- **The bridge answers in JSON when a machine asks for it:** `GHYDRA_MCP_OUTPUT=json` hands the raw envelope as one JSON document instead of the formatted table. The default stays text — that is the contract the agents are written against — and the mode is for a program that parses the answer.
- **The REA parity, measured instead of assumed:** the catalogue was read off the REA's own server over MCP `tools/list` — 139 tools in the installed 6.0.0, against the "170 tools" of a later release — and the comparison by capability is in `REA_PARITY.md`. The native reverse-engineering core is covered; four native gaps are named, and the rest of the REA's breadth comes from engines for Apple, Android, web and .NET.

### Changed
- **The README is the upstream's rewrite, with this fork's own work back in it.** The upstream rewrote the README around the resources and the two local integrations; the sections that document the headless mode, the doctor, the evidence ledger and the sessions, the MCP resources a client can read, and the parity against the REA are in it again — once each, where they had been carried three times over. The counts are the ones this branch's bridge actually has: 91 tools over the REST API, 110 in total, and 28 namespaces.
- **The headless runner refuses a port that is already served:** starting on a port that another instance holds would make the wait accept the server that is already there, and the command would report a run that never bound the port.
- **The headless runner only signals its own process:** a run that crashed leaves its state file behind, and the operating system hands its PID to somebody else. The command line is read before anything is killed, and a process that does not carry the marker of the headless script is left alone.
- **The headless runner reaps the child it started:** a child that was never reaped stays a zombie, and a zombie is a process that `kill(pid, 0)` still finds alive.
- **The report checks that the instance has the binary that was asked for:** the report labels its files with the binary that was asked for and carries the addresses of the program the instance has, so an instance with another file open would produce a report that says one thing and shows another. When it does not match, another run is started for the right binary, on the next free port.
- **The annotations are refused when the binary is not loaded:** the first module the debugger has was used as a fallback, which translated every address with the base of a module that had nothing to do with the file, and the comments landed at addresses that meant nothing.
- **The scripts of a headless instance get its project:** a script that asks for the current project was given none, because there is no CodeBrowser to take it from.
- **The test suites skip the cursor tests on a headless instance:** a headless instance has no window, and therefore no cursor, so the endpoints that read it answer 503. The tests that need one are skipped there, instead of being reported as failures.
- **The README documents the headless mode again, and its counts agree.** The merge of the upstream's rewrite took the sections that document the run without a window, the report and the annotations for the debugger out of the file — the ones the branch exists for. They are in it again, once each. The overview said 72 tools over the REST API and 91 in total while the list of the namespaces said 99; it now says 80 over the REST API, 99 in total, and 24 namespaces.
- **The headless server is the same server.** The bootstrap lives in `GhydraServerFactory`, which registers the same twenty-one resources for the CodeBrowser plugin and for the headless run. The list is in one place on purpose: a resource added to the plugin and not there would answer 404 in the headless instance and 200 in the GUI one.
- **A Ghidra script has to import `ghidra.app.script.GhidraScript`.** The class the script extends is not in the default package, and Ghidra only adds the import to the template it writes for a *new* script — an existing one has to carry it. Without it the script does not compile, and the error says nothing about the import: `cannot find symbol` on the class, and on everything the class brings with it (`currentProgram`, `state`, `getScriptArgs()`). It was measured: the same failure happens for a script inside a Ghidra module and for one outside every module, so it is not about where the script lives.
- **A Ghidra project path may not hold an element that starts with a dot.** `analyzeHeadless` refuses it with "Path element starting with '.' is not permitted", which rules out anything under `~/.ghidra`. The launcher uses Ghidra's own convention — `ghidra_projects` in the home directory — and says so when the path it is given is refused.
- **A headless run is stopped politely.** The launcher leaves a stop file behind and the script returns when it sees it; the headless analyzer then saves the program and closes the project, and the project is left unlocked. Killing the process instead leaves the lock file behind, and the next run refuses to open the project.
- **The bookmarks are set with the command x64dbg knows.** The plugin's own `SetBookmark` runs `bookmarkadd`, which is not an x64dbg command — the log answers "Unknown command" and the plugin still reports "Bookmark set.". x64dbg's commands are `bookmarkset` (alias `bookmark`), `bookmarkdel` and `bookmarklist`, so the annotation flow runs `bookmarkset` directly.
- **An annotation that fails is tried again.** Setting a comment and setting a bookmark are the same operation twice over, so repeating them is safe — and the local network stack resets a loopback connection every now and then (measured: 7% of the connections), which is what makes a call fail without the debugger having done anything wrong. Three of sixty annotations failed on the first pass against the real debugger and all sixty were set on the second.
- **The x64dbg integration was verified against the real plugin**, with `cmd.exe` loaded under the debugger: the token and the port were read from the plugin's own `mcp_config.json`, the server reported its 80 tools and the five loaded modules, and the address model was checked against the running debugger — the static entry point of `cmd.exe` translated to the address the loader had given the module, it disassembled to the real entry stub, and the breakpoint set there was listed by the debugger as `cmd.exe!entry breakpoint`, resolved by name.
- **The x64dbg pass-through takes `tool_arguments`, as one piece of JSON text.** The argument of `x64dbg_call` was called `arguments`, which is the name of the container the MCP protocol itself uses for a tool's parameters, and the two get confused easily; the parameter is renamed, and a guard asserts that no bridge tool declares a parameter the protocol reserves.
- **Why the arguments travel as text.** A client that re-encodes that container flattens what is nested in it: every value of a nested object arrives as a string. Measured on this desktop, where an integer `count` arrived as `"3"` — and the plugin, which ignores a parameter it cannot read, answered with its default count instead of the one that was asked for, so the call looked like it had worked while doing something else. The official GitHub MCP server showed the same thing, with a `labels` array arriving as something that was not an array. The schema now asks for the form that survives the client: `tool_arguments` is a string holding the JSON text, which the bridge parses itself. An object is still accepted, and its types are put back from the plugin's own input schema before the call. The live test against the desktop caught this; the unit tests did not, because they called the function instead of the protocol — there is now a test that drives the tool through the MCP binding with both forms, one that asserts the schema does not ask for an object, and one that asserts the types a client flattened are restored. Proven against the real plugin: the translated entry point of `cmd.exe` disassembled to the three instructions that were asked for, and the breakpoint set there was listed by the debugger as `cmd.exe!entry breakpoint`.
- **The x64dbg failure taxonomy:** a request that never left the client and a request whose answer was lost on the way back are no longer the same failure. The first one is `X64DBG_MISSING` — the debugger is not listening and nothing happened. The second one is the new `X64DBG_UNCERTAIN` — the debugger took the request, the connection died before the answer came, and the request was not repeated because the debugger may already have acted on it. The old behaviour reported both as "could not reach the x64dbg MCP server", which was wrong in the second case: the server had answered, and the agent was told the debugger was gone.
- **The CLI puts the arguments' types back too.** A `--arg count=3` reaches the plugin as the string `"3"`, and the plugin ignores a parameter it cannot read and answers with its default: the call came back with ten instructions when three were asked for. The bridge already restores the types from the plugin's own input schema; the CLI now does the same, so the two sides do not disagree about what a call means.
- **The CLI keeps the plugin's `[state]` marker.** Every answer from the plugin carries a `[state]` line, and Rich reads a bracketed word as a style: without the escape the marker was swallowed and the agent lost the line that says what the debugger is doing. The plugin's own text is escaped now — the markup around it is not.
- **The plugin's own file no longer overrules an explicit host or port.** It says which address the plugin listens on, and that is what is used when nothing else says so — but a host or a port that came from the config file or from the environment is a decision the user made, and the file does not get to overrule it.
- **The port walk starts from the configured port.** The fixed plugin walks up from the port it was told to use, so the walk does too: a server on the configured port plus one is found instead of being missed.
- **No token is `X64DBG_DISABLED` on both sides.** There is no way to talk to the server without one, and probing the ports would only report a missing server or a rejected token — neither of which says what is actually wrong. The bridge now refuses the same way the CLI already did.
- **A filtered Kuna export is not reused for an unfiltered request.** The digest is keyed by the path and the modification time, not by the filter, so the same directory serves a filtered export and an unfiltered one. An export made with `--functions main` holds only that function, and reusing it for the whole binary would answer with the subset and call it the whole thing. The sidecar records the filter, and the whole binary is analysed again.
- **A named export directory is only reused when its provenance matches.** The digest directory carries the provenance in its name; a directory given with `-o` does not. The sidecar now records the modification time as well as the binary, so another binary — or the same path rebuilt — is analysed again instead of answered with stale artifacts.
- **Kuna documentation:** `GHYDRA_KUNA.md` documents the resources, the digest, the reuse and the failure codes; the status sample no longer implies that the benchmarked Kuna version is the installed one; the perf table states which version it was measured against. `ghydra kuna status` now says "nothing (the integration is off)" when neither the config file nor the environment variable decided, instead of naming an opt-in that did not happen. `max_lines` is documented as a cap on the answer and not on the work: it is applied after the function has been fetched, so it saves context but no time.
- **CI:** the `verify` job now also compiles the Python sources (`bridge_mcp_hydra.py` and the `ghydra` package). A syntax error in either broke the release without failing the Java build.
- **Release credentials:** the GitHub workflows take the automatic job token from `github.token` instead of `secrets.GITHUB_TOKEN`, and the Gitea release workflow probes which secret authenticates against which API. On Gitea the `GITHUB_TOKEN` secret is the instance's own job token: it works against the Gitea API and is rejected by GitHub, so the public Ghidra release list is read unauthenticated.
- **Gitea release build:** the release workflow installs the JDK each Ghidra series needs (21 for 11.x, 25 for 12.2) instead of a fixed one, because a single job builds both series and `javac` cannot read a newer class file.

### Fixed
- **Ad-hoc Python 3 execution (PyGhidra regression from v3.0.0)**: the merge that removed
  `/script/execute` left `ScriptService.runSource` writing only `.java` files and demanding
  `extends GhidraScript`, so Python source answered `BAD_REQUEST`. `POST /scripts/run`, the
  bridge's `scripts_run` and `ghydra scripts run` now take an explicit `language`
  (`java`/`python`) and `filename`; a `.py` name (or `language=python`) writes a temporary
  `.py` file so Ghidra selects the PyGhidra provider, and a missing provider names the
  `pyghidraRun` remedy. Java support and the existing execution opt-in are unchanged.
  `skills/ghydra-cli/SKILL.md` no longer teaches the removed `script execute` /
  `script capabilities` commands. `scripts_list`/`scripts_run`/`programs_save` also gained the
  missing `@text_output` decorator (their formatters were dead), and `scripts_run`'s `args` is
  now one piece of text instead of a list some MCP clients flatten.
- **Ghidra 11.x/12.2 compatibility (`I3`)**: `DataTypeComponent.setFieldName` is resolved
  reflectively (its return type changed in 12.2, and a direct call site produced
  `NoSuchMethodError` — an `Error` that escaped every `catch (Exception)` and every Javalin
  handler, giving an empty 500). `TransactionHelper` now catches `Throwable`, converts
  `LinkageError` into `IncompatibleGhidraBuildException`, and the server answers a structured
  `500 INCOMPATIBLE_GHIDRA_BUILD` with a remedy. `CompatibilityService` probes the runtime
  signatures at startup and publishes them in `/capabilities`.
- **The 28 tools that answered `"Done"`**: every MCP tool now has a `FORMATTERS` entry, so
  `scripts_list` shows the script catalogue and `scripts_run` the captured `output` again.
  `test_surface_parity.py` (`python run_tests.py --surface`) asserts the invariant over the
  whole registered catalogue, not just one namespace.
- **The sixth version copy**: `ghydra/x64dbg.py` uses `ghydra.__version__` instead of a
  hardcoded `3.0.0`, bringing it under `scripts/version.py --check`.
- **Instance discovery**: the full sweep now reaches every port the plugin can bind
  (`MAX_PORT_ATTEMPTS = 256`, 8192-8447) instead of stopping at 8211.
- **Documentation drift**: `CONTRIBUTING.md` points at `scripts/version.py` instead of
  hand-editing `v2.0.0`/`API_VERSION=2`; `TESTING.md` lists all flags and no longer asserts a
  `port` field the envelope never emits; `AGENTS.md` names the bridge env vars correctly
  (`GHIDRA_*`).
- **Dead CLI command**: the duplicate `inspect-address` in `ghydra/cli/inspect.py` is gone.
- **A remote target does not start a headless run.** The run is started on this machine and serves this machine, so a report pointed at another machine that is not serving the API waited for an answer that could never come - and left the analyzer behind, because the failure came before the cleanup. A remote target has to be up already, and a run that does not come up is stopped instead of left behind.
- **The port is checked before anything is started.** The script falls back to 8192 for a port it cannot use, so a port of 0, a negative one or one above 65535 made the launcher wait for an answer on a port that was never bound, with an analyzer sitting on another one. The runner refuses the port now, with the code `HEADLESS_BAD_PORT`.
- **The backslash is a separator everywhere.** On POSIX, `os.path.basename()` takes the whole `C:\bin\cmd.exe` as the name, so the lookup of the program in the index of the project and the name of the project were wrong for a Windows path on a POSIX machine - and the lookup would import a program that was already in the project, which fails. The name of the file is taken with both separators in mind now.
- **The second round of the upstream review:** eight more findings from the review of the headless pull request, fixed the same way upstream.
- **A headless run ends the way it should.** The script that serves the API never stopped the server it had started, and the threads of a Jetty are not daemons: the JVM did not exit when the script returned, the run stayed alive after the analyzer had saved the program, and the launcher had to kill it - the polite stop turned into the blunt one, and the analysis of a program that was being saved was lost. The server is stopped before the script returns now, and a stop takes a second instead of a timeout.
- **The answer says whether the analysis is in the project.** The API save is refused in a headless run - the program is inside the transaction of the script that serves the API, and the analyzer saves it when the script returns - so the answer is built from the project: the content of the program is written there when the analyzer saves it, and that is what `headless stop` reports.
- **A refused start does not erase the state of another run.** A start that was refused before the child was launched has no PID of its own, and the state on disk belongs to a run that is still there: erasing it left that run untracked, and the next start walked past the guard that remembers it. The state is erased only while it is still the state of the run being stopped.
- **The port is claimed before the child is launched.** Two starts that arrived together both found the port free, and both launched an analyzer: the one that bound the API first answered both waits, and the state file ended up naming the loser - so one report could combine the Ghidra data of one binary with the Kuna data of another. The claim is written before the launch, carries a token that says which runner made it, and a claim that nobody took up is given back after a minute.
- **The PID is checked against the port.** A run that crashed left its PID behind, and the operating system hands that PID to another run of the same script - on another port, with another project. Stopping that one would have killed a live analysis. The command line of the process has to carry the port of the run as well as its marker.
- **The lock of a live Ghidra is left alone.** The lock file of a project carries no owner that can be read, so a lock left behind by a killed run and a lock held by a CodeBrowser that has the project open look the same. The lock is only removed when no other Ghidra holds the project.
- **The provenance is written when the run is serving.** It was written before the analyzer was launched, so a run that failed - an unexecutable launcher, a project that would not open - left behind the sidecar of a binary that was never in the project, and the next run analysed the old bytes again.
- **A binary rebuilt in the same second is imported again.** The sidecar kept the size and the time of the file truncated to the second, so a rebuild that happened inside the same second looked like the same file and the run served the old program. The time is kept with its sub-second part now.
- **Two files with the same name are told apart by their path.** The report compared the program of the instance with the binary of the request by name alone: a CodeBrowser that serves /a/foo.exe answered for /b/foo.exe, and the report combined the Ghidra addresses of the first with the Kuna output of the second - a report about a file nobody had. The full path is what tells them apart, and the name is only the answer when one of the two paths is not known.
- **`headless stop` says whether the analysis was saved.** It answered "true" whether the save was asked for or not, and a save the server refused was reported as a save. The answer is the one the save gave.
- **`/instances` reads the snapshot of a headless run.** The registry of the instances was given the handle of the server instead of the snapshot of the program, so the file, the project, the executable, the architecture and the image base were missing for a headless run.
- **An address of this machine is local, even without the DNS.** The report asked the name of the machine and compared it with the addresses of the interfaces, so a secondary address of a LAN card and an IPv6 address that the hostname does not carry were not local - and the report refused to start a run on a machine that was serving it. The operating system is asked now: a socket that binds to the address is accepted, and one that binds to an address of somebody else is refused.
- **`/program` says whether the instance runs headless.** A headless instance has no window: the endpoints that read the cursor answer 503, and a client has to be able to tell that from a fault. The flag was on `/instances` and not on `/program`, and `/program` is the endpoint a client already has - so the tests that need a window ran against a headless instance and failed.
- **A local variable can be renamed, and renamed back.** The listing merges what the database holds with what the decompiler knows, and the lookup only answered for the decompiler's half: a variable that the database holds was renamed through the decompiler, a variable that had already been renamed was a unique symbol in the global map and was not found at all - so the same variable could not be renamed twice, and a rename that used one of the decompiler's own names ("local_res20") was a rename of nothing. The lookup answers for the database first, then for the unique symbols of the function, and the answer says what a name the decompiler invented is: not a variable.
- **The call path keeps the function in the middle.** The path was rebuilt from the last hop back to the source, and the rebuild appended the source twice while dropping the function in between: a path of A → B → C came back as A, A, C. The chain is walked from the cursor and the source is added once, so every link of the path is a node of it. Measured against the live instance: `FUN_140001008 → FUN_140001ba8 → EventWriteTransfer` now comes back with the three functions in it and a depth of 2.
- **A path that the cap cut short says so.** The search stops at 5 000 visited functions, and the reason it gave still claimed that no path exists within the requested depth - so a path beyond the cap was reported as absent. The reason says now that the search stopped at the cap, because "there is none" and "it was not looked for" are not the same answer.
- **The references to a name are paged before the DTOs.** Every reference resolves the functions on both of its sides, and the endpoint built a DTO for all of them and sliced the page afterwards - so a hot symbol made every page pay for the references it did not return. The count comes from the references themselves, and only the ones of the page become DTOs.
- **The deadline of a batch covers the batch.** The server runs the targets of a batch one after the other, and the transport deadline was derived from the query - but the timeout of a batch travels in the body, so the deadline was one function long and the bridge answered `REQUEST_TIMEOUT` while the server was still decompiling. The deadline is now the timeout times the number of targets the server accepts.
- **The CLI's deadline of a batch covers the batch too.** The multiplier was capped at ten targets, so a batch of eleven functions whose decompilations approached the timeout each lost the whole response before every target could be reported.
- **A part that failed does not throw away what came before it.** The CLI's `functions analyze` fetched the callers, the callees and the references one after the other, and a failure in any of them raised - discarding the function that had been found and the decompilation that came with it. Each part is now caught on its own and reported as empty, as the rule says: only the function the caller asked for decides the success.
- **The relations of a function are rendered even when the decompilation worked.** The formatter returned as soon as the decompilation was there, so the default table of `ghydra functions analyze` carried the function and the C code and nothing else. The code is rendered after the three related sections.
- **A page that is not the whole list says so.** The callers and the callees took no `offset` and no `limit`, so a function with 136 callers came back as a list of 100 that read as "there are 100". They are paged now, and the answer says how many there are in total when the page holds fewer - on both surfaces.
- **A binary that was rebuilt is imported again.** A file that is replaced has the same name and the same path, and the program in the project is the old one - so the run analysed the stored copy again, and the addresses were the ones of a file that is not there any more. The project remembers the size and the time of the binary it was built from, and a binary that changed is imported again, with the file that is on disk now.
- **The stop flag of a run that was killed is removed.** The flag would stop the next run on that port as soon as it started - and the run that was killed never got to see it. It is removed after the kill, and before a new run starts.
- **A run that is already there is refused.** A run that is still analysing has not bound the API yet, so the port looks free - but the run is there, and a second one took its state and left it untracked. The PID that is remembered is checked before anything is started.
- **The analyzer of a start that failed is stopped.** `ghydra headless start` with a timeout shorter than the analysis reported the failure and exited, and the analyzer it had spawned kept the project busy and might start serving later. It is stopped now.
- **A port of 0 is not replaced by the default.** The command asked for a port of 0 - which is not a port, and the runner says so - and the helper threw the 0 away because it was false. The test is whether the option was given.
- **The machine by its own name is this machine.** The report refused to start a run when the configuration named the machine by its hostname or by a local address, even though the server binds every interface and a run started here answers to them. The name is resolved and compared with the addresses of this machine.
- **Two binaries with the same name do not share a project.** Ghidra identifies a program by its file name, so a project that holds one of them cannot hold the other - and the second run was served the analysis of the first, because the launcher processed the program by its basename. The default project name now carries a short digest of the absolute path (`cmd-3f2a1b9c`), which is what tells the two apart.
- **The report has something to say without Kuna.** A stripped binary read without Kuna has no name of its own to rank by, and the report ended with no decompilation and no debugger annotations. There is a third group now: the functions that are really in the program, the ones that take arguments first, and the thunks are left out of it.
- **`POST /dev/shutdown` no longer throws away a headless analysis.** The guard against unsaved changes asked the ProgramManager, and a headless instance has none - so the answer was "nothing unsaved" and the exit discarded the analysis. The program the instance serves is asked now.
- **`POST /project/open` on a headless instance answers 503, not 500.** Opening a file needs a CodeBrowser; that is the server's limitation and not a fault, and the client can tell the two apart.
- **The save is checked before it is reported.** `requests.post` does not raise on a 4xx, so a refused save was reported as `saved: true` and the run went on. The answer is looked at now, and the reason goes to the log of the run.
- **The lock of a run that died is cleaned up.** A crashed analyzer leaves `<project>.lock` behind, every later start refuses the project, and stopping the dead run only cleared the state. The lock of a run that is gone is removed now; the lock of a live process that is not ours is left alone.
- **The report goes to the instance the CLI chose.** The command built a request of its own, on `localhost:8192`, and ignored the host and the port of the configuration, of the environment and of `--host/--port`. It uses the client the root command built now.
- **The Kuna suite that failed on a filesystem race:** the bridge watches an export process in a daemon thread, and that thread writes the sidecar into the work directory when the process ends. The test removed the temporary directory while the thread was still running, so the cleanup walked a directory that was being written to and the suite failed with "the directory is not empty" — on the machine's timing, not on the code. The test now waits for the watcher.
- **The findings of the upstream review:** the port that is already served, the PID that was never ours, the child that was never reaped, the instance that had another binary open, the Kuna code that was missing from the report, the runner that was built outside the `try` that should have caught it, the annotations that landed on an unrelated module, and the project that the headless scripts never got. Eight in all, from the review of the headless pull request.
- **The MCP resources that nobody could read:** the seven `instance` templates carried a relative URI (`/instance/{port}/...`), and the protocol types the URI of a read as a URL — the server refused it before the resource was looked up, so no client could name the resource and no client could read it. They carry the `ghidra://` scheme now, and all seven are read back in the test.
- **The disassembly resources that answered "could not extract":** the v3000 API hands the instruction list back as the result itself, and the resources only knew the older shape (the list nested under `result["instructions"]`). Both shapes are read now, by one helper.
- **`memory_read` and the base64 it promises:** the tool documents a `rawBytes` field with the contents in base64, and the server answers with hex — so the field was never there. The bridge derives it.
- **The MCP test suite that had stopped testing anything:** it was written when the bridge answered in JSON, and it failed on the first `json.loads` of a text answer — so the suite had been red for every run since the bridge moved to text. It now drives the bridge in `GHYDRA_MCP_OUTPUT=json` (the raw envelope, for a machine that parses it) and asserts against the fields the API actually returns: `decompilation` and `decompiled_text` instead of a `decompiled_code` that never existed, the instruction list instead of a `disassembly_text` that the v3000 API does not build, and a `BASE_URL` that was never defined in the file.
- **The data tests that wrote outside the program:** the probe asked for a data item and waited for a 404, but the API answers 200 with `isDefined: false` for an address that holds nothing — so the probe never matched, the list of free addresses came out empty, and the fallback pointed at `0x08000100`, which is outside a program whose image base is `0x140000000`. The probe reads `isDefined` now, and the free address is chosen from the memory map. The MCP test had the same disease with an address from the v2 API frozen into it.
- **The debugger written off while it was running:** the scan that looks for the x64dbg plugin probed each port **once**, and the ports where the server almost always is — the configured one and the two defaults — were no more patient than the walk. The local network stack resets about one loopback connection in fourteen, and a loaded machine can take a couple of seconds to give an answer, so a single hiccup made the bridge say that the debugger was not there. The likely ports are probed three times and are given five seconds to answer; the walk still asks for one attempt, because a closed port stays closed. And the port the plugin was found on is kept: the plugin does not move while the debugger runs, and the scan opens ninety connections — so the scan is only paid again when the port stops answering. The status of a running debugger now comes back in milliseconds instead of a second.
- **A variable that could be renamed only once:** the rename looked the variable up in the decompiler's local symbol map, and the listing merged what the database holds with what the decompiler knows — so the two disagreed. A local that was already renamed is a *unique symbol*, and a unique symbol lives in the global map, so the second rename of the same variable answered "variable not found" and the rename could not be undone. The lookup now covers the database and the unique symbols of the function, and the test asserts that the rename can be taken back.
- **A name the decompiler invented, offered as if it were a variable:** what the decompiler calls a register it did not map (`puVar13`) is not a variable — there is nothing behind it to rename, and the name is re-numbered on the next decompile, so the listing and the rename disagreed about it. Renaming one now fails with a message that says so, and the listing keeps saying where each name came from (`source`): `database` is a variable, `decompiler` is the decompiler's own word for a value.
- **Python packaging:** the wheel shipped the `ghydramcp` entry point but not the `bridge_mcp_hydra` module it points at. Defining `tool.hatch.build.targets.wheel.packages` disables `include`-based file selection, so the top-level bridge file never entered the wheel and installs via `uvx --from git+https://github.com/TeskesLab/GhydraMCP ghydramcp` (or `pip install ghydramcp`) died with `ModuleNotFoundError: No module named 'bridge_mcp_hydra'`. The bridge module is now force-included in the wheel.

Automated by MisterMal

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

[unreleased]: https://github.com/TeskesLab/GhydraMCP/compare/v3.1.1...HEAD
[3.1.1]: https://github.com/TeskesLab/GhydraMCP/compare/v3.1.0...v3.1.1
[3.1.0]: https://github.com/TeskesLab/GhydraMCP/compare/v3.0.0...v3.1.0
[3.0.0]: https://github.com/TeskesLab/GhydraMCP/compare/v2.4.1...v3.0.0
[3.0.0-rc.1]: https://github.com/starsong-consulting/GhydraMCP/compare/v3.0.0-beta...v3.0.0-rc.1
[2.0.0]: https://github.com/teal-bauer/GhydraMCP/compare/v1.4.0...v2.0.0
[1.4.0]: https://github.com/teal-bauer/GhydraMCP/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/teal-bauer/GhydraMCP/compare/v1.2...v1.3.0
[1.2]: https://github.com/teal-bauer/GhydraMCP/compare/v1.1...v1.2
[1.1]: https://github.com/teal-bauer/GhydraMCP/compare/1.0...v1.1
[1.0]: https://github.com/teal-bauer/GhydraMCP/releases/tag/1.0

- **The doctor had no test at all.** `ghydra doctor` is the command a user runs
  when something does not work, and nothing tested it. It also named a locked
  project **twice** — Ghidra leaves a `<name>.lock` and a `<name>.lock~`, and the
  two were counted as two projects. The project is named once now, the verb
  follows the count, and a new suite pins the checks a user would notice being
  wrong: a missing installation, a JDK that is too old, an extension built for
  another Ghidra version, a port taken by something else, and the promise that
  every finding carries the command that fixes it.
- **The suite list in `docs/TESTING.md` drifted.** The runner's own usage line
  had fallen behind — twelve suites worked and were not in it, and it is now
  generated from the suites so it cannot. The document's list carries a
  description per flag, so it cannot be generated; a **guard** catches the drift
  instead: every suite the runner has must be named in the document.
- **The module entry ran the command twice.** `ghydra/cli/__init__.py` imports
  `main`, so `python -m ghydra.cli.main` executed it once as `ghydra.cli.main`
  and once as `__main__`, and Python warned about it on stderr. The package
  imports the command lazily now, and `python -m ghydra.cli` is a clean entry.
- **The two x64dbg plugin branches had never been merged.** `fix/mcp-server-defects`
  (ten commits: the namespaced commands, the free-port walk, the closed CORS, the
  growable frames) and `fix/thread-safety-and-honest-frames` (the state lock, the
  honest JSON frames, the tool that lied) had diverged and neither contained the
  other. They are merged in `fix/all-defects`, with the namespaced commands and
  the lock and the overflow guard all in force — 56 tests green under Zig 0.14.0
  and 0.17.0. The rename table is generated from the merged branch.

- **An explicitly requested JDK was silently replaced by a different one.** The
  launcher tries its layers — what the caller asked for, the configuration file,
  `JAVA_HOME`, Ghidra's own choice, the installed JDKs — and the code treated
  them all alike: a JDK the caller **asked for** which was older than the
  installation needs was added to the rejected list and the search carried on.
  The answer was another JDK, with no word about it, although the launcher's own
  docstring and `AGENTS.md` both say that an explicit one is an error while a
  JDK the environment merely points at is "only a place the search did not
  stop". The explicit layer is now answered on its own.
- **The launcher had no test of its own.** It is what the headless runner and
  the doctor both stand on: it finds the installation, reads the JDK version the
  installation asks for, picks a JDK that is new enough, and builds the JVM
  invocation. Nothing exercised it. A new suite pins the properties that matter:
  the required JDK comes from `application.java.min`, the version comes from the
  `release` file, a malformed properties file is not fatal, the requested JDK
  wins, an environment JDK that is too old is a place the search moves on from,
  and a Windows path still has a file name on POSIX.

- **A step that failed said "done".** The progress reporter wrote "done in 1.2s"
  from a `finally`, so a step that raised looked exactly like a step that
  succeeded — and the person waiting, who cannot tell a step that hung from one
  that failed, had a third thing to be misled by. It says it failed, and how
  long it lasted, and it re-raises. The reporter had no test at all; it has one
  now, and the package has no module left that no test reaches.
