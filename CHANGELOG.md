# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed
- **Ad-hoc Python 3 execution via PyGhidra**: the v3.0.0 merge that removed
  `/script/execute` left `ScriptService.runSource` writing only `.java` files and
  requiring `extends GhidraScript`, so Python 3 source answered `BAD_REQUEST`.
  `POST /scripts/run`, `scripts_run` and `ghydra scripts run` now accept an explicit
  `language` (`java`/`python`) and `filename`; a `.py` name (or `language=python`)
  writes a temporary `.py` file so Ghidra selects the PyGhidra provider, and a
  missing provider names the `pyghidraRun` remedy. Java support and the existing
  execution opt-in are unchanged. `skills/ghydra-cli/SKILL.md` no longer teaches the
  removed `script execute` / `script capabilities` commands.
- **The script tools lost their output**: `scripts_list` and `scripts_run` had no
  `@text_output` and no `FORMATTERS` entry, so the script catalogue and the captured
  `output` degraded to a bare `"Done"`. Both are formatted now, and `scripts_run`'s
  `args` is one piece of text instead of a list that some MCP clients flatten.
- **Ad-hoc scripts no longer touch the user's script directory**: source is written
  into a unique temporary subdirectory (removed recursively afterwards), so a
  caller-supplied `filename` can never truncate and delete an existing script and
  concurrent runs cannot overwrite one another. Python 3 ad-hoc source is also
  bound explicitly to the provider whose runtime is `PyGhidra`, instead of relying
  on `GhidraScriptUtil.getProvider` — which can resolve a bare `.py` file to Jython
  when both runtimes are installed. When no PyGhidra provider exists the answer
  names the `pyghidraRun` remedy. (Addresses the two Codex review findings.)

## [3.1.0] - 2026-11-06

### Added
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

[unreleased]: https://github.com/TeskesLab/GhydraMCP/compare/v3.1.0...HEAD
[3.1.0]: https://github.com/TeskesLab/GhydraMCP/compare/v3.0.0...v3.1.0
[3.0.0]: https://github.com/TeskesLab/GhydraMCP/compare/v2.4.1...v3.0.0
[3.0.0-rc.1]: https://github.com/starsong-consulting/GhydraMCP/compare/v3.0.0-beta...v3.0.0-rc.1
[2.0.0]: https://github.com/teal-bauer/GhydraMCP/compare/v1.4.0...v2.0.0
[1.4.0]: https://github.com/teal-bauer/GhydraMCP/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/teal-bauer/GhydraMCP/compare/v1.2...v1.3.0
[1.2]: https://github.com/teal-bauer/GhydraMCP/compare/v1.1...v1.2
[1.1]: https://github.com/teal-bauer/GhydraMCP/compare/1.0...v1.1
[1.0]: https://github.com/teal-bauer/GhydraMCP/releases/tag/1.0
