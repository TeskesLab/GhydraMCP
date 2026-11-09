# Unifying GhydraMCP and x64dbg-mcp-server

Status: **proposal** — written 2026-11-02, against GhydraMCP `main` (3.0.0, API 3000) and
`danalec/x64dbg-mcp-server` `main` (18be30a, "v1.6").

## Verdict in one paragraph

Do **not** merge the two codebases. They cannot be merged: GhidraMCP's server is a Java/Javalin
plugin inside a JVM application, x64dbg-mcp-server's is a Zig DLL inside a native Windows
debugger. They share no runtime, no language, no build system, and no ABI. What can — and should —
be unified is the **contract between them and the agent**: one tool vocabulary, one target/address
model, one error envelope, and one combined client surface. That is a three-phase plan, and the
first phase is documentation plus conformance tests, not code movement.

---

## 1. The two systems, as they actually are

| | **GhidraMCP** | **x64dbg-mcp-server** |
| --- | --- | --- |
| Language | Java (plugin) + Python (bridge, CLI) | Zig (everything) |
| Where the MCP server lives | A **separate Python bridge process** speaking stdio MCP (FastMCP) | **Inside the plugin**, speaking HTTP JSON-RPC |
| What the plugin exposes | A **custom REST/HATEOAS API** (Javalin) — not MCP at all | **MCP itself** (`tools/list`, `tools/call`) |
| MCP protocol | Whatever FastMCP negotiates (current spec) | Hard-coded `2024-11-05` (`mcp_server.zig:13`) |
| Transports to the client | stdio | POST-only Streamable HTTP + legacy SSE |
| Tool count | **85** in **22** namespaces | **80**, flat, PascalCase |
| Authentication | none (localhost stdio, no trust boundary crossed) | mandatory Bearer token, 32 hex chars |
| Instance discovery | auto-scan of ports **8192–8447**, registry, walk-up | **static** port 9094 (x64) / 9095 (x32), no walk-up |
| Multi-instance | supported (registry keyed by port) | not supported — a second instance silently fails to bind |
| Client-facing state | registry lives in the bridge process | none (stateless except the event ring buffer) |

The two are **architecturally inverted**. GhidraMCP puts MCP in a separate process and keeps the
plugin on a private REST API. x64dbg puts MCP inside the plugin and has no REST layer at all.

This inversion is the single fact that drives everything below. It also means the two projects
share **no code** worth extracting — not the transport, not the tool registry, not the formatters,
not the build. A shared library would have to be a specification, not an implementation.

### A correction to the x64dbg docs

The README says "84 MCP Tools" in one place and "72 MCP tools" in another; `SKILL.md` says "All 84
Tools". The registry in `src/mcp/tools.zig:31` holds **80** entries, and the README's own tool
tables list exactly 80 rows. Both prose counts are wrong. Fix them before publishing anything
that references a combined tool count.

---

## 2. Why a code merge is impossible

- **Different runtimes.** Ghidra is a Java application; its extension is a JAR loaded by Ghidra's
  extension framework. x64dbg is a native Windows debugger; its plugin is a `.dp32`/`.dp64` DLL
  loaded by the debugger's own loader. There is no host process that can load both.
- **Different ABIs.** x64dbg's plugin is built with the **MinGW (`.gnu`) ABI** to match x64dbg's
  own build. The Ghidra side is JDK 21 bytecode. They cannot be one binary.
- **Different SDKs.** The x64dbg side resolves 33 symbols at runtime out of `x64bridge.dll` and
  `x64dbg.dll` (`bridge.zig:338-395`). The Ghidra side talks to Ghidra's `Program`/`Listing`/
  `SymbolTable` object model. The overlap is zero.
- **Different lifecycles.** The x64dbg MCP server lives and dies with the debugger GUI
  (`pluginit` → `plugsetup` → `mcp.start()`; `plugstop` → `mcp.stop()`). Ghidra's server lives
  with a CodeBrowser window and can have several instances open at once.

**Conclusion:** the unification point must be **the agent / the client side**. Either one MCP
client registered against two servers, or one gateway process in front of both.

---

## 3. What actually needs to be unified: the contract

Four things. None of them is source code.

### 3.1 One tool vocabulary

GhidraMCP uses `resource_verb` snake_case in namespaces (`functions_get_cfg`, `data_create`).
x64dbg uses flat PascalCase (`SetBreakpoint`, `ReadMemory`). The names also collide conceptually:
x64dbg's `ReadMemory` reads live process memory; GhidraMCP's `memory_read` reads the static image.
An agent that has both loaded must not confuse them.

**Rule to adopt:** namespace-qualified, snake_case, `domain_verb`, everywhere. x64dbg becomes
`x64dbg_read_memory`, `x64dbg_set_breakpoint`, … The prefix is not decoration — it is what stops
`memory_read` (static) and `x64dbg_read_memory` (live) from being confused.

### 3.2 One target and address model

This is the hard part, and it is what makes the union worth more than a bundle.

Ghidra works on the **static image**: a function at file offset/vaddr `0x140001234` in a PE whose
image base is `0x140000000`. x64dbg works on the **runtime address**: the same function at
`0x7FF7A1234010` in the loaded module, because of ASLR.

The conversion is mechanical but it must be explicit:

```
runtime_addr = static_addr - static_image_base + runtime_module_base
```

- `static_image_base` — from the Ghidra program.
- `runtime_module_base` — from x64dbg's `ListModules`.

**Rule to adopt:** every tool that takes or returns an address returns **both** forms, labelled.
A `TargetDescriptor` is introduced:

```
{ "binary": "...", "arch": "x86-64", "image_base": "0x140000000",
  "module_base": "0x7FF7A1230000", "session_id": "..." }
```

### 3.3 Relationship to the Central Plugin Refactor

`docs/plans/2026-04-23-central-plugin-refactor.md` (April 2026, **not implemented**) proposes
moving GhydraMCP to one HTTP server on port 8192 inside the FrontEndTool, with programs addressed
by path (`/files/{urlencoded_path}/...`) and tool-scoped endpoints for cursor state — replacing the
per-CodeBrowser ports, `/instances` and `/registerInstance`.

Verified state of that proposal today:

| Expected | Actual |
| --- | --- |
| `util/ProgramResolver.java` | does not exist |
| `resource/ToolResource.java`, `resource/FileResource.java` | do not exist |
| `util/ProgramCache.java` — a `Program` cache with idle TTL | exists, but is a **symbol-count / CFG cache** (`ProgramCache.java:21-25`), unrelated |
| `resource/InstanceResource.java` — deleted | still present |
| Single port 8192 | `ApiConstants.java:6-7` still has `DEFAULT_PORT` 8192 **and** `MAX_PORT_ATTEMPTS` 256 |

**The two proposals converge on the same idea**, and that is not a coincidence: address a program
by *which file it is*, not by *which port happens to be serving it*. The unification needs exactly
that, because the gateway has to correlate a Ghidra program with an x64dbg module, and the only
stable identity both sides have is the file path.

**Recommendation: treat path-based addressing as a prerequisite of Phase 3, and land central-plugin
separately.** Concretely:

- If central-plugin lands first, `TargetDescriptor.binary` comes straight from the URL path, and
  the gateway needs no port discovery at all.
- If it does not, the gateway must still key on the path, but has to ask the Ghidra side which
  program a given port is serving (`GET /program`) and cache that mapping.
- If central-plugin lands, the bridge's instance registry must be **replaced** by path resolution —
  `/instances` and `/registerInstance` are exactly the cross-instance coordination it uses today.
  The `kuna_*` tools are unaffected: they take no `port` and touch no instance.

Do not entangle the two. Central-plugin is a substantial change to the Java side (17 resources, the
bridge, the CLI and every test URL); the unification's Phase 1 is independent of it, and coupling
them would make both harder to review.

### 3.4 One error envelope

GhidraMCP's REST layer returns `{success, id, instance, result, _links}`; the bridge flattens it
for the agent. x64dbg returns MCP-standard `content[].text` with `isError: true`, and the error
text is free-form English (`"Error: No active debug session."`). There are **no structured error
codes** on the x64dbg side, and `handleToolsCall` decides "this is an error" by *sniffing the
result string for the prefix `{"error":`*.

**Rule to adopt:** every tool error carries a stable machine-readable code
(`NO_ACTIVE_SESSION`, `TARGET_RUNNING`, `NOT_FOUND`, `INVALID_ADDRESS`, …) alongside the human
text. This is what lets an agent branch instead of guessing from prose.

### 3.5 One conformance suite

A JSON Schema per tool plus a shared fixture set, run against both plugins in both CIs. It
catches the drift that is already present (the 84/72/80 count) before it reaches an agent.

---

## 4. The phased plan

### Phase 1 — Align and harden (no cross-repo code)

**GhydraMCP**
- Nothing required for the unification itself. The bridge already speaks current MCP over stdio
  and the CLI is independent of the bridge.
- Optional but valuable: expose the Java plugin's REST endpoints as **MCP resources** so an
  agent can read program metadata (image base, segments, function index) without a tool round
  trip per item.

**x64dbg-mcp-server** — fix these first. They are real defects, they are cheap, and several of
them make the plugin unsafe to point at a real debugging session:

| # | Issue | Where | Why it matters here |
| --- | --- | --- | --- |
| 1 | **No locking anywhere.** `build.zig` sets `.single_threaded = true`; a grep for `Mutex\|atomic\|Interlocked` over `src/` finds zero real hits — yet `pending_events`, `event_log` and `sse_clients` are written by x64dbg callback threads and read by HTTP client threads. | `main.zig:25`, `tools.zig`, `mcp_server.zig` | Data race. Highest-severity defect in the codebase. Must be fixed before the server is exposed to a concurrent agent. |
| 2 | **`GuiGetDisassembly` called from the HTTP worker thread.** x64dbg GUI functions are main-thread-affine. | `tools.zig:1361,1683-1711`, `mcp_server.zig:802` | UI-thread violation; runs on *every* response via `buildStateSnippet`. |
| 3 | **`tools/list` writes the whole list into a fixed 65536-byte buffer, and `JsonWriter.raw` silently drops bytes on overflow.** 80 tools ≈ 32 KB today — within one doubling of the ceiling. | `mcp_server.zig:702`, `json.zig:16` | Overflow produces **malformed JSON**, not an error. Any move toward a combined tool surface makes this reachable. |
| 4 | **Static port, no walk-up.** `bind()` failure logs `"bind() failed."` and sets `server_running = false` — the plugin silently stops serving. | `mcp_server.zig:374` | A second x64dbg instance is unusable. GhydraMCP walks 8192–8447; adopt that model or document the limit. |
| 5 | **`Access-Control-Allow-Origin: *`**, and `OPTIONS` is answered *before* the auth check. | `mcp_server.zig:447,845` | A server with full debugger control and memory write access should not invite browser-originated traffic. |
| 6 | Advertises `tools.listChanged: true` but never sends `notifications/tools/list_changed`. | `mcp_server.zig:669+` | Clients may wait for a notification that never comes. |
| 7 | `ListCommandsByCategory` **ignores its own parameter** — there is no category concept in the code at all. | `tools.zig:1169-1182` | The tool lies about what it does. |
| 8 | Docs contradict the code: "84"/"72" tools, default bind `0.0.0.0` (code: `127.0.0.1`), "Zig 0.16-dev" (code + CI: 0.14.0), `Disassemble count` default 16 (schema: 10), `WaitForPause timeout` 10000 (schema: 30000). | README.md, SKILL.md | Cheap fixes; they are what an integrator will read first. |
| 9 | **Singleton command registration**: `StartMCPServer` / `StopMCPServer` are registered into x64dbg's **flat global** command namespace, unprefixed. | `main.zig:94-97` | Any future plugin registering the same name collides. Namespace them now. |

### Phase 2 — One agent surface

Ship a **combined installer and MCP client configuration** that registers both servers under the
namespaces agreed in §3.1. This is where the first real user value lands, and it needs almost no
new code.

Guard against the obvious failure mode: **165 tools in one agent's context degrades tool-selection
accuracy.** x64dbg already ships a 12-rule instruction string inside its `initialize` response
precisely because 80 flat tools is too many to self-describe. Mitigation: keep the two servers
registered separately (the client can enable/disable each), and make the combined configuration
opt-in per tool group rather than all-or-nothing.

### Phase 3 — The gateway (the actual unification)

A single MCP server that fronts both plugins and exposes **cross-tool workflows** that neither
can express alone. The static↔dynamic loop is the whole point:

```
analyze_open(binary)      -> TargetDescriptor (image_base + module_base + session_id)
function_locate(name)     -> static address + size       [Ghidra]
breakpoint_set(addr)      -> runtime breakpoint           [x64dbg, address converted]
run_to(addr)              -> stops, returns registers    [x64dbg]
decompile(addr)           -> recovered C                  [Ghidra or Kuna]
```

This requires the §3.2 address model to be real, and it requires both plugins to be working on
**the same file** — the gateway must verify that the Ghidra program's path matches the x64dbg
module's path, and refuse to correlate otherwise.

---

## 5. Where this should live

**Recommendation: a third repository, not a monorepo.**

```
re-mcp-suite/
  contract/          # JSON Schemas per tool, error-code table, TargetDescriptor schema
  conformance/       # the shared test suite, run in both CIs
  client-config/     # combined .mcp.json generator + installer for both plugins
  gateway/           # Phase 3, optional
```

A monorepo buys shared CI and shared versioning, and costs a build system that must handle
Maven + Python + Zig + two extension formats, with no code shared between them. The third repo
buys the only thing that is actually shared — the contract — without that cost.

The x64dbg repository is a fork of `duty1g/x64dbg-mcp-server`; upstream sync will get noisier as
changes land. Factor that in before committing to a shared-repo layout.

---

## 6. Explicitly out of scope

- **Porting Kuna to Java, or the x64dbg tools to Python/Java.** The stacks are deliberately
  different; the duplication is in the *request logic*, which is already the acknowledged pattern
  in both repos.
- **Making the Ghidra plugin speak MCP directly.** Tempting — it would make the two symmetric —
  but it means porting 85 formatters to Java and losing stdio. The bridge is fine where it is.
- **Making x64dbg serve a REST API for symmetry.** No consumer needs it.
- **Embedding RAG/vector search.** See `KUNA-MCP-ANALYSIS.md` — the retrieval here is exact, and
  embeddings would make it worse, not better.

---

## 7. Risks

| Risk | Likelihood | Mitigation |
| --- | --- | --- |
| 165 tools degrade agent tool-selection accuracy | High | Keep the servers separately toggleable; ship combined config opt-in per group |
| The x64dbg data races bite under real concurrent agent use | Medium-high | Phase 1 item #1 before any wider exposure |
| Ghidra and x64dbg end up on different binary builds, and address correlation silently produces garbage | Medium | The gateway must verify path identity before offering any cross-tool workflow; refuse otherwise |
| Upstream `duty1g` merges into the fork conflict with local contract changes | Medium | Keep contract changes in the contract repo, not the plugin |
| Scope creep into "rewrite both" | Medium | This plan's Phase 1 is deliberately small and mechanical |

---

## Appendix — evidence

- Tool counts: x64dbg registry `src/mcp/tools.zig:31-677` (80 entries); GhidraMCP 85 `@mcp.tool()`
  decorators across 22 namespaces in `bridge_mcp_hydra.py`.
- x64dbg protocol/version: `src/core/mcp_server.zig:13` (`PROTOCOL_VERSION`), `:537-547` (dispatch),
  `:667-698` (`initialize` result and the 12-rule instructions string).
- x64dbg transport: `src/core/mcp_server.zig:343-405` (Winsock accept loop, thread per connection),
  `:440-515` (no keep-alive; one request per connection), `:472-512` (Streamable HTTP vs SSE split).
- x64dbg auth: `src/core/config.zig:193` (token generation), `:302` (persistence),
  `src/core/mcp_server.zig:453-470` (enforcement).
- x64dbg SDK binding: `src/core/bridge.zig:338-395` (33 runtime-resolved symbols).
- GhidraMCP server: `src/main/java/eu/starsong/ghidra/api/ApiConstants.java` (`API_VERSION` 3000,
  port range), `GhydraPlugin.java` (resource registration).

---

## 8. Progress

Updated as the plan is executed. A phase is "done" for a side only when the
`--contract` suite proves it there.

### Phase 1 — GhydraMCP side: done (2026-11-09)

The plan said this side needed nothing for the unification itself, and offered one
optional item (expose metadata as MCP resources — those already exist:
`ghidra://instance/{port}`, and the function resources). What Phase 1 *did* need from
this repository is the contract, and that now exists:

| Contract rule | Where it lives | Proof |
| --- | --- | --- |
| vocabulary (`namespace_verb`, snake_case, no reserved parameter) | `contract/vocabulary.json`, `contract/tools.json` (generated) | `tests/test_contract.py`: 134 names match, 0 reserved, 134 formatters |
| address model (`TargetDescriptor`, both address forms, identity) | `contract/target-descriptor.schema.json`, `ghydra/target.py` | conversion round-trips; a descriptor over two different files is **not correlatable**; the schema rejects a bad one |
| error envelope (stable code + human text) | `contract/error-codes.json` (generated) | 112 codes, shaped, unique, each with its side and its `file:line` |
| conformance | `tests/test_contract.py`, run as `--contract` (and in CI) | 24 tests |

What this does **not** do is fix the x64dbg side. Its nine Phase-1 defects are
untouched — including the data race (#1) and the UI-thread call (#2), which are the
two that make it unsafe to point at a real debugging session. Those live in
`danalec/x64dbg-mcp-server` (verified at `9d7a93e`, 80 flat tools), and the plan's
own rule applies: do not entangle the repositories.

### What Phase 2 and 3 still need

- **Phase 2** — one agent surface: a combined MCP client configuration that registers
  both servers, with the two sides separately toggleable. It depends on the x64dbg
  side adopting the vocabulary, or on aliases.
- **Phase 3** — the gateway: `analyze_open → function_locate → breakpoint_set →
  run_to → decompile`. The `TargetDescriptor` is its first requirement and it now
  exists on this side; the gateway still needs the debugger's `module_base` and
  `module_path` from a second server, and the path-identity refusal it already has.
