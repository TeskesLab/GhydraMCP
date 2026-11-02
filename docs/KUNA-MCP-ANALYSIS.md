# Should the Kuna parameters go straight into MCP — and as RAG?

Status: **analysis with a recommendation** — written 2026-11-02, against GhydraMCP `main`
(3.0.0). Companion to `UNIFICATION-PLAN.md`.

## Verdict

Three answers, one per layer of the question:

1. **The Kuna parameters are already in MCP.** 13 `kuna_*` tools, each a curated wrapper over one
   Kuna CLI invocation. Nothing is missing in terms of coverage.
2. **Do not expose Kuna's raw flag surface.** The curated subset is the adapter boundary, and
   widening it makes tool selection worse, not better. The gaps worth closing are *not* flags.
3. **Yes to RAG-shaped retrieval — but as MCP resources, addressed exactly, not with embeddings.**
   The real defect is that exports are addressed by an **in-memory job id** that dies with the
   bridge process. That is the thing to fix, and resources are the right primitive for it.

There is also one bug worth more than every design question in this document: `kuna_export_start`
**always re-runs the analysis**, even when a complete export for the same binary is already on
disk. See §5.1.

---

## 1. What exists today

### MCP surface — 13 tools (`bridge_mcp_hydra.py:4468-5091`)

| Tool | Parameters |
| --- | --- |
| `kuna_status` | — |
| `kuna_summary` | `binary_path`, `mode` |
| `kuna_functions` | `binary_path`, `name_filter`, `offset`, `limit` |
| `kuna_decompile` | `binary_path`, `function`, `addr`, `mode`, `max_lines` |
| `kuna_disassemble` | `binary_path`, `target`, `count`, `bytes`, `addr`, `mode` |
| `kuna_read` | `binary_path`, `target`, `bytes`, `addr` |
| `kuna_strings` | `binary_path`, `pattern`, `limit`, `min_length`, `encoding`, `section` |
| `kuna_crypto` | `binary_path`, `algorithm`, `section` |
| `kuna_xrefs` | `binary_path`, `target`, `direction`, `kind` |
| `kuna_unpack` | `binary_path`, `output` |
| `kuna_export_start` | `binary_path`, `functions`, `jobs`, `job_id` |
| `kuna_export_status` | `job_id` |
| `kuna_export_read` | `job_id`, `function`, `artifact`, `max_bytes` |

None takes a `port` — the integration is local, and `test_kuna.py:153-160` enforces that.

### CLI surface — 12 commands (`ghydra/cli/kuna.py`)

`status`, `summary`, `functions`, `decompile`, `disassemble`, `read`, `strings`, `crypto`,
`xrefs`, `unpack`, `export`, `export-read`.

### Invocation

`_kuna_run` (`bridge_mcp_hydra.py:230-260`) shells out with
`subprocess.run([executable, *args], capture_output=True, text=True, encoding="utf-8",
errors="replace", timeout=limit)`. Binary resolution order: config `kuna.path` → `GHYDRA_KUNA_PATH`
→ `PATH` → Scoop shims (`:170-196`).

Export layout under `~/.ghydra/kuna/<digest>/`, where
`digest = sha256(f"{binary}|{mtime}")[:12]` (`:300-311`):
`index.jsonl`, `<stem>.c`, `<stem>.h`, `<stem>.asm`, `README.md`, `.streaming` (during export).

---

## 2. Why raw Kuna flags should not go straight into MCP

**Parameter explosion.** The 13 tools already carry 46 parameters. Kuna's own flag set
(`--json`, `--stream`, `--jobs`, `--output`, `--addr`, `--mode`, `--section`, `--kind`,
`--algorithm`, `--functions`, `--filter`, `--min-length`, `--encoding`, `--bytes`, `--count`)
would roughly double that. Tool-selection accuracy falls as the schema grows, and x64dbg already
demonstrates the failure mode: its `initialize` response ships a **12-rule instruction string**
(`mcp_server.zig:682-698`) because 80 flat tools is already too many for a tool list to
self-describe.

**Version skew.** Kuna's flags are Kuna's ABI. This machine has Kuna **1.988** installed via
Scoop; `GHYDRA_KUNA.md` still documents and benchmarks **1.785**. The bridge is the right place to
absorb that skew — but it absorbs it by *curating*, not by mirroring.

**Most flags are not per-call decisions.** `--json` and `--stream` are output-shape choices the
bridge already makes. `--jobs` and `--output` are export-shape choices, made once. Exposing them
per call gives an agent knobs that have no meaningful per-call value.

**What the curated set gets right.** The one flag that *is* a genuine per-call decision — `--mode`
(`auto` / `reliable` / `fast`) — is already exposed on the three tools where it changes the
result: `kuna_summary`, `kuna_decompile` and `kuna_disassemble`. That is the pattern: expose the
decisions the agent actually makes, hide the ones that belong to the adapter.

---

## 3. The real gap is addressing, not flags

Three concrete problems, in descending order of impact.

### 3.1 Exports are addressed by an ephemeral job id

`kuna_export_read(job_id, ...)` looks the job up in `_kuna_jobs`, an **in-memory dict in the
bridge process** (`bridge_mcp_hydra.py:127-128, 4993-4998`). The failure mode is stated plainly in
the error message:

> `unknown job id '{job_id}'; jobs live in the bridge process that started them`

So: restart the bridge, and a completed export sitting on disk becomes **unreachable**. Start a
second bridge, and it cannot see the first one's export. The export is the expensive, valuable
artifact — the thing the whole export flow exists to produce — and it is the one thing the agent
cannot address.

### 3.2 The CLI's exports are invisible to the MCP side

`ghydra kuna export -o <dir>` writes wherever the user says, and `ghydra kuna export-read <dir>`
reads any directory it likes. The MCP tools cannot: `kuna_export_start` has **no output
directory parameter** (it always uses the digest path), and `kuna_export_read` only reads
directories belonging to jobs in its own registry. The two surfaces are not equivalent, and
`GHYDRA_KUNA.md` describes the CLI behaviour while implying MCP parity.

### 3.3 Error typing is lost on the bridge side

The CLI has 13 error codes (`KUNA_DISABLED`, `KUNA_MISSING`, `KUNA_TIMEOUT`, `KUNA_FAILED`,
`KUNA_NO_JSON`, `KUNA_TOO_LARGE`, `KUNA_NO_FILE`, `KUNA_NO_DIR`, `KUNA_NO_INDEX`,
`KUNA_BAD_ARTIFACT`, `KUNA_NO_FUNCTION`, `KUNA_IO`, `KUNA_LAUNCH` — `ghydra/kuna.py:39-49`).
The bridge has **two** (`KUNA_ERROR`, `KUNA_DISABLED` — `:199-213`). An agent using the bridge
cannot distinguish "Kuna is not installed" from "the export is not ready" from "the function name
does not exist" — it gets a prose string and has to guess.

---

## 4. The recommendation: MCP resources, exact addressing, no embeddings

### 4.1 Why "RAG" is the right instinct and the wrong implementation

The intuition behind RAG is exactly right for this problem: **do not push the whole binary into
the agent's context; give it a way to pull only the slice it needs.** Kuna's own numbers make the
case — one-shot calls on a 22 MB binary cost 10–19 s each and return hundreds of KB.

But **vector/embedding RAG is the wrong tool here**:

- The corpus is a decompiled program with an **exact index** (`index.jsonl`, keyed by function
  name, address and size). "Show me `sub_401000`" is an exact lookup, not a similarity search.
- Embeddings would add a model dependency, an index to build, and a cold-start cost — in exchange
  for retrieving the *wrong* function when the exact name is already known.
- Decompiled C is a poor embedding corpus anyway: two functions with the same name in different
  binaries are near-identical in embedding space and completely different in meaning.

What is wanted is RAG's **shape** — a corpus the client lists and pulls from, with the server
deciding what is addressable — using **exact** retrieval. That is precisely what the MCP
**resources** primitive is for: application-controlled context, addressed by URI.

### 4.2 The design

**Expose the export directory as a resource tree, keyed by the existing digest.**

```
kuna://export/<digest>/index.jsonl          # the function index
kuna://export/<digest>/<function>.c         # recovered C
kuna://export/<digest>/<function>.asm       # disassembly
kuna://export/<digest>/README.md            # the export report
kuna://export/                              # the list of available exports
```

The digest is already `sha256(path|mtime)[:12]` — **stable across processes and restarts**. That
is the property the job id lacks. A URI built from it survives the bridge, survives a restart, and
can be handed from the CLI to the agent.

FastMCP supports this directly:

```python
@mcp.resource("kuna://export/{digest}/index.jsonl")
def kuna_export_index(digest: str) -> str: ...
```

The retrieval loop the agent gets is exactly the RAG loop, with exact addressing:

1. `resources/list` → which binaries have been exported.
2. `resources/read` on `index.jsonl` → the function list (one small read).
3. `resources/read` on `<function>.c` → that one function's recovered C.

Nothing is dumped that the agent did not ask for by name, and every step is a cheap file read.

**Keep the tools for the one-shot path.** `kuna_decompile` on a 332 KB binary costs 492 ms — the
export machinery is pure overhead there. The tools serve "just decompile this one function from
this small binary"; the resources serve "work through a large binary without paying the analysis
twenty times".

**Keep `kuna_export_read(job_id, ...)`** as the job-scoped convenience, but let it accept a
directory or digest as well, so the CLI↔bridge asymmetry in §3.2 disappears.

### 4.3 What this deliberately does not do

- **No embeddings, no vector store, no similarity search.** The retrieval is exact and the index
  is already structured for it.
- **No new "RAG service" or sidecar.** The bridge stays the only place Kuna is driven from; a
  second process would mean a second copy of the opt-in logic, the path resolution and the job
  registry.
- **No raw flag exposure.** §2 stands.

---

## 5. Work items

### 5.1 Fix the export cache (highest value per line)

`_kuna_work_dir`'s own docstring states the intent:

> "Keyed by path and mtime, so a rebuilt binary gets a fresh directory while a re-analysis of the
> same file reuses it."

**The reuse is not implemented.** `kuna_export_start` (`:4870-4909`) computes the directory and
unconditionally launches `kuna decompile-project`. There is no check for an existing complete
export. The docstring documents a behaviour that does not exist.

The fix: before launching, check for `index.jsonl` present **and** no `.streaming` marker; if so,
return the existing export instead of re-analysing. The digest already guarantees the binary and
its mtime are the same.

Effect: a second export of the same binary goes from **19 s to instant**, and the resource URI
becomes meaningful — the export can be referenced before it is re-made.

Estimate: ~15 lines plus three tests in `test_kuna.py`.

### 5.2 Expose the export tree as MCP resources

~60 lines in `bridge_mcp_hydra.py` (the resource functions can reuse `_kuna_index_records`,
`_kuna_extract_c`, `_kuna_extract_asm` as they stand), plus tests for
`resources/list` and `resources/read`.

### 5.3 Let `kuna_export_read` accept a directory

~10 lines. Closes §3.2.

### 5.4 Align the error taxonomy

Bring the bridge from 2 codes to the CLI's 13, reusing `ghydra/kuna.py`'s table. ~40 lines, and
it needs the two duplicated implementations to stay in step — the known duplication cost of this
project, already accepted for the request logic.

### 5.5 Fix the documentation drift

- `GHYDRA_KUNA.md:210` and the perf table (`:62`) benchmark **Kuna 1.785**; this machine has
  **1.988** installed via Scoop. The timings are stale and should be re-measured, or explicitly
  labelled as measured against a named version.
- `GHYDRA_KUNA.md:240` says `ghydra kuna status` "shows which of the two decided", but the CLI
  has only two outputs and prints *"disabled (opt-in via $GHYDRA_KUNA)"* when neither is set —
  which is false. The bridge has the correct third branch (`"nothing (the integration is off)"`).
- `GHYDRA_KUNA.md:199` describes the export destination but does not say that the MCP side has no
  `-o` and cannot read an arbitrary directory.
- `GHYDRA_KUNA.md:52` says `GHYDRA_KUNA_TIMEOUT` defaults to 900; on the bridge the default
  actually inherits `GHYDRA_TIMEOUT` (`:63,117`), while the CLI's 900 is fixed and ignores
  `ghydra config set timeout`.
- `GHYDRA_KUNA.md:250` quotes the CLI's `"the export has no index yet"`; the bridge's wording
  differs.

### 5.6 Note `max_lines` semantics

`max_lines` is a **formatter cap**, not an API parameter — it is applied to the text after the
whole function has been fetched (`bridge_mcp_hydra.py:1684-1686`). It saves *context*, not *time*.
That is the right trade (context is the scarce resource), but the docstring should say so
explicitly, because a reader will reasonably assume it limits the work Kuna does.

---

## 6. Summary

| Question | Answer |
| --- | --- |
| Are Kuna's parameters already in MCP? | Yes — 13 curated tools, 46 parameters. |
| Should the raw flag surface go in too? | No. It doubles the schema, couples the agent to Kuna's ABI, and exposes knobs with no per-call meaning. |
| Is RAG the right pattern? | The *shape*, yes. Embeddings, no. |
| What to build instead | MCP resources over the export directory, addressed by the existing `sha256(path|mtime)` digest. |
| What to fix first | The missing export cache check — 19 s → instant, ~15 lines. |
| What not to do | Embeddings, a sidecar service, a raw flag mirror, or a second copy of the opt-in logic. |
