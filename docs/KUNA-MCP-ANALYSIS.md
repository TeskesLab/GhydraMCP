# Should the Kuna parameters go straight into MCP — and as RAG?

Status: **implemented** — written 2026-11-02 against GhydraMCP `main` (3.0.0), companion to
`UNIFICATION-PLAN.md`. Every item in §5 is now in the code; the "Work items" section records what
was built and how to verify it.

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

**Done.** The bridge registers five resources: the concrete `kuna://exports` manifest, and the
templates `kuna://export/{digest}/index.jsonl`, `kuna://export/{digest}/README.md`,
`kuna://export/{digest}/{function}.c` and `kuna://export/{digest}/{function}.asm`. The templates
serve any export by digest, and `_kuna_sync_resources()` also registers the index and the report
of every export on disk as concrete resources, so a client that only reads `resources/list` sees
them. A function name is percent-decoded, because a name may hold a slash.

### 5.3 Let `kuna_export_read` accept a directory

**Done.** `kuna_export_read` takes `job_id` (optional) and `directory` (optional); the directory
may be a path or the 12-character digest. One of the two is required, and the answer names the
other. The CLI's `export-read` takes a digest too.

### 5.4 Align the error taxonomy

**Done.** The bridge carries the same 14 codes as the CLI, and `test_kuna.py` asserts the two
lists are identical — so adding a code on one side without the other fails the suite. The bridge
also distinguishes a missing binary, a timeout and a launch failure, which it used to flatten
into one generic code.

Bring the bridge from 2 codes to the CLI's 13, reusing `ghydra/kuna.py`'s table. ~40 lines, and
it needs the two duplicated implementations to stay in step — the known duplication cost of this
project, already accepted for the request logic.

### 5.5 Fix the documentation drift

**Done**, except the benchmark itself, which was not re-measured: the perf table stays labelled
as measured against Kuna 1.785, and the doc says so.

- The status sample no longer implies that 1.785 is the installed version, and it shows the
  exports listing.
- `ghydra kuna status` now says `"nothing (the integration is off)"` when neither the config file
  nor the env var decided — the third branch the bridge already had.
- The reference now says that the MCP side has no `-o` and that `directory` is how an arbitrary
  export is read.
- The timeout difference between the two sides is now stated: the bridge inherits
  `GHYDRA_TIMEOUT`, the CLI's 900 is fixed and `ghydra config set timeout` does not change it.
- The two wordings of "the export has no index yet" are both described.

### 5.6 Note `max_lines` semantics

**Done.** The reference states that `max_lines` caps the answer and not the work: it is applied to
the text after the function has been fetched, so it saves context but no time.

---

## 6. Summary

| Question | Answer |
| --- | --- |
| Are Kuna's parameters already in MCP? | Yes — 13 curated tools, 46 parameters. |
| Should the raw flag surface go in too? | No. It doubles the schema, couples the agent to Kuna's ABI, and exposes knobs with no per-call meaning. |
| Is RAG the right pattern? | The *shape*, yes. Embeddings, no. |
| What to build instead | MCP resources over the export directory, addressed by the existing `sha256(path|mtime)` digest. **Built.** |
| What to fix first | The missing export cache check. **Built**: measured 691 ms to 26 ms on a 332 KB binary. |
| What not to do | Embeddings, a sidecar service, a raw flag mirror, or a second copy of the opt-in logic. |

### What is in the code now

| Change | Where |
| --- | --- |
| Export reuse, and the `reused` flag in the report | `bridge_mcp_hydra.py` (`kuna_export_start`), `ghydra/kuna.py` (`export`) |
| The digest as an address | `kuna_export_read(directory=...)`, `ghydra kuna export-read <digest>`, `kuna_status` |
| The resources | `bridge_mcp_hydra.py`, the "Kuna resources" section |
| The 14 error codes | `bridge_mcp_hydra.py` (`KUNA_ERROR_CODES`), `ghydra/kuna.py` (`KunaError`) |
| The sidecar and the listing | `.ghydra.json` next to an export; `kuna_status` and `ghydra kuna status` |
| The tests | `test_kuna.py` - `KunaExportAddressingTests` and `KunaErrorTaxonomyTests` |

`python run_tests.py --kuna` covers all of it and needs neither Ghidra nor the Kuna binary.
