# BSim — signature similarity across a local or remote corpus


<!-- toc -->

- [1. What it is (and what it is not)](#1-what-it-is-and-what-it-is-not)
- [2. Setup](#2-setup)
- [3. Build a corpus: `ingest`](#3-build-a-corpus-ingest)
- [4. Ask it: `query`](#4-ask-it-query)
- [5. Act on it: `apply-names`](#5-act-on-it-apply-names)
- [6. Compare two versions: `diff`](#6-compare-two-versions-diff)
- [7. The traps (all measured, all now encoded)](#7-the-traps-all-measured-all-now-encoded)
- [Agent workflow and current limits](#agent-workflow-and-current-limits)
- [8. Reference](#8-reference)
- [9. Reproducing the numbers](#9-reproducing-the-numbers)

<!-- /toc -->

Ghidra ships a signature system, **BSim**, that turns a function into a vector and
lets you ask "which functions in this corpus look like this one?". That is the one
question a decompiler cannot answer well, and it is what this integration exposes
— on all three surfaces.

Historical measurements below used **Ghidra 12.2 with local H2**; they are not
remote performance claims. The native reflective client factory supports H2,
PostgreSQL and Elasticsearch on Ghidra 11/12 without compile-time BSim dependencies.

---

## 1. What it is (and what it is not)

| It is | It is not |
| --- | --- |
| local H2 or a worker-provisioned remote BSim profile | arbitrary caller-supplied servers or credentials |
| a **similarity** measure over compiled shapes | an identification of source code |
| a way to pair a moved function across builds | a decompiler (use `/functions/{addr}/decompile`) |
| a lead for an analyst | a verdict — every answer says so |

BSim is a Ghidra **feature**, not a plugin API. The extension discovers it by
loading the class (`ghidra.features.bsim.query.BSimServerInfo`), so a build
without it answers `available: false` instead of failing oddly. All the BSim
calls are reflective on purpose: that API is internal and has moved between the
11.x and 12.x series, and the extension compiles against both.

---

## 2. Setup

```bash
# local H2 only; the database does not need to exist yet
export GHYDRA_BSIM_DATABASE=/var/tmp/signatures          # Linux/macOS
# or: set GHYDRA_BSIM_DATABASE=C:\tmp\signatures         (Windows)
# or: -Dghidra.bsim.database=<path> on the Ghidra JVM

ghydra bsim status        # engine? database? what is missing?
```

For remote PostgreSQL or Elasticsearch, an administrator provisions the profile
and credentials under a separate worker identity; see [connections](GHYDRA_CONNECTIONS.md).
Only profile IDs cross CLI/MCP/HTTP. Do not put a remote URL, username or password
in `GHYDRA_BSIM_DATABASE` or `-Dghidra.bsim.database`: legacy configuration accepts
local filesystem paths only. Credentials are never command-line arguments.

```bash
ghydra connections list
ghydra bsim status --profile corpus
ghydra bsim query --profile corpus --name main
ghydra bsim diff app-1.2.exe --profile corpus
ghydra bsim ingest --profile corpus --max-functions 500
```

Every BSim command accepts `--profile ID`; every HTTP BSim route accepts
`?profile=ID`. Omission uses the worker manifest's `default_bsim`, or the existing
local H2 configuration when there is no default. Selection is request-scoped and
never rewrites global configuration. Query, apply-names and diff require the
profile's `query` grant; ingest requires `ingest`. Status validates the profile
without requiring either grant or opening its credentials/database.

**Remote databases must already exist.** Ingest never creates a PostgreSQL or
Elasticsearch database. It uses Ghidra's native client under worker-only,
non-interactive authentication callbacks; authentication failures do not prompt
the GUI or retry for another password.

`ghydra bsim status` reports configuration, not a successful remote connection:

```json
{"available": true, "database": "/var/tmp/signatures",
 "database_exists": false, "ready": false, "can_ingest": true,
 "reason": "the local signature database does not exist; ingest a program first"}
```

Status fields:

- **`ready`** — the engine and query permission are present, and a local H2 file
  exists or a remote profile is selected. A remote operation still must connect.
- **`can_ingest`** — the engine and ingest permission are present; only a local
  H2 database is created if absent.
- **`database_exists`** — local filesystem fact; `null` for a remote database.
- **`connection_checked`** — `false`: status never authenticates or probes a server.

For profiles, `database` and `profile` contain only the profile ID, and `backend`
identifies the native backend. Status/results do not disclose remote endpoints,
credential references or native exception reasons.

`/capabilities` carries the same facts as features: `bsim`, `bsim_ingest`,
`bsim_query`, `bsim_apply_names`.

---

## 3. Build a corpus: `ingest`

Ingest takes the **open program** — one binary per call:

```bash
ghydra bsim ingest --max-functions 500   # a bounded first look
```

Measured on `where.exe` (104 functions discovered):

```
discovered: 104 functions
scanned: 104 (0 skipped)
described: 94
inserted: 94 functions into 1 executable(s)
took: 3.1s
database: C:\...\where.bsim (created)     # 120 KB .mv.db
```

**The scan is capped at 5 000 functions by default.** Every function is a
decompilation, so "all of them" on a large binary is hours inside one request:
the client gives up at its timeout and the Jetty thread stays busy. Ask for more
with `--max-functions 20000`, or for everything with `--max-functions 0`. The
answer reports the cap (`functions_cap`) and whether it bit (`capped`) — a
partial ingest must not be read later as "not in the corpus".

- **`described` < `discovered`** is normal: functions without a body (thunks,
  externals) cannot carry a signature. They are not in the database, and the
  comparison later says so instead of pretending.
- **Ingesting the same program again is not an error.** BSim deduplicates by the
  executable fingerprint: the answer is `success: true, already_present: true,
  inserted_functions: 0`. A pipeline that treated that as failure would be wrong.
- **The call graph is off by default** — a query does not need it and it makes the
  database bigger. With `--track-call-graph` it works (measured: 189 functions for
  `where.exe`); the trap below explains the bug that used to make it fail.

To build a corpus, ingest each binary in turn (headless runs are the cheap way):

```bash
ghydra headless start /bin/ls --port 8192
ghydra bsim ingest
ghydra headless stop
```

---

## 4. Ask it: `query`

```bash
ghydra bsim query --address 0x140001010
ghydra bsim query --name main --min-similarity 0.9
```

```
BSim query: FUN_140001010 at 140001010
  threshold: similarity >= 0.7
  matches: 1 (of 1 considered)
  1.0 similarity, significance 26.024: FUN_140001010 @ 0x140001010 in where.exe
```

- **`similarity`** is 0..1 over the function's shape; **`significance`** is BSim's
  score for how unlikely the match is to be chance. Both are BSim's own numbers,
  passed through — not recomputed.
- A **1.0** match is the same vector, not proof of the same source.
- **An empty answer names the threshold it used** (`no stored function is at
  least 0.8 similar (threshold used)`), so "not in the corpus" and "searched with
  a high floor" are never confused.
- A function with **no body** answers `BSIM_NO_BODY`: there was never a signature
  to compare.

Measured without metadata filters: 0.2 s by name, 0.8 s by address, on the
database above.

### Narrow the search with metadata

```bash
ghydra --json bsim query --profile corpus-reader --name decode_packet \
  --executable libcodec.so --architecture 'x86:LE:64:default' --compiler gcc \
  --category Library=codec --category Version=1.0 --max-matches 5
```

```python
bsim_query(name="decode_packet", profile="corpus-reader",
           executable="libcodec.so", architecture="x86:LE:64:default",
           compiler="gcc", categories='{"Library":"codec","Version":"1.0"}',
           max_matches=5)
```

Filters match exact database metadata values and combine with **AND**. Native
BSim applies them before the match limit, so better matches from other binaries
do not use up the requested result slots. Filtering supports local H2 and native
PostgreSQL BSim profiles; credentials stay on the worker. Elasticsearch and
unknown backends refuse metadata filters rather than silently ignoring them.

`categories` is JSON **text**, not a nested MCP object. Use category names from
the query result's `available_categories` and values recorded in your corpus.
The CLI accepts one `--category NAME=VALUE` per category; duplicate category
names are refused. Blank/non-string values, malformed category objects, unknown
categories and unavailable native filters fail instead of searching a broader
corpus. `result.filters` reports the applied predicates. An empty filtered result
is evidence only about that scope and those similarity/significance thresholds.
Values must have no surrounding whitespace or control characters. At most
32 category predicates are accepted, within 16384 JSON characters; category names are
limited to 256 characters and individual values to 4096 characters.


---

## 5. Act on it: `apply-names`

```bash
ghydra bsim apply-names --address 0x140001010              # dry run (default)
ghydra bsim apply-names --address 0x140001010 --apply      # rename
```

```
BSim apply: my_local_name -> FUN_140001010
  from: where.exe FUN_140001010 @ 0x140001010
  similarity: 1.0 (significance 26.024)
  floor: 0.8
  applied: no (dry run) — pass dry_run=False to rename
```

The rules, all of them deliberate:

- **dry run by default** — a signature match is a heuristic and a wrong rename is
  a wrong map of the program; the caller has to ask for the change;
- **a similarity floor** (0.8 by default) — nothing below it is applied;
- **one transaction** — `TransactionHelper`, so the rename is undoable in Ghidra
  like any other edit;
- **no no-op write** — a function already carrying the matched name answers
  `already_named` instead of being rewritten;
- **the numbers travel with the change** — similarity and significance are in the
  answer, so the edit can be judged (and reverted) later.

Measured end to end: a function renamed locally to `my_local_name` was reported
as `would_rename` on the dry run (and verified unchanged through
`/functions/{address}`), then renamed back to `FUN_140001010` with `--apply`.

---

## 6. Compare two versions: `diff`

`GET /analysis/diff` compares **by address and name**: the right answer for "what
moved in the file". `bsim diff` compares **by shape**, which is what a signature
database is uniquely good at:

```bash
ghydra bsim diff app-1.2.exe --max-functions 50
```

```
BSim diff: app-1.1.exe against app-1.2.exe
  compared 50 (54 not compared)
  same: 41, moved: 3, not found: 6, no signature: 0
  [moved] FUN_140002000 @ 140002000 -> FUN_140009000 @ 0x140009000 (0.93 similar)
```

Every row has a **class**, and the four are different facts:

| Class | Meaning |
| --- | --- |
| `same` | paired, at the same address |
| `moved` | paired, at another address (a function that moved or was rebuilt) |
| `not_found` | no function of the other version above the floor |
| `no_signature` | the function has no body, so it cannot be in the database at all |

`query_failures` lists queries that *failed* — kept apart from `not_found` on
purpose: "not in the other version" would be a lie about a function that was never
ingested.

**The cost is the honest part:** one BSim query per function, measured at
0.2–0.8 s, so the walk is bounded (`--max-functions`, default 25, cap 500) and the
answer reports `not_compared`.

Measured: `where.exe` against itself — 6 of 8 paired as `same` in 2.4 s; the two
imported thunks came back `not_found`. Against an executable that is not in the
database, every function answered `not_found` rather than an invented pair.

---

## 7. The traps (all measured, all now encoded)

1. **The call graph needs the records sorted — it is not a limit of H2.** The
   insert used to fail with `Unique index violation … callgraphtable(src,dest)` on
   ordinary recursion, and the first conclusion (recorded here) was "H2 cannot
   take call graphs". It was ours: Ghidra's own script sorts every function's
   call-graph records before the insert
   (`listAllFunctions().forEachRemaining(fd -> fd.sortCallgraph())`), and without
   that sort the records collide. With the sort, a call-graph database ingests
   `where.exe` completely (189 functions). The default stays off because a query
   does not need it.
2. **`initialize()` does not create an H2 database.** On a missing file it answers
   `Database does not exist: …mv.db`. Ingest therefore creates it first, with
   Ghidra's `CreateDatabase` command and the `medium_nosize` template, and only
   then connects.
3. **An H2 database is not the path that names it.** The file is
   `<path>.mv.db` (older builds `.h2.db`). Measured: a 120 KB database was
   reported as missing because only the bare path was checked.
4. **The executable name is `getNameExec()`.** `getName()` exists on
   `ExecutableRecord` and answers `null` — which left every match without the
   binary it came from until the live run showed it.
5. **`GenSignatures(boolean)` takes `trackcallgraph`, not a cache flag**, and a
   generator without `setVectorFactory(...)` dies with
   `NullPointerException: LSHVectorFactory.getSettings()` on a database created in
   the same call.
6. **The decompiler must include BSim's signature module.** The installed Nix
   runtime tested here rejected signature generation with
   `Decompiler executable not built with signature module`, despite database
   authentication and metadata queries succeeding. Use a matching Ghidra runtime
   with a signature-capable decompiler; ordinary C decompilation is not proof.

---

## Agent workflow and current limits

1. Search the target instance with `bsim_query` and an approved BSim profile.
   Each result has a `match_id`, executable MD5, repository URL, architecture and
   compiler metadata. `reference_available=false` means the row cannot be resolved
   automatically; BSim vectors alone do not contain reference code.
2. Select the exact row, not just the highest score. Call `bsim_compare_match`
   with its ID, the approved repository profile and the reference worker port.
   Both workers use the configured HTTP host; they may be the same worker when
   it has both profiles. Neither worker's active program changes.
3. Review the textual unified C diff, signature changes and recursive type
   descriptions/conflicts. The preview contains exact before/after annotations,
   not a command to apply them. `applied` is always `false`.
4. To apply the chosen signature and its dependency types, explicitly prepare
   it with `bsim_prepare_apply` (CLI: `bsim prepare-apply`). Review that operation's
   exact preview and retain its opaque `apply_token`.
5. Only an explicit `bsim_apply_match` call (CLI: `bsim apply-match`) with that
   token changes the target. Querying, comparing and preparing never apply changes.

```bash
ghydra --port 8192 --json bsim query --profile corpus-reader --name target_function
ghydra --port 8192 bsim compare-match MATCH_ID --profile corpus-reader \
  --reference-profile ghidra-reader --reference-port 8193
ghydra --port 8192 bsim prepare-apply MATCH_ID --profile corpus-reader \
  --reference-profile ghidra-reader --reference-port 8193
ghydra --port 8192 bsim apply-match MATCH_ID --profile corpus-reader \
  --apply-token APPLY_TOKEN
```

```python
bsim_compare_match(match_id="MATCH_ID", profile="corpus-reader",
                   reference_profile="ghidra-reader", reference_port=8193, port=8192)
```

The selected row binds the target program, exact function address and modification
stamp. IDs last only for that worker process; the newest 256 rows are retained.
Source changes, another active target or an evicted ID require a new search.
The reference is opened temporarily read-only at a concrete stored version.
Its URL must match the approved repository binding, and its executable MD5 and
exact function address must match the selected row. Comparison does not import
signatures/types or rename anything; application is a separate explicit operation.
When an unqualified stored offset occurs in multiple address spaces, the exact
indexed fully-qualified name must select a single function; unresolved ambiguity
is refused instead of preferring the default space.

`--max-code-lines` / `max_code_lines` defaults to 1000 per function (1..10000).
Truncated/unavailable decompilation or bounded/incomplete type evidence sets
`complete=false`; no differences then does **not** establish equality.
Architecture, compiler and pointer-size differences produce warnings.
This is textual C comparison, not the UI's instruction alignment or native
CodeDiffPlugin analysis.

`bsim_diff_versions` remains a bounded function-matching summary: `same` means a
matched function at the same address, not identical code. `bsim_apply_names`
still re-queries the best qualifying match and changes a name only; it does not
consume a selected-match preview. Unsolicited changes, comment transfer,
instruction-level comparison and bulk acceptance remain outside this workflow.

### Explicit signature and type application

Preparation exports the selected reference signature and its dependency types in
a native Ghidra archive; it does not reconstruct them from the bounded comparison
graph. Recursive types, typedef chains, structures, unions, bitfields, enums and
function definitions retain their native definitions. Dynamic hidden parameters,
class namespaces and explicit register/stack storage retain their native ABI
shape. The reference stays read-only.

The target checks the selection identity, source modification stamp, ABI and
existing type conflicts before issuing a worker-local apply token. Incompatible
existing types are refused, not silently overwritten. Review the returned preview:
similarity is still only a lead, and a prepared operation is not approval to apply.

The bridge/CLI is a **trusted coordinator**: it must fetch the export directly
from the approved reference worker over the configured protected transport.
The target's `selection_identity_checked` confirms that the forwarded payload
matches its selected row; it is not an attestation of the archive's origin.
The raw HTTP preparation endpoint does not authenticate caller-authored exports.
Do not use the archive digest or apply token as proof of remote provenance.

Prepared tokens expire after five minutes; only the newest 32 previews are
retained. Native archives are bounded at 512 KiB and fail explicitly if too large,
never truncate dependency definitions. Archive bytes stay inside the coordinator.

Explicit application imports dependency types and updates the selected target's
name/namespace and signature in one transaction. Failures roll back the complete
transaction. Stale, unknown or already-used tokens cannot apply a different match.
Target edits require a new query and preparation. Application does not change
binary bytes or local variables, copy comments, save the program, check out a
repository file, or check in a version. Native read-only and write guards still
apply; the operator must separately authorize any repository checkout/publication.

---

## 8. Reference

| REST | MCP tool | CLI |
| --- | --- | --- |
| `GET /bsim/status` | `bsim_status` | `ghydra bsim status` |
| `POST /bsim/ingest` | `bsim_ingest` | `ghydra bsim ingest` |
| `GET /bsim/query` | `bsim_query` | `ghydra bsim query` |
| `POST /bsim/apply-names` | `bsim_apply_names` | `ghydra bsim apply-names` |
| `GET /bsim/diff` | `bsim_diff_versions` | `ghydra bsim diff` |
| composed selected-match/reference inspection | `bsim_compare_match` | `ghydra bsim compare-match` |
| reference export + target preparation | `bsim_prepare_apply` | `ghydra bsim prepare-apply` |
| `POST /bsim/matches/{match_id}/apply` | `bsim_apply_match` | `ghydra bsim apply-match` |

The HTTP shapes and the error codes are in `GHIDRA_HTTP_API.md` § 13.

**BSim is not the digital twin.** A twin (`ghydra twin build`) is a snapshot of
the *facts already fetched* and answers offline; BSim is a similarity engine that
needs its database. They compose: use BSim to find the corpus match, use a twin to
answer repeated questions about a binary without a Ghidra running.

---

## 9. Reproducing the numbers

```bash
export GHYDRA_BSIM_DATABASE=/tmp/sig/where.bsim
mkdir -p /tmp/sig

ghydra headless start "C:\Windows\System32\where.exe" --port 8192
curl -s -X POST http://127.0.0.1:8192/bsim/ingest | python -m json.tool
curl -s "http://127.0.0.1:8192/bsim/query?address=140001010" | python -m json.tool
curl -s -X POST "http://127.0.0.1:8192/bsim/apply-names?address=140001010" \
  | python -m json.tool          # dry run
curl -s "http://127.0.0.1:8192/bsim/diff?other_executable=where.exe&max_functions=8" \
  | python -m json.tool
ghydra headless stop
```

### Live MCP regression

With a worker serving an analyzed program and an existing **query-only** remote
profile, run this from the source checkout with the project's Python dependencies:

```bash
GHYDRAMCP_TEST_PORT=8192 \
GHYDRAMCP_BSIM_PROFILE=corpus-reader \
GHYDRAMCP_BSIM_FUNCTION=main \
python -m unittest tests.test_bsim_remote.BSimMcpRemoteTests
```

This uses real MCP stdio, HTTP and native BSim: similarity search, naming dry run
and denied ingestion. It never enables remote writes. Without these settings the
live test skips; that skip is not a successful integration test.

To exercise selected-match comparison too, set `GHYDRAMCP_REFERENCE_PROFILE` and
`GHYDRAMCP_REFERENCE_PORT` for a separately provisioned read-only repository worker.
The query must return a resolvable positive match. Optionally set
`GHYDRAMCP_REFERENCE_MD5` to choose its indexed executable identity. The test compares
real decompiled code through MCP and checks that the target function and the
reference worker's active program remain unchanged. It never applies the preview.