# BSim — signature similarity across a corpus (R1)


<!-- toc -->

- [1. What it is (and what it is not)](#1-what-it-is-and-what-it-is-not)
- [2. Setup](#2-setup)
- [3. Build a corpus: `ingest`](#3-build-a-corpus-ingest)
- [4. Ask it: `query`](#4-ask-it-query)
- [5. Act on it: `apply-names`](#5-act-on-it-apply-names)
- [6. Compare two versions: `diff`](#6-compare-two-versions-diff)
- [7. The traps (all measured, all now encoded)](#7-the-traps-all-measured-all-now-encoded)
- [8. Reference](#8-reference)
- [9. Reproducing the numbers](#9-reproducing-the-numbers)

<!-- /toc -->

Ghidra ships a signature system, **BSim**, that turns a function into a vector and
lets you ask "which functions in this corpus look like this one?". That is the one
question a decompiler cannot answer well, and it is what this integration exposes
— on all three surfaces.

Everything here was measured against **Ghidra 12.2** on a local H2 database; the
numbers are in the sections they belong to, and the commands that produced them
are at the end.

---

## 1. What it is (and what it is not)

| It is | It is not |
| --- | --- |
| a **local H2 file** you build yourself | a server you connect to |
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
# point the extension at a database; it does not need to exist yet
export GHYDRA_BSIM_DATABASE=/var/tmp/signatures          # Linux/macOS
# or: set GHYDRA_BSIM_DATABASE=C:\tmp\signatures         (Windows)
# or: -Dghidra.bsim.database=<path> on the Ghidra JVM

ghydra bsim status        # engine? database? what is missing?
```

`ghydra bsim status` is the first command to run and the one to trust:

```json
{"available": true, "database": "/var/tmp/signatures",
 "database_exists": false, "ready": true, "can_ingest": true,
 "reason": "the configured signature database does not exist: /var/tmp/signatures"}
```

Two flags to know:

- **`ready`** — a *query* is possible (the file is on disk);
- **`can_ingest`** — an *ingest* is possible (the file is created if absent).

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

Measured: 0.2 s by name, 0.8 s by address, on the database above.

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

---

## 8. Reference

| REST | MCP tool | CLI |
| --- | --- | --- |
| `GET /bsim/status` | `bsim_status` | `ghydra bsim status` |
| `POST /bsim/ingest` | `bsim_ingest` | `ghydra bsim ingest` |
| `GET /bsim/query` | `bsim_query` | `ghydra bsim query` |
| `POST /bsim/apply-names` | `bsim_apply_names` | `ghydra bsim apply-names` |
| `GET /bsim/diff` | `bsim_diff_versions` | `ghydra bsim diff` |

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