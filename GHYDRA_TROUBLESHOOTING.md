# Troubleshooting


<!-- toc -->

- ["No instances found" / the CLI sees nothing](#no-instances-found-the-cli-sees-nothing)
- [The extension does not load](#the-extension-does-not-load)
- [Version mismatch](#version-mismatch)
- ["It says ready but the query fails"](#it-says-ready-but-the-query-fails)
- [An assertion fails when the binary looks fine](#an-assertion-fails-when-the-binary-looks-fine)
- [The mission exits 1 but "found" things](#the-mission-exits-1-but-found-things)
- [A command mutates the program when it should not](#a-command-mutates-the-program-when-it-should-not)
- [The twin does not know a function](#the-twin-does-not-know-a-function)
- [Kuna does not run](#kuna-does-not-run)
- [x64dbg is "not there" when it is running](#x64dbg-is-not-there-when-it-is-running)
- [A route answers 403](#a-route-answers-403)
- [A route answers 409](#a-route-answers-409)
- [A route answers 503](#a-route-answers-503)
- [The same call is slower than the numbers in the docs](#the-same-call-is-slower-than-the-numbers-in-the-docs)
- [Where to look next](#where-to-look-next)

<!-- /toc -->

Organised by **symptom**, because that is what you have when you go looking. Every
entry says what the message means and what to do — a check that fails is never a
dead end.

Start here when something is off:

```bash
ghydra doctor        # installation, JDK, extension, port, project dir, API, Kuna, x64dbg
```

---

## "No instances found" / the CLI sees nothing

| Cause | Check | Fix |
| --- | --- | --- |
| no Ghidra is running | `ghydra instances list` | start a CodeBrowser or `ghydra headless start <binary>` |
| the instance is above port 8201 | `ghydra instances discover` | the quick scan only covers 8192–8201; `ghydra instances register --port <n>` |
| wrong host | `ghydra --host <ip> instances list` | `GHYDRA_HOST`, `~/.ghydra/config.json` |
| a firewall is dropping the probe | the quick scan uses a 0.2 s probe | `ghydra instances register --port <n> --host <ip>` once, and it is remembered |

The bridge reads a **different** environment than the CLI: `GHIDRA_HYDRA_HOST` >
`GHIDRA_HOST`, and it **never** reads `GHYDRA_PORT`. If the CLI works and MCP does
not, that asymmetry is usually why.

---

## The extension does not load

| Symptom | Cause | Fix |
| --- | --- | --- |
| Ghidra says the extension needs another version | `extension.properties` `ghidraVersion` ≠ install | rebuild with `-Dghidra.version=<exact install version>` |
| `NoClassDefFoundError: io/javalin/http/Handler` | a jar with only the compiled classes | use the shaded `Ghydra.jar` (or `scripts/make_uberjar.py`) |
| class file version errors while building | JDK older than the Ghidra needs (12.2 wants 25) | build with the JDK Ghidra ships for |
| `NoSuchMethodError` at runtime, `500` with an **empty body** | the jar was compiled against different Ghidra jars than the ones running it | compile against the install's own jars (install first on the classpath, `lib/` last) |

That last one is worth recognising: **a 500 with no body and nothing in the log is
a build against the wrong Ghidra series.** It is an `Error`, not an `Exception`, so
the transaction helper does not catch it and Javalin answers with nothing.

---

## Version mismatch

The bridge compares `API_VERSION` **once**, when an instance is registered, and
refuses with both versions and the remedy. If you see it:

- the plugin is older than the bridge (or the other way round);
- `scripts/version.py --check` proves the repository agrees with itself;
- a mismatch is a real incompatibility, not a warning — the routes differ.

Optional features do **not** move `API_VERSION`: they are discovered from
`/capabilities`' `features` map, so a missing feature shows as
`features.<name>: false`, never as a version error.

---

## "It says ready but the query fails"

BSim answers three different states, and confusing them wastes time:

| Answer | Meaning |
| --- | --- |
| `available: false` | this Ghidra build has no BSim engine |
| `database: null` | no database configured (`-Dghydra.bsim.database` / `GHYDRA_BSIM_DATABASE`) |
| `database_exists: false` | nothing ingested yet (an H2 database is `<path>.mv.db`) |
| `ready: true` | a query is possible |
| `can_ingest: true` | an ingest is possible (the file is created if absent) |

An ingest that finds the program already there answers **`already_present: true`
with 0 inserted** — that is the goal being satisfied, not a failure.

---

## An assertion fails when the binary looks fine

Check the **verdict**, not just the exit code:

- `fail` — a property was violated, and the evidence says which;
- `inconclusive` — the question could not be answered (a truncated listing, an
  instance that failed). This does **not** fail the build; narrow the assertion or
  raise the page cap;
- exit `2` — the check itself could not run: bad file, unknown kind, no instance.

`ASSERTION_UNKNOWN_KIND` means the `kind` is not one of the eight (see
`examples/README.md`). `ASSERTION_BAD_SPEC` means the JSON is not a list of
assertions.

---

## The mission exits 1 but "found" things

`1` means a conclusion could not be kept: its evidence moved when the mission
re-read it. Look for `unverified` in the dossier — the finding is still there, with
the reason. That is the verification working, not failing.

`MISSION_BUDGET` means a budget was spent (calls, tokens, or wall clock) and the
dossier says which. Raise `--max-calls`/`--max-tokens`, or accept the partial
answer: it is honest about what it did not determine.

---

## A command mutates the program when it should not

- `bsim apply-names` is dry-run **by default**; only `--apply` (CLI) or
  `dry_run=false` renames. An invalid value such as `?dry_run=yes` is a `400` and
  changes nothing — it used to be read as "false", and that is fixed.
- `--dry-run` on the CLI root describes the mutation without sending it.
- `GHYDRA_READ_ONLY=1` makes the *server* refuse (403), which protects every
  client, not just this one.

If a rename already happened, it is inside a Ghidra transaction: undo it in
Ghidra's undo history.

---

## The twin does not know a function

A snapshot is not the program:

- the function may not have existed when it was built (`built_at` is in the file);
- the snapshot may be **capped** — the answer then says the function may exist;
- a snapshot shorter than the API's own count is marked `functions_complete:
  false`, and a diff over it must not be read as "these functions were removed".

Rebuild it (`ghydra twin build --name <name>`) if the binary changed.

---

## Kuna does not run

| Code | Meaning |
| --- | --- |
| `KUNA_DISABLED` | the integration is off: `GHYDRA_KUNA=1` or `"kuna": {"enabled": true}` |
| `KUNA_MISSING` | the `kuna` binary is not on `PATH` |
| `KUNA_TIMEOUT` | the analysis took longer than `GHYDRA_KUNA_TIMEOUT` |
| `KUNA_NO_FILE`, `KUNA_NO_DIR`, `KUNA_NO_INDEX` | the path or the export does not hold what was asked |
| `KUNA_NO_FUNCTION`, `KUNA_BAD_ARTIFACT` | the export exists but not that function/artifact |
| `KUNA_TOO_LARGE` | the output exceeded the cap (ask for a narrower question) |

**The config file wins over the environment**, including an explicit
`"enabled": false`. A config written by `ghydra config init` has `"enabled": null`,
which leaves the decision to the environment on purpose.

---

## x64dbg is "not there" when it is running

| Code | Meaning |
| --- | --- |
| `X64DBG_DISABLED` | no token: set `"x64dbg": {"path": "<install>"}` or `{"token": …}` |
| `X64DBG_MISSING` | nothing answered on the ports that were scanned |
| `X64DBG_UNCERTAIN` | the request was delivered and the answer lost; a mutating call is **not** repeated |
| `X64DBG_UNAUTHORIZED` | the token was refused |

The plugin binds 9094 (64-bit debuggee) and 9095 (32-bit); the released build does
not walk ports, so a busy port means no server. This machine also resets about one
loopback connection in fourteen — a single `X64DBG_MISSING` on a loaded machine is
worth one retry, not an investigation.

---

## A route answers 403

- `ORIGIN_NOT_ALLOWED` — a state-changing request must carry the Origin header the
  server allows. The bridge adds it from the payload's `headers`; a hand-written
  `curl -X POST` needs it too.
- `SCRIPTS_DISABLED` — `POST /scripts/run` needs `-Dghidra.dev.allowScripts=true`.
- `READ_ONLY` — the server is in read-only mode.

---

## A route answers 409

`TRANSACTION_FAILED` means Ghidra refused the edit: the program is read-only, the
transaction was cancelled, or the program is locked (a headless run is inside a
transaction of its own). A `409` is never a bug in the request — the same request
against a writable program succeeds.

---

## A route answers 503

`HEADLESS_LIMITATION` — `/address` and `/function` read the CodeBrowser cursor,
and a headless run has none. Every other endpoint behaves the same.

---

## The same call is slower than the numbers in the docs

The docs quote **medians** measured on one machine, with the command that produced
them. The usual causes of a difference:

- the decompiler is cold (the first decompile of a function is the expensive one);
- a large program: listings are paged on the server, but a *composed* answer
  gathers several pages;
- a mission or a BSim diff does one query per function by design — bound it.

If a single endpoint is slow, `telemetry_summary` (MCP) or `ghydra telemetry` shows
per-tool latency from the local log, which is a better starting point than a guess.

---

## Where to look next

- [TESTING.md](TESTING.md) — which suite proves which contract;
- [GHYDRA_CONCEPTS.md](GHYDRA_CONCEPTS.md) — the envelope, completeness, budgets;
- [AGENTS.md](AGENTS.md) — the conventions, including the known drift that is not
  a bug (Ghidra 12.2's JDK, the `lib/` jars, the loading of the extension).