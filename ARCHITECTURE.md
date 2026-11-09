# Architecture


<!-- toc -->

- [The three tiers](#the-three-tiers)
- [The single core, and the generator](#the-single-core-and-the-generator)
- [The Java side](#the-java-side)
- [Three surfaces, one answer](#three-surfaces-one-answer)
- [Where the data lives](#where-the-data-lives)
- [Testing as architecture](#testing-as-architecture)
- [The decisions worth knowing](#the-decisions-worth-knowing)

<!-- /toc -->

How the pieces fit, and why they are shaped this way. Read this before changing
something structural; [AGENTS.md](AGENTS.md) has the day-to-day rules.

---

## The three tiers

```
   MCP client                 CLI                    curl / CI
       │                       │                        │
       ▼                       ▼                        ▼
 bridge_mcp_hydra.py      ghydra (Click)          any HTTP client
   (one file, PEP 723)     (a package)                   │
       └───────────┬───────────┘                        │
                   ▼                                    ▼
              HTTP REST  ◄──────────────────────────────┘
                   │
                   ▼
        GhydraPlugin (Java 21, Javalin)
        resource → service → Ghidra DB
```

- **The REST API is the contract.** Every capability is a route first; the bridge
  and the CLI are clients of it.
- **The bridge is a single file** and must not import the `ghydra` package: it
  ships standalone (`uv run bridge_mcp_hydra.py`). That constraint is the reason
  the next section exists.
- **The CLI is a package** with a client, formatters and commands; it never imports
  the bridge either.

---

## The single core, and the generator

The bridge and the CLI need the same pure logic (canonical JSON, digests, the
capability rules, the cache key, the mission dossier…). The bridge cannot import
it, so before I1 that logic was written **twice** — and the two copies drifted
(the Codex review of the first release found four bugs, one per duplicate).

Now:

```
ghydra/core/*.py          ← the single definition (pure functions only)
      │  scripts/gen_core.py
      ▼
bridge_mcp_hydra.py
  # >>> generated from ghydra/core/digest.py (sha256) — edit the core, then run …
  def _core_digest(...) …
  # <<< end generated
```

Rules that make it safe:

- **only pure functions** go in the core: a generated copy of a pure function is
  identical on both sides. Anything with I/O stays in the callers;
- the named helpers (`_runbook_digest`, `_mission_parse_goal`, …) are **one-line
  delegations**, so a fix lands in one place;
- `gen_core.py --check` fails when a region is stale, and **both CI pipelines run
  it** before compiling;
- a name that the bridge lacks (an import the core uses) makes the generator
  **refuse** to write, naming the fix;
- the region goes **right after the imports**: inserting it lower puts the names
  after their users, which is a `NameError` at import.

What this does *not* do is shorten the bridge: the generated copy *is* the module's
body, so every migration adds a few lines. The claim is "one definition", and
`test_core.py` enforces it (byte-identical region, no definition outside it, a
public name may only be a delegating wrapper).

Eleven modules live there today: `digest`, `runbook`, `hints`, `cache`, `diff`,
`fleet`, `capabilities`, `contextpack`, `telemetry`, `taint`, `mission`.

---

## The Java side

```
resource/      routes only: parse the request, call a service, build the envelope
service/       business logic, transactions, EDT discipline
dto/           what goes on the wire (records/flat maps)
hateoas/       Response, links, pagination, the envelope itself
middleware/    read-only guard, audit trail
util/          TransactionHelper, GhidraSwing, PagedCollector, ProgramCache
```

Two rules carry most of the weight:

- **The EDT rule.** Ghidra's database is only safe to traverse under the Swing EDT,
  so compound reads and DTO construction go inside `GhidraSwing.runRead(...)` — the
  whole traversal, not just the iterator. Decompiler work must stay **outside** the
  EDT, or an open CodeBrowser freezes for the duration.
- **Transactions.** Every mutation goes through
  `TransactionHelper.executeInTransaction(program, name, supplier)`, which rejects
  a null or unchangeable program and rolls back on exception. Services own
  transactions; resources never touch DB mutators.

The headless path and the CodeBrowser path share **`GhydraServerFactory`**, so the
same resources are registered in both. A resource added to one and not the other
answers 404 in one instance and 200 in the other — which is the bug that factory
prevents.

---

## Three surfaces, one answer

A new capability means up to six edits (Java route + bridge tool + formatter + CLI
command + formatter output + docs). The project's guards exist because forgetting
one is silent:

| Guard | Catches |
| --- | --- |
| a `FORMATTERS` key per tool | a tool whose answer degrades to `"Done"` |
| `test_surface_parity.py` | a tool/command that is registered but absent from another surface |
| `scripts/check_docs.py` | a document whose counts disagree with the code |
| `gen_tools_doc.py --check` | a catalogue that drifted from the tools |
| a literal code in every `Response.error` | an unreviewable, client-branching code |

---

## Where the data lives

Everything is under `GHYDRA_STATE_DIR` (default `~/.ghydra`):

| Path | What |
| --- | --- |
| `cache/v1/<key>.json` | decompile cache (opt-in; keyed on program identity + request) |
| `missions/<id>.json` | mission checkpoints, and the dossiers next to them |
| `evidence/<name>.json` | the evidence ledger (IDs that are never reused) |
| `twins/<name>.json` | digital-twin snapshots |
| `kuna/<digest>/` | Kuna exports (reused, with a provenance sidecar) |
| `telemetry.jsonl` | tool-name/latency/error log (local only; 1 MB cap) |
| `audit.jsonl` | the mutating calls the server accepted |

The BSim database is **not** here: it is a path you configure
(`-Dghydra.bsim.database`), because it is a corpus you may want to share or keep
somewhere else.

---

## Testing as architecture

23 suites, split by what they need:

- **contract suites** (22) run with **no Ghidra**: they exercise the bridge, the
  CLI, the formatters, the protocols, the local integrations against fakes, the
  generated core, the twin, the docs guards. CI runs exactly these.
- **live suites** need an instance and **skip** themselves without one: HTTP, MCP,
  data, comments, ports, and the live half of the REA parity checks.

A green run against no Ghidra means nothing for the live suites — that is why the
runner prints which suites actually executed.

---

## The decisions worth knowing

| Decision | Reason |
| --- | --- |
| one file for the bridge | it must run through `uv run` with no install |
| a generated core rather than an import | the constraint above, with one definition |
| reflective BSim access | its API is internal and moved between 11.x and 12.x |
| dry run by default on `apply-names` | a signature match is a heuristic |
| read-only as *server* middleware | it protects every client, not just this one |
| a twin as a snapshot | some questions cost more to fetch than to keep |
| completeness in every composed answer | "not found" from an unfinished listing is a lie |