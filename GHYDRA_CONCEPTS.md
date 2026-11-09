# Concepts

The mental model. Once these ten ideas are clear, the 134 tools stop being a list
and become a surface you can navigate.

---

## 1. Three surfaces, one API

```
MCP client ──► bridge_mcp_hydra.py ─┐
CLI (ghydra) ──────────────────────┼──► HTTP REST ──► Ghidra plugin
                                   │
                   (both consume the same envelopes)
```

Every capability exists on the REST API first. The bridge and the CLI are clients
of it — which is why a route you can `curl` is also a tool and a command. The
**local integrations** (Kuna, x64dbg, the twin) are the exception: they never
speak HTTP to Ghidra, and they are marked `local` in the catalogue.

The bridge is a **single file** and does not import the `ghydra` package (it ships
standalone through `uv run`). The pure logic it shares with the CLI is therefore
**generated into it** from `ghydra/core/` — see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## 2. An instance is a port

One Ghidra process serves one program on one port. `ghydra instances list` scans;
`--port` selects. A *fleet* is several instances, and a fleet query merges answers
**by file identity** (`programId`), not by port — two ports serving the same binary
are one row, and their disagreement is reported instead of averaged.

---

## 3. The envelope

Every answer has the same shape, and the shape is a promise:

```json
{
  "success": true,
  "id": "8f66b1cf-…",
  "instance": "http://localhost:8192",
  "timestamp": 1794199852898,
  "result": { … },
  "_links": { "self": {"href": "/functions/0x401000"}, … }
}
```

- **`success`** decides everything: a failure carries `error: {code, message}` and
  a non-2xx status, never an empty `result` that looks like "nothing found";
- **`_links`** say what to ask next, with real values — the bridge turns them into
  a `Next:` line, and the REST client follows them instead of hardcoding URLs;
- **`id`** is the request id: quote it when an answer looks wrong.

---

## 4. Absence, incompleteness and inconclusiveness are different

This is the rule that shapes the whole project:

| Situation | The answer says |
| --- | --- |
| the listing was read to its end, no match | `matched: 0` — a real absence |
| the listing was truncated at a cap | `complete: false`, and an assertion verdict of **`inconclusive`**, never `pass` |
| the query failed | `success: false` with the code — not "nothing found" |
| a similarity match | the number, not a verdict |
| an evidence item moved | `unverified`, and the command exits `1` |

A tool that answers "not there" from a page it did not finish is the single most
expensive bug a reverse-engineering assistant can have. Every composed call
carries the completeness of its parts.

---

## 5. Evidence has identity

The runbook records every answer with a **digest of the stable part** (the volatile
keys — `id`, `timestamp`, `instance`, `_links` — are dropped first). Replaying a
runbook compares digests: `identical`, `changed`, or `failed`.

The same idea in three other places:

- the **mission** re-reads its evidence and marks a finding `unverified` when the
  digest moved;
- the **decompile cache** keys on the program identity plus the request, and is
  off by default because the server exposes no modification counter;
- the **twin** records the executable md5, so a snapshot knows which binary it is.

---

## 6. Budgets are hard stops

`analysis_context_pack` has a token budget; `mission` has calls, tokens and
wall-clock. When a budget is spent, the answer stops — it does not quietly do less
and call it done. The mission records *why* it stopped and leaves the rest as
`not determined`.

---

## 7. Tools are grouped, and the group is a profile

134 tools in one list degrade a model's tool selection, so the bridge groups them:
`core` (always), `functions`, `data`, `types`, `scripts`, `headless`, `kuna`,
`x64dbg`, `runbook`, `fleet`.

```bash
GHYDRA_TOOL_GROUPS=core,functions ghydramcp     # a profile fixed at startup
ghydra tools groups                             # what is loaded (CLI/MCP)
```

`tools_load_group` / `tools_unload_group` change it at runtime, and
`tools_search` searches **the whole catalogue** (including unloaded tools) and
names the group to load.

---

## 8. Local integrations are local, and say so

| Integration | What it talks to | Needs Ghidra? |
| --- | --- | --- |
| Kuna | the `kuna` CLI, as a subprocess | no |
| x64dbg | the debugger's own MCP plugin | no |
| BSim | a local H2 database it builds | yes (it makes signatures with the decompiler) |
| twin | a JSON snapshot | no |

Kuna is **opt-in** (`GHYDRA_KUNA=1`) because it lets the bridge run a program on
the host. The twin is a snapshot: it answers facts already fetched and cannot
decompile, read memory, or see later changes.

---

## 9. Read-only, dry run, audit

Three different protections, for three different fears:

- **`GHYDRA_READ_ONLY=1`** (a server-side middleware) refuses every mutating
  request, wherever it comes from;
- **`--dry-run`** (CLI root flag) describes the mutation without sending it;
- **`bsim apply-names`** is dry-run **by default**: the caller has to ask for the
  rename.

The audit trail records the mutating calls the server accepted (locally, in the
state directory). Telemetry is a different file and a different promise: tool
name, timestamp, success, code, duration, answer size — never arguments, results,
paths or binary content. `GHYDRA_TELEMETRY=0` turns it off.

---

## 10. What this is not

- **not a vulnerability finder** — it produces hypotheses with evidence and a
  confidence, and says so;
- **not an oracle** — every heuristic is labelled (similarity, significance,
  `weak`/`reachable`/`direct`);
- **not a replacement for the analyst** — it is a way to spend fewer round trips
  and to keep the evidence of what was checked.

---

### Where these ideas show up

| Idea | In practice |
| --- | --- |
| the envelope | every response; `_links` drive the `Next:` line |
| completeness | `complete`/`inconclusive`, `analysis_diff` reporting a floor |
| evidence identity | `runbook replay`, `mission` verification, `cache` keys |
| budgets | `--budget`, `--max-calls`, `mission` stopping with a reason |
| profiles | `GHYDRA_TOOL_GROUPS`, `tools_groups` |
| local | `kuna_*`, `x64dbg_*`, `ghydra twin`, `ghydra bsim` |
| protections | read-only middleware, `--dry-run`, dry-run defaults |
| honesty | the disclaimers in `taint`, `bsim`, and the twin's provenance |