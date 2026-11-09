# Recipes


<!-- toc -->

- [1. Triage a file you know nothing about](#1-triage-a-file-you-know-nothing-about)
- [2. Understand one function, with the evidence](#2-understand-one-function-with-the-evidence)
- [3. Ask "does input reach a dangerous call?"](#3-ask-does-input-reach-a-dangerous-call)
- [4. Gate a build in CI](#4-gate-a-build-in-ci)
- [5. Reproduce a session, and notice when it changes](#5-reproduce-a-session-and-notice-when-it-changes)
- [6. Put a goal against a budget](#6-put-a-goal-against-a-budget)
- [7. One question, several binaries](#7-one-question-several-binaries)
- [8. Build a corpus, then find a function by its shape](#8-build-a-corpus-then-find-a-function-by-its-shape)
- [9. Answer again with Ghidra closed](#9-answer-again-with-ghidra-closed)
- [10. Run without a window, and keep the report](#10-run-without-a-window-and-keep-the-report)
- [11. Attach a live debugger to a static address](#11-attach-a-live-debugger-to-a-static-address)
- [12. Run it where you do not trust the binary](#12-run-it-where-you-do-not-trust-the-binary)
- [The shape every recipe follows](#the-shape-every-recipe-follows)

<!-- /toc -->

Each recipe is a job, the commands that do it, and the trap that makes people
think it is broken. Every command was run against Ghidra 12.2.

---

## 1. Triage a file you know nothing about

```bash
ghydra inspect ./sample                # what it is, from the bytes (no Ghidra needed)
ghydra headless start ./sample
ghydra analysis overview                # size, counts, imports
ghydra analysis capabilities-summary    # ATT&CK-style leads from imports and strings
```

`inspect` identifies PE/ELF/Mach-O/DEX/APK/WASM/EVM/firmware/Electron/core
dumps from the **bytes**, never the extension, and says which tool fits the file.

**Trap:** `capabilities-summary` lists *leads*. Two imports that look alarming are
two imports until something shows them being used.

---

## 2. Understand one function, with the evidence

```bash
ghydra functions analyze --address 0x140001010        # function + decompilation + callers/callees + xrefs
ghydra analysis context-pack -q "what does this function do?" -a 0x140001010 --budget 2000
```

`analyze` composes five answers into one; `context-pack` ranks them and cuts to a
budget, listing what it left out.

**Trap:** if the function has no body (a thunk or an import), every signature-based
tool says `no body` — that is a fact about the function, not a failure.

---

## 3. Ask "does input reach a dangerous call?"

```bash
ghydra analysis taint --source recv --sink system --max-depth 8
```

Read the confidence: `direct` (same function, sink after source), `reachable`
(through the call graph), `weak` (name-based only). The answer carries the
disclaimer because branches are not modelled.

**Trap:** `weak` alone is not a finding, and a `direct` finding is a *path in the
graph*, not a proven input path.

---

## 4. Gate a build in CI

```bash
ghydra assert -f examples/asserts.json --format sarif -o analysis.sarif
ghydra assert -f examples/asserts.json --format junit -o analysis.xml
```

Exit codes: `0` pass, `1` a property was violated, `2` the check could not run.
Upload the SARIF to code scanning and keep the JUnit report as the artifact — see
[`examples/ci/analyze.yml`](examples/ci/analyze.yml) for the whole workflow.

**Trap:** `no_import` can only pass when the listing was read to its end. A
truncated listing yields `inconclusive`, never `pass` — raise `--page-limit` or
narrow the assertion.

---

## 5. Reproduce a session, and notice when it changes

```bash
ghydra runbook record '[
  {"endpoint": "program"},
  {"endpoint": "functions/decompile/0x140001010"}
]' -o session.ghydrarb.jsonl

ghydra runbook replay session.ghydrarb.jsonl --fail-on-change
```

Every step is called once and its answer digested (volatile keys dropped). Replay
tells `identical` from `changed` from `failed`, and `--fail-on-change` makes a
pipeline notice that a binary is no longer the one the session was recorded on.

---

## 6. Put a goal against a budget

```bash
ghydra mission start -g "does data from recv reach system?" --max-calls 40 -o dossier.md
ghydra mission show <id>
```

The dossier has sections for findings, verification, and **not determined**. A
mission that runs out of budget stops and says so; a finding whose evidence moved
is `unverified` and the command exits `1`.

---

## 7. One question, several binaries

```bash
ghydra fleet has-import CreateFileW --ports 8192,8193,8194
ghydra fleet xrefs-to strlen --ports 8192,8193
```

Rows are **binaries**, not ports: two instances serving one file merge into one row
and a disagreement between them is reported. An instance that did not answer is
listed as unreachable — "did not ask" is never reported as "does not have it".

---

## 8. Build a corpus, then find a function by its shape

```bash
export GHYDRA_BSIM_DATABASE=/var/tmp/sigs

ghydra headless start ./app-1.2 --port 8192
ghydra bsim ingest                                   # signatures into the local H2 file
ghydra headless stop

ghydra headless start ./app-1.2 --port 8192
ghydra bsim query --name main --min-similarity 0.9   # which stored function looks like this?
ghydra bsim apply-names --name main                  # dry run: what it would rename
ghydra bsim diff app-1.1.exe --max-functions 50      # two versions, paired by signature
```

Measured on `where.exe`: 94 functions ingested in 3.1 s; a self-query answered
similarity 1.0 in 0.2 s. See [GHYDRA_BSIM.md](GHYDRA_BSIM.md).

**Trap:** a match is a lead. `apply-names` is dry-run by default for exactly that
reason.

---

## 9. Answer again with Ghidra closed

```bash
ghydra twin build --name app-1.2         # snapshot: program, functions, imports, strings
ghydra headless stop

ghydra twin query app-1.2                 # works with no Ghidra running
ghydra twin query app-1.2 --kind functions --match str
ghydra twin diff app-1.1 app-1.2          # what changed, offline
```

Measured 359x–8337x faster than the live API for the facts it holds
(`scripts/bench_twin.py`).

**Trap:** a twin cannot decompile or see later changes, and a snapshot that is
shorter than the API's own count says `functions_complete: false` — a diff over it
would otherwise report phantom removals.

---

## 10. Run without a window, and keep the report

```bash
ghydra headless start ./sample --port 8192
ghydra report build --output report.md      # Ghidra + Kuna + debugger annotations
ghydra headless stop
```

The report combines the static analysis, the Kuna decompilation (if enabled) and
the x64dbg session (if attached), and marks every part it could not obtain.

**Trap:** a headless run has no cursor, so `/address` and `/function` answer
`503 HEADLESS_LIMITATION`. Every other endpoint behaves the same as in the
CodeBrowser.

---

## 11. Attach a live debugger to a static address

```bash
ghydra x64dbg status                       # is the plugin there, and what is loaded?
ghydra x64dbg target                       # image base ↔ module base
ghydra x64dbg breakpoint 0x140001234       # a Ghidra address, translated
ghydra x64dbg call ListModules
```

The address model is `runtime = static − image_base + module_base`, and the
translation happens for you.

**Trap:** a mutating tool is never retried after a lost answer — the request may
have reached the debugger. `X64DBG_UNCERTAIN` says exactly that.

---

## 12. Run it where you do not trust the binary

```bash
GHYDRA_READ_ONLY=1 ghydramcp               # server refuses every mutation
ghydra --dry-run functions rename --address 0x401000 --new-name suspicious
ghydra audit                               # what was changed, locally
```

Three layers for three fears: read-only (the server), dry-run (the client), and
the audit trail (the record).

---

## The shape every recipe follows

1. **know what you have** (`triage`, `overview`);
2. **ask the smallest question** that answers it (`functions analyze`,
   `context-pack`);
3. **check the confidence** and the completeness in the answer;
4. **record it** (`runbook`, `mission`, `assert`) so the next person — or the next
   build — can tell what changed.