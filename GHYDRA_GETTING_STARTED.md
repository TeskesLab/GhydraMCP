# Getting started


<!-- toc -->

- [1. Is there an instance to talk to?](#1-is-there-an-instance-to-talk-to)
- [2. What is loaded?](#2-what-is-loaded)
- [3. Read one function](#3-read-one-function)
- [4. Ask a question instead of asking for an endpoint](#4-ask-a-question-instead-of-asking-for-an-endpoint)
- [5. Turn a guess into an evidenced lead](#5-turn-a-guess-into-an-evidenced-lead)
- [6. Put the analysis in a pipeline](#6-put-the-analysis-in-a-pipeline)
- [7. Answer a question you cannot finish](#7-answer-a-question-you-cannot-finish)
- [Where to go next](#where-to-go-next)

<!-- /toc -->

From an installed extension to a first answer. Every command and output below was
run; the values are from a real `where.exe` analysis on Ghidra 12.2.

If you have not installed anything yet, do that first — [README.md](README.md) has
the three ways (extension, CLI, MCP bridge).

---

## 1. Is there an instance to talk to?

```bash
ghydra instances list
```

```
http://localhost:8192    (CodeBrowser)
```

An instance is one Ghidra process serving the API on a port. **The CLI finds it by
scanning** — you rarely name a port, and when several are open the `--port` flag
picks one:

```bash
ghydra --port 8193 functions list        # talk to the second instance
ghydra instances use --port 8193         # or make it the default for this shell
```

Nothing listening? Start one. The cheapest is a headless run, which needs no
window:

```bash
ghydra headless start /bin/ls            # or C:\Windows\System32\where.exe
# ... work ...
ghydra headless stop
```

`ghydra doctor` tells you why a start would fail before you try it: the Ghidra
installation, the JDK it needs, the extension and the port.

---

## 2. What is loaded?

```bash
ghydra analysis overview
```

```
Program: where.exe
  path: C:\Windows\System32\where.exe
  language: x86:LE:64:default
  image base: 0x140000000
  functions: 198, symbols: 1229, memory blocks: 9
  imports: 99 (KERNEL32.DLL::CreateFileW, ...)
```

This is the **first thing to run on an unknown binary**: it answers "what is this,
how big, what does it pull in" in one call, and every number is the server's own.

---

## 3. Read one function

```bash
ghydra functions list --limit 5
ghydra functions decompile --name main
ghydra functions get-cfg --address 0x140001010
```

Errors here are the useful kind: a name that does not exist is a 404 with
`FUNCTION_NOT_FOUND`, not an empty answer.

---

## 4. Ask a question instead of asking for an endpoint

This is the step that changes how the tool feels. Instead of picking endpoints, ask:

```bash
ghydra analysis context-pack -q "what does this function do?" -a 0x140001010
```

```
Question: what does this function do?
Template: what_it_does
Sections: 3 (function, decompilation, callers)
Budget: 4000 tokens, used 812
Omitted: callees (dropped: over the token budget)
Citations: 0x140001010, 0x1400010f0, 0x140001140
```

Three things to notice, because they are the project's rules:

- **it is budgeted** — `--budget 1200` narrows it, and the answer says what was
  dropped and why;
- **it lists what it left out** — a dossier that hides an omission is a lie of
  proportion;
- **every claim carries an address** you can open with `ghydra inspect-address`.

---

## 5. Turn a guess into an evidenced lead

```bash
ghydra analysis taint --source recv --sink system
```

```
Hypotheses: 2 (1 direct, 1 reachable)
[direct]    FUN_140003a00: recv at 0x140003a40 -> system at 0x140003a90
[reachable] FUN_140002100 -> ... -> FUN_140003a00 (depth 3)
Note: these are hypotheses from pcode and the call graph, not proof of
exploitability. Branches are not modelled.
```

The disclaimer is part of the answer, not a footnote. A `direct` finding means the
sink call appears **after** the source call **in the same function**; it does not
mean the path is reachable with attacker-controlled data.

---

## 6. Put the analysis in a pipeline

The same questions, as a gate:

```bash
cat > asserts.json <<'JSON'
[{"kind": "has_function", "name": "main"},
 {"kind": "no_import", "name": "CreateRemoteThread"},
 {"kind": "has_string", "name": "/api/v1/"}]
JSON

ghydra assert -f asserts.json --format sarif -o report.sarif ; echo "exit=$?"
```

Exit codes are part of the contract: `0` every assertion held, `1` at least one
failed, `2` the check could not run (bad file, no instance) — a pipeline can tell
"the binary is wrong" from "the check did not run".

`examples/` has a full CI workflow to copy.

---

## 7. Answer a question you cannot finish

A mission takes a goal in prose, a hard budget, and produces a dossier that
**re-reads its own evidence** before keeping a conclusion:

```bash
ghydra mission start -g "does data from recv reach system?" --max-calls 40
```

```
Mission: m-3f2a
Findings: 4 (2 verified, 1 unknown)
  F1 capabilities: CreateRemoteThread present (high)
  F2 taint: direct recv -> system at 0x140003a00 (medium) [verified]
  F3 unknown: no function named "main" (the goal named it, the binary has not)
Not determined: F3
Verification: 5 evidence items re-read; every conclusion still holds
```

If evidence moved between the finding and the check, the finding is `unverified`
and the command exits `1` — the dossier never upgrades a hypothesis to a fact.

---

## Where to go next

| You want | Read |
| --- | --- |
| the mental model (surfaces, envelope, budgets, groups) | [GHYDRA_CONCEPTS.md](GHYDRA_CONCEPTS.md) |
| a recipe for a specific job | [GHYDRA_RECIPES.md](GHYDRA_RECIPES.md) |
| the exact tool or command | [GHYDRA_TOOLS.md](GHYDRA_TOOLS.md) · [GHYDRA_CLI.md](GHYDRA_CLI.md) |
| an answer that looks wrong | [GHYDRA_TROUBLESHOOTING.md](GHYDRA_TROUBLESHOOTING.md) |
| signatures across a corpus | [GHYDRA_BSIM.md](GHYDRA_BSIM.md) |