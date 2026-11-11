# Documentation

Where to read what. This project has three surfaces (REST, MCP, CLI) and two
local integrations (Kuna, x64dbg), so the documentation is split by **what you
are trying to do**, not by where the code lives.

> **New here?** [Installation and building](GHYDRA_INSTALLATION.md) gets the
> extension and Python clients ready; [Getting started](GHYDRA_GETTING_STARTED.md)
> takes you from an installed extension to a first dossier.

---

## The map

| If you want to… | Read | It is |
| --- | --- | --- |
| install and get a first answer | [GHYDRA_INSTALLATION.md](GHYDRA_INSTALLATION.md) → [GHYDRA_GETTING_STARTED.md](GHYDRA_GETTING_STARTED.md) | installation, builds, onboarding |
| connect an MCP client | [GHYDRA_MCP_CLIENTS.md](GHYDRA_MCP_CLIENTS.md) | Claude Desktop/Code, Cline, 5ire, resources, output |
| understand how the pieces fit | [GHYDRA_CONCEPTS.md](GHYDRA_CONCEPTS.md) | the mental model |
| do a specific job | [GHYDRA_RECIPES.md](GHYDRA_RECIPES.md) | task recipes and an illustrative assistant session |
| translate an answer that looks wrong | [GHYDRA_TROUBLESHOOTING.md](GHYDRA_TROUBLESHOOTING.md) | error codes → cause → fix |
| parse an answer, or wire it into CI | [GHYDRA_OUTPUT.md](GHYDRA_OUTPUT.md) | formats, the envelope, exit codes |
| look up a tool | [GHYDRA_TOOLS.md](GHYDRA_TOOLS.md) | the generated catalogue (134 tools) |
| look up an error code | [GHYDRA_ERRORS.md](GHYDRA_ERRORS.md) | every code, its status and the line that raises it |
| unify this with the x64dbg side | [../contract/README.md](../contract/README.md) | the contract: vocabulary, address model, error envelope, conformance |
| recall a command | [GHYDRA_CHEATSHEET.md](GHYDRA_CHEATSHEET.md) | **generated** one-liner for every command |
| use the CLI | [GHYDRA_CLI.md](GHYDRA_CLI.md) | every command |
| call the REST API | [GHIDRA_HTTP_API.md](GHIDRA_HTTP_API.md) | every route, `API_VERSION` 3000 |
| work with signatures | [GHYDRA_BSIM.md](GHYDRA_BSIM.md) | BSim: corpus, queries, comparisons, traps |
| run without a window | [GHYDRA_HEADLESS.md](GHYDRA_HEADLESS.md) | headless runs and the report |
| use Kuna | [GHYDRA_KUNA.md](GHYDRA_KUNA.md) | the decompiler integration, and its costs |
| use x64dbg | [GHYDRA_X64DBG.md](GHYDRA_X64DBG.md) | the debugger integration, the address model |
| contribute code | [AGENTS.md](../AGENTS.md) · [CONTRIBUTING.md](../CONTRIBUTING.md) · [ARCHITECTURE.md](ARCHITECTURE.md) | conventions, workflow, internals |
| look up a verified rough edge | [GHYDRA_INTERNALS.md](GHYDRA_INTERNALS.md) | known drift, the REA gaps, the composed calls |
| run or add tests | [TESTING.md](TESTING.md) | the 23 suites and what each proves |
| cut a release | [RELEASING.md](RELEASING.md) | the one-tag procedure |

---

## Reading paths

**An analyst who wants answers.** [README](../README.md) →
[INSTALLATION](GHYDRA_INSTALLATION.md) → [GETTING STARTED](GHYDRA_GETTING_STARTED.md)
→ [RECIPES](GHYDRA_RECIPES.md). MCP users can branch to
[CLIENT SETUP](GHYDRA_MCP_CLIENTS.md). The catalogue and references are lookup
tables, not reading.

**Someone wiring this into a pipeline.** [CONCEPTS](GHYDRA_CONCEPTS.md) (the
envelope, pagination, read-only mode, exit codes) → [RECIPES](GHYDRA_RECIPES.md)
(the CI gate) → [GHYDRA_TOOLS](GHYDRA_TOOLS.md) for the exact tool names.

**A contributor.** [ARCHITECTURE](ARCHITECTURE.md) (the three tiers and the
single core) → [AGENTS](../AGENTS.md) (the rules: EDT, transactions, the generated
blocks) → [TESTING](TESTING.md) (what a change must keep green).

**Someone debugging.** [TROUBLESHOOTING](GHYDRA_TROUBLESHOOTING.md) first: most
"it does not work" cases are a version mismatch, an instance that is not serving,
or a feature that is off by design.

---

## How this documentation is kept honest

- **Counts are checked, not remembered.** `scripts/check_docs.py` reads the code
  (tools, formatters, namespaces, REST routes) and fails when a document
  disagrees. Both CI pipelines run it.
- **The catalogue is generated.** [GHYDRA_TOOLS.md](GHYDRA_TOOLS.md) comes from
  `scripts/gen_tools_doc.py`, and `--check` fails when it drifts.
- **Measured numbers carry the command that produced them.** When a guide says
  "94 functions in 3.1 s", it also says how to reproduce it — because a number
  without a command is a rumour.
- **Limits are stated next to the feature.** Every answer that could be
  over-read (a similarity match, a source-to-sink hypothesis, a snapshot) says
  what it is not, and the guides repeat it.

---

## History and proposals

These are working documents, kept because the reasoning is worth more than the
conclusion. They are **not** reference material: read the status line before you
act on one.

| Document | Status | What it argues |
| --- | --- | --- |
| [KUNA-MCP-ANALYSIS.md](KUNA-MCP-ANALYSIS.md) | **implemented** | whether the Kuna parameters belong in MCP, and as RAG |
| [UNIFICATION-PLAN.md](UNIFICATION-PLAN.md) | **proposal** | unifying this project with the x64dbg MCP server |
| [plans/2026-04-23-central-plugin-refactor.md](plans/2026-04-23-central-plugin-refactor.md) | **a design note** | one HTTP server on 8192 instead of a port per CodeBrowser |
