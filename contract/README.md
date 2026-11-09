# The contract

GhydraMCP and [x64dbg-mcp-server](https://github.com/danalec/x64dbg-mcp-server)
cannot share code: one is a Java plugin inside Ghidra, the other a Zig DLL inside a
native Windows debugger. They share no runtime, no build system and no ABI. What
they can share is the **contract with the agent**, and that is what this directory
holds — the specification, and the machine-readable half of it generated from this
repository.

Why unify at all is argued in [`docs/UNIFICATION-PLAN.md`](../docs/UNIFICATION-PLAN.md);
what follows is the contract itself, rule by rule, with what this side has done.

| Rule | What it says | GhydraMCP | x64dbg |
| --- | --- | --- | --- |
| **1. Vocabulary** | `namespace_verb`, snake_case, one rule for both | **conforms** — 134 tools, 36 namespaces, generated in [`tools.json`](tools.json) | **does not** — 80 flat PascalCase tools |
| **2. Address model** | every address comes in both forms, through a [`TargetDescriptor`](target-descriptor.schema.json) | **implemented** — `ghydra/target.py`, validated by the `--contract` suite | needs to return `module_base` + `module_path` (it does, as text) |
| **3. Error envelope** | a stable machine-readable code next to the human text | **conforms** — 112 codes, generated in [`error-codes.json`](error-codes.json) | **does not** — free-form English, and "is this an error" is decided by sniffing the text |
| **4. Conformance** | one suite both sides run | this repository's `--contract` suite | not yet |

---

## 1. Vocabulary — [`vocabulary.json`](vocabulary.json)

Every tool name is `namespace_verb` in snake_case:

```
functions_decompile      analysis_taint       x64dbg_set_breakpoint
memory_read              mission_start        kuna_decompile
```

The prefix is load-bearing. `memory_read` reads the **static image** Ghidra has
open; a live-process read must not be reachable by that name, or an agent will
report a value that was never in the running program. The rules, the mapping from
the x64dbg side and the three collisions that matter are in
[`vocabulary.json`](vocabulary.json).

One parameter name is reserved by the protocol: **`arguments`**. A client that
re-encodes the tool-parameter container loses it, and the tool then runs with its
defaults instead of failing. This repository has a guard for it (it happened once).

## 2. Address model — [`target-descriptor.schema.json`](target-descriptor.schema.json)

Ghidra works on the image as it sits in the file, at its image base. x64dbg works
on the module wherever the loader put it. The conversion is:

```
runtime = static − image_base + module_base
```

Mechanical — and dangerous, because the same arithmetic applied to two different
builds of a binary produces plausible garbage. So a `TargetDescriptor` carries the
identity of the file each side is looking at, and says whether correlation is
allowed:

```json
{
  "contract_version": 1,
  "binary": "C:\\bin\\sample.exe",
  "arch": "x86:LE:64:default",
  "image_base": "0x140000000",
  "module_base": "0x7ff7a1230000",
  "module_path": "C:\\bin\\sample.exe",
  "delta": "0x7ff661230000",
  "identity": { "same_binary": true, "match": "path", "reason": null },
  "correlatable": true
}
```

`identity.match` has four values, and `correlatable` is true **only** for `path`:
`name-only` means the same file name in another directory — a copy, a symlink or a
rebuild — and the addresses of one do not describe the other. A consumer that
ignores `correlatable` has reintroduced the risk the field exists to remove.

Implementation on this side: [`ghydra/target.py`](../ghydra/target.py) —
`TargetDescriptor.from_program_and_module`, `to_runtime`, `to_static`,
`same_binary`, `correlatable`, `problems`.

## 3. Error envelope — [`error-codes.json`](error-codes.json)

Every failure carries the same envelope, and a **stable code** inside it:

```json
{"success": false,
 "error": {"code": "BSIM_NO_DATABASE", "message": "a comparison needs an ingested database: …"},
 "id": "…", "instance": "http://localhost:8192", "timestamp": 1794199852898}
```

A client branches on `code`, never on the prose. The codes are
`^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$`, unique, and each one is documented with the side
that produces it, the HTTP status it travels with and the `file:line` where it
originates — the same data as [`docs/GHYDRA_ERRORS.md`](../docs/GHYDRA_ERRORS.md).

The x64dbg side has no codes: its tools answer MCP `isError: true` with English
text, and the server decides an answer is an error by looking for the prefix
`{"error":`. Adding codes there is a mechanical change to `handleToolsCall` plus a
table, and it is what lets an agent retry a `NO_ACTIVE_SESSION` and give up on a
`NOT_FOUND`.

## 4. Conformance — the `--contract` suite

`tests/test_contract.py` (run by `python run_tests.py --contract`, and by CI) proves
this side of the contract:

- the generated files are current (`scripts/gen_contract.py --check`);
- every one of the 134 names matches the vocabulary rule, and none declares a
  reserved parameter;
- every tool has a formatter — a tool whose answer degrades to `"Done"` is a tool
  the contract does not describe;
- every error code is shaped, unique, and carries a side and an origin;
- a `TargetDescriptor` validates against the JSON schema, the conversion round-trips,
  and a descriptor built from **different** paths refuses to be correlatable;
- the vocabulary and the errors documents agree with the generated counts.

The x64dbg side of the conformance suite does not exist yet. The plan puts it in a
third repository (`re-mcp-suite/conformance/`), and this directory is written so it
can be lifted there unchanged: the rules are data, not code.

---

## How the files relate

| File | Hand-written or generated | What it is |
| --- | --- | --- |
| `README.md` | hand | the specification (this page) |
| `vocabulary.json` | hand | the naming rule, both sides' status, the mapping and the collisions |
| `target-descriptor.schema.json` | hand | the address/identity shape |
| `tools.json` | **generated** | every tool, its namespace, group, parameters, formatter |
| `error-codes.json` | **generated** | every code, its side, status, message, origin |

```bash
python scripts/gen_contract.py           # rewrite the two generated files
python scripts/gen_contract.py --check   # fail when either is stale
python run_tests.py --contract           # the conformance suite
```