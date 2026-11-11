# Examples

Four examples, in the order you should read them. Two run with **nothing
installed but the CLI**; two need a Ghidra instance, because the thing they
demonstrate is a question to a live program.

| Example | Needs | What it shows |
| --- | --- | --- |
| [`twin/`](twin/) | nothing | a snapshot that answers queries with no Ghidra running |
| [`asserts.json`](asserts.json) + [`ci/`](ci/) | a Ghidra instance | the analysis as a CI gate: assertions, exit codes, SARIF |
| [`mission/`](mission/) | a Ghidra instance | a goal against a hard budget, with a dossier that re-reads its evidence |
| [`fleet/`](fleet/) | two Ghidra instances | one question across several binaries, merged by file |

---

## `twin/` — answer again with Ghidra closed

```bash
ghydra twin query examples/twin/example-snapshot.json
ghydra twin query examples/twin/example-snapshot.json --kind functions --match Parse
ghydra twin query examples/twin/example-snapshot.json --kind function --match ParseConfig
ghydra twin diff examples/twin/example-snapshot.json examples/twin/example-snapshot.json
```

```
Twin: example.dll (built 2026-11-09 04:53 UTC from http://localhost:8192)
  functions: 6, imports: 4, exports: 2, strings: 5
```

**The snapshot is synthetic**, and says so in its README: six functions, four
imports and five strings invented to look like a real program. It is here so the
example runs anywhere and prints the same thing every time — `test_examples.py`
asserts that it does. To make a real one: `ghydra twin build --name <name>`.

## `asserts.json` and `ci/` — the analysis as a gate

```bash
ghydra assert -f examples/asserts.json                       # text, exit 0/1/2
ghydra assert -f examples/asserts.json --format sarif -o report.sarif
ghydra assert -f examples/asserts.json --format junit -o report.xml
```

The eight assertions are the ones worth having by default: the entry point
exists, the injection pair is absent, the interesting strings are present. The
`ci/analyze.yml` workflow is a complete GitHub Actions job that analyses a
binary, runs the assertions, uploads the SARIF and fails the build.

**The eight kinds are the contract** — and only these exist:
`has_import`, `no_import`, `has_string`, `no_string`, `has_function`,
`no_function`, `has_xref_to`, `reaches`. `test_examples.py` fails if this file, or
`asserts.json`, ever names one that does not.

## `mission/` — a goal, a budget, a dossier

```bash
bash examples/mission/mission.sh              # starts a headless run, runs the mission, stops it
```

The script shows the whole shape: a goal in prose, a budget, and the dossier that
comes out — with a `not determined` section and a `verification` section that
re-reads every piece of evidence before keeping a conclusion.

## `fleet/` — one question, several binaries

```bash
bash examples/fleet/fleet.sh 'C:\Windows\System32\where.exe' 'C:\Windows\System32\whoami.exe'
```

Starts two headless instances on two ports, asks the same question of both, and
prints the merged table — one row per **file**, with an unreachable instance
reported as unreachable rather than as "does not have it".

---

## How the examples are kept true

`test_examples.py` (suite `--examples`, run by CI) does four things: it runs the
offline example and compares the output, it validates `asserts.json` against the
kinds the code has, it checks that every path this README names exists, and it
loads the snapshot through `ghydra/twin.py` and checks its version and md5. An
example that stops working fails the build.