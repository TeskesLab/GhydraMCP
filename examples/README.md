# Reverse engineering as a CI test

This directory is the smallest useful example of the thing that makes this
project different from a Ghidra wrapper: **an analysis that a pipeline can gate
on.**

Two files:

| File | What it is |
| --- | --- |
| [`asserts.json`](asserts.json) | eight assertions — the shape of the binary you expect |
| [`ci/analyze.yml`](ci/analyze.yml) | a GitHub Actions workflow that runs them and publishes SARIF |

Copy them into your own repository, change the `BINARY` and the assertions, and
your CI starts failing when a build stops looking like it should.

---

## Run it locally

The assertions are checked against a **running instance**. Start one headless on
the binary you care about (any binary — here, a small Windows tool):

```bash
ghydra headless start /path/to/binary --port 8192
ghydra assert -f examples/asserts.json
```

Text output, one line per assertion, with the evidence that decided it:

```
Assertions: 8 (7 passed, 1 failed, 0 inconclusive)
  [PASS] A1 has_function main
         scanned 0 of 0 entries; matched 'main'
  [FAIL] A2 no_import CreateRemoteThread
         scanned 412 of 412 entries; matched 'CreateRemoteThread'
  ...
```

Exit codes: `0` all passed, `1` at least one failed, `2` the file or the instance
could not be used — so a pipeline can tell "the binary is wrong" from "the check
did not run".

The other formats are for machines:

```bash
ghydra assert -f examples/asserts.json --format junit -o report.xml
ghydra assert -f examples/asserts.json --format sarif -o report.sarif
```

Finally:

```bash
ghydra headless stop
```

---

## Run it in CI

[`ci/analyze.yml`](ci/analyze.yml) is a template — copy it to
`.github/workflows/analyze.yml` **in your repository** (not this one: it expects
your binary). It:

1. installs the CLI (`pip install -e .` from a checkout, or `pip install ghydra`),
2. starts a headless run on the artifact you built,
3. runs the assertions with `--format sarif`,
4. uploads the SARIF to code scanning **and keeps the JUnit report as an artifact**,
5. stops the run even when the assertions fail (`if: always()`).

The interesting step is the fourth: a binary that loses a property it used to
have now shows up where a reviewer already looks — in the security tab — instead
of in a log nobody reads.

---

## The eight kinds of assertion

| Kind | Question | Reads |
| --- | --- | --- |
| `has_import` / `no_import` | does the binary import this symbol? | the import listing |
| `has_string` / `no_string` | does it contain this text? | the defined strings |
| `has_function` / `no_function` | is there a function by this name? | the function table |
| `has_xref_to` | does anything reference this name? | the references |
| `reaches` | does `from` reach `to` in the call graph? | the call path search |

A field worth knowing: **`message`**. It is printed on failure and put in the
`failure` element of the JUnit report, so the person reading the red build learns
*why* the assertion exists, not just that it broke.

---

## Two rules that make the result trustworthy

**A truncated listing is not proof.** `no_import` and `no_string` can only pass
when the listing was read to its end. If the page cap was hit, the verdict is
`inconclusive` — never `pass` — and the evidence says the listing was truncated.
Proving the *absence* of an import from half a list is a lie a CI gate cannot
afford.

**Inconclusive does not fail the build.** `1` means a property was violated; an
`inconclusive` verdict means the question could not be answered (raise the page
cap, or narrow the assertion). The exit code keeps them apart on purpose.

---

## Where to go next

- `ghydra analysis context-pack -q "what does this function do?" -a 0x401000` —
  one budgeted dossier instead of a dozen calls.
- `ghydra runbook record` / `replay --fail-on-change` — when the *whole session*
  should be reproducible, not just eight properties.
- `ghydra analysis diff --a-port 8192 --b-port 8193` — what changed between two
  builds, as a report.