# Output formats and exit codes


<!-- toc -->

- [The four shapes](#the-four-shapes)
- [The envelope (JSON)](#the-envelope-json)
- [The CLI's two modes](#the-clis-two-modes)
- [The MCP bridge](#the-mcp-bridge)
- [The assertion report: JUnit and SARIF](#the-assertion-report-junit-and-sarif)
- [Exit codes](#exit-codes)
- [Sizes, and why the answers are not pretty-printed](#sizes-and-why-the-answers-are-not-pretty-printed)
- [Where a number comes from](#where-a-number-comes-from)

<!-- /toc -->

The same answer reaches you in different shapes depending on where you asked from.
This page is the contract for those shapes — what each format is for, and what the
process exit code means.

---

## The four shapes

| Shape | Where | For |
| --- | --- | --- |
| **text** | CLI (default), MCP bridge | a human reading a terminal, or an agent reading a tool result |
| **JSON** | CLI `--json`, MCP with `GHYDRA_MCP_OUTPUT=json` | a program: `jq`, a script, a test |
| **table** | CLI (rich tables) | many rows of the same shape |
| **report** | `ghydra assert --format junit\|sarif` | a pipeline, and the code-scanning tab |

One rule holds across all of them: **the text output is a rendering of the same
envelope** the JSON carries. A number that appears in the table is a field of the
JSON; a text answer never invents a fact the envelope does not have.

---

## The envelope (JSON)

```json
{
  "success": true,
  "id": "8f66b1cf-…",
  "instance": "http://localhost:8192",
  "timestamp": 1794199852898,
  "result": { "…": "the answer" },
  "meta": { "total": 198, "offset": 0, "limit": 100 },
  "_links": { "self": {"href": "/functions"}, "next": {"href": "…&offset=100"} }
}
```

- **`success: false`** always carries `error: {code, message}` and a non-2xx
  status. A failure never arrives as an empty `result`.
- **`meta`** appears on paginated answers: `total` is the count, and a page that
  is not the whole listing says so.
- **`_links`** carry real values; the CLI and the bridge use them instead of
  building URLs from strings.

### `jq` recipes

```bash
ghydra --json functions list --limit 5 | jq -r '.result[].name'
ghydra --json analysis overview       | jq '.result.statistics'
ghydra --json bsim query --address 0x140001010 | jq '.result.matches[0].similarity'
```

---

## The CLI's two modes

```bash
ghydra functions list --limit 5          # a table (rich), for a person
ghydra --json functions list --limit 5   # the envelope, for a program
```

`--json` may appear **anywhere** in the command line: the root command lifts it out
of the arguments before parsing, so `ghydra functions list --json` and
`ghydra --json functions list` are the same thing. Paging is applied by the CLI
for tables and left to the caller under `--json` (the envelope carries `meta`).

The CLI reconfigures its output to UTF-8 with `errors="replace"` at startup, so a
Rich table survives a `cp1252` Windows pipe instead of raising
`UnicodeEncodeError`.

---

## The MCP bridge

The bridge answers in **text**: that is the contract agents are written against.
Two things shape it:

- **every answer ends with a `Next:` line** built from the envelope's `_links` —
  the tool call that follows (`functions_decompile(address="0x…")`, the next page,
  a related resource). A link that does not map to a registered tool is left out
  rather than guessed.
- **`GHYDRA_MCP_OUTPUT=json`** returns the raw envelope as one JSON document
  instead of the formatted text. It exists for a machine that parses the answer
  (the MCP test suite drives the bridge this way); the default stays text.

A tool with no `FORMATTERS` entry degrades to `"Done"` — which is why the suite
asserts that every one of the 134 tools has a formatter.

---

## The assertion report: JUnit and SARIF

`ghydra assert` is the one place with a machine format that is not the envelope:

```bash
ghydra assert -f asserts.json --format text              # a line per assertion
ghydra assert -f asserts.json --format junit -o report.xml
ghydra assert -f asserts.json --format sarif -o report.sarif
```

- **`junit`** is XML a CI already understands: one `<testcase>` per assertion, with
  the `message` as the failure text;
- **`sarif`** is 2.1.0, one result per **failure** and one rule per kind used — so
  the violations land in code scanning, where a reviewer looks;
- both are also what `examples/ci/analyze.yml` uploads.

Inconclusive verdicts (`inconclusive`) are reported in the report but do **not**
fail the build: they mean the question could not be answered (a truncated listing,
an unreachable instance), which is different from a violated property.

---

## Exit codes

**`ghydra assert`** — the CI gate:

| Code | Meaning |
| --- | --- |
| `0` | every assertion held |
| `1` | at least one assertion failed |
| `2` | the check could not run: bad file, unknown kind, no instance |

**Everything else** — the CLI:

| Code | Meaning |
| --- | --- |
| `0` | the command did what it says |
| `1` | it did not: the API refused, the instance is gone, the file is bad |
| `2` | the command line itself is wrong (missing argument, both `--address` and `--name` absent) |

`ghydra mission start` exits `1` when a finding it kept could not be verified —
the dossier is still produced, with `unverified` next to the finding.

**The test runner** exits `0` only when every selected suite passed; a suite that
failed is named in the summary, and a suite that **skipped** is not a pass.

---

## Sizes, and why the answers are not pretty-printed

The server does not indent its JSON: measured, indentation made a 100-item page
38% bigger (33 954 against 24 553 bytes) and the client parses it either way. A
human who wants it indented can pipe it:

```bash
ghydra --json functions list | jq .
```

Lists are **paged on the server** (`util/PagedCollector`), so a page costs what the
page costs — not what the whole program costs. The one large answer that is
composed instead of paged is a context pack, and it is bounded by its token
budget, which is the point.

---

## Where a number comes from

Every answer distinguishes:

| Field | Meaning |
| --- | --- |
| `result` | the answer itself |
| `meta.total` | how many there are, not how many were returned |
| `complete` | whether the listing was read to its end (`false` = a floor, not a fact) |
| `truncated` | what was capped, on a twin or a composed answer |
| `omitted` | what a budgeted answer left out, with the reason |

If a script needs "does it have X", read `matched` **and** `complete`: an
assertion over an incomplete listing is `inconclusive`, and the same rule applies
to anything you build on top.