# Internals: the drift, the REA gaps and the composed calls

Reference material split out of [AGENTS.md](../AGENTS.md) so that file fits the
instruction budget. Open this when a symptom points at it.

`AGENTS.md` holds the rules that apply to every change; this page holds the
things that are true of this machine and this Ghidra, and the history of two
comparisons.

---
## Known drift

Verified rough edges — check before trusting anything downstream:

- **Transaction failures return `409 TRANSACTION_FAILED`.** `TransactionHelper.TransactionException` has
  a handler in `GhydraServer`. It is deliberately **unchecked**: resources guard service calls with
  `catch (RuntimeException e) { throw e; }` then a broader `catch (Exception e) { throw new
  RuntimeException(...) }`, so a checked exception would be rewrapped and surface as 500. Keep it a
  `RuntimeException` or the 409 mapping breaks.
- **Committed `lib/*.jar` are Ghidra 12.0.1, and `pom.xml` defaults to `ghidra.version=12.0.1`** so a
  bare `mvn package` (no `GHIDRA_HOME`) builds and stamps honestly. Building against a real install needs
  both: `GHIDRA_HOME=/path/to/ghidra_12.1.2_PUBLIC mvn clean package -Dghidra.version=12.1.2`. GitHub
  Actions does exactly that per matrix leg. Refresh `lib/` and bump the pom default if you want the
  no-flag build to target a newer Ghidra.
- **A jar built against `lib/` runs against the installed Ghidra, and the two do not have the same
  signatures.** `DataTypeComponent.setFieldName(String)` returns `void` in 12.0.1 and
  `DataTypeComponent` in 12.2, and the return type is part of the JVM descriptor: a call site compiled
  against `lib/` asks for `setFieldName(Ljava/lang/String;)V` and the installed 12.2 only has
  `setFieldName(Ljava/lang/String;)Lghidra/program/model/data/DataTypeComponent;`. It fails at runtime
  with a `NoSuchMethodError`, and an `Error` is not an `Exception`: `TransactionHelper` catches
  `Exception`, so nothing is logged, the exception escapes Javalin, and the answer is a `500` with an
  **empty body**. The jar must be compiled against the Ghidra that will run it — the install's own
  jars first on the classpath, `lib/` last. The symptom to recognise: a `500` with no body and nothing
  in the log is a build that was compiled against the wrong series.

- **`ghydra functions set-variable` is the only variable-editing CLI command.** The duplicate
  `update-variable` was removed in 3.0.0.
- **Ghidra 12.2 (2026-10-22) needs JDK 25 and moved the data type removal API.** Two
  consequences, both handled:
  - `javac` cannot read a class file newer than itself, so building against 12.2 with
    JDK 21 fails with `bad class file` on every Ghidra class — for any source, not just
    the change that triggered it. The workflow derives the JDK from the distribution
    instead of hardcoding it: the class file major version is 44 plus the JDK number
    (65 = 21, 69 = 25), with a floor of 21 because the extension targets Java 21.
  - `remove(DataType, TaskMonitor)` is gone; 12.2 has `remove(DataType)` and
    `remove(List<DataType>, TaskMonitor)`. No overload exists in 11.x, 12.0-12.1 and
    12.2 at once, so `GhidraUtil.removeDataType` resolves the call by name.
- The pom's Ghidra dependency `<version>` tags are hardcoded to `12.1.2`; `-Dghidra.version` only
  rewrites the `ghidraVersion` property in `extension.properties`, not those tags. They're
  system-scoped, so this is cosmetic — the `systemPath` jars are what matter.
- **The rich tables used to break on a Windows pipe.** `TableFormatter` renders with rich's default
  `HEAVY_HEAD` box, whose frame characters are outside cp1252; piped on a Western Windows
  (`sys.stdout.encoding == 'cp1252'`) `click.echo` raised `UnicodeEncodeError`. Fixed: the CLI
  entrypoint now reconfigures stdout/stderr to UTF-8 with `errors="replace"` before any output
  (covered by `tests/test_errors.py`, which runs the CLI under `PYTHONIOENCODING=cp1252`). The Kuna
  tables keep `box=box.ASCII` as defense in depth.


## The four gaps closed against the REA

`REA_PARITY.md` compared this project with the REA (139 tools in `rea-agents` 6.0.0) and named four
gaps that were native and cheap. All four are closed, on the three surfaces at once, and
`tests/test_rea_parity.py` is what proves they agree:

| REA | REST API | Bridge tool | CLI |
| --- | --- | --- | --- |
| `batch_decompile` | `POST /functions/decompile-batch` | `functions_batch_decompile` | `ghydra functions decompile-batch --targets '["main"]'` |
| `find_xrefs_to_name` | `GET /xrefs/to-name/{name}` | `xrefs_find_by_name` | `ghydra xrefs find-by-name strlen` |
| `inspect_address_context` | `GET /inspect/address/{address}` | `inspect_address` | `ghydra inspect-address 0x140001008` |
| `trace_call_path` | `GET /analysis/call-path?from=&to=` | `analysis_trace_call_path` | `ghydra analysis trace-call-path --from main --to strcmp` |

- **A batch reports each target separately.** A target that resolves to nothing comes back as a failed
  entry with the reason, and the other targets are still decompiled: a triage pass wants to know which
  ones were wrong, not lose the nine that were right. The server caps a batch at 200 targets.
- **The list of targets is text.** `functions_batch_decompile` declares `targets` as a `str` (JSON text),
  because a client that hands over a nested list flattens it - every value arrives as a string. The
  schema asks for the form that survives the client, and the parser reads a JSON array, a bare name or
  a comma-separated list.
- **The deadline of a batch covers the batch.** The server runs the targets one after the other and
  each of them may take the whole timeout, so the transport deadline is the timeout times the number
  of targets the server accepts (200). The timeout of a batch travels in the body and not in the
  query, so a deadline derived from the query alone is one function long - and the bridge answers
  `REQUEST_TIMEOUT` while the server is still decompiling the targets that are left.
- **A name is a name.** `xrefs_find_by_name` resolves the name to the symbols that carry it (a bare name
  matches every namespace, a qualified one matches that namespace) and returns the references to them.
  A name that resolves to nothing is a 404 with `SYMBOL_NOT_FOUND`, not an empty list. The page is cut
  before the DTOs are built: each reference resolves the functions on both of its sides, so a hot
  symbol would make every page pay for the references it does not return.
- **The address context is one traversal.** `inspect_address` gathers the symbol, the containing
  function, the data, the instruction, both comments and the references on both sides inside a single
  `GhidraSwing.runRead`, so the answer is consistent and the agent pays one round trip.
- **The call path is the shortest one.** `analysis_trace_call_path` is a breadth-first walk over the
  call edges, bounded by the depth limit (16 at most) and by a cap on the functions it visits. When
  there is no path it says how many functions it explored and why it gave up - it never says "not
  found" without saying what it looked at. The path is rebuilt from the last hop back to the source,
  and every link of it is a node of the path: the function in the middle is not dropped, and the
  source is not put in twice. When the cap of visited functions cut the search short, the reason
  says so - a path beyond the cap was not looked for, and "there is none" is not the same answer.


## The composed calls

Four more that the REA has and this project did not, closed the same way: one tool, one command,
one formatter each. None of them needed a new endpoint - they compose what was already there.

| REA | Bridge tool | CLI | What it composes |
| --- | --- | --- | --- |
| `procedure_callers` | `analysis_callers` | `ghydra analysis callers ADDR` | `GET /analysis/callers/{address}` |
| `procedure_callees` | `analysis_callees` | `ghydra analysis callees ADDR` | `GET /analysis/callees/{address}` |
| `analyze_function` | `functions_analyze` | `ghydra functions analyze --address ADDR` | the function, its decompilation, its callers, its callees and its references |
| `binary_overview` | `programs_overview` | `ghydra analysis overview` | the program, its segments, its counts and its imports |

**The callers and the callees existed in the API and in neither of the other two surfaces.** The
endpoints were there since v3.0.0; the bridge and the CLI simply never exposed them, which is the
kind of gap that only a real comparison finds.

**A page that is not the whole list says so.** The callers and the callees take an `offset` and a
`limit`, and the text of the answer says how many there are in total when the page holds fewer - a
list of 100 that reads as "there are 100" when there are 136 is a lie an agent cannot see.

**A composed answer must not hide a failure.** `functions_analyze` and `programs_overview` gather
several answers into one, and a part that failed is reported as empty rather than as the whole
thing having failed. The one part that decides the success is the one the caller asked for: the
function, and the program. The CLI follows the same rule: a caller, a callee or a reference that
fails does not throw away the function that was found and the decompilation that came with it.
