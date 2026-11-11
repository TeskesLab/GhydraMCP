# The twin example

A snapshot of a program that answers questions with **no Ghidra running**.

```bash
ghydra twin query examples/twin/example-snapshot.json
ghydra twin query examples/twin/example-snapshot.json --kind functions --match Parse
ghydra twin query examples/twin/example-snapshot.json --kind function --match ParseConfig
ghydra twin query examples/twin/example-snapshot.json --kind imports --match file
ghydra twin diff examples/twin/example-snapshot.json examples/twin/example-snapshot.json
```

```
Twin: example.dll (built 2026-11-09 04:53 UTC from http://localhost:8192)
  functions: 6, imports: 4, exports: 2, strings: 5
```

## The snapshot is synthetic, on purpose

`example-snapshot.json` is **invented**: six functions, four imports, two exports
and five strings, chosen to look like a real program so that the example is
readable and prints the same thing every time. It is not the analysis of anything.

That has two consequences worth saying plainly:

- the addresses (`0x180001000`, …), the md5 (`0123456789abcdef…`) and the source
  (`http://localhost:8192`) are placeholders — a real snapshot records the md5 of
  the binary it came from, and a reader can tell a stale twin by it;
- `test_examples.py` runs the queries above and compares the output, which is what
  makes this an example rather than a decoration.

## Making a real one

```bash
ghydra headless start /bin/ls --port 8192     # or a CodeBrowser on 8192
ghydra twin build --name ls-1                 # -> ~/.ghydra/twins/ls-1.json
ghydra headless stop

ghydra twin query ls-1                        # no Ghidra needed any more
ghydra twin diff ls-1 ls-2                    # what changed between two builds
```

Measured with `scripts/bench_twin.py` on real binaries: a name search is **715x**
and **359x** faster from a snapshot than from the API, and a function by address
**7993x** and **8337x**.

## What it cannot do

A twin cannot decompile, cannot read memory, and cannot see a change made after it
was taken. A snapshot that was capped, or that holds fewer functions than the API
counted, is marked `functions_complete: false` — because a diff over it would
otherwise report functions as removed that were simply never captured.