# The headless GhydraMCP

The plugin serves the REST API from a window a human is looking at. A headless Ghidra run serves
the very same API with nobody watching: the binary is imported, analysed, and the API answers for
that analysis.

It is not a second implementation. The headless run starts the same server, registers the same
twenty-one resources and uses the same decompiler service. What is behind them is what differs:
one fixed program and one fixed project, instead of a ProgramManager, a tool and a UI.

```
ghydra headless start C:\bin\cmd.exe      # analyse and serve, on port 8192
ghydra headless status                    # what is running
ghydra headless stop                      # end it; the analysis is saved first
```

The run outlives the command that started it: the state lives under `~/.ghidra`, so another command
— or the MCP bridge, which discovers the instance on its own — finds it later.

---

## The commands

### `ghydra headless start <binary>`

| Option | What it is |
| --- | --- |
| `--port`, `-p` | the port to serve on (default: 8192) |
| `--project-dir` | where the Ghidra project lives (default: `~/ghidra_projects`) |
| `--project-name` | the name of the project (default: the name of the binary) |
| `--ghidra-home` | the Ghidra installation (default: `GHIDRA_HOME`) |
| `--java-home` | the JDK (default: `JAVA_HOME`) |
| `--timeout` | how long to wait for the API, in seconds (default: 900) |

The command waits for the API to answer before it returns, so a script can use it as a gate: the
next command talks to an instance that is up.

### `ghydra headless status`

What is on the port: whether the run is alive, whether the API answers, the program it serves, the
project, the log and the pid.

### `ghydra headless stop`

Ends the run. The program is saved first, so the project holds the analysis and the program can be
opened in Ghidra later.

---

## Where things live

**The installation.** `GHIDRA_HOME` points at it; without it the launcher looks in the places
Ghidra is usually installed — `%LOCALAPPDATA%\Programs\Ghidra`, `%ProgramFiles%\Ghidra`,
`~/scoop/apps/ghidra/current` on Windows, and `/opt/ghidra`, `/usr/local/ghidra`,
`~/ghidra` on Linux and macOS.

**The launcher.** `support/analyzeHeadless` on POSIX and `support/analyzeHeadless.bat` on Windows.
The JDK comes from `JAVA_HOME`; Ghidra 12 needs a JDK 21 or newer, and the machine's default is
often an older one, so `--java-home` is there for that.

**The project.** `ghidra_projects` in your home directory — Ghidra's own convention. Not
`~/.ghidra`: **Ghidra refuses a project path with an element that starts with a dot** ("Path
element starting with '.' is not permitted"), and `.ghidra` is exactly that. The launcher says so
when the path it is given is refused.

**The state.** `~/.ghidra/headless-<port>.json` remembers the run, and `~/.ghidra/headless-<port>.log`
holds its output. The log is where the reasons a run failed are.

---

## Import or process

A program that is already in the project is processed again; one that is not is imported. Importing
a program that is already there fails, and the run never reaches the script that starts the server —
so the launcher reads the index of the project to tell the two apart.

The index of a Ghidra project is plain text, one line per file:

```
VERSION=1
/
 00000000:cmd.exe:a9fe536bff6c5085139269700
NEXT-ID:1
```

---

## The report

```
ghydra report build C:\bin\cmd.exe --output out
```

Three files come out:

| File | What it is |
| --- | --- |
| `cmd-report.md` | the report a human reads |
| `cmd-report.json` | the same, machine-readable |
| `cmd-x64dbg.json` | the annotations, for the debugger |

**Ghidra and Kuna, side by side.** The report holds the program, its functions, its imports, its
exports, its strings and its segments as Ghidra sees them, next to the C that Kuna recovered. The
two are matched **by address**: both tools read the same binary at the same addresses, so the
functions Ghidra found and the functions Kuna found can be put next to each other without any
conversion.

**The functions worth a look.** Three groups, in this order: the ones Kuna found big (the size is
in its index, and it is the only one of the two tools that measures it), the ones Ghidra found with
a name of their own, and the entry point. The top of the report is the decompilation of the first
of them.

**The options.** `--no-kuna` leaves Kuna out, `--no-headless` uses the instance that is already
there instead of starting one, `--keep` leaves the headless run running when the report is done,
and `--max-functions`, `--max-strings`, `--max-decompile` and `--max-annotations` say how much of
each to read.

---

## The annotations

The report writes the annotations with the image base, so the debugger can translate them into the
addresses of the live process:

```
ghydra x64dbg annotate cmd-x64dbg.json --bookmarks
```

Every function becomes a comment — the signature, the size, what Kuna called it — and, with
`--bookmarks`, a bookmark. `--mode Label` sets labels instead of comments.

The translation is `runtime = static − image_base + module_base`, the same model the `ghydra
x64dbg breakpoint` and `ghydra x64dbg go-to` commands use. The module is the one that matches the
binary of the report; the plugin's own module list is what says where the loader put it.

![The debugger at an annotated function](../images/x64dbg-annotated-function.png)

**A note on the bookmarks.** The x64dbg plugin's own `SetBookmark` runs `bookmarkadd`, which is
not an x64dbg command: the log answers "Unknown command" and the plugin still reports "Bookmark
set.". x64dbg's commands are `bookmarkset` (alias `bookmark`), `bookmarkdel` and `bookmarklist`,
so the annotation flow runs `bookmarkset` directly.

![The debugger log, with the bookmarks set](../images/x64dbg-bookmarks.png)

**A note on the retries.** A local TCP connection is reset every now and then on some machines
(measured: 7% of the connections). Setting a comment and setting a bookmark are the same operation
twice over, so the annotation flow repeats what failed. Against the real debugger, three of sixty
annotations failed on the first pass and all sixty were set on the second.

---

## The dynamic half

```
ghydra x64dbg report --output out
```

What the debugger is doing right now: the state, the registers, the modules with their bases, the
breakpoints, the disassembly at the instruction pointer, the call stack and the memory map — as a
Markdown document and a JSON file. It needs no Ghidra.

---

## What the headless run does not have

The endpoints that need the GUI's cursor — `/address` and `/function` — answer `503` with
`HEADLESS_LIMITATION` in a headless run. There is no cursor without a window, and pretending
otherwise would be worse than saying so. The test suites that exercise them need the CodeBrowser;
every other endpoint behaves the same in both.

The debugger is a different matter: the x64dbg plugin drives it without a human, but the debugger
is a program with a window, and there is no build of it that runs without one. The headless part
of this document is about Ghidra.

---

## The script that starts the server

The headless run is Ghidra's own `analyzeHeadless`, with one extra script:

```
analyzeHeadless <project-dir> <project-name> \
    -import <binary> -postScript GhidraHeadlessServer port=8192
```

The script lives in the extension (`ghidra_scripts/`), so the server it starts is the same server
the CodeBrowser plugin starts. It stays in the run for as long as the server is wanted: the
headless analyzer waits for the script to return, and it only returns when the launcher asks for
it.

**A script has to import the class it extends.** `GhidraScript` is not in the default package, and
Ghidra only adds the import to the template it writes for a *new* script. An existing one has to
carry it:

```java
import ghidra.app.script.GhidraScript;

public class GhidraHeadlessServer extends GhidraScript {
```

Without it the script does not compile, and the error says nothing about the import: "cannot find
symbol" on the class, and on everything the class brings with it (`currentProgram`, `state`,
`getScriptArgs()`). It was measured: the same failure happens for a script inside a Ghidra module
and for one outside every module, so it is not about where the script lives.

**Stopping the run.** The launcher leaves a stop file behind (`~/.ghidra/headless-<port>.stop`) and
the script returns when it sees it. The headless analyzer then saves the program and closes the
project, and the project is left unlocked. Killing the process instead leaves the lock file
behind, and the next run refuses to open the project.

---

## Building without Maven

The extension needs a JDK and the Ghidra jars; the Maven build shades Javalin, Jetty, SLF4J and
Kotlin into `Ghydra.jar`. On a machine that has a JDK and no Maven:

```
python scripts/make_uberjar.py target/classes target/lib lib/Ghydra.jar
```

The script merges the compiled classes and the runtime dependencies into one jar, the way the
Maven build does. The script that starts the server is not in the jar: it is a file of the
extension, in `ghidra_scripts/`.
