# Installation and building

This guide covers the detailed installation and build instructions formerly in
[README.md](../README.md). After installation, follow
[Getting started](GHYDRA_GETTING_STARTED.md) for a first analysis, or
[MCP client setup](GHYDRA_MCP_CLIENTS.md) to connect an assistant.

## Prerequisites

- **Ghidra 11.x or 12.x**, with an extension built for your exact Ghidra version.
- **Python 3.11 or later** for the CLI and MCP bridge.
- **uv** (recommended) or pip for Python installation.
- To build the plugin: **Java 21 or later**, Maven, and the jars from your Ghidra
  installation. Use the JDK required by that Ghidra release.

## Ghidra extension

1. Download the matching plugin zip from the
   [TeskesLab releases](https://github.com/TeskesLab/GhydraMCP/releases).
   Each release ships per-Ghidra-version artifacts, such as
   `Ghydra-v<release>-...-ghidra12.2.zip` and
   `...-ghidra11.4.3.zip`. A `Ghydra-Complete-...` variant also carries the bridge
   script. The `ghidra<version>` suffix must match your installation **exactly**:
   Ghidra refuses to load an extension with a different declared `ghidraVersion`.
2. In Ghidra, choose `File` → `Install Extensions` → `+`, select the zip, and
   confirm with `OK`.
3. Restart Ghidra and open a program in CodeBrowser.
4. Choose `File` → `Configure` → `Developer`, tick **Ghidra**, and confirm.

Installing makes the plugin discoverable; it does **not** enable it. Without the
last step, `GhydraPlugin` is never constructed, no HTTP port binds, and neither
client can reach the program. The first CodeBrowser binds port 8192, the next
8193, and so on, in the 8192–8447 range.

For a later update, you can replace `lib/Ghydra.jar` in the installed extension
and restart Ghidra instead of reinstalling the full package. Keep the build
matched to the installed Ghidra version.

For failures, consult [Troubleshooting](GHYDRA_TROUBLESHOOTING.md). For a run
without CodeBrowser, see [Headless GhydraMCP](GHYDRA_HEADLESS.md).

## CLI tool and Python dependencies

Clone the repository first:

```bash
git clone https://github.com/TeskesLab/GhydraMCP.git
cd GhydraMCP
```

Install the CLI into its own environment:

```bash
uv tool install .
```

For editable development, create an environment first:

```bash
uv venv
uv pip install -e .
```

Alternatively, with Python and pip on Linux/macOS:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

On Windows, activate `.venv\Scripts\activate` instead. A GUI MCP client needs
an absolute interpreter path rather than an activated shell environment; see
[MCP client setup](GHYDRA_MCP_CLIENTS.md#using-python-directly).

For a repository-local environment managed by uv, `uv sync` is also available.
If you use asdf, run `asdf reshim` after installation. The full CLI reference is
[GHYDRA_CLI.md](GHYDRA_CLI.md).

### Installing on Linux and NixOS

The `uv tool install .` and virtualenv approaches above also work on Linux.
On NixOS, point uv at the interpreter provided by the shell rather than letting
it download one:

```bash
nix-shell -p python3 -p uv
```

Inside that shell:

```bash
uv tool install --python python3 .
```

For Kuna outside your default profile, use `kuna.path` in
`~/.ghydra/config.json` or put it on `PATH`; see
[the Kuna integration](GHYDRA_KUNA.md).

## Configuration and timeouts

CLI connection settings resolve in this order: CLI flags →
`GHYDRA_HOST`/`GHYDRA_PORT` → `~/.ghydra/config.json` → defaults
(`localhost:8192`). The bridge uses `GHIDRA_HYDRA_HOST` for its host; see
[MCP client setup](GHYDRA_MCP_CLIENTS.md).

Timeout defaults accommodate large binaries:

- CLI/bridge HTTP timeout: `900s` (`GHYDRA_TIMEOUT`).
- Decompilation timeout: `1200s` (`GHYDRA_DECOMP_TIMEOUT`).
- Incomplete decompilation responses include `retry_recommended` and
  `suggested_timeout_seconds` guidance.

These Ghidra timeouts are not the debugger's timeout rules; see
[x64dbg limits](GHYDRA_X64DBG.md#limits-and-gotchas).

## Building from source

The Maven build needs Ghidra's module jars. Set `GHIDRA_HOME` to your install
(recommended), or place the jars in `lib/`. Stamp the extension with the exact
version of the Ghidra installation you are building against:

```bash
GHIDRA_HOME=/path/to/ghidra_12.1.2_PUBLIC mvn clean package -Dghidra.version=12.1.2
```

The build supports Ghidra 11.x and 12.x. CI builds a matrix over the latest
supported versions in each series and attaches per-version zips to releases.

### Build everything (default)

```bash
mvn clean package
```

This creates the plugin-only `target/Ghydra-[version].zip` and the complete
`target/Ghydra-Complete-[version].zip`, which includes the bridge script.

### Build Ghidra plugin only

```bash
mvn clean package -P plugin-only
```

### Build complete package only

```bash
mvn clean package -P complete-only
```

The extension contains `lib/Ghydra.jar`, `extension.properties`, and
`Module.manifest`, which Ghidra needs to recognize it. Install the zip through
Ghidra's extension dialog as above.

For a machine without Maven, see
[Building without Maven](GHYDRA_HEADLESS.md#building-without-maven). Contributor
workflow and release instructions remain in
[CONTRIBUTING.md](../CONTRIBUTING.md) and [RELEASING.md](RELEASING.md).
