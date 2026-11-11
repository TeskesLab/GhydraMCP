[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release](https://img.shields.io/github/v/release/TeskesLab/GhydraMCP)](https://github.com/TeskesLab/GhydraMCP/releases)
[![API Version](https://img.shields.io/badge/API-v3000-orange)](https://github.com/TeskesLab/GhydraMCP/blob/main/docs/GHIDRA_HTTP_API.md)
[![GitHub stars](https://img.shields.io/github/stars/TeskesLab/GhydraMCP)](https://github.com/TeskesLab/GhydraMCP/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/TeskesLab/GhydraMCP)](https://github.com/TeskesLab/GhydraMCP/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/TeskesLab/GhydraMCP)](https://github.com/TeskesLab/GhydraMCP/graphs/contributors)
[![Build Status](https://github.com/TeskesLab/GhydraMCP/actions/workflows/build.yml/badge.svg)](https://github.com/TeskesLab/GhydraMCP/actions/workflows/build.yml)

# GhydraMCP

**Ghidra static analysis, x64dbg live debugging, and a second opinion from the
Kuna decompiler — through a CLI or MCP.**

![GhydraMCP logo](images/logo/ghydramcp-logo.png)

## Overview

The Ghidra extension exposes a HATEOAS REST API. The `ghydra` CLI and standalone
MCP bridge use it to inspect functions, decompile code, follow references, and
edit analysis. Multiple CodeBrowser instances can serve different binaries;
headless runs expose the same API without a window.

Optional local integrations connect the
[x64dbg MCP server](https://github.com/duty1g/x64dbg-mcp-server) and
[Kuna](https://github.com/Noelo-Lab/kuna). The bridge exposes
**134 tools in 36 namespaces**, grouped into workflow profiles; see the
[generated catalogue](docs/GHYDRA_TOOLS.md), not a second list here.

**Prefer the CLI** for terminal, scripting, and shell-capable assistants. The
MCP bridge is being deprecated as the recommended integration path, but remains
available for MCP clients and resources.

Analysis leads are not vulnerability proofs, similarity is not identification,
and offline snapshots cannot see later changes. See
[Concepts](docs/GHYDRA_CONCEPTS.md) for budgets, evidence, and limits.

## Installation

### Prerequisites

- Ghidra **11.x or 12.x** and a plugin zip matching its **exact version**.
- Python **3.11+** and **uv** (recommended) or pip for the CLI/bridge.
- Building the plugin additionally requires Maven and **Java 21+**, using the
  JDK required by your Ghidra release.

### Ghidra

1. Download the matching extension zip from
   [Releases](https://github.com/TeskesLab/GhydraMCP/releases).
2. In Ghidra: `File` → `Install Extensions` → `+` → select the zip → `OK`.
3. Restart, open a program in CodeBrowser, then choose
   `File` → `Configure` → `Developer` → tick **Ghidra**.

Installing alone does not enable the plugin. The first CodeBrowser serves port
8192, the next 8193. See [detailed installation](docs/GHYDRA_INSTALLATION.md) for
version matching, updates, virtualenvs, Linux/NixOS, and timeout configuration.

### CLI tool

```bash
git clone https://github.com/TeskesLab/GhydraMCP.git
cd GhydraMCP
uv tool install .
```

For an editable pip/uv environment, follow
[the Python installation guide](docs/GHYDRA_INSTALLATION.md#cli-tool-and-python-dependencies).

## Example session

With an analyzed program open and the plugin enabled:

```bash
ghydra doctor
ghydra instances list
ghydra analysis overview
ghydra functions decompile --name main
ghydra --json functions list --limit 5
```

Use a name present in your binary; `--json` goes **before** the subcommand.
[Getting started](docs/GHYDRA_GETTING_STARTED.md) walks through a first dossier;
[Recipes](docs/GHYDRA_RECIPES.md) covers comparison, evidence, CI, and an
[illustrative assistant session](docs/GHYDRA_RECIPES.md#13-an-illustrative-assistant-session).

## MCP clients

### Client setup

For a stdio MCP client with uv available, use an absolute path to the bridge:

```json
{
  "mcpServers": {
    "ghydra": {
      "command": "uv",
      "args": ["run", "--script", "/ABSOLUTE_PATH_TO/GhydraMCP/bridge_mcp_hydra.py"],
      "env": {"GHIDRA_HYDRA_HOST": "localhost"}
    }
  }
}
```

[Client setup](docs/GHYDRA_MCP_CLIENTS.md) covers Claude Desktop, Claude Code,
Cline, 5ire, Python interpreters, profiles, generated configurations, and
addressable MCP resources. Tool output defaults to text; use
`GHYDRA_MCP_OUTPUT=json` for a raw JSON envelope.

## Documentation

**[Documentation map](docs/DOCUMENTATION.md)** — all guides and reading paths.

| Read | For |
| --- | --- |
| [Getting started](docs/GHYDRA_GETTING_STARTED.md) · [Recipes](docs/GHYDRA_RECIPES.md) | First answers and task workflows |
| [CLI reference](docs/GHYDRA_CLI.md) · [Cheat sheet](docs/GHYDRA_CHEATSHEET.md) | Commands and options |
| [Concepts](docs/GHYDRA_CONCEPTS.md) · [Output formats](docs/GHYDRA_OUTPUT.md) | Evidence, budgets, envelopes, exit codes |
| [Headless](docs/GHYDRA_HEADLESS.md) · [BSim](docs/GHYDRA_BSIM.md) | Runs, reports, and signature comparisons |
| [Kuna](docs/GHYDRA_KUNA.md) · [x64dbg](docs/GHYDRA_X64DBG.md) | Optional decompiler and debugger integrations |
| [Troubleshooting](docs/GHYDRA_TROUBLESHOOTING.md) · [Error codes](docs/GHYDRA_ERRORS.md) | Failures and remedies |

### API reference

The [HTTP API reference](docs/GHIDRA_HTTP_API.md) documents API **3000**,
including JSON communication, HATEOAS links, pagination, and errors.
The [tool catalogue](docs/GHYDRA_TOOLS.md) also includes the local integrations,
which do not add Ghidra REST endpoints.

### Building from source

See [Installation and building](docs/GHYDRA_INSTALLATION.md#building-from-source)
for Maven setup and plugin-only/complete package builds;
[Contributing](CONTRIBUTING.md) and [Architecture](docs/ARCHITECTURE.md) cover development.

### Testing

[Testing](docs/TESTING.md) describes the suites and their prerequisites.
A skipped Ghidra-dependent suite is not evidence that the integration works.

### What's new

See [CHANGELOG.md](CHANGELOG.md) for release history and API 3000 migration
notes. [REA parity](docs/REA_PARITY.md) and
[Internals](docs/GHYDRA_INTERNALS.md) document the capability comparison and
composed analysis calls.

## Related work

GhydraMCP started as a fork of
[Laurie Wired's GhidraMCP](https://github.com/LaurieWired/GhidraMCP/).
The [x64dbg MCP server](https://github.com/duty1g/x64dbg-mcp-server) and
[Kuna](https://github.com/Noelo-Lab/kuna) are independent projects driven by the
optional integrations, not reimplementations.
[REA](https://github.com/morluto/rea) covers additional formats and headless
investigations; GhydraMCP focuses on Ghidra sessions, a live debugger, and a second
decompiler. None is a drop-in replacement for the others.
