# Contributing to GhydraMCP

Thank you for your interest in contributing to GhydraMCP! This document provides guidelines and information for contributors.

## Table of Contents

- [Project Structure](#project-structure)
- [Development Setup](#development-setup)
- [Versioning](#versioning)
- [Code Standards](#code-standards)
- [Pull Request Process](#pull-request-process)
- [Release Process](#release-process)

## Project Structure

GhydraMCP consists of three main components:

1. **Java Plugin for Ghidra** (`src/main/java/eu/starsong/ghidra/`): a Javalin/Jetty
   HTTP server embedded in Ghidra, layered as:
   - Main class: `GhydraPlugin.java`
   - HTTP server + routing: `server/` (Javalin setup, `GhidraContext`)
   - REST resources (route handlers): `resource/` directory
   - Business logic / program access: `service/` directory
   - Response/request DTOs: `dto/` directory
   - HATEOAS responses + pagination: `hateoas/` directory
   - CORS / error handling: `middleware/` directory
   - API constants: `api/ApiConstants.java`
   - Utilities (EDT marshalling, transactions, decompiler cache): `util/` directory

2. **Python MCP Bridge** (`bridge_mcp_hydra.py`):
   - Implements the Model Context Protocol (MCP)
   - Connects AI assistants to the Ghidra plugin via HTTP

3. **Python CLI** (`ghydra/`):
   - Click-based command-line tool with Rich formatting
   - Talks to the same HTTP API as the bridge

## Development Setup

### Prerequisites

- Java 21 (required for plugin development)
- Maven 3.8+
- Python 3.11+
- Ghidra 12.x (built/tested against 12.1.2). Build with `GHIDRA_HOME` pointing at your install.

### Building from Source

```bash
# Clone the repository
git clone https://github.com/starsong-consulting/GhydraMCP.git
cd GhydraMCP

# Build the project (point GHIDRA_HOME at your Ghidra 12.x install)
GHIDRA_HOME=/path/to/ghidra_12.1.2_PUBLIC mvn clean package
```

This creates:
- `target/Ghydra-[version].zip` - The Ghidra plugin only
- `target/Ghydra-Complete-[version].zip` - Complete package with plugin and bridge script

### Installing for Development

1. Build the project as described above
2. In Ghidra, go to `File` -> `Install Extensions`
3. Click the `+` button
4. Select the `Ghydra-[version].zip` file
5. Restart Ghidra
6. Enable the plugin in `File` -> `Configure` -> `Developer`

### Python Bridge Setup

Install the required Python dependencies:

```bash
pip install mcp==1.6.0 requests==2.32.3
```

Or use uv:

```bash
uv pip install mcp==1.6.0 requests==2.32.3
```

## Versioning

GhydraMCP follows semantic versioning (SemVer) and uses explicit API versions:

### Version Numbers

**Do not edit version constants by hand.** `scripts/version.py` is the single source of
truth: it writes all five locations at once, and `--check` proves they agree. Both CI
workflows run the check on every push.

```bash
python scripts/version.py --set 3.1.0      # writes all five locations
python scripts/version.py --check         # fails CI when they disagree
python scripts/prepare_release.py 3.1.0   # CHANGELOG section + versions in one step
```

The five locations are `ApiConstants.PLUGIN_VERSION`, `bridge_mcp_hydra.py`'s
`BRIDGE_VERSION`, `pyproject.toml`, `ghydra/__init__.py` and
`src/main/resources/extension.properties`. `API_VERSION` / `REQUIRED_API_VERSION`
are a separate axis (currently `3000`): they move only for a breaking API change and
`--set` never touches them.

### When to Update Versions

- **Patch** (`x.y.Z`): bug fixes that don't affect API compatibility
- **Minor** (`x.Y.z`): new features that are backward compatible
- **Major** (`X.y.z`): breaking changes
- **API version**: only for incompatible API changes

### Important Versioning Rules

1. Run `python scripts/version.py --check` before opening a PR; CI runs it too.
2. A release needs a `## [<version>]` section in `CHANGELOG.md` — `scripts/release_notes.py`
   refuses a tag whose section is missing or empty.
3. A release tag `vX.Y.Z` must be pushed to **both** remotes (`github` and `forgejo`).
4. The bridge verifies `API_VERSION` by exact equality in `register_instance`; a mismatch
   surfaces later as "No active Ghidra instance".

## Code Standards

### Java Code Standards

- Follow Java naming conventions
- Add comprehensive JavaDoc comments for public methods
- Ensure proper exception handling
- Follow Ghidra extension development best practices
- Follow HATEOAS principles for API endpoints
- Implement proper null checks and input validation

### Python Code Standards

- Follow PEP 8 style guidelines
- Add docstrings for all functions
- Use type hints for function parameters and return types
- Implement proper error handling
- Ensure thread-safety for multi-threaded operations

### Commit Message Standards

Follow the conventional commits format:

```
<type>: <description>

[optional body]

[optional footer(s)]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring without functionality changes
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `build`: Build system changes
- `ci`: CI configuration changes
- `chore`: Other changes that don't modify src or test files

Example:
```
feat: Add support for string listing in binary files

This adds a new endpoint to list all defined strings in the binary
with pagination and filtering by content.

Closes #123
```

## Pull Request Process

1. **Branch Naming Convention**:
   - Features: `feature/short-description`
   - Fixes: `bugfix/issue-description`
   - Breaking API changes: `api/breaking-change`

   These are the prefixes the CI workflows actually trigger on
   (`.github/workflows/build.yml` and `.gitea/workflows/build.yml` both watch
   `main`, `api-*`, `feature/*`, `feat/*`, `bugfix/*`, and pull requests against
   `main`). GitHub Actions additionally accepts `feat/*`, but Gitea Actions does
   not — prefer the names above so every push builds. Note that a `fix/*` or
   `docs/*` branch will **not** run CI at all; open a PR from `feature/*` (or use
   `feature/docs-*`) if the change needs a build to run against it.

2. **Before Creating a PR**:
   - Ensure all tests pass
   - Update documentation if needed
   - Update version numbers if needed
   - Add appropriate entries to CHANGELOG.md

3. **PR Template**:
   - Clearly describe the changes
   - Reference any related issues
   - Include any special testing instructions
   - List any breaking changes

4. **Review Process**:
   - At least one core contributor must review and approve
   - Address all requested changes
   - Ensure CI checks pass

## Release Process

Releases are driven by a single tag, `vX.Y.Z`, pushed to both remotes. The full
runbook is in [RELEASING.md](RELEASING.md); the short version:

1. **Preparation**:
   - Ensure all tests pass
   - Move the `Unreleased` notes into a dated release section and write the
     version into every place that carries it, with one command:
     ```bash
     python scripts/prepare_release.py --version 3.1.0
     ```
     It updates `ApiConstants.PLUGIN_VERSION`, `bridge_mcp_hydra.py`'s
     `BRIDGE_VERSION`, `pyproject.toml`, `ghydra/__init__.py` and
     `extension.properties`, and refuses to continue if the result is
     inconsistent.
   - Merge all changes to the main branch

2. **Creating a Release**:
   - Commit the release preparation and tag it: `git tag v3.1.0`
   - Push the commit and the tag to **both** remotes:
     ```bash
     git push github main && git push github v3.1.0
     git push forgejo main && git push forgejo v3.1.0
     ```
   - The tag push triggers the release workflows, which automatically:
     - Verify the version constants and the CHANGELOG entry for the tag
     - Build the release artifacts for Ghidra 11.x and 12.x
     - Create the release with the artifacts and a `SHA256SUMS` file
     - Verify the release exists with its assets

3. **Post-Release**:
   - Create a new "Unreleased" section in CHANGELOG.md
   - Announce the release in appropriate channels

## Testing

Please include appropriate tests for your changes:

1. **HTTP API Tests**: For Java plugin endpoint changes
2. **MCP Bridge Tests**: For Python bridge functionality

Run the tests with:
```bash
python run_tests.py
```

See TESTING.md for more detailed information on testing procedures.

## Questions and Support

If you have questions or need help, please:
1. Open an issue on GitHub
2. Check existing documentation
3. Reach out to the maintainers directly

Thank you for contributing to GhydraMCP!