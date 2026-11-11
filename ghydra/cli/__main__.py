"""`python -m ghydra.cli` — the module entry point.

`ghydra/cli/__init__.py` imports `main` so that `from ghydra.cli import cli`
works, and running `python -m ghydra.cli.main` therefore executes the module
**twice** — once as `ghydra.cli.main` (through the package) and once as
`__main__` — and Python says so on stderr:

    RuntimeWarning: 'ghydra.cli.main' found in sys.modules after import of
    package 'ghydra.cli', but prior to execution of 'ghydra.cli.main'

The double execution is harmless for a module of definitions, but the warning
is noise in every run, and the project's own error suite runs the CLI this
way. This file is the entry the warning does not apply to: the target is the
package, and `__main__.py` is what runs.
"""

from .main import cli

if __name__ == "__main__":
    cli()
