"""CLI command modules.

The command itself lives in `main`. It is imported **lazily** here, so that
`python -m ghydra.cli.main` does not execute the module twice: the package
imports `main`, and then `runpy` runs `main` again as `__main__`, which Python
reports as

    RuntimeWarning: 'ghydra.cli.main' found in sys.modules after import of
    package 'ghydra.cli', but prior to execution of 'ghydra.cli.main'

A lazy attribute (PEP 562) keeps `from ghydra.cli import cli` working — the
import happens on the first access — and leaves the module out of the package
until somebody asks for it.
"""

__all__ = ["cli"]


def __getattr__(name):
    """The command, imported when it is first asked for."""
    if name == "cli":
        from .main import cli

        return cli
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
