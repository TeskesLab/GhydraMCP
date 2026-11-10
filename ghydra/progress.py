"""Progress, for the steps that take a while.

An analysis of a big binary takes minutes, and a decompiler that loads and
analyses the whole image on every run takes more. A command that says
nothing for two minutes looks like a command that hung, and the person
waiting has no way to tell it apart from one that did.

So the long steps say what they are doing and how long they took. The
output goes to stderr, so that the result of the command - the report, the
JSON - stays clean on stdout for the programs that read it.
"""

from __future__ import annotations

import sys
import time
from contextlib import contextmanager
from typing import Any, Iterator, Optional, TextIO


class Progress:
    """The steps of a command, said out loud as they happen."""

    def __init__(self, enabled: bool = True, stream: Optional[TextIO] = None) -> None:
        self.enabled = enabled
        self.stream = stream if stream is not None else sys.stderr
        self.steps = 0
        self.elapsed = 0.0

    def _write(self, message: str) -> None:
        if not self.enabled:
            return
        try:
            self.stream.write(message + "\n")
            self.stream.flush()
        except (OSError, ValueError):
            pass

    @contextmanager
    def step(self, message: str) -> Iterator[None]:
        """One step, said before and after.

        A step that raised did not finish, so it does not say "done": it says it
        failed, and how long it lasted before it did. The whole reason this
        reporter exists is that the person waiting cannot tell a step that hung
        from one that failed — and a step that says "done" after failing is the
        third thing, and the most misleading one.
        """
        if not self.enabled:
            yield
            return
        self.steps += 1
        start = time.time()
        self._write(f"  [{self.steps}] {message} ...")
        try:
            yield
        except BaseException:
            took = time.time() - start
            self.elapsed += took
            self._write(f"      failed after {took:.1f}s")
            raise
        else:
            took = time.time() - start
            self.elapsed += took
            self._write(f"      done in {took:.1f}s")

    def note(self, message: str) -> None:
        """Something worth saying, without a step of its own."""
        self._write(f"      {message}")

    def say(self, message: str) -> None:
        """A line of its own."""
        self._write(message)
