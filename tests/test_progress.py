"""The progress reporter: what a long step is doing, and how it ended.

The module is small and it is what keeps a two-minute command from looking
hung. It had no test.

The property that matters: **a step that failed must not say "done"**. The
reporter said "done in 1.2s" in a `finally`, so a step that raised looked
exactly like a step that succeeded — and the person waiting has no way to tell
them apart, which is the whole reason the reporter exists.

The other property: the output goes to **stderr**, so the result of the command
— the report, the JSON — stays clean on stdout for the programs that read it.
"""

import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ghydra.progress import Progress  # noqa: E402


class ProgressTests(unittest.TestCase):
    """What the reporter says, and where it says it."""

    def _stream(self):
        return io.StringIO()

    def test_a_step_is_said_before_and_after(self):
        stream = self._stream()
        progress = Progress(stream=stream)
        with progress.step("analysing the binary"):
            pass
        text = stream.getvalue()
        self.assertIn("analysing the binary", text)
        self.assertIn("done in", text)
        self.assertEqual(1, progress.steps)

    def test_a_failed_step_says_that_it_failed(self):
        """The reason the reporter exists: a step that hung and one that failed
        must not look the same."""
        stream = self._stream()
        progress = Progress(stream=stream)
        with self.assertRaises(RuntimeError):
            with progress.step("analysing the binary"):
                raise RuntimeError("the decompiler gave up")
        text = stream.getvalue()
        self.assertNotIn("done in", text)
        self.assertIn("failed", text.lower())

    def test_a_failed_step_still_reports_its_time(self):
        stream = self._stream()
        progress = Progress(stream=stream)
        with self.assertRaises(RuntimeError):
            with progress.step("analysing the binary"):
                raise RuntimeError("no")
        self.assertIn("after", stream.getvalue())

    def test_a_disabled_reporter_says_nothing(self):
        stream = self._stream()
        progress = Progress(enabled=False, stream=stream)
        with progress.step("analysing the binary"):
            progress.note("something")
            progress.say("something else")
        self.assertEqual("", stream.getvalue())
        # The counters still work, so the caller can ask about them.
        self.assertEqual(0, progress.steps)

    def test_a_note_is_indented_under_the_step(self):
        stream = self._stream()
        progress = Progress(stream=stream)
        with progress.step("analysing the binary"):
            progress.note("the export was reused")
        self.assertIn("the export was reused", stream.getvalue())

    def test_the_elapsed_time_is_kept(self):
        stream = self._stream()
        progress = Progress(stream=stream)
        with progress.step("one"):
            pass
        with progress.step("two"):
            pass
        self.assertGreaterEqual(progress.elapsed, 0.0)

    def test_the_steps_are_numbered(self):
        stream = self._stream()
        progress = Progress(stream=stream)
        with progress.step("one"):
            pass
        with progress.step("two"):
            pass
        text = stream.getvalue()
        self.assertIn("[1] one", text)
        self.assertIn("[2] two", text)

    def test_the_default_stream_is_stderr(self):
        """The result of the command goes to stdout and must stay clean."""
        progress = Progress()
        self.assertIs(sys.stderr, progress.stream)

    def test_a_broken_stream_does_not_break_the_step(self):
        """A closed pipe is not the step's problem."""
        stream = self._stream()
        progress = Progress(stream=stream)
        stream.close()
        with progress.step("analysing the binary"):
            pass


if __name__ == "__main__":
    unittest.main()
