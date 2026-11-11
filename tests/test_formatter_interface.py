"""The three formatters, and the rule that keeps them in step.

The rule for adding an endpoint says the output method goes on `BaseFormatter`
**and** on both `JSONFormatter` and `TableFormatter` — so a command answers the
same way whichever formatter the user picked.

Nine methods were on both children and **not** on the base: the base is the
interface, and a third formatter would not have been asked for them at all. The
base declares them now, and this test keeps the three sets in step.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ghydra.formatters.base import BaseFormatter  # noqa: E402
from ghydra.formatters.json_formatter import JSONFormatter  # noqa: E402
from ghydra.formatters.table_formatter import TableFormatter  # noqa: E402


def _outputs(cls):
    """The public output methods of a formatter."""
    return {name for name, member in vars(cls).items()
            if callable(member) and not name.startswith("_")}


class FormatterInterfaceTests(unittest.TestCase):
    """The base, the JSON formatter and the table formatter agree."""

    def test_every_output_method_is_on_the_base(self):
        base = _outputs(BaseFormatter)
        for name in sorted(_outputs(JSONFormatter)):
            self.assertIn(name, base,
                          f"{name} is on the JSON formatter but not on the base")
        for name in sorted(_outputs(TableFormatter)):
            self.assertIn(name, base,
                          f"{name} is on the table formatter but not on the base")

    def test_every_output_method_is_on_both_children(self):
        base = _outputs(BaseFormatter)
        for name in sorted(base):
            self.assertIn(name, _outputs(JSONFormatter),
                          f"{name} is on the base but not on the JSON formatter")
            self.assertIn(name, _outputs(TableFormatter),
                          f"{name} is on the base but not on the table formatter")

    def test_the_three_sets_are_the_same_size(self):
        self.assertEqual(len(_outputs(BaseFormatter)),
                         len(_outputs(JSONFormatter)))
        self.assertEqual(len(_outputs(BaseFormatter)),
                         len(_outputs(TableFormatter)))

    def test_the_base_cannot_be_instantiated(self):
        """It is the interface: a formatter that skips a method is not one."""
        with self.assertRaises(TypeError):
            BaseFormatter()

    def test_both_children_can_be_instantiated(self):
        self.assertIsNotNone(JSONFormatter())
        self.assertIsNotNone(TableFormatter(use_colors=False))


if __name__ == "__main__":
    unittest.main()
