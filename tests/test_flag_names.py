"""The flags the documentation names, and the flags the code reads.

The script endpoints, the dev shutdown and the BSim database are turned on
with a system property or an environment variable, and the **name** of that
property is the whole switch: `-Dghidra.dev.allowScripts=true` is a different
switch from `-Dghydra.dev.allowScripts=true`.

Three of them were misspelled that way, so the documented switch did nothing:
the plugin refused the endpoint and the message it printed named a switch that
worked. Nothing caught it: the property was read in a place no test reached,
and the spelling was in no contract.

So the names are pinned here. A switch is a `-Dname=value` in the text, and
the namespace of the switches is `ghidra.mcp`, `ghidra.dev` and `ghidra.bsim`
— which is also what keeps a BSim class name (`ghidra.features.bsim.…`) out of
the comparison.
"""

import io
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Where the documentation lives. The project file is the one an agent reads.
DOCUMENTS = (
    "AGENTS.md",
    "README.md",
    "docs/ARCHITECTURE.md",
    "docs/GHYDRA_HTTP_API.md",
    "docs/GHYDRA_CLI.md",
    "docs/GHYDRA_HEADLESS.md",
    "docs/GHYDRA_BSIM.md",
    "docs/GHYDRA_TROUBLESHOOTING.md",
)

JAVA = os.path.join(ROOT, "src", "main", "java")

#: The namespace of the switches.
NAMESPACE = r"(?:ghidra|ghydra)\.(?:mcp|dev|bsim)\.[A-Za-z0-9_.]+"

#: A switch in the documentation: `-D<name>=` or `-D<name> `.
DOCUMENTED_SWITCH = re.compile(r"-D(" + NAMESPACE + r")")

#: A property name anywhere in the Java, however it is read.
PROPERTY_LITERAL = re.compile(r'"(' + NAMESPACE + r')"')

#: The namespace the switches use. `ghidra.` and `ghydra.` are different
#: switches, and only one of them is the one a user types.
CANONICAL = "ghidra."


def _java_properties():
    """The switch names the Java reads."""
    found = set()
    for base, _dirs, files in os.walk(JAVA):
        for name in files:
            if not name.endswith(".java"):
                continue
            text = io.open(os.path.join(base, name), encoding="utf-8").read()
            for match in PROPERTY_LITERAL.finditer(text):
                found.add(match.group(1))
    return found


def _documented_switches():
    """The switch names the documentation names."""
    found = set()
    for relative in DOCUMENTS:
        path = os.path.join(ROOT, relative)
        if not os.path.isfile(path):
            continue
        text = io.open(path, encoding="utf-8").read()
        for match in DOCUMENTED_SWITCH.finditer(text):
            found.add(match.group(1))
    return found


class FlagNameTests(unittest.TestCase):
    """The name of a switch is the switch."""

    def _plugin_properties(self):
        return {name for name in _java_properties()
                if name.startswith(CANONICAL)}

    def _documented_plugin_switches(self):
        return {name for name in _documented_switches()
                if name.startswith(CANONICAL)}

    def test_every_property_the_code_reads_is_the_documented_one(self):
        documented = self._documented_plugin_switches()
        self.assertTrue(documented, "the documentation names no switch")
        for name in sorted(self._plugin_properties()):
            self.assertIn(name, documented,
                          f"the code reads {name}, which the documentation "
                          "does not name")

    def test_every_documented_switch_is_one_the_code_reads(self):
        read = _java_properties()
        for name in sorted(self._documented_plugin_switches()):
            self.assertIn(name, read,
                          f"the documentation names {name}, which the code "
                          "does not read")

    def test_the_namespace_is_spelled_one_way(self):
        """`ghidra.` and `ghydra.` are different switches.

        The project is GhydraMCP and the Python package is `ghydra`, but the
        properties the Java reads are named after the tool the plugin serves,
        and the documentation is what a user types.
        """
        for name in sorted(_java_properties() | _documented_switches()):
            self.assertTrue(name.startswith(CANONICAL),
                            f"{name} does not use the {CANONICAL} namespace")

    def test_the_three_switches_are_named(self):
        """The switches that were misspelled, named so they cannot drift."""
        read = _java_properties()
        for name in ("ghidra.dev.allowScripts", "ghidra.dev.allowShutdown",
                     "ghidra.bsim.database"):
            self.assertIn(name, read, f"{name} is not read")
            self.assertIn(name, self._documented_plugin_switches(),
                          f"{name} is not documented")


if __name__ == "__main__":
    unittest.main()
