"""The `--contract` suite: the GhydraMCP side of the unification contract.

The contract lives in `contract/` (see its README). This suite is what makes it
true rather than aspirational:

* the generated halves are current;
* the vocabulary rule holds for every tool, and no tool declares a parameter the
  MCP protocol reserves;
* every tool has a formatter — a tool whose text degrades to `"Done"` is not a tool
  an agent can use;
* every error code is shaped, unique and traceable to a file and a line;
* a `TargetDescriptor` validates against its JSON schema, converts in both
  directions, and **refuses to be correlatable** when the two sides are different
  files.

No Ghidra, no debugger, no network.
"""

import io
import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ghydra.target import CONTRACT_VERSION, TargetDescriptor  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTRACT = os.path.join(ROOT, "contract")

NAME_PATTERN = re.compile(r"^[a-z][a-z0-9]*(_[a-z0-9]+)+$")
CODE_PATTERN = re.compile(r"^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$")


def load_json(name):
    with io.open(os.path.join(CONTRACT, name), encoding="utf-8") as handle:
        return json.load(handle)


# --------------------------------------------------------------------- schema
def validate(instance, schema, path="value", problems=None):
    """A small validator for the subset this schema uses.

    Deliberately small: the schema is ours, and a dependency on a full validator
    would make the guard fail to run on a machine without it. It covers `type`
    (including a union), `const`, `enum`, `pattern`, `minLength`, `minimum`,
    `required`, `properties` and `additionalProperties: false`.
    """
    problems = [] if problems is None else problems

    expected = schema.get("type")
    if expected is not None:
        kinds = expected if isinstance(expected, list) else [expected]
        matches = {
            "object": lambda value: isinstance(value, dict),
            "array": lambda value: isinstance(value, list),
            "string": lambda value: isinstance(value, str),
            "integer": lambda value: isinstance(value, int) and not isinstance(value, bool),
            "number": lambda value: isinstance(value, (int, float)) and not isinstance(value, bool),
            "boolean": lambda value: isinstance(value, bool),
            "null": lambda value: value is None,
        }
        if not any(matches.get(kind, lambda value: True)(instance) for kind in kinds):
            problems.append(f"{path}: expected {expected}, got {type(instance).__name__}")
            return problems

    if "const" in schema and instance != schema["const"]:
        problems.append(f"{path}: expected const {schema['const']!r}, got {instance!r}")
    if "enum" in schema and instance not in schema["enum"]:
        problems.append(f"{path}: {instance!r} is not one of {schema['enum']}")
    if isinstance(instance, str):
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            problems.append(f"{path}: {instance!r} does not match {schema['pattern']}")
        if "minLength" in schema and len(instance) < schema["minLength"]:
            problems.append(f"{path}: shorter than {schema['minLength']}")
    if isinstance(instance, int) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            problems.append(f"{path}: below the minimum {schema['minimum']}")

    if isinstance(instance, dict):
        for name in schema.get("required", []):
            if name not in instance:
                problems.append(f"{path}: missing required field {name!r}")
        properties = schema.get("properties", {})
        for name, value in instance.items():
            if name in properties:
                validate(value, properties[name], f"{path}.{name}", problems)
            elif schema.get("additionalProperties") is False:
                problems.append(f"{path}: unexpected field {name!r}")
    return problems


class GeneratorTests(unittest.TestCase):
    """The generated half of the contract must be current."""

    def test_the_generated_files_are_current(self):
        import subprocess
        result = subprocess.run([sys.executable, "scripts/gen_contract.py", "--check"],
                                cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_both_files_exist_and_declare_their_version(self):
        for name in ("tools.json", "error-codes.json"):
            with self.subTest(name=name):
                document = load_json(name)
                self.assertEqual(CONTRACT_VERSION, document["contract_version"])
                self.assertEqual("scripts/gen_contract.py", document["generated_by"])


class VocabularyTests(unittest.TestCase):
    """Rule 1: namespace_verb, snake_case, nothing reserved."""

    def setUp(self):
        self.document = load_json("tools.json")
        self.tools = self.document["tools"]

    def test_every_tool_name_matches_the_rule(self):
        for tool in self.tools:
            with self.subTest(tool=tool["name"]):
                self.assertRegex(tool["name"], NAME_PATTERN)

    def test_the_names_are_unique(self):
        names = [tool["name"] for tool in self.tools]
        self.assertEqual(len(names), len(set(names)))

    def test_no_tool_declares_a_reserved_parameter(self):
        offenders = [tool["name"] for tool in self.tools
                     if tool["reserved_parameters"]]
        self.assertEqual([], offenders,
                         "a parameter the MCP protocol reserves loses its value")

    def test_every_tool_has_a_formatter(self):
        missing = [tool["name"] for tool in self.tools if not tool["has_formatter"]]
        self.assertEqual([], missing,
                         "a tool without a formatter answers \"Done\"")

    def test_the_counts_agree_with_the_tools(self):
        counts = self.document["counts"]
        self.assertEqual(len(self.tools), counts["tools"])
        self.assertEqual(len({tool["namespace"] for tool in self.tools}),
                         counts["namespaces"])
        self.assertEqual(sum(1 for tool in self.tools if tool["has_formatter"]),
                         counts["with_formatter"])

    def test_the_local_namespaces_are_prefixed(self):
        """A local integration must not collide with the static side's names."""
        for tool in self.tools:
            if tool["namespace"] == "x64dbg":
                self.assertTrue(tool["name"].startswith("x64dbg_"))
                # The prefixed names never name an instance: the debugger is local.
                if tool["name"] in ("x64dbg_status", "x64dbg_call", "x64dbg_tools"):
                    self.assertFalse(tool["takes_instance"])

    def test_the_vocabulary_document_agrees_with_the_generated_counts(self):
        vocabulary = load_json("vocabulary.json")
        self.assertTrue(vocabulary["ghydra_side"]["conforms"])
        proxied = vocabulary["ghydra_side"]["proxied_tools"]
        self.assertGreater(len(proxied), 0)
        for name in proxied:
            self.assertIn(name, {tool["name"] for tool in self.tools})

    def test_the_other_side_is_marked_as_not_conforming(self):
        """The contract says what is not true yet; a green check would be a lie."""
        vocabulary = load_json("vocabulary.json")
        self.assertFalse(vocabulary["x64dbg_side"]["conforms"])
        self.assertGreater(len(vocabulary["x64dbg_side"]["mapping_examples"]), 0)


class ErrorCodeTests(unittest.TestCase):
    """Rule 3: a stable code next to the human text."""

    def setUp(self):
        self.document = load_json("error-codes.json")
        self.codes = self.document["codes"]

    def test_every_code_is_shaped(self):
        for entry in self.codes:
            with self.subTest(code=entry["code"]):
                self.assertRegex(entry["code"], CODE_PATTERN)

    def test_codes_are_unique(self):
        names = [entry["code"] for entry in self.codes]
        self.assertEqual(len(names), len(set(names)))

    def test_every_code_carries_a_side_and_an_origin(self):
        for entry in self.codes:
            with self.subTest(code=entry["code"]):
                self.assertIn(entry["side"], ("Java", "Python"))
                self.assertRegex(entry["origin"], r"^`.+:\d+`$")

    def test_the_envelope_rule_is_stated(self):
        envelope = self.document["envelope"]
        self.assertEqual("success", envelope["success_field"])
        self.assertIn("error.code", envelope["required_on_failure"])
        self.assertIn("error.message", envelope["required_on_failure"])

    def test_the_bridge_codes_are_in_the_contract(self):
        """A code the CLI or the bridge raises must be listed, or a client misses it."""
        import subprocess
        result = subprocess.run(
            [sys.executable, "-c",
             "import bridge_mcp_hydra as b; print(' '.join(sorted(b.FORMATTERS)))"],
            cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr)
        known = {entry["code"] for entry in self.codes}
        for code in ("REQUEST_TIMEOUT", "CONNECTION_ERROR", "KUNA_DISABLED",
                     "X64DBG_DISABLED", "BSIM_NO_DATABASE"):
            with self.subTest(code=code):
                self.assertIn(code, known)


class TargetDescriptorTests(unittest.TestCase):
    """Rule 2: one address model, and an identity that can refuse."""

    PROGRAM = {"path": "C:\\bin\\sample.exe", "language": "x86:LE:64:default",
               "image_base": "0x140000000"}
    MODULE = {"base": 0x7FF7A1230000, "size": 0x25000,
              "path": "C:\\bin\\sample.exe"}

    def descriptor(self, program=None, module=None):
        return TargetDescriptor.from_program_and_module(
            program or dict(self.PROGRAM), module or dict(self.MODULE),
            session={"host": "127.0.0.1", "port": 9094},
            source={"host": "127.0.0.1", "port": 8192})

    def test_the_conversion_round_trips(self):
        descriptor = self.descriptor()
        static = 0x140001234
        runtime = descriptor.to_runtime(static)
        self.assertEqual(static, descriptor.to_static(runtime))
        self.assertEqual(0x7FF7A1230000 - 0x140000000, descriptor.delta())

    def test_the_descriptor_validates_against_its_schema(self):
        schema = load_json("target-descriptor.schema.json")
        problems = validate(self.descriptor().as_dict(), schema, "descriptor")
        self.assertEqual([], problems)

    def test_a_descriptor_with_a_different_file_is_not_correlatable(self):
        module = dict(self.MODULE, path="C:\\bin\\other.exe")
        descriptor = self.descriptor(module=module)
        self.assertFalse(descriptor.same_binary())
        self.assertFalse(descriptor.correlatable())
        identity = descriptor.identity()
        self.assertEqual("different", identity["match"])
        self.assertIn("different files", identity["reason"])

    def test_the_same_name_in_another_directory_is_not_the_same_target(self):
        """A copy or a rebuild: the addresses of one do not describe the other."""
        module = dict(self.MODULE, path="D:\\builds\\sample.exe")
        descriptor = self.descriptor(module=module)
        identity = descriptor.identity()
        self.assertFalse(identity["same_binary"])
        self.assertEqual("name-only", identity["match"])
        self.assertIn("copy", identity["reason"])
        self.assertFalse(descriptor.correlatable())

    def test_windows_spelling_differences_are_the_same_file(self):
        module = dict(self.MODULE, path="c:/bin/SAMPLE.EXE")
        descriptor = self.descriptor(module=module)
        self.assertTrue(descriptor.same_binary())
        self.assertTrue(descriptor.correlatable())

    def test_a_static_only_descriptor_refuses_to_translate(self):
        descriptor = TargetDescriptor.from_program_and_module(
            dict(self.PROGRAM), {})
        self.assertIsNone(descriptor.module_base)
        self.assertFalse(descriptor.correlatable())
        with self.assertRaises(ValueError):
            descriptor.to_runtime(0x140001000)
        self.assertIsNone(descriptor.delta())

    def test_the_problems_list_the_mismatch(self):
        module = dict(self.MODULE, path="D:\\builds\\sample.exe")
        problems = self.descriptor(module=module).problems()
        self.assertTrue(any("not the same file" in problem for problem in problems))

    def test_a_clean_descriptor_has_no_problems(self):
        self.assertEqual([], self.descriptor().problems())

    def test_the_schema_rejects_a_bad_descriptor(self):
        """The schema is a guard, not decoration: it must refuse what we would."""
        schema = load_json("target-descriptor.schema.json")
        broken = self.descriptor().as_dict()
        broken["identity"]["match"] = "probably"
        self.assertNotEqual([], validate(broken, schema, "descriptor"))
        missing = self.descriptor().as_dict()
        del missing["binary"]
        self.assertNotEqual([], validate(missing, schema, "descriptor"))


if __name__ == "__main__":
    unittest.main(verbosity=2)