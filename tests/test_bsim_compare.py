"""Consumer-visible behavior of the selected BSim comparison, without native I/O."""
import os
import sys
import unittest
from copy import deepcopy

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ghydra.core.bsim_compare import BSimComparisonError, compare_match, render_comparison


def instruction(address, mnemonic, operands=None, operand_types=None, encoded="90"):
    return {"address": address, "mnemonic": mnemonic, "operands": list(operands or []),
            "operand_types": list(operand_types or []), "bytes": encoded, "length": len(encoded) // 2}


def native_instructions(rows, **overrides):
    decoded = sum(row["length"] for row in rows)
    return dict({"rows": rows, "complete": True, "error": None, "limit": 1000,
                 "body_bytes": decoded, "decoded_bytes": decoded}, **overrides)


def fixture():
    target = {
        "program": {"name": "target", "md5": "a" * 32, "language": "x86:LE:64:default",
                    "compiler": "gcc", "pointer_size": 8, "version": 1, "path": "/target"},
        "function": {"name": "f", "address": "ram::0x1000", "prototype": "int f(int count)",
                     "calling_convention": "__cdecl", "varargs": False, "return_type": "int",
                     "parameters": [{"ordinal": 0, "name": "count", "type": "int"}], "comment": None},
        "types": {"int": {"kind": "integer", "name": "int", "path": "/int", "length": 4}},
        "types_complete": True, "code": {"text": "int f(int count) {\n  return count;\n}\n",
                                        "complete": True, "error": None},
        "instructions": native_instructions([
            instruction("ram::0x1000", "MOV", ["EAX", "EDI"], [512, 512], "89F8"),
            instruction("ram::0x1002", "RET", encoded="C3")]),
        "modification": 10,
    }
    reference_snapshot = deepcopy(target)
    reference_snapshot["program"].update(name="reference", md5="b" * 32, path="/reference", version=7)
    reference_snapshot["function"]["address"] = "ram::0x2000"
    reference_snapshot["instructions"]["rows"][0]["address"] = "ram::0x2000"
    reference_snapshot["instructions"]["rows"][1]["address"] = "ram::0x2002"
    reference_snapshot["modification"] = 20
    selection = {"match_id": "selected-1", "profile": "corpus", "target": {
        "md5": "a" * 32, "address": "ram::0x1000", "modification": 10},
        "match": {"match_id": "selected-1", "executable_md5": "B" * 32, "address": "2000",
                  "function_name": "f", "repository_url": "ghidra://approved/repo/reference",
                  "similarity": 0.99}}
    reference = {"match_id": "selected-1", "identity_verified": True, "profile": "approved",
                 "path": "/reference", "version": 7, "snapshot": reference_snapshot}
    return selection, target, reference


def recursive_types(snapshot, prefix):
    snapshot["types"] = {
        prefix + "node": {"kind": "struct", "name": "Node", "path": "/Node", "length": 8,
                          "components": [{"name": "next", "offset": 0, "length": 8,
                                          "bitfield": False, "type": prefix + "pointer"}]},
        prefix + "pointer": {"kind": "pointer", "name": "Node *", "path": "/Node *", "length": 8,
                             "target": prefix + "node"},
        prefix + "int": {"kind": "integer", "name": "int", "path": "/int", "length": 4},
    }
    snapshot["function"]["return_type"] = prefix + "pointer"
    snapshot["function"]["parameters"][0]["type"] = prefix + "int"
    snapshot["function"]["prototype"] = "Node * f(int count)"


class BSimComparisonTests(unittest.TestCase):
    def test_equal_complete_snapshots_and_directional_identity(self):
        result = compare_match(*fixture())
        self.assertEqual({"match_id", "selected_match", "identity_verified", "complete", "source",
                          "target_reference", "comparison", "preview", "warnings", "applied"}, set(result))
        self.assertTrue(result["complete"])
        self.assertTrue(result["identity_verified"])
        self.assertFalse(result["applied"])
        self.assertEqual([], result["preview"])
        self.assertEqual("target", result["source"]["program"]["name"])
        self.assertEqual("reference", result["target_reference"]["program"]["name"])
        self.assertEqual(7, result["target_reference"]["version"])
        for section in ("code", "instructions", "signature", "types"):
            self.assertEqual("equal", result["comparison"][section]["status"])
            self.assertIs(True, result["comparison"][section]["equal"])

    def test_unified_code_diff_proposes_reference_not_reverse(self):
        selection, target, reference = fixture()
        reference["snapshot"]["code"]["text"] = "int f(int count) {\n  return count + 1;\n}\n"
        result = compare_match(selection, target, reference)
        code = result["comparison"]["code"]
        self.assertEqual("textual_unified_c", code["kind"])
        self.assertEqual("different", code["status"])
        self.assertIn("--- target.c\n+++ reference.c\n", code["unified_diff"])
        self.assertIn("-  return count;\n+  return count + 1;", code["unified_diff"])
        self.assertEqual([], result["preview"], "Decompiled C is evidence, never an applicable change")
        self.assertFalse(result["applied"])

    def test_missing_final_newline_is_a_real_textual_change(self):
        selection, target, reference = fixture()
        reference["snapshot"]["code"]["text"] = target["code"]["text"].rstrip("\n")
        result = compare_match(selection, target, reference)
        self.assertEqual("different", result["comparison"]["code"]["status"])
        self.assertIn("\\ No newline at end of file", result["comparison"]["code"]["unified_diff"])

    def test_inputs_and_output_are_independent(self):
        args = fixture()
        before = deepcopy(args)
        result = compare_match(*args)
        self.assertEqual(before, args)
        result["source"]["program"]["name"] = "changed"
        result["selected_match"]["address"] = "dead"
        result["target_reference"]["program"]["path"] = "/changed"
        self.assertEqual(before, args)

    def test_selected_identity_failures_are_typed_not_comparisons(self):
        mutations = [
            lambda s, t, r: r.update(identity_verified=False),
            lambda s, t, r: r.update(identity_verified=1),
            lambda s, t, r: r.update(match_id="other"),
            lambda s, t, r: s["match"].update(match_id="other"),
            lambda s, t, r: s["match"].update(executable_md5="c" * 32),
            lambda s, t, r: r["snapshot"]["program"].update(md5="c" * 32),
            lambda s, t, r: r["snapshot"]["function"].update(address="ram::0x2001"),
            lambda s, t, r: t["program"].update(md5="c" * 32),
            lambda s, t, r: t["function"].update(address="ram::0x1001"),
            lambda s, t, r: t.update(modification=11),
            lambda s, t, r: t.update(modification=True),
            lambda s, t, r: s["target"].update(modification=True),
            lambda s, t, r: s["match"].update(executable_md5=None),
            lambda s, t, r: s["match"].update(address="not-an-address"),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                args = fixture()
                mutate(*args)
                with self.assertRaises(BSimComparisonError) as caught:
                    compare_match(*args)
                self.assertEqual("BSIM_IDENTITY_MISMATCH", caught.exception.code)
                self.assertNotIn("c" * 32, str(caught.exception))

    def test_named_spaces_must_agree_but_unqualified_index_address_is_supported(self):
        selection, target, reference = fixture()
        selection["match"]["address"] = "other::0x2000"
        with self.assertRaises(BSimComparisonError):
            compare_match(selection, target, reference)
        selection["match"]["address"] = "0X00002000"
        self.assertTrue(compare_match(selection, target, reference)["identity_verified"])

    def test_malformed_envelope_is_a_typed_argument_error(self):
        for args in ((None, {}, {}), ({}, {}, {})):
            with self.subTest(args=args), self.assertRaises(BSimComparisonError) as caught:
                compare_match(*args)
            self.assertEqual("BSIM_COMPARISON_INVALID", caught.exception.code)

    def test_indexed_name_difference_does_not_reject_verified_address_and_md5(self):
        selection, target, reference = fixture()
        selection["match"]["function"] = "old_indexed_name"
        result = compare_match(selection, target, reference)
        self.assertTrue(result["identity_verified"])
        self.assertTrue(any("Indexed match name differs" in warning for warning in result["warnings"]))

    def test_structured_signature_annotations_return_and_parameter_changes(self):
        selection, target, reference = fixture()
        other = reference["snapshot"]
        other["types"]["long"] = {"kind": "integer", "name": "long", "path": "/long", "length": 8}
        other["function"].update(name="library::renamed", calling_convention="__stdcall", varargs=True,
                                  return_type="long", comment="reference annotation")
        other["function"]["parameters"] = [{"ordinal": 3, "name": "length", "type": "long"},
                                              {"ordinal": 4, "name": "flags", "type": "int"}]
        result = compare_match(selection, target, reference)
        changes = {row["field"]: row for row in result["comparison"]["signature"]["changes"]}
        self.assertEqual({"field": "namespace", "before": "", "after": "library"}, changes["namespace"])
        self.assertEqual("renamed", changes["name"]["after"])
        self.assertEqual("__cdecl", changes["calling_convention"]["before"])
        self.assertIs(True, changes["varargs"]["after"])
        self.assertEqual("reference annotation", changes["comment"]["after"])
        self.assertEqual(2, changes["parameter_count"]["after"])
        self.assertEqual(3, changes["parameters[0].ordinal"]["after"])
        self.assertEqual("length", changes["parameters[0].name"]["after"])
        self.assertEqual("long", changes["return_type"]["after"]["root"])
        self.assertEqual(8, changes["return_type"]["after"]["types"]["long"]["length"])
        self.assertEqual("long", changes["parameters[0].type"]["after"]["root"])
        self.assertEqual("flags", changes["parameters[1]"]["after"]["name"])
        self.assertEqual("different", result["comparison"]["types"]["status"])
        self.assertFalse(result["applied"])

    def test_parameter_order_and_removal_are_explicit(self):
        selection, target, reference = fixture()
        target["function"]["parameters"].append({"ordinal": 1, "name": "flags", "type": "int"})
        reference["snapshot"]["function"]["parameters"] = [
            {"ordinal": 0, "name": "flags", "type": "int"}, {"ordinal": 1, "name": "count", "type": "int"}]
        result = compare_match(selection, target, reference)
        change = next(row for row in result["comparison"]["signature"]["changes"]
                      if row["field"] == "parameter_order")
        self.assertEqual(["count", "flags"], change["before"])
        self.assertEqual(["flags", "count"], change["after"])
        reference["snapshot"]["function"]["parameters"].pop()
        result = compare_match(selection, target, reference)
        removal = next(row for row in result["preview"] if row["kind"] == "signature"
                       and row["field"] == "parameters[1]")
        self.assertEqual("flags", removal["before"]["name"])
        self.assertIsNone(removal["after"])

    def test_recursive_type_ids_are_local_and_cycles_are_reported(self):
        selection, target, reference = fixture()
        recursive_types(target, "source-")
        recursive_types(reference["snapshot"], "reference-")
        result = compare_match(selection, target, reference)
        self.assertTrue(result["complete"])
        self.assertEqual("equal", result["comparison"]["types"]["status"])
        self.assertEqual("equal", result["comparison"]["signature"]["status"])
        self.assertEqual([], result["preview"])
        self.assertTrue(result["comparison"]["types"]["cycles"]["source"])
        self.assertTrue(result["comparison"]["types"]["cycles"]["reference"])

    def test_same_named_recursive_type_layout_conflict_is_not_equal(self):
        selection, target, reference = fixture()
        recursive_types(target, "source-")
        recursive_types(reference["snapshot"], "reference-")
        reference["snapshot"]["types"]["reference-node"]["components"][0]["offset"] = 4
        result = compare_match(selection, target, reference)
        types = result["comparison"]["types"]
        self.assertEqual("different", types["status"])
        layout = next(row for row in types["differences"] if row["field"].endswith("components[0].offset"))
        self.assertEqual(0, layout["before"])
        self.assertEqual(4, layout["after"])
        self.assertTrue(any(conflict["path"] == "/Node" for conflict in types["conflicts"]))
        self.assertFalse(result["applied"])

    def test_changed_recursive_target_is_not_hidden_by_cycle_termination(self):
        selection, target, reference = fixture()
        recursive_types(target, "a-")
        recursive_types(reference["snapshot"], "b-")
        reference["snapshot"]["types"]["b-pointer"]["target"] = "b-int"
        result = compare_match(selection, target, reference)
        self.assertEqual("different", result["comparison"]["types"]["status"])
        self.assertTrue(result["comparison"]["types"]["differences"])

    def test_typedef_array_enum_bitfield_and_function_definition_edges(self):
        for kind in ("typedef", "array", "enum", "struct", "union", "bitfield", "function_definition"):
            with self.subTest(kind=kind):
                selection, target, reference = fixture()
                common = {"kind": kind, "name": "Custom", "path": "/Custom", "length": 8}
                shapes = {
                    "typedef": {"base": "int"}, "array": {"element": "int", "count": 2},
                    "bitfield": {"base": "int", "bit_offset": 0, "bit_size": 3},
                    "enum": {"values": {"FIRST": 1}},
                    "struct": {"components": [{"name": "bits", "offset": 0, "length": 4, "type": "int",
                                                 "bitfield": True, "bit_offset": 0, "bit_size": 3}]},
                    "union": {"components": [{"name": "bits", "offset": 0, "length": 4, "type": "int",
                                                "bitfield": False}]},
                    "function_definition": {"return_type": "int", "parameters": [
                        {"ordinal": 0, "name": "value", "type": "int"}], "varargs": False,
                        "calling_convention": "__cdecl"},
                }
                descriptor = dict(common, **shapes[kind])
                target["types"]["custom"] = deepcopy(descriptor)
                reference["snapshot"]["types"]["custom"] = deepcopy(descriptor)
                target["function"]["return_type"] = "custom"
                reference["snapshot"]["function"]["return_type"] = "custom"
                changed = reference["snapshot"]["types"]["custom"]
                if kind in ("typedef", "array", "bitfield", "function_definition"):
                    reference["snapshot"]["types"]["int"]["length"] = 2
                elif kind == "enum":
                    changed["values"]["FIRST"] = 9
                elif kind == "struct":
                    changed["components"][0]["bit_size"] = 4
                else:
                    changed["components"][0]["offset"] = 4
                result = compare_match(selection, target, reference)
                self.assertTrue(result["complete"])
                self.assertEqual("different", result["comparison"]["types"]["status"])
                self.assertTrue(result["comparison"]["types"]["differences"])

    def test_unreferenced_types_are_not_false_conflicts(self):
        selection, target, reference = fixture()
        target["types"]["unused"] = {"kind": "integer", "name": "Unused", "path": "/Unused", "length": 4}
        reference["snapshot"]["types"]["unused"] = {
            "kind": "integer", "name": "Unused", "path": "/Unused", "length": 8}
        result = compare_match(selection, target, reference)
        self.assertEqual("equal", result["comparison"]["types"]["status"])
        self.assertEqual([], result["comparison"]["types"]["conflicts"])

    def test_incomplete_or_missing_code_is_unknown_even_when_observed_text_matches(self):
        mutations = [lambda snapshot: snapshot.pop("code"),
                     lambda snapshot: snapshot["code"].update(text=None),
                     lambda snapshot: snapshot["code"].update(text=""),
                     lambda snapshot: snapshot["code"].update(complete=False),
                     lambda snapshot: snapshot["code"].update(error="private native error text")]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                selection, target, reference = fixture()
                mutate(reference["snapshot"])
                result = compare_match(selection, target, reference)
                self.assertFalse(result["complete"])
                self.assertEqual("incomplete", result["comparison"]["code"]["status"])
                self.assertIsNone(result["comparison"]["code"]["equal"])
                self.assertNotIn("private native error text", str(result))
                self.assertTrue(any("incomplete" in warning for warning in result["warnings"]))

    def test_partial_code_diff_is_evidence_only_and_explicitly_incomplete(self):
        selection, target, reference = fixture()
        reference["snapshot"]["code"].update(text="int f(int count) {\n", complete=False)
        result = compare_match(selection, target, reference)
        self.assertTrue(result["comparison"]["code"]["observed_differences"])
        self.assertFalse(result["comparison"]["code"]["complete"])
        self.assertEqual([], result["preview"])

    def test_missing_type_evidence_never_claims_equality_or_a_type_deletion(self):
        for missing in ("types", "return_type", "type_descriptor", "type_edge", "types_complete"):
            with self.subTest(missing=missing):
                selection, target, reference = fixture()
                other = reference["snapshot"]
                if missing == "types":
                    other.pop("types")
                elif missing == "return_type":
                    other["function"].pop("return_type")
                elif missing == "type_descriptor":
                    other["types"]["int"].pop("length")
                elif missing == "type_edge":
                    other["types"]["int"] = {"kind": "pointer", "name": "int *", "path": "/int *", "length": 8}
                else:
                    other["types_complete"] = False
                result = compare_match(selection, target, reference)
                self.assertFalse(result["complete"])
                self.assertIsNone(result["comparison"]["types"]["equal"])
                self.assertEqual("incomplete", result["comparison"]["signature"]["status"])
                self.assertFalse(any(row["field"] == "return_type" and row["after"] is None
                                     for row in result["preview"]))

    def test_missing_signature_annotation_is_not_proposed_as_a_deletion(self):
        selection, target, reference = fixture()
        target["function"]["comment"] = "keep me"
        reference["snapshot"]["function"].pop("comment")
        result = compare_match(selection, target, reference)
        self.assertEqual("incomplete", result["comparison"]["signature"]["status"])
        self.assertIn("comment", result["comparison"]["evidence"]["reference"]["missing_signature"])
        self.assertFalse(any(row["field"] == "comment" for row in result["preview"]))

    def test_type_depth_limit_is_explicit(self):
        selection, target, reference = fixture()
        for snapshot in (target, reference["snapshot"]):
            for index in range(20):
                snapshot["types"][f"pointer-{index}"] = {
                    "kind": "pointer", "name": f"Pointer{index}", "path": f"/Pointer{index}", "length": 8,
                    "target": f"pointer-{index + 1}" if index < 19 else "int"}
            snapshot["function"]["return_type"] = "pointer-0"
        result = compare_match(selection, target, reference)
        self.assertFalse(result["complete"])
        self.assertTrue(any(row["reason"] == "type_graph_limit"
                            for row in result["comparison"]["evidence"]["source"]["types"]["missing"]))

    def test_architecture_compiler_and_pointer_size_differences_are_warnings_not_identity_failures(self):
        selection, target, reference = fixture()
        reference["snapshot"]["program"].update(language="ARM:LE:32:v7", compiler="clang", pointer_size=4)
        result = compare_match(selection, target, reference)
        self.assertTrue(result["identity_verified"])
        for text in ("Architecture/language differs", "Compiler differs", "Pointer size differs"):
            self.assertTrue(any(text in warning for warning in result["warnings"]))
        self.assertFalse(result["applied"])
        self.assertFalse(any("safe to apply" in warning.lower() for warning in result["warnings"]))

    def test_deterministic_results(self):
        args = fixture()
        recursive_types(args[1], "a-")
        recursive_types(args[2]["snapshot"], "b-")
        args[2]["snapshot"]["types"]["b-node"]["length"] = 16
        first = compare_match(*args)
        self.assertEqual(first, compare_match(*deepcopy(args)))


class BSimInstructionComparisonTests(unittest.TestCase):
    def test_rebased_addresses_are_paired_without_normalizing_evidence_or_claiming_semantics(self):
        result = compare_match(*fixture())
        section = result["comparison"]["instructions"]
        self.assertEqual("native_instruction_sequence", section["kind"])
        self.assertEqual("equal", section["status"])
        self.assertTrue(section["complete"])
        self.assertEqual(2, section["summary"]["equal"])
        self.assertEqual("ram::0x1000", section["rows"][0]["source"]["address"])
        self.assertEqual("ram::0x2000", section["rows"][0]["reference"]["address"])
        self.assertTrue(any("semantic equivalence" in warning for warning in result["warnings"]))
        self.assertEqual([], result["preview"])

    def test_insertions_and_deletions_preserve_direction_and_surrounding_pairs(self):
        for added_to in ("source", "reference"):
            with self.subTest(added_to=added_to):
                selection, target, reference = fixture()
                snapshot = target if added_to == "source" else reference["snapshot"]
                rows = snapshot["instructions"]["rows"]
                rows.insert(1, instruction("ram::0x1800", "NOP"))
                snapshot["instructions"] = native_instructions(rows)
                section = compare_match(selection, target, reference)["comparison"]["instructions"]
                change = "deleted" if added_to == "source" else "inserted"
                self.assertEqual(["equal", change, "equal"], [row["status"] for row in section["rows"]])
                self.assertEqual("different", section["status"])
                self.assertTrue(section["observed_differences"])
                row = section["rows"][1]
                self.assertEqual("NOP", row[added_to]["mnemonic"])
                self.assertIsNone(row["reference" if added_to == "source" else "source"])
                self.assertEqual(1, section["summary"][change])
                self.assertEqual(2, section["summary"]["equal"])

    def test_replace_blocks_pair_in_order_and_keep_leftovers(self):
        selection, target, reference = fixture()
        reference["snapshot"]["instructions"] = native_instructions([
            instruction("ram::0x2000", "ADD", ["EAX", "EDI"], [512, 512], "01F8"),
            instruction("ram::0x2002", "INC", ["EAX"], [512], "FFC0"),
            instruction("ram::0x2004", "RET", encoded="C3")])
        section = compare_match(selection, target, reference)["comparison"]["instructions"]
        self.assertEqual(["changed", "inserted", "equal"], [row["status"] for row in section["rows"]])
        self.assertEqual("MOV", section["rows"][0]["source"]["mnemonic"])
        self.assertEqual("ADD", section["rows"][0]["reference"]["mnemonic"])
        self.assertEqual(1, section["summary"]["changed"])

    def test_constants_registers_branch_targets_bytes_types_and_lengths_remain_changes(self):
        pairs = [
            (instruction("ram::0x1000", "MOV", ["EAX", "0x1"], [512, 16384], "B801000000"),
             instruction("ram::0x2000", "MOV", ["EAX", "0x2"], [512, 16384], "B802000000")),
            (instruction("ram::0x1000", "MOV", ["EAX", "EDI"], [512, 512], "89F8"),
             instruction("ram::0x2000", "MOV", ["ECX", "EDI"], [512, 512], "89F9")),
            (instruction("ram::0x1000", "JMP", ["ram::0x1010"], [16384], "EB0E"),
             instruction("ram::0x2000", "JMP", ["ram::0x2010"], [16384], "EB0E")),
            (instruction("ram::0x1000", "NOP", encoded="90"),
             instruction("ram::0x2000", "NOP", encoded="91")),
            (instruction("ram::0x1000", "MOV", ["EAX"], [512], "89F8"),
             instruction("ram::0x2000", "MOV", ["EAX"], [16384], "89F8")),
            (instruction("ram::0x1000", "NOP", encoded="90"),
             instruction("ram::0x2000", "NOP", encoded="6690")),
            (instruction("ram::0x1000", "mov", ["EAX"], [512], "89F8"),
             instruction("ram::0x2000", "MOV", ["EAX"], [512], "89F8")),
        ]
        for before, after in pairs:
            with self.subTest(before=before, after=after):
                selection, target, reference = fixture()
                target["instructions"] = native_instructions([before])
                reference["snapshot"]["instructions"] = native_instructions([after])
                section = compare_match(selection, target, reference)["comparison"]["instructions"]
                self.assertEqual("different", section["status"])
                self.assertEqual(["changed"], [row["status"] for row in section["rows"]])
                self.assertEqual(before, section["rows"][0]["source"])
                self.assertEqual(after, section["rows"][0]["reference"])

    def test_repeated_mnemonics_are_not_discarded_as_popular_alignment_tokens(self):
        selection, target, reference = fixture()
        source = [instruction(f"ram::0x{0x1000 + index:x}", "NOP") for index in range(250)]
        other = [instruction(f"ram::0x{0x2000 + index:x}", "NOP") for index in range(251)]
        other[240] = instruction("ram::0x20f0", "INT3", encoded="CC")
        target["instructions"] = native_instructions(source)
        reference["snapshot"]["instructions"] = native_instructions(other)
        section = compare_match(selection, target, reference)["comparison"]["instructions"]
        self.assertEqual(250, section["summary"]["equal"])
        self.assertEqual(1, section["summary"]["inserted"])
        self.assertEqual(0, section["summary"]["changed"])
        self.assertEqual(0, section["summary"]["deleted"])
        self.assertEqual("INT3", section["rows"][240]["reference"]["mnemonic"])

    def test_language_mismatch_refuses_alignment_but_preserves_other_comparisons(self):
        selection, target, reference = fixture()
        reference["snapshot"]["program"]["language"] = "ARM:LE:32:v7"
        reference["snapshot"]["code"]["text"] = "different C"
        result = compare_match(selection, target, reference)
        section = result["comparison"]["instructions"]
        self.assertTrue(result["identity_verified"])
        self.assertFalse(result["complete"])
        self.assertEqual("not_comparable", section["status"])
        self.assertEqual("language_mismatch", section["reason"])
        self.assertFalse(section["complete"])
        self.assertIsNone(section["equal"])
        self.assertFalse(section["observed_differences"])
        self.assertEqual([], section["rows"])
        self.assertEqual("different", result["comparison"]["code"]["status"])

    def test_missing_language_is_incomplete_not_a_meaningful_alignment(self):
        for side in ("source", "reference"):
            with self.subTest(side=side):
                selection, target, reference = fixture()
                snapshot = target if side == "source" else reference["snapshot"]
                snapshot["program"].pop("language")
                section = compare_match(selection, target, reference)["comparison"]["instructions"]
                self.assertEqual("incomplete", section["status"])
                self.assertEqual("missing_language", section["reason"])
                self.assertEqual([], section["rows"])

    def test_missing_malformed_and_empty_evidence_never_claims_equality(self):
        mutations = [
            lambda s: s.pop("instructions"),
            lambda s: s.update(instructions=[]),
            lambda s: s["instructions"].update(rows=None),
            lambda s: s["instructions"].update(complete=False),
            lambda s: s["instructions"].pop("complete"),
            lambda s: s["instructions"].update(limit=1001),
            lambda s: s["instructions"].update(body_bytes=True),
            lambda s: s["instructions"].update(decoded_bytes=1),
            lambda s: s["instructions"].update(body_bytes=20),
            lambda s: s["instructions"].update(rows=[], body_bytes=0, decoded_bytes=0),
            lambda s: s["instructions"].pop("error"),
            lambda s: s["instructions"].update(error={"unsupported": True}),
            lambda s: s["instructions"].update(error="x" * 4097),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                selection, target, reference = fixture()
                mutate(reference["snapshot"])
                result = compare_match(selection, target, reference)
                section = result["comparison"]["instructions"]
                self.assertFalse(result["complete"])
                self.assertEqual("incomplete", section["status"])
                self.assertIsNone(section["equal"])
                self.assertTrue(section["reasons"]["reference"])
                self.assertFalse(section["reference_complete"])

    def test_malformed_or_oversized_rows_are_bounded_and_explained(self):
        mutations = [
            lambda r: r.update(address="not-an-address"),
            lambda r: r.update(address="1000"),
            lambda r: r.update(mnemonic=""),
            lambda r: r.update(mnemonic="M" * 257),
            lambda r: r.update(operands=["x" * 4097], operand_types=[512]),
            lambda r: r.update(operands=["x"] * 65, operand_types=[512] * 65),
            lambda r: r.update(operand_types=[True, 512]),
            lambda r: r.update(operand_types=[]),
            lambda r: r.update(bytes="89f8"),
            lambda r: r.update(bytes="89"),
            lambda r: r.update(length=True),
            lambda r: r.update(length=5000, bytes="90" * 5000),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                selection, target, reference = fixture()
                mutate(reference["snapshot"]["instructions"]["rows"][0])
                section = compare_match(selection, target, reference)["comparison"]["instructions"]
                self.assertEqual("incomplete", section["status"])
                self.assertIn("malformed_instruction_row[0]", section["reasons"]["reference"])
                self.assertEqual(1, section["summary"]["reference_rows"])
                self.assertFalse(any(row["reference"] and row["reference"]["mnemonic"] == "MOV"
                                     for row in section["rows"]))

    def test_native_truncation_and_errors_preserve_observed_raw_differences(self):
        selection, target, reference = fixture()
        listing = reference["snapshot"]["instructions"]
        listing.update(complete=False, error="undefined bytes in function body", body_bytes=30)
        listing["rows"][0]["operands"][0] = "ECX"
        result = compare_match(selection, target, reference)
        section = result["comparison"]["instructions"]
        self.assertEqual("incomplete", section["status"])
        self.assertTrue(section["observed_differences"])
        self.assertEqual(1, section["summary"]["changed"])
        self.assertIn("native_instruction_error", section["reasons"]["reference"])
        evidence = result["comparison"]["evidence"]["reference"]["instructions"]
        self.assertEqual("undefined bytes in function body", evidence["error"])
        self.assertEqual(30, evidence["body_bytes"])
        self.assertEqual(3, evidence["decoded_bytes"])
        self.assertIsNone(section["equal"])

    def test_oversized_sequences_are_never_fully_aligned_or_equal(self):
        selection, target, reference = fixture()
        for snapshot, base in ((target, 0x1000), (reference["snapshot"], 0x2000)):
            snapshot["instructions"] = native_instructions([
                instruction(f"ram::0x{base + index:x}", "NOP") for index in range(1001)])
        section = compare_match(selection, target, reference)["comparison"]["instructions"]
        self.assertEqual("incomplete", section["status"])
        self.assertIsNone(section["equal"])
        self.assertEqual(1000, len(section["rows"]))
        for side in ("source", "reference"):
            self.assertIn("instruction_row_limit", section["reasons"][side])
            self.assertEqual(1000, section["summary"][side + "_rows"])

    def test_native_operand_types_are_opaque_signed_flags(self):
        selection, target, reference = fixture()
        flags = [-(2 ** 31), -1]
        for snapshot in (target, reference["snapshot"]):
            snapshot["instructions"]["rows"][0]["operand_types"] = list(flags)
        section = compare_match(selection, target, reference)["comparison"]["instructions"]
        self.assertEqual("equal", section["status"])
        self.assertTrue(section["complete"])
        self.assertEqual(flags, section["rows"][0]["source"]["operand_types"])
        reference["snapshot"]["instructions"]["rows"][0]["operand_types"][1] = -2
        section = compare_match(selection, target, reference)["comparison"]["instructions"]
        self.assertEqual("different", section["status"])
        self.assertEqual("changed", section["rows"][0]["status"])

    def test_equal_available_rows_never_override_native_gap_or_cap_incompleteness(self):
        for error in ("undefined body bytes", "instruction limit reached"):
            with self.subTest(error=error):
                selection, target, reference = fixture()
                reference["snapshot"]["instructions"].update(complete=False, error=error)
                result = compare_match(selection, target, reference)
                section = result["comparison"]["instructions"]
                self.assertFalse(result["complete"])
                self.assertEqual("incomplete", section["status"])
                self.assertFalse(section["complete"])
                self.assertIsNone(section["equal"])
                self.assertFalse(section["observed_differences"])
                self.assertEqual(2, section["summary"]["equal"])
                self.assertEqual(error, result["comparison"]["evidence"]["reference"]["instructions"]["error"])

    def test_one_sided_identical_prefix_keeps_unobserved_suffix_unknown(self):
        for side in ("source", "reference"):
            for error in (None, "instruction limit reached", "memory read failed"):
                for retained in (0, 1):
                    with self.subTest(side=side, error=error, retained=retained):
                        selection, target, reference = fixture()
                        snapshot = target if side == "source" else reference["snapshot"]
                        rows = snapshot["instructions"]["rows"][:retained]
                        snapshot["instructions"] = native_instructions(
                            rows, complete=False, error=error, body_bytes=3)
                        result = compare_match(selection, target, reference)
                        section = result["comparison"]["instructions"]
                        self.assertEqual("incomplete", section["status"])
                        self.assertFalse(section["observed_differences"])
                        self.assertIsNone(section["equal"])
                        self.assertEqual(retained, section["summary"]["equal"])
                        self.assertEqual(2 - retained, section["summary"]["unknown"])
                        self.assertEqual(0, section["summary"]["inserted"])
                        self.assertEqual(0, section["summary"]["deleted"])
                        for index, row in enumerate(section["rows"][retained:], retained):
                            self.assertEqual("unknown", row["status"])
                            self.assertEqual(side, row["unobserved"])
                            self.assertIsNone(row[side])
                            self.assertEqual("MOV" if index == 0 else "RET",
                                             row["reference" if side == "source" else "source"]["mnemonic"])
                        text = render_comparison(result)
                        self.assertIn("[unknown]", text)
                        self.assertIn("(unobserved)", text)

    def test_internal_unmatched_rows_are_unknown_against_incomplete_capture(self):
        selection, target, reference = fixture()
        target["instructions"]["rows"].insert(1, instruction("ram::0x1001", "NOP"))
        target["instructions"] = native_instructions(target["instructions"]["rows"])
        reference["snapshot"]["instructions"].update(complete=False, error="undecoded body bytes")
        section = compare_match(selection, target, reference)["comparison"]["instructions"]
        self.assertEqual(["equal", "unknown", "equal"], [row["status"] for row in section["rows"]])
        self.assertFalse(section["observed_differences"])

    def test_input_rows_are_not_mutated_or_shared_with_result_rows(self):
        args = fixture()
        args[2]["snapshot"]["instructions"]["rows"][0]["operands"][0] = "ECX"
        before = deepcopy(args)
        result = compare_match(*args)
        self.assertEqual(before, args)
        rows = result["comparison"]["instructions"]["rows"]
        rows[0]["source"]["operands"].append("changed")
        rows[0]["reference"]["operand_types"].append(123)
        rows[1]["reference"]["bytes"] = "90"
        self.assertEqual(before, args)

    def test_native_evidence_remains_available_without_decompiled_c(self):
        selection, target, reference = fixture()
        target.pop("code")
        reference["snapshot"].pop("code")
        result = compare_match(selection, target, reference)
        self.assertFalse(result["complete"])
        self.assertEqual("incomplete", result["comparison"]["code"]["status"])
        self.assertEqual("equal", result["comparison"]["instructions"]["status"])
        self.assertTrue(result["comparison"]["instructions"]["complete"])


class BSimComparisonRenderingTests(unittest.TestCase):
    def test_shared_renderer_shows_actual_diff_once_and_no_code_proposal(self):
        selection, target, reference = fixture()
        reference["snapshot"]["code"]["text"] = "int f(int count) {\n  return count + 1;\n}\n"
        result = compare_match(selection, target, reference)
        text = render_comparison(result)
        self.assertIn("BSim selected match: selected-1", text)
        self.assertIn("Identity verified: yes", text)
        self.assertIn("Evidence: COMPLETE", text)
        self.assertIn("No changes applied", text)
        self.assertIn("Code (textual unified C): different", text)
        self.assertIn("Signature: equal", text)
        self.assertIn("Referenced types: equal", text)
        self.assertEqual(1, text.count("--- target.c"))
        self.assertEqual(1, text.count("+++ reference.c"))
        self.assertIn("-  return count;\n+  return count + 1;", text)
        self.assertNotIn("[code]", text)
        self.assertNotIn('"modification"', text)

    def test_shared_renderer_shows_exact_structured_proposals_and_conflicts(self):
        selection, target, reference = fixture()
        reference["snapshot"]["function"]["comment"] = "Reference annotation"
        reference["snapshot"]["types"]["int"]["length"] = 8
        text = render_comparison(compare_match(selection, target, reference))
        self.assertIn("[signature] comment", text)
        self.assertIn("before: null", text)
        self.assertIn('after: "Reference annotation"', text)
        self.assertIn('"root": "int"', text)
        self.assertIn('"length": 8', text)
        self.assertIn("Unresolved type conflicts:", text)
        self.assertIn("Warnings:", text)

    def test_native_rendering_shows_paired_raw_evidence_summary_and_honest_limits(self):
        selection, target, reference = fixture()
        reference["snapshot"]["instructions"]["rows"][0]["operands"][0] = "ECX"
        text = render_comparison(compare_match(selection, target, reference))
        self.assertIn("Instructions (native listing sequence): different", text)
        self.assertIn("ram::0x1000 [89F8] MOV", text)
        self.assertIn('["EAX", "EDI"]', text)
        self.assertIn("ram::0x2000 [89F8] MOV", text)
        self.assertIn('["ECX", "EDI"]', text)
        self.assertIn("[changed]", text)
        self.assertIn("[equal]", text)
        self.assertIn('"changed": 1', text)
        self.assertIn("Complete: yes", text)
        self.assertIn("not CodeDiffPlugin correlation", text)
        self.assertIn("proof of semantic equivalence", text)

    def test_native_rendering_explains_incompleteness_and_language_refusal(self):
        selection, target, reference = fixture()
        reference["snapshot"]["instructions"].update(complete=False, error="missing decoding")
        text = render_comparison(compare_match(selection, target, reference))
        self.assertIn("Instructions (native listing sequence): incomplete", text)
        self.assertIn("Complete: NO", text)
        self.assertIn("reference reasons:", text)
        self.assertIn("missing decoding", text)
        reference["snapshot"]["program"]["language"] = "other-language"
        text = render_comparison(compare_match(selection, target, reference))
        self.assertIn("not_comparable", text)
        self.assertIn("Reason: language_mismatch", text)
        self.assertIn("No aligned rows", text)

    def test_incomplete_evidence_is_prominent_not_an_empty_success(self):
        selection, target, reference = fixture()
        reference["snapshot"].pop("code")
        text = render_comparison(compare_match(selection, target, reference))
        self.assertIn("Evidence: INCOMPLETE - absence of differences is not equality", text)
        self.assertIn("Code (textual unified C): incomplete", text)
        self.assertIn("None observed in available evidence", text)
        self.assertIn("Unavailable: code evidence missing", text)
        self.assertIn("No changes applied", text)


if __name__ == "__main__":
    unittest.main()
