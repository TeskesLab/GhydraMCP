"""The headless runner, the report and the annotations for the debugger.

None of this needs Ghidra: the launcher is exercised on the files it reads
and the commands it builds, the report on the data it is given, and the
annotations on a client that records what it was asked to do.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ghydra import headless
from ghydra import report as report_module
from ghydra import x64dbg as x64dbg_helper


class HeadlessProjectTests(unittest.TestCase):
    """The project directory and the program inside it."""

    @staticmethod
    def _fake_home(tmp):
        """A Ghidra installation with the launcher in it."""
        support = os.path.join(tmp, "support")
        os.makedirs(support, exist_ok=True)
        name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
        with open(os.path.join(support, name), "w", encoding="utf-8") as handle:
            handle.write("")
        return tmp

    def test_dotted_project_dir_is_refused(self):
        """Ghidra refuses a path element that starts with a dot."""
        with self.assertRaises(headless.HeadlessError) as caught:
            headless.check_project_dir(os.path.join(os.path.expanduser("~"), ".ghidra", "p"))
        self.assertEqual(caught.exception.code, "HEADLESS_BAD_PROJECT_DIR")

    def test_plain_project_dir_is_accepted(self):
        """A plain directory is what Ghidra wants."""
        headless.check_project_dir(os.path.join(os.path.expanduser("~"), "ghidra_projects"))

    def test_default_project_dir_has_no_dotted_element(self):
        """The default is Ghidra's own convention, not something dotted."""
        default = headless.default_project_dir()
        headless.check_project_dir(default)
        self.assertTrue(default.endswith("ghidra_projects"))

    def test_program_is_found_in_the_project_index(self):
        """The index of the project says whether the program is in it."""
        with tempfile.TemporaryDirectory() as tmp:
            index = os.path.join(tmp, "cmd.rep", "idata")
            os.makedirs(index)
            with open(os.path.join(index, "~index.dat"), "w", encoding="utf-8") as handle:
                handle.write(
                    "VERSION=1\r\n/\r\n 00000000:cmd.exe:a9fe536bff6c5085139269700\r\n"
                    "NEXT-ID:1\r\n"
                )
            self.assertTrue(headless.project_has_program(tmp, "cmd", "C:\\bin\\cmd.exe"))
            self.assertFalse(headless.project_has_program(tmp, "cmd", "C:\\bin\\other.exe"))

    def test_missing_project_index_means_no_program(self):
        """A project that is not there holds nothing."""
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(headless.project_has_program(tmp, "cmd", "cmd.exe"))

    def test_command_imports_when_the_program_is_not_there(self):
        """A program that is not in the project is imported."""
        with tempfile.TemporaryDirectory() as tmp:
            binary = os.path.join(tmp, "cmd.exe")
            with open(binary, "w", encoding="utf-8") as handle:
                handle.write("MZ")
            runner = headless.HeadlessRunner(
                binary=binary, project_dir=tmp,
                ghidra_home=self._fake_home(tmp))
            command = runner.command()
            self.assertIn("-import", command)
            self.assertNotIn("-process", command)

    def test_command_processes_when_the_program_is_there(self):
        """A program that is already in the project is processed again."""
        with tempfile.TemporaryDirectory() as tmp:
            binary = os.path.join(tmp, "cmd.exe")
            with open(binary, "w", encoding="utf-8") as handle:
                handle.write("MZ")
            index = os.path.join(tmp, "cmd.rep", "idata")
            os.makedirs(index)
            with open(os.path.join(index, "~index.dat"), "w", encoding="utf-8") as handle:
                handle.write("VERSION=1\r\n/\r\n 00000000:cmd.exe:abc\r\n")
            runner = headless.HeadlessRunner(
                binary=binary, project_dir=tmp,
                ghidra_home=self._fake_home(tmp))
            command = runner.command()
            self.assertIn("-process", command)
            self.assertNotIn("-import", command)

    def test_command_carries_the_port_to_the_script(self):
        """The script is told which port to serve on."""
        with tempfile.TemporaryDirectory() as tmp:
            binary = os.path.join(tmp, "cmd.exe")
            with open(binary, "w", encoding="utf-8") as handle:
                handle.write("MZ")
            runner = headless.HeadlessRunner(
                binary=binary, project_dir=tmp,
                ghidra_home=self._fake_home(tmp), port=8200)
            command = runner.command()
            self.assertIn("GhidraHeadlessServer", command)
            self.assertIn("port=8200", command)


class HeadlessDiscoveryTests(unittest.TestCase):
    """Where the Ghidra installation is, and which launcher it has."""

    def test_explicit_home_wins(self):
        """The path that is given is the one that is used."""
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(headless.find_ghidra_home(tmp), os.path.abspath(tmp))

    def test_missing_home_is_reported(self):
        """A machine without Ghidra says so, with a code."""
        original = headless.candidate_homes
        headless.candidate_homes = lambda: []
        try:
            with self.assertRaises(headless.HeadlessError) as caught:
                headless.find_ghidra_home(os.path.join(tempfile.gettempdir(), "no-such-ghidra"))
            self.assertEqual(caught.exception.code, "HEADLESS_NO_GHIDRA")
        finally:
            headless.candidate_homes = original

    def test_launcher_is_looked_for_in_support(self):
        """The launcher lives in the support directory of the installation."""
        with tempfile.TemporaryDirectory() as tmp:
            support = os.path.join(tmp, "support")
            os.makedirs(support)
            expected = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
            path = os.path.join(support, expected)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("")
            self.assertEqual(headless.launcher_for(tmp), path)

    def test_missing_launcher_is_reported(self):
        """An installation without the launcher says so, with a code."""
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(headless.HeadlessError) as caught:
                headless.launcher_for(tmp)
            self.assertEqual(caught.exception.code, "HEADLESS_NO_LAUNCHER")

    def test_project_name_comes_from_the_binary(self):
        """The name of the project is the name of the binary."""
        self.assertEqual(headless.slug_for("C:\\bin\\cmd.exe"), "cmd")
        self.assertEqual(headless.slug_for("/usr/bin/ls"), "ls")
        self.assertEqual(headless.slug_for("weird name!.exe"), "weird_name")

    def test_stop_file_lives_with_the_state(self):
        """The stop file is where the launcher can find it."""
        path = headless.stop_file_path(8192)
        self.assertTrue(path.endswith(os.path.join(".ghidra", "headless-8192.stop")))

    def test_status_of_an_unknown_port(self):
        """A port nobody serves is reported as such."""
        state = headless.status(65533)
        self.assertFalse(state["known"])
        self.assertFalse(state["running"])


class ReportTests(unittest.TestCase):
    """The report: what goes in, and what comes out."""

    def _ghidra(self):
        return {
            "program": {"name": "cmd.exe", "imageBase": "140000000",
                        "language": "x86:LE:64:default"},
            "functions": [
                {"name": "FUN_140001000", "address": "140001000", "signature": "void f()"},
                {"name": "FUN_140002000", "address": "140002000", "signature": "void g()"},
                {"name": "WinMain", "address": "140003000", "signature": "int w()"},
            ],
            "function_total": 3,
            "strings": [{"address": "140004000", "value": "hello"}],
            "string_total": 1,
            "imports": [{"name": "CreateFileW"}],
            "exports": [],
            "segments": [{"name": ".text", "start": "140001000", "size": "1000"}],
            "errors": [],
        }

    def _kuna(self):
        return {
            "enabled": True,
            "functions": 2,
            "failed": 0,
            "reused": True,
            "directory": "/tmp/kuna",
            "errors": [],
            "index": [
                {"name": "sub_140001000", "addr": "0x140001000", "size": 4096},
                {"name": "sub_140002000", "addr": "0x140002000", "size": 32},
            ],
        }

    def test_the_big_functions_come_first(self):
        """The function Kuna found big is the one worth a look."""
        chosen = report_module.interesting_functions(self._ghidra(), self._kuna(), 10)
        self.assertEqual(chosen[0]["address"], "140001000")
        self.assertEqual(chosen[0]["kuna_size"], 4096)

    def test_the_named_functions_are_kept(self):
        """A function with a name of its own is worth a look too."""
        chosen = report_module.interesting_functions(self._ghidra(), self._kuna(), 10)
        names = [item["name"] for item in chosen]
        self.assertIn("WinMain", names)

    def test_the_annotations_carry_the_image_base(self):
        """The annotations know the base the addresses belong to."""
        chosen = report_module.interesting_functions(self._ghidra(), self._kuna(), 10)
        annotations = report_module.build_annotations("C:\\bin\\cmd.exe",
                                                      self._ghidra()["program"], chosen)
        self.assertEqual(annotations["image_base"], "140000000")
        self.assertTrue(annotations["annotations"])
        first = annotations["annotations"][0]
        self.assertIn("4096 bytes", first["comment"])

    def test_kuna_addresses_are_keyed_the_same_way(self):
        """The addresses of the two tools are in the same space."""
        index = report_module.kuna_functions_by_address(self._kuna()["index"])
        self.assertIn("140001000", index)
        self.assertEqual(index["140001000"]["name"], "sub_140001000")

    def test_the_markdown_carries_every_section(self):
        """The document a human reads has the sections it should have."""
        report = {
            "binary": "C:\\bin\\cmd.exe",
            "generated_at": 0,
            "ghidra": self._ghidra(),
            "kuna": self._kuna(),
            "functions": report_module.interesting_functions(
                self._ghidra(), self._kuna(), 10),
            "decompiled": [{"address": "140001000", "name": "FUN_140001000",
                            "code": "void f() { }"}],
            "annotations": {"annotations": []},
        }
        text = report_module.render_markdown(report)
        for section in ("## What Ghidra found", "## What Kuna found",
                        "## The functions worth a look", "## Decompilation"):
            self.assertIn(section, text)

    def test_the_three_files_are_written(self):
        """The report leaves a document, the data and the annotations."""
        report = {
            "binary": os.path.join("C:\\bin", "cmd.exe"),
            "generated_at": 0,
            "ghidra": self._ghidra(),
            "kuna": self._kuna(),
            "functions": [],
            "decompiled": [],
            "annotations": {"annotations": []},
        }
        with tempfile.TemporaryDirectory() as tmp:
            paths = report_module.write_report(report, tmp)
            self.assertTrue(os.path.isfile(paths["markdown"]))
            self.assertTrue(os.path.isfile(paths["json"]))
            self.assertTrue(os.path.isfile(paths["annotations"]))
            with open(paths["json"], "r", encoding="utf-8") as handle:
                self.assertEqual(json.load(handle)["binary"], report["binary"])


class _RecordingClient:
    """A client that records what it was asked to do."""

    def __init__(self, failures=0, modules=None):
        self.calls = []
        self.failures = failures
        self.modules = modules if modules is not None else [
            {"base": 0x7FF7A1230000, "size": 0x100000,
             "path": "C:\\Windows\\System32\\cmd.exe"},
        ]

    def call_tool(self, name, arguments=None):
        self.calls.append((name, arguments or {}))
        if name == "ListModules":
            text = "".join(
                f"0x{module['base']:X} | 0x{module['size']:X} | {module['path']}\n"
                for module in self.modules
            )
            return text
        if self.failures > 0:
            self.failures -= 1
            raise x64dbg_helper.X64dbgError(
                "the connection died while the answer was coming",
                code="X64DBG_UNCERTAIN")
        return "done"


class AnnotationTests(unittest.TestCase):
    """Putting the annotations of a report into the debugger."""

    def _annotations(self):
        return {
            "binary": "C:\\Windows\\System32\\cmd.exe",
            "image_base": "0x140000000",
            "annotations": [
                {"address": "140001000", "name": "FUN_140001000", "comment": "big one"},
                {"address": "140002000", "name": "WinMain", "comment": "the entry"},
            ],
        }

    def test_the_addresses_are_translated(self):
        """The static address becomes the address of the live process."""
        client = _RecordingClient()
        result = x64dbg_helper.apply_annotations(client, self._annotations())
        self.assertEqual(result["module_base"], "0x7ff7a1230000")
        self.assertEqual(result["applied"][0]["runtime_address"], "0x7ff7a1231000")

    def test_the_comment_is_written(self):
        """Every annotation becomes a comment."""
        client = _RecordingClient()
        x64dbg_helper.apply_annotations(client, self._annotations())
        names = [call[0] for call in client.calls]
        self.assertIn("CommentOrLabelAtAddress", names)

    def test_the_bookmark_uses_the_command_x64dbg_knows(self):
        """The plugin's own SetBookmark runs a command that does not exist."""
        client = _RecordingClient()
        x64dbg_helper.apply_annotations(client, self._annotations(), bookmarks=True)
        commands = [call[1].get("command", "") for call in client.calls
                    if call[0] == "ExecuteDebuggerCommand"]
        self.assertEqual(len(commands), 2)
        self.assertTrue(commands[0].startswith("bookmarkset "))
        self.assertNotIn("bookmarkadd", commands[0])

    def test_a_failure_is_tried_again(self):
        """A connection that dies is a retry, not a lost annotation."""
        client = _RecordingClient(failures=1)
        result = x64dbg_helper.apply_annotations(client, self._annotations())
        self.assertEqual(len(result["failed"]), 0)
        self.assertEqual(len(result["applied"]), 2)

    def test_a_failure_that_persists_is_reported(self):
        """What keeps failing is said, with the reason."""
        client = _RecordingClient(failures=99)
        result = x64dbg_helper.apply_annotations(client, self._annotations())
        self.assertTrue(result["failed"])
        self.assertIn("error", result["failed"][0])

    def test_a_file_without_annotations_is_refused(self):
        """A file that holds no annotations says so."""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bad.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"binary": "x"}, handle)
            with self.assertRaises(x64dbg_helper.X64dbgError) as caught:
                x64dbg_helper.load_annotations(path)
            self.assertEqual(caught.exception.code, "X64DBG_BAD_ARGS")


if __name__ == "__main__":
    unittest.main(verbosity=2)
