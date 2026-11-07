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
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ghydra import headless
from ghydra import report as report_module
from ghydra import x64dbg as x64dbg_helper
from ghydra.cli import report as report_cli


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

    @staticmethod
    def _program_in_project(tmp, project_name, name="cmd.exe"):
        """A project that holds a program."""
        index = os.path.join(tmp, f"{project_name}.rep", "idata")
        os.makedirs(index, exist_ok=True)
        with open(os.path.join(index, "~index.dat"), "w", encoding="utf-8") as handle:
            handle.write(f"VERSION=1\r\n/\r\n 00000000:{name}:abc\r\n")

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
            runner = headless.HeadlessRunner(
                binary=binary, project_dir=tmp,
                ghidra_home=self._fake_home(tmp))
            self._program_in_project(tmp, runner.project_name)
            headless.write_provenance(tmp, runner.project_name, binary)
            command = runner.command()
            self.assertIn("-process", command)
            self.assertNotIn("-import", command)

    def test_a_program_without_a_record_is_imported_again(self):
        """A project that does not say where its program came from.

        Nothing is known about the file in it, so the binary is imported
        again - with the file that is on disk now.
        """
        with tempfile.TemporaryDirectory() as tmp:
            binary = os.path.join(tmp, "cmd.exe")
            with open(binary, "w", encoding="utf-8") as handle:
                handle.write("MZ")
            runner = headless.HeadlessRunner(
                binary=binary, project_dir=tmp,
                ghidra_home=self._fake_home(tmp))
            self._program_in_project(tmp, runner.project_name)
            command = runner.command()
            self.assertIn("-import", command)
            self.assertIn("-overwrite", command)

    def test_a_binary_that_was_rebuilt_is_imported_again(self):
        """A program that is in the project but is not the file of today.

        The binary was rebuilt: it has the same name and the same path, and
        the program in the project is the old one. Processing it again would
        analyse the stored copy, and the addresses would be the ones of a
        file that is not there any more.
        """
        with tempfile.TemporaryDirectory() as tmp:
            binary = os.path.join(tmp, "cmd.exe")
            with open(binary, "w", encoding="utf-8") as handle:
                handle.write("MZ")
            runner = headless.HeadlessRunner(
                binary=binary, project_dir=tmp,
                ghidra_home=self._fake_home(tmp))
            self._program_in_project(tmp, runner.project_name)
            # The project remembers an older file.
            with open(headless.provenance_path(tmp, runner.project_name), "w",
                      encoding="utf-8") as handle:
                json.dump({"binary": binary, "size": 1, "mtime": 1}, handle)
            command = runner.command()
            self.assertIn("-import", command)
            self.assertIn("-overwrite", command)
            self.assertNotIn("-process", command)

    def test_a_program_that_is_current_is_processed_again(self):
        """The file has not changed, so the program in the project is the one."""
        with tempfile.TemporaryDirectory() as tmp:
            binary = os.path.join(tmp, "cmd.exe")
            with open(binary, "w", encoding="utf-8") as handle:
                handle.write("MZ")
            runner = headless.HeadlessRunner(
                binary=binary, project_dir=tmp,
                ghidra_home=self._fake_home(tmp))
            self._program_in_project(tmp, runner.project_name)
            headless.write_provenance(tmp, runner.project_name, binary)
            command = runner.command()
            self.assertIn("-process", command)
            self.assertNotIn("-overwrite", command)

    def test_the_project_carries_the_path_of_the_binary(self):
        """Two binaries with the same name do not share a project.

        Ghidra identifies a program by its file name, so a project that holds
        one of them cannot hold the other - and the second run would be
        served the analysis of the first.
        """
        first = headless.default_project_name(os.path.join("one", "cmd.exe"))
        second = headless.default_project_name(os.path.join("two", "cmd.exe"))
        self.assertNotEqual(first, second)
        self.assertTrue(first.startswith("cmd-"))
        self.assertEqual(first, headless.default_project_name(os.path.join("one", "cmd.exe")))

    def test_the_name_of_the_project_can_be_given(self):
        """The caller may name the project himself."""
        with tempfile.TemporaryDirectory() as tmp:
            binary = os.path.join(tmp, "cmd.exe")
            with open(binary, "w", encoding="utf-8") as handle:
                handle.write("MZ")
            runner = headless.HeadlessRunner(
                binary=binary, project_dir=tmp, project_name="my-project",
                ghidra_home=self._fake_home(tmp))
            self.assertEqual(runner.project_name, "my-project")

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


class HeadlessStopTests(unittest.TestCase):
    """Stopping a run: the save, the lock and the state."""

    def _runner(self, tmp, port=65431):
        binary = os.path.join(tmp, "cmd.exe")
        with open(binary, "w", encoding="utf-8") as handle:
            handle.write("MZ")
        runner = headless.HeadlessRunner(
            binary=binary, port=port, project_dir=tmp, project_name="cmd",
            ghidra_home=tmp)
        runner.instance.log = os.path.join(tmp, "run.log")
        return runner

    def test_a_refused_save_is_not_a_save(self):
        """The server refusing the save is not a save."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner(tmp)
            answer = mock.Mock(ok=False, status_code=409, text="unsaved changes")
            with mock.patch.object(headless, "api_answers", return_value=True), \
                    mock.patch("requests.post", return_value=answer):
                self.assertFalse(runner.save())

    def test_an_accepted_save_is_a_save(self):
        """A save the server accepts is a save."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner(tmp)
            answer = mock.Mock(ok=True, status_code=200, text="{}")
            with mock.patch.object(headless, "api_answers", return_value=True), \
                    mock.patch("requests.post", return_value=answer):
                self.assertTrue(runner.save())

    def test_a_dead_run_leaves_no_lock(self):
        """A run that died leaves a lock that nobody owns any more.

        The lock of a project keeps the next run out of it, so a crash that
        leaves one behind has to be cleaned up.
        """
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner(tmp)
            lock = os.path.join(tmp, "cmd.lock")
            with open(lock, "w", encoding="utf-8") as handle:
                handle.write("")
            runner.instance.pid = 999999
            runner.save = lambda: False
            with mock.patch.object(headless, "process_is_ours", return_value=False), \
                    mock.patch.object(headless, "process_alive", return_value=False):
                runner.stop()
            self.assertFalse(os.path.exists(lock))

    def test_a_live_process_that_is_not_ours_keeps_its_lock(self):
        """The lock of a live process is not ours to remove."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner(tmp)
            lock = os.path.join(tmp, "cmd.lock")
            with open(lock, "w", encoding="utf-8") as handle:
                handle.write("")
            runner.instance.pid = 999999
            runner.save = lambda: False
            with mock.patch.object(headless, "process_is_ours", return_value=False), \
                    mock.patch.object(headless, "process_alive", return_value=True):
                runner.stop()
            self.assertTrue(os.path.exists(lock))

    def test_the_stop_flag_is_removed_after_a_kill(self):
        """A run that was killed leaves no flag behind.

        The flag would stop the next run on that port as soon as it starts.
        """
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner(tmp)
            runner.instance.pid = 999999
            runner.save = lambda: False
            flag = headless.stop_file_path(runner.port)
            os.makedirs(os.path.dirname(flag), exist_ok=True)
            with open(flag, "w", encoding="utf-8") as handle:
                handle.write("stop")
            with mock.patch.object(headless, "process_is_ours", return_value=True), \
                    mock.patch.object(runner, "_child_exited", return_value=False), \
                    mock.patch("subprocess.run"):
                runner.stop(timeout=1)
            self.assertFalse(os.path.exists(flag))

    def test_a_run_that_is_already_there_is_refused(self):
        """A run that is still analysing keeps the port.

        The API is not bound yet, so the port looks free - but the run is
        there, and a second one would take its state and leave it
        untracked.
        """
        with tempfile.TemporaryDirectory() as tmp:
            binary = os.path.join(tmp, "cmd.exe")
            with open(binary, "w", encoding="utf-8") as handle:
                handle.write("MZ")
            runner = headless.HeadlessRunner(
                binary=binary, port=65432, project_dir=tmp, ghidra_home=tmp)
            remembered = headless.HeadlessInstance(port=65432, pid=4242)
            with mock.patch.object(headless, "load_state", return_value=remembered), \
                    mock.patch.object(headless, "process_is_ours", return_value=True), \
                    mock.patch.object(headless, "api_answers", return_value=False):
                with self.assertRaises(headless.HeadlessError) as caught:
                    runner.start(timeout=1)
            self.assertEqual(caught.exception.code, "HEADLESS_ALREADY_RUNNING")


class HeadlessSaveTests(unittest.TestCase):
    """Whether the analysis ended up in the project.

    In a headless run the API save is refused: the program is inside the
    transaction of the script that serves the API, and the analyzer saves
    the program when the script returns. The answer is about the analysis,
    not about the call - and the project is what answers it.
    """

    def _runner(self, tmp, port=65434):
        binary = os.path.join(tmp, "cmd.exe")
        with open(binary, "w", encoding="utf-8") as handle:
            handle.write("MZ")
        runner = headless.HeadlessRunner(
            binary=binary, port=port, project_dir=tmp, project_name="cmd",
            ghidra_home=tmp)
        runner.instance.log = os.path.join(tmp, "run.log")
        return runner

    def _content(self, tmp, name="db.1.gbf"):
        """The file that holds the content of the program in the project."""
        directory = os.path.join(tmp, "cmd.rep", "idata", "00", "~00000001.db")
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("content")
        return path

    def test_the_project_says_whether_the_content_was_written(self):
        """The content of the program in the project is the witness."""
        with tempfile.TemporaryDirectory() as tmp:
            self._content(tmp)
            self.assertTrue(
                headless.project_content_written_since(tmp, "cmd", time.time() - 60))
            self.assertFalse(
                headless.project_content_written_since(tmp, "cmd", time.time() + 60))

    def test_a_save_that_is_in_progress_is_not_a_save(self):
        """The file that a save writes while it is in progress does not count.

        It is there whether the save finished or not, and its name says so.
        """
        with tempfile.TemporaryDirectory() as tmp:
            directory = os.path.join(tmp, "cmd.rep", "idata", "00", "~00000001.db")
            os.makedirs(directory, exist_ok=True)
            with open(os.path.join(directory, "tmp14189909769944492164.ps"), "w",
                      encoding="utf-8") as handle:
                handle.write("")
            self.assertFalse(
                headless.project_content_written_since(tmp, "cmd", time.time() - 60))

    def test_a_refused_api_save_still_reports_the_save_the_analyzer_made(self):
        """The answer is about the analysis, not about the API call.

        The API save is refused, the stop is polite, the script returns, and
        the analyzer writes the content of the program: the analysis is in
        the project, and the answer says so.
        """
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner(tmp)
            runner.save = lambda: False
            runner.instance.pid = 4242

            def wait_and_save(pid, timeout):
                self._content(tmp)
                return True

            with mock.patch.dict(os.environ, {"GHYDRA_STATE_DIR": tmp}), \
                    mock.patch.object(headless, "process_is_ours", return_value=True), \
                    mock.patch.object(runner, "_wait_for_exit",
                                      side_effect=wait_and_save):
                saved = runner.stop(timeout=1)
            self.assertTrue(saved,
                            "the analysis was saved and the answer said it was not")

    def test_a_refused_api_save_without_a_write_is_not_a_save(self):
        """A run that was killed did not save the analysis."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner(tmp)
            runner.save = lambda: False
            runner.instance.pid = 4242
            with mock.patch.dict(os.environ, {"GHYDRA_STATE_DIR": tmp}), \
                    mock.patch.object(headless, "process_is_ours", return_value=True), \
                    mock.patch.object(runner, "_wait_for_exit", return_value=True):
                saved = runner.stop(timeout=1)
            self.assertFalse(saved)

    def test_the_script_stops_the_server_before_it_returns(self):
        """A headless run has to be able to end.

        The threads of the server are not daemons, and a JVM with a live
        Jetty does not exit: the run stayed alive after the analyzer had
        saved the program, and the launcher had to kill it - the polite stop
        turned into the blunt one, and the analysis of a program that was
        being saved was lost.
        """
        script = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "src", "main", "resources", "ghidra_scripts",
            "GhidraHeadlessServer.java")
        with open(script, "r", encoding="utf-8") as handle:
            body = handle.read()
        self.assertIn("handle.stop()", body,
                      "the script does not stop the server it started")
        self.assertLess(body.index("handle.stop()"), body.index("HEADLESS STOPPED"),
                        "the server is stopped after the script announced that it stopped")


class HeadlessOwnershipTests(unittest.TestCase):
    """Who owns the port, the state and the lock.

    A start that was refused must not erase the state of the run that is
    there, a port that is being claimed must not be claimed twice, and a
    lock that a live Ghidra holds must survive the death of a run.
    """

    def _runner(self, tmp, port=65433):
        binary = os.path.join(tmp, "cmd.exe")
        with open(binary, "w", encoding="utf-8") as handle:
            handle.write("MZ")
        # A Ghidra installation with the launcher in it: a run that gets as
        # far as the launcher is a run that was not refused before it.
        support = os.path.join(tmp, "support")
        os.makedirs(support, exist_ok=True)
        name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
        with open(os.path.join(support, name), "w", encoding="utf-8") as handle:
            handle.write("")
        runner = headless.HeadlessRunner(
            binary=binary, port=port, project_dir=tmp, project_name="cmd",
            ghidra_home=tmp)
        runner.instance.log = os.path.join(tmp, "run.log")
        return runner

    def test_a_refused_start_keeps_the_state_of_the_run_that_is_there(self):
        """The state on disk belongs to the run that is running.

        A start that was refused - because a run is already there - has no
        PID of its own, and the cleanup of the failed command used to erase
        the state of the run that was there: the next start would walk past
        the guard that remembers it, and two analyzers would share a project.
        """
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner(tmp)
            other = headless.HeadlessInstance(
                port=runner.port, pid=4242, binary="other.exe",
                project_dir=tmp, project_name="cmd")
            with mock.patch.dict(os.environ, {"GHYDRA_STATE_DIR": tmp}):
                headless.save_state(other)
                runner.save = lambda: False
                with mock.patch.object(headless, "process_is_ours", return_value=False):
                    runner.stop()
                remembered = headless.load_state(runner.port)
            self.assertIsNotNone(remembered, "the state of the other run was erased")
            self.assertEqual(remembered.pid, 4242)

    def test_the_port_is_claimed_before_the_child_is_launched(self):
        """Two starts that arrive together cannot both launch an analyzer.

        The claim is written before the child is launched, so the second
        start finds the port taken instead of finding it free - and the one
        that binds the API first does not end up with the state of the other
        one, which would combine the Ghidra data of one binary with the Kuna
        data of another.
        """
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner(tmp)
            claimed = []

            def fake_popen(command, **kwargs):
                remembered = headless.load_state(runner.port)
                claimed.append(bool(remembered and remembered.reserved))
                raise OSError("no launcher here")

            with mock.patch.dict(os.environ, {"GHYDRA_STATE_DIR": tmp}), \
                    mock.patch.object(headless, "api_answers", return_value=False), \
                    mock.patch.object(headless.subprocess, "Popen", side_effect=fake_popen):
                with self.assertRaises(headless.HeadlessError):
                    runner.start(timeout=1)
            self.assertEqual(claimed, [True], "the port was not claimed before the launch")
            # The claim of a child that never came up is given back.
            self.assertIsNone(headless.load_state(runner.port))

    def test_a_claim_that_nobody_took_up_is_free_again(self):
        """A claim of a process that died in between is not a claim."""
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner(tmp)
            runner.instance.reserved = True
            with mock.patch.dict(os.environ, {"GHYDRA_STATE_DIR": tmp}):
                headless.save_state(runner.instance)
                path = headless.state_path(runner.port)
                old = time.time() - headless.RESERVATION_TTL - 10
                os.utime(path, (old, old))
                self.assertFalse(headless.reservation_is_live(runner.port))

    def test_the_process_is_matched_to_its_port(self):
        """The PID of a crashed run can belong to another run.

        The marker of the script is not enough: another run of the same
        script, on another port, would be stopped by mistake - and it would
        leave a stop flag that the new run never sees.
        """
        with mock.patch.object(headless, "process_command_line",
                               return_value="analyzeHeadless.bat proj cmd -postScript "
                                           "GhidraHeadlessServer port=8193"):
            self.assertTrue(headless.process_is_ours(4242, port=8193))
            self.assertFalse(headless.process_is_ours(4242, port=8192))
        with mock.patch.object(headless, "process_command_line",
                               return_value="analyzeHeadless.bat proj cmd -postScript "
                                           "GhidraHeadlessServer port=81920"):
            # "port=8192" is not "port=81920".
            self.assertFalse(headless.process_is_ours(4242, port=8192))

    def test_the_lock_of_a_live_ghidra_survives(self):
        """A CodeBrowser that has the project open holds the lock.

        The run that was refused the project died because of that lock, and
        removing it would let a second analyzer open the project beside the
        CodeBrowser - and the project would be written by two of them.
        """
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner(tmp)
            lock = os.path.join(tmp, "cmd.lock")
            with open(lock, "w", encoding="utf-8") as handle:
                handle.write("")
            runner.instance.pid = 999999
            runner.save = lambda: False
            project = os.path.normcase(os.path.abspath(tmp)).replace("\\", "/").lower()
            with mock.patch.object(headless, "process_is_ours", return_value=False), \
                    mock.patch.object(headless, "process_alive", return_value=False), \
                    mock.patch.object(headless, "live_processes", return_value=[
                        (4242, "javaw.exe ghidra.Ghidra " + project + "/cmd")]):
                runner.stop()
            self.assertTrue(os.path.exists(lock))

    def test_the_provenance_is_written_when_the_run_is_serving(self):
        """The sidecar says which binary the project holds.

        It is written when the run is serving: a run that failed before
        that - an unexecutable launcher, a project that would not open -
        must not leave the sidecar of a binary that is not in the project,
        or the next run would analyse the old bytes again.
        """
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner(tmp)
            with mock.patch.object(headless, "api_answers", return_value=False), \
                    mock.patch.object(headless.subprocess, "Popen",
                                      side_effect=OSError("no launcher here")):
                with self.assertRaises(headless.HeadlessError):
                    runner.start(timeout=1)
            self.assertFalse(os.path.exists(headless.provenance_path(tmp, "cmd")))

    def test_the_provenance_keeps_the_sub_second_part(self):
        """A rebuild inside the same second is still a rebuild.

        The size and the second can be the same, and the project would then
        serve the old bytes while Kuna reads the new file.
        """
        with tempfile.TemporaryDirectory() as tmp:
            binary = os.path.join(tmp, "cmd.exe")
            with open(binary, "wb") as handle:
                handle.write(b"MZ")
            stamp = 1700000000
            os.utime(binary, (stamp, stamp))
            first = headless.binary_provenance(binary)
            os.utime(binary, (stamp + 0.5, stamp + 0.5))
            second = headless.binary_provenance(binary)
            self.assertEqual(first["size"], second["size"])
            self.assertEqual(first["mtime"], second["mtime"])
            self.assertNotEqual(first["mtime_ns"], second["mtime_ns"])

    def test_a_polite_stop_reports_the_save_it_got(self):
        """A save the server refused is not a save.

        The run ends on its own when it sees the flag, and the answer of
        the save is the answer of the command: "saved: true" for a save
        that did not happen is a lie the caller cannot see.
        """
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner(tmp)
            runner.instance.pid = 4242
            runner.save = lambda: False
            with mock.patch.object(headless, "process_is_ours", return_value=True), \
                    mock.patch.object(headless.HeadlessRunner, "_wait_for_exit",
                                      return_value=True):
                self.assertFalse(runner.stop())


class HeadlessReportTargetTests(unittest.TestCase):
    """Which machine and which file the report is about."""

    def test_an_address_of_this_machine_is_local(self):
        """The addresses of the machine are asked of the operating system.

        A secondary address of a LAN card and an IPv6 address that the name
        of the machine does not carry are both local, and neither is in the
        DNS of the hostname - which is why the list of the interfaces is not
        the answer.
        """
        self.assertTrue(report_module.address_is_local("127.0.0.1"))
        self.assertFalse(report_module.address_is_local("203.0.113.7"))

    def test_the_machine_by_one_of_its_addresses_is_this_machine(self):
        """The name of the machine is not the only way to name it."""
        for address in report_module.local_addresses():
            if address not in ("127.0.0.1", "::1"):
                self.assertTrue(report_module.address_is_local(address))
                self.assertTrue(report_module.is_local_host(address))
                return
        self.skipTest("this machine has no address beyond the loopback")

    def test_the_program_is_matched_by_its_full_path(self):
        """Two files with the same name are two files.

        A CodeBrowser that serves /a/foo.exe is not serving the /b/foo.exe
        that the report asks about, and a report that combined the Ghidra
        addresses of the first with the Kuna output of the second would be
        about a file nobody has.
        """

        class _Client:
            def __init__(self, path):
                self.path = path

            def get(self, endpoint, **kwargs):
                return {"result": {"path": self.path}}

        self.assertTrue(report_module._serves_binary(
            _Client("/C:/bin/foo.exe"), "C:\\bin\\foo.exe"))
        self.assertFalse(report_module._serves_binary(
            _Client("/C:/a/foo.exe"), "C:\\b\\foo.exe"))


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

    def test_a_windows_path_is_read_on_posix(self):
        """The backslash is a separator everywhere.

        A Windows path handed to a POSIX machine still has a file name at the
        end, and Ghidra identifies a program by that name.
        """
        self.assertEqual(headless.binary_name("C:\\bin\\cmd.exe"), "cmd.exe")
        self.assertEqual(headless.binary_name("C:/bin/cmd.exe"), "cmd.exe")
        self.assertEqual(headless.slug_for("C:\\bin\\cmd.exe"), "cmd")

    def test_a_port_that_is_not_a_port_is_refused(self):
        """The port is checked before anything is started.

        The script falls back to 8192 for a port it cannot use, and the wait
        would keep polling a port that was never bound.
        """
        with tempfile.TemporaryDirectory() as tmp:
            binary = os.path.join(tmp, "cmd.exe")
            with open(binary, "w", encoding="utf-8") as handle:
                handle.write("MZ")
            for port in (0, -1, 70000):
                with self.assertRaises(headless.HeadlessError) as caught:
                    headless.HeadlessRunner(binary=binary, port=port)
                self.assertEqual(caught.exception.code, "HEADLESS_BAD_PORT")

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

    def test_the_functions_are_chosen_without_kuna(self):
        """A stripped binary read without Kuna still has functions to show.

        Nothing ranked anything: Kuna is off, and every name is one Ghidra
        made up. The report still has to say something.
        """
        ghidra = self._ghidra()
        ghidra["functions"] = [
            {"name": "FUN_140001000", "address": "140001000", "signature": "void f()"},
            {"name": "FUN_140002000", "address": "140002000",
             "signature": "void g(int a)", "parameterCount": 1},
        ]
        chosen = report_module.interesting_functions(
            ghidra, {"enabled": False, "index": []}, 10)
        self.assertEqual(len(chosen), 2)
        self.assertEqual(chosen[0]["address"], "140002000")

    def test_the_thunks_are_left_out_of_the_fallback(self):
        """A thunk is a jump, not code worth reading."""
        ghidra = self._ghidra()
        ghidra["functions"] = [
            {"name": "FUN_140001000", "address": "140001000", "isThunk": True},
            {"name": "FUN_140002000", "address": "140002000"},
        ]
        chosen = report_module.interesting_functions(
            ghidra, {"enabled": False, "index": []}, 10)
        self.assertEqual([item["address"] for item in chosen], ["140002000"])

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

    def test_the_markdown_shows_the_code_of_both_tools(self):
        """The document shows what each of the two decompilers recovered.

        The JSON carries the C that Kuna read out of the export; the Markdown
        a human reads has to show it too, or the promise of the report is
        half kept.
        """
        report = {
            "binary": "C:\\bin\\cmd.exe",
            "generated_at": 0,
            "ghidra": self._ghidra(),
            "kuna": self._kuna(),
            "functions": report_module.interesting_functions(
                self._ghidra(), self._kuna(), 10),
            "decompiled": [{"address": "140001000", "name": "FUN_140001000",
                            "code": "void f() { }"}],
            "kuna_code": [{"address": "140001000", "name": "sub_140001000",
                           "code": "int f(void) { }"}],
            "annotations": {"annotations": []},
        }
        text = report_module.render_markdown(report)
        self.assertIn("void f() { }", text)
        self.assertIn("int f(void) { }", text)

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


class ReportCommandTests(unittest.TestCase):
    """The report command talks to the instance the CLI chose."""

    class _Ctx:
        def __init__(self, obj):
            self.obj = obj

    def test_the_report_goes_to_the_endpoint_of_the_cli(self):
        """The host and the port come from the client the CLI built.

        A report that went to localhost while the CLI was pointed at another
        machine would say one thing and show another.
        """
        client = mock.Mock(host="192.168.0.10", port=8200)
        ctx = self._Ctx({"client": client})
        self.assertEqual(report_cli.target_endpoint(ctx), ("192.168.0.10", 8200))

    def test_the_options_of_the_command_win(self):
        """What the command is told is what it uses."""
        client = mock.Mock(host="192.168.0.10", port=8200)
        ctx = self._Ctx({"client": client})
        self.assertEqual(report_cli.target_endpoint(ctx, "localhost", 8192),
                         ("localhost", 8192))

    def test_without_a_client_the_default_is_used(self):
        """A command without the CLI around still has somewhere to go."""
        ctx = self._Ctx({})
        self.assertEqual(report_cli.target_endpoint(ctx), ("127.0.0.1", 8192))

    def test_a_port_of_zero_is_not_replaced(self):
        """A port of 0 is a port that is not a port, and the runner says so."""
        client = mock.Mock(host="192.168.0.10", port=8200)
        ctx = self._Ctx({"client": client})
        self.assertEqual(report_cli.target_endpoint(ctx, None, 0)[1], 0)


class ReportTargetTests(unittest.TestCase):
    """Where the report goes, and what it leaves behind."""

    def test_a_remote_target_does_not_start_a_run(self):
        """A headless run serves this machine, so a remote target is refused.

        Starting one anyway would wait for an answer that cannot come - the
        local server is not the remote one - and leave the analyzer behind.
        """
        request = report_module.ReportRequest(
            binary=os.path.abspath(__file__), host="192.168.0.10", port=8192)
        with mock.patch.object(report_module, "api_answers", return_value=False), \
                mock.patch.object(report_module, "HeadlessRunner") as runner:
            with self.assertRaises(report_module.ReportError) as caught:
                report_module.build_report(request)
        self.assertEqual(caught.exception.code, "REPORT_NO_INSTANCE")
        runner.assert_not_called()

    def test_a_run_that_does_not_come_up_is_not_left_behind(self):
        """The analyzer of a start that failed is stopped."""
        request = report_module.ReportRequest(
            binary=os.path.abspath(__file__), host="127.0.0.1", port=8192)
        runner = mock.Mock()
        runner.start.side_effect = headless.HeadlessError(
            "the run ended", code="HEADLESS_DIED")
        with mock.patch.object(report_module, "api_answers", return_value=False), \
                mock.patch.object(report_module, "HeadlessRunner", return_value=runner):
            with self.assertRaises(report_module.ReportError) as caught:
                report_module.build_report(request)
        self.assertEqual(caught.exception.code, "HEADLESS_DIED")
        runner.stop.assert_called()

    def test_the_name_of_the_machine_is_local(self):
        """The machine by its own name is this machine.

        The server binds every interface, so a run started here answers to
        the name of the machine as well.
        """
        import socket
        self.assertTrue(report_module.is_local_host(socket.gethostname()))
        self.assertTrue(report_module.is_local_host("localhost"))
        self.assertFalse(report_module.is_local_host("192.0.2.1"))

    def test_a_run_that_does_not_come_up_is_stopped(self):
        """The analyzer of a start that failed is not left behind.

        The command reports the failure and exits, but the analyzer was
        already spawned - and it would keep the project busy and might
        start serving later.
        """
        from click.testing import CliRunner
        from ghydra.cli import headless as headless_cli

        class _Formatter:
            def format_error(self, exc):
                return str(exc)

        runner = mock.Mock()
        runner.start.side_effect = headless.HeadlessError(
            "the run ended", code="HEADLESS_DIED")
        with mock.patch.object(headless_cli, "HeadlessRunner", return_value=runner):
            result = CliRunner().invoke(
                headless_cli.headless, ["start", "C:\\bin\\cmd.exe"],
                obj={"formatter": _Formatter()})
        self.assertEqual(result.exit_code, 1)
        runner.stop.assert_called()


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
