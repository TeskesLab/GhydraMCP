"""`ghydra doctor` — the command that says what is wrong with this machine.

The doctor was the one command with **no test at all**, and it is the one a user
runs when something does not work: it names the Ghidra installation, the JDK it
needs, the extension, the port, the projects, the API, Kuna and the x64dbg plugin,
and every finding carries the command that fixes it.

So the properties worth pinning are the ones a user would notice being wrong:

* a missing installation is a **failure**, and it says how to point at one;
* a JDK that is too old is a failure, because the installation's VM arguments
  carry flags only the newer JVMs take;
* an extension built for another version is a failure — Ghidra will not load it;
* a locked project is a warning, and the project is named **once**, whatever
  lock files the run left behind;
* every finding that is not "ok" carries a hint that says what to do.
"""

import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ghydra import doctor  # noqa: E402
from ghydra.config.defaults import GhidraConfig  # noqa: E402


class ProjectCheckTests(unittest.TestCase):
    """The locked projects: the one a run has open."""

    def _directory(self, *names):
        directory = tempfile.mkdtemp(prefix="ghydra-doctor-test-")
        for name in names:
            open(os.path.join(directory, name), "w").close()
        return directory

    def test_a_locked_project_is_a_warning(self):
        directory = self._directory("where-5d97bdfd.lock")
        check = doctor.check_project(directory)
        self.assertEqual(doctor.STATUS_WARN, check.status)
        self.assertIn("where-5d97bdfd", check.detail)
        self.assertTrue(check.hint, "a warning has to say what to do")

    def test_the_backup_lock_file_is_the_same_project(self):
        """Ghidra leaves a `.lock` and a `.lock~`; that is one project."""
        directory = self._directory("where-5d97bdfd.lock",
                                    "where-5d97bdfd.lock~")
        check = doctor.check_project(directory)
        self.assertEqual(1, check.detail.count("where-5d97bdfd"),
                         f"the project is named twice: {check.detail}")

    def test_two_projects_are_both_named(self):
        directory = self._directory("a.lock", "b.lock")
        check = doctor.check_project(directory)
        self.assertIn("a", check.detail)
        self.assertIn("b", check.detail)

    def test_a_free_directory_is_ok(self):
        directory = self._directory("where-5d97bdfd.rep")
        check = doctor.check_project(directory)
        self.assertEqual(doctor.STATUS_OK, check.status)


class GhidraCheckTests(unittest.TestCase):
    """The installation, the JDK and the extension."""

    def test_a_missing_installation_is_a_failure_with_a_way_out(self):
        with mock.patch("ghydra.launcher.find_ghidra_home",
                        side_effect=doctor.ghidra_launcher.LauncherError(
                            "no Ghidra installation was found")):
            check = doctor.check_ghidra()
        self.assertEqual(doctor.STATUS_FAIL, check.status)
        self.assertIn("GHIDRA_HOME", check.hint)

    def test_an_installation_without_the_utility_jar_is_a_warning(self):
        with tempfile.TemporaryDirectory() as home:
            with mock.patch("ghydra.launcher.find_ghidra_home",
                            return_value=home):
                with mock.patch("ghydra.launcher.ghidra_version",
                                return_value="12.2"):
                    check = doctor.check_ghidra(home)
        self.assertEqual(doctor.STATUS_WARN, check.status)
        self.assertIn("Utility.jar", check.detail)

    def test_a_too_old_jdk_is_a_failure(self):
        with mock.patch("ghydra.launcher.find_java_home",
                        return_value="C:/jdk17"):
            with mock.patch("ghydra.launcher.java_version",
                            return_value=(17, 0, 1)):
                with mock.patch("ghydra.launcher.required_jdk_major",
                                return_value=21):
                    check = doctor.check_jdk("C:/ghidra")
        self.assertEqual(doctor.STATUS_FAIL, check.status)
        self.assertIn("21", check.detail)

    def test_a_new_enough_jdk_is_ok(self):
        with mock.patch("ghydra.launcher.find_java_home",
                        return_value="C:/jdk25"):
            with mock.patch("ghydra.launcher.java_version",
                            return_value=(25, 0, 1)):
                with mock.patch("ghydra.launcher.required_jdk_major",
                                return_value=21):
                    check = doctor.check_jdk("C:/ghidra")
        self.assertEqual(doctor.STATUS_OK, check.status)
        self.assertIn("21", check.detail)

    def test_an_extension_for_another_version_is_a_failure(self):
        with mock.patch("ghydra.launcher.extension_status", return_value={
                "installed": True, "matches": False, "version": "3.35.0",
                "expected_version": "12.2", "directory": "C:/ext"}):
            check = doctor.check_extension("C:/ghidra")
        self.assertEqual(doctor.STATUS_FAIL, check.status)
        self.assertIn("12.2", check.detail)
        self.assertTrue(check.hint)

    def test_a_missing_extension_is_a_failure(self):
        with mock.patch("ghydra.launcher.extension_status", return_value={
                "installed": False, "directory": "C:/ext"}):
            check = doctor.check_extension("C:/ghidra")
        self.assertEqual(doctor.STATUS_FAIL, check.status)


class PortAndApiTests(unittest.TestCase):
    """The port and the instance."""

    def test_a_port_taken_by_something_else_is_a_warning(self):
        """A port taken by something that is not the API is not the API's fault."""
        with mock.patch("ghydra.doctor.api_answers", return_value=False):
            with mock.patch("ghydra.doctor.port_is_open", return_value=True):
                check = doctor.check_port("127.0.0.1", 8192)
        self.assertEqual(doctor.STATUS_WARN, check.status)
        self.assertTrue(check.hint)

    def test_a_free_port_is_ok(self):
        with mock.patch("ghydra.doctor.api_answers", return_value=False):
            with mock.patch("ghydra.doctor.port_is_open", return_value=False):
                check = doctor.check_port("127.0.0.1", 8192)
        self.assertEqual(doctor.STATUS_OK, check.status)

    def test_a_port_serving_the_api_is_ok(self):
        with mock.patch("ghydra.doctor.api_answers", return_value=True):
            check = doctor.check_port("127.0.0.1", 8192)
        self.assertEqual(doctor.STATUS_OK, check.status)

    def test_no_instance_is_a_warning_not_a_failure(self):
        """It is normal: a headless run starts one when it is needed."""
        with mock.patch("ghydra.doctor.api_answers", return_value=False):
            check = doctor.check_api("127.0.0.1", 8192)
        self.assertEqual(doctor.STATUS_WARN, check.status)
        self.assertIn("headless", check.hint)


class ReportTests(unittest.TestCase):
    """The report: every check, in order, and every finding with a way out."""

    def test_every_check_is_present_and_in_order(self):
        with mock.patch.object(doctor, "check_ghidra",
                               return_value=doctor.Check("ghidra", doctor.STATUS_OK, "g")):
            with mock.patch.object(doctor, "check_jdk",
                                   return_value=doctor.Check("jdk", doctor.STATUS_OK, "j")):
                with mock.patch.object(doctor, "check_extension",
                                       return_value=doctor.Check("extension", doctor.STATUS_OK, "e")):
                    with mock.patch.object(doctor, "check_config",
                                           return_value=doctor.Check("config", doctor.STATUS_OK, "c")):
                        with mock.patch.object(doctor, "check_port",
                                               return_value=doctor.Check("port", doctor.STATUS_OK, "p")):
                            with mock.patch.object(doctor, "check_project",
                                                   return_value=doctor.Check("project", doctor.STATUS_OK, "pr")):
                                with mock.patch.object(doctor, "check_api",
                                                       return_value=doctor.Check("api", doctor.STATUS_OK, "a")):
                                    with mock.patch.object(doctor, "check_kuna",
                                                           return_value=doctor.Check("kuna", doctor.STATUS_OK, "k")):
                                        with mock.patch.object(doctor, "check_x64dbg",
                                                               return_value=doctor.Check("x64dbg", doctor.STATUS_OK, "x")):
                                            report = doctor.run_checks(GhidraConfig())
        names = [check.name for check in report.checks]
        self.assertEqual(sorted(names, key=doctor.CHECK_ORDER.index), names)
        self.assertEqual(9, len(names))

    def test_every_finding_the_doctor_builds_carries_a_hint(self):
        """A finding without a way out is a dead end, and the doctor promises
        that every problem carries the command that solves it."""
        cases = (
            lambda: doctor.check_api("127.0.0.1", 8192),
            lambda: doctor.check_config(GhidraConfig()),
            lambda: doctor.check_kuna(GhidraConfig()),
        )
        with mock.patch("ghydra.doctor.api_answers", return_value=False):
            with mock.patch("ghydra.launcher.find_ghidra_home",
                            side_effect=doctor.ghidra_launcher.LauncherError(
                                "no installation")):
                cases = cases + (
                    lambda: doctor.check_ghidra(),
                )
            for build in cases:
                check = build()
                if check.status == doctor.STATUS_OK:
                    continue
                self.assertTrue(check.hint,
                                f"{check.name} has no hint: {check.detail}")

    def test_the_text_rendering_carries_the_hint(self):
        check = doctor.Check("api", doctor.STATUS_WARN, "nothing is serving",
                             "start a headless run")
        report = doctor.Report()
        report.add(check)
        text = doctor.render_text(report)
        self.assertIn("nothing is serving", text)
        self.assertIn("start a headless run", text)

    def test_the_failures_and_the_warnings_are_counted(self):
        report = doctor.Report()
        report.add(doctor.Check("ghidra", doctor.STATUS_FAIL, "no", "hint"))
        report.add(doctor.Check("api", doctor.STATUS_WARN, "none", "hint"))
        report.add(doctor.Check("port", doctor.STATUS_OK, "free"))
        self.assertEqual(1, len(report.failures))
        self.assertEqual(1, len(report.warnings))


if __name__ == "__main__":
    unittest.main()
