"""The launcher: the JDK Ghidra runs on, and the command it runs.

The launcher is what the headless runner and the doctor both stand on: it finds
the installation, reads the JDK version the installation asks for, picks a JDK
that is new enough, and builds the JVM invocation.

It had **no test of its own** — the doctor mocked it, and nothing exercised it.

The rule that matters is the one about the layers: an **explicit** JDK that is
too old is an error, because the caller asked for that one; a JDK that the
environment merely points at is only a place the search did not stop.
"""

import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ghydra import launcher  # noqa: E402
from ghydra.launcher import LauncherError  # noqa: E402


def _jdk(directory, major=21, minor=0):
    """A fake JDK: the `release` file is where the version is read from."""
    os.makedirs(os.path.join(directory, "bin"), exist_ok=True)
    with open(os.path.join(directory, "release"), "w", encoding="utf-8") as handle:
        handle.write(f'JAVA_VERSION="{major}.{minor}"\n'
                     f'OS_NAME="Windows"\n')
    return directory


def _installation(directory, version="12.2", java_min=21):
    """A fake Ghidra installation, with the properties Ghidra ships."""
    ghidra = os.path.join(directory, "Ghidra")
    os.makedirs(ghidra, exist_ok=True)
    with open(os.path.join(ghidra, "application.properties"), "w",
              encoding="utf-8") as handle:
        handle.write(f"application.version={version}\n")
        handle.write(f"application.java.min={java_min}\n")
        handle.write("application.release.marking=PUBLIC\n")
    return directory


class PropertiesTests(unittest.TestCase):
    """The properties file Ghidra ships."""

    def test_the_version_is_read(self):
        with tempfile.TemporaryDirectory() as home:
            installation = _installation(home)
            self.assertEqual("12.2", launcher.ghidra_version(installation))
            self.assertEqual("PUBLIC", launcher.release_marking(installation))

    def test_the_required_jdk_is_the_minimum(self):
        with tempfile.TemporaryDirectory() as home:
            installation = _installation(home, java_min=25)
            self.assertEqual(25, launcher.required_jdk_major(installation))

    def test_the_maximum_is_used_when_there_is_no_minimum(self):
        with tempfile.TemporaryDirectory() as home:
            ghidra = os.path.join(home, "Ghidra")
            os.makedirs(ghidra, exist_ok=True)
            with open(os.path.join(ghidra, "application.properties"), "w",
                      encoding="utf-8") as handle:
                handle.write("application.java.max=21\n")
            self.assertEqual(21, launcher.required_jdk_major(home))

    def test_a_malformed_properties_file_is_not_fatal(self):
        """A properties file is configuration, not a contract."""
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, "a.properties")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("# a comment\n"
                             "! another comment\n"
                             "key=value\n"
                             "no equals here\n"
                             "= no key\n"
                             "spaced = value \n")
            values = launcher.read_properties(path)
            self.assertEqual("value", values["key"])
            self.assertEqual("value", values["spaced"])
            self.assertNotIn("", values)

    def test_a_missing_file_is_no_properties(self):
        self.assertEqual({}, launcher.read_properties("/no/such/file.properties"))


class JavaVersionTests(unittest.TestCase):
    """The version, read from the file the JDK ships."""

    def test_the_release_file_is_read(self):
        with tempfile.TemporaryDirectory() as home:
            _jdk(home, 21, 0)
            self.assertEqual((21, 0), launcher.java_version(home))

    def test_a_minor_version_is_read(self):
        with tempfile.TemporaryDirectory() as home:
            _jdk(home, 17, 0, )
            with open(os.path.join(home, "release"), "w",
                      encoding="utf-8") as handle:
                handle.write('JAVA_VERSION="17.0.13"\n')
            self.assertEqual((17, 0), launcher.java_version(home))

    def test_a_directory_without_a_release_file_has_no_version(self):
        with tempfile.TemporaryDirectory() as home:
            self.assertIsNone(launcher.java_version(home))


class FindJavaHomeTests(unittest.TestCase):
    """The layers, and what happens when one is too old."""

    def _hermetic(self):
        """No Ghidra's own choice and no installed JDKs: only what the test gives."""
        return (mock.patch("ghydra.launcher._launch_support_jdk",
                           return_value=None),
                mock.patch("ghydra.launcher._jdk_candidates",
                           return_value=[]))

    def test_the_requested_jdk_is_used(self):
        with tempfile.TemporaryDirectory() as home:
            wanted = _jdk(os.path.join(home, "wanted"), 21)
            support, candidates = self._hermetic()
            with support, candidates:
                self.assertEqual(os.path.abspath(wanted),
                                 launcher.find_java_home(explicit=wanted))

    def test_a_requested_jdk_that_is_too_old_is_an_error(self):
        """The caller asked for that one: substituting another is not allowed.

        The installation's VM arguments carry flags that only the newer JVMs
        take, so a too-old JDK dies with a message about a flag rather than
        about the JDK. Silently running a different one is worse.
        """
        with tempfile.TemporaryDirectory() as home:
            too_old = _jdk(os.path.join(home, "old"), 17)
            newer = _jdk(os.path.join(home, "new"), 21)
            support, candidates = self._hermetic()
            with support, candidates:
                with self.assertRaises(LauncherError) as caught:
                    launcher.find_java_home(explicit=too_old,
                                           required_major=21)
            self.assertIn("JDK 21", str(caught.exception))
            self.assertIn(too_old, str(caught.exception))
            # The newer one was there, and was not used: that is the point.
            self.assertTrue(os.path.isdir(newer))

    def test_an_environment_jdk_that_is_too_old_is_only_a_place_to_stop(self):
        """`JAVA_HOME` is a hint, not an order: the search goes on."""
        with tempfile.TemporaryDirectory() as home:
            old = _jdk(os.path.join(home, "old"), 17)
            new = _jdk(os.path.join(home, "new"), 21)
            # The installed JDKs are the last layer, so the search has somewhere
            # to go after the environment pointed at one that is too old.
            with mock.patch("ghydra.launcher._launch_support_jdk",
                            return_value=None):
                with mock.patch("ghydra.launcher._jdk_candidates",
                                return_value=[new]):
                    with mock.patch.dict(os.environ,
                                         {launcher.ENV_JAVA_HOME: old}):
                        found = launcher.find_java_home(required_major=21)
            self.assertEqual(os.path.abspath(new), found)

    def test_the_configuration_comes_before_the_environment(self):
        with tempfile.TemporaryDirectory() as home:
            configured = _jdk(os.path.join(home, "configured"), 21)
            env = _jdk(os.path.join(home, "env"), 21)
            support, candidates = self._hermetic()
            with support, candidates:
                with mock.patch.dict(os.environ,
                                     {launcher.ENV_JAVA_HOME: env}):
                    found = launcher.find_java_home(configured=[configured],
                                                    required_major=21)
            self.assertEqual(os.path.abspath(configured), found)

    def test_no_jdk_at_all_is_an_error_that_says_what_to_do(self):
        support, candidates = self._hermetic()
        with support, candidates:
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaises(LauncherError) as caught:
                    launcher.find_java_home(required_major=21)
        self.assertIn("JAVA_HOME", str(caught.exception))

    def test_a_jdk_with_no_version_is_skipped(self):
        with tempfile.TemporaryDirectory() as home:
            broken = os.path.join(home, "broken")
            os.makedirs(broken, exist_ok=True)
            good = _jdk(os.path.join(home, "good"), 21)
            support, candidates = self._hermetic()
            with support, candidates:
                found = launcher.find_java_home(configured=[broken, good],
                                                required_major=21)
            self.assertEqual(os.path.abspath(good), found)


class PathTests(unittest.TestCase):
    """The names and the splits."""

    def test_a_windows_path_has_a_name_on_posix(self):
        """Ghidra identifies a program by that name."""
        self.assertEqual("cmd.exe", launcher.binary_name("C:\\bin\\cmd.exe"))
        self.assertEqual("cmd.exe", launcher.binary_name("/usr/bin/cmd.exe"))

    def test_the_options_split_on_the_spaces(self):
        self.assertEqual(["-Xmx2G", "-XX:+UseG1GC"],
                         launcher._split_options("-Xmx2G -XX:+UseG1GC"))

    def test_an_empty_options_string_is_no_options(self):
        self.assertEqual([], launcher._split_options(""))


if __name__ == "__main__":
    unittest.main()
