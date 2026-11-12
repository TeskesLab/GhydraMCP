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
        handle.write("application.release.name=PUBLIC\n")
    return directory


class PropertiesTests(unittest.TestCase):
    """The properties file Ghidra ships."""

    def test_the_version_is_read(self):
        with tempfile.TemporaryDirectory() as home:
            installation = _installation(home)
            self.assertEqual("12.2", launcher.ghidra_version(installation))
            self.assertEqual("PUBLIC", launcher.release_name(installation))

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


class ExtensionLocationTests(unittest.TestCase):
    def test_fresh_worker_extension_path_uses_the_native_dotted_version(self):
        with tempfile.TemporaryDirectory() as root:
            installation = _installation(os.path.join(root, "installation"), version="12.1.2")
            home = os.path.join(root, "fresh-home")
            with mock.patch.dict(os.environ, {"HOME": home, "XDG_CONFIG_HOME": os.path.join(home, "config")},
                                 clear=True):
                self.assertEqual(
                    os.path.join(home, "config", "ghidra", "ghidra_12.1.2_PUBLIC", "Extensions", "Ghydra"),
                    launcher.extension_dir(installation))

    def test_known_installation_does_not_reuse_another_versions_settings(self):
        with tempfile.TemporaryDirectory() as root:
            installation = _installation(os.path.join(root, "installation"), version="12.1.2")
            config = os.path.join(root, "config")
            os.makedirs(os.path.join(config, "ghidra", "ghidra_11.4.3_PUBLIC"))
            with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": config}, clear=True):
                self.assertEqual(
                    os.path.join(config, "ghidra", "ghidra_12.1.2_PUBLIC", "Extensions", "Ghydra"),
                    launcher.extension_dir(installation))


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


class HeadlessCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        utility = os.path.join(self.root, "Ghidra", "Framework", "Utility", "lib")
        os.makedirs(utility)
        with open(os.path.join(utility, "Utility.jar"), "wb") as handle:
            handle.write(b"synthetic")
        patcher = mock.patch.object(launcher, "vm_args", return_value=[])
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.dict(os.environ, {"HOME": self.root}, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def command(self, binary="", **kwargs):
        return launcher.headless_command(
            self.root, self.root, os.path.join(self.root, "projects"), "analysis",
            binary, 8192, script="GhidraHeadlessServer", script_args=["port=8192"], **kwargs)

    def test_empty_script_run_has_local_project_and_no_binary_operation(self):
        command = self.command(empty=True, connections_dir="/operator/worker-store",
                               repository_profile="opaque-profile")
        analyzer = command.index("ghidra.app.util.headless.AnalyzeHeadless")
        self.assertEqual([os.path.join(self.root, "projects"), "analysis",
                          "-postScript", "GhidraHeadlessServer", "port=8192"], command[analyzer + 1:])
        self.assertIn("-Dghydra.connections.dir=/operator/worker-store", command)
        for obsolete in ("-import", "-process", "-connect", "-p", "-keystore", "-commit", "-readOnly"):
            self.assertNotIn(obsolete, command)
        self.assertFalse(any("initial-profile" in argument for argument in command))

    def test_ordinary_binary_import_process_and_overwrite_remain_distinct(self):
        binary = os.path.join(self.root, "a binary.exe")
        imported = self.command(binary)
        self.assertEqual(binary, imported[imported.index("-import") + 1])
        self.assertNotIn("-process", imported)
        overwritten = self.command(binary, overwrite=True)
        self.assertIn("-overwrite", overwritten)
        processed = self.command(binary, process=True)
        self.assertEqual("a binary.exe", processed[processed.index("-process") + 1])
        self.assertNotIn("-import", processed)
        self.assertNotIn("-overwrite", processed)

    def test_empty_run_refuses_binary_operations_or_missing_script(self):
        for options in ({"binary": "local.bin"}, {"process": True}, {"overwrite": True}):
            with self.subTest(options=options), self.assertRaises(LauncherError):
                self.command(empty=True, **options)
        with self.assertRaises(LauncherError):
            launcher.headless_command(self.root, self.root, self.root, "empty", "", 8192, empty=True)

    def test_repository_bootstrap_never_accepts_arbitrary_native_extras(self):
        with self.assertRaises(LauncherError):
            self.command(empty=True, repository_profile="approved", extra=["-preScript", "evil.java"])
        with self.assertRaises(LauncherError):
            launcher.headless_command(
                self.root, self.root, self.root, "empty", "", 8192,
                empty=True, repository_profile="approved", script="AnotherScript")


if __name__ == "__main__":
    unittest.main()
