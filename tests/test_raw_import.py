"""Raw imports preserve native arguments, mapping identity and saved contexts."""

import hashlib
import json
import os
import tempfile
import unittest
from unittest import mock

from click.testing import CliRunner

from ghydra import headless, launcher, sessions
from ghydra.cli import headless as headless_cli
from ghydra.cli import session as session_cli
from ghydra.core.raw_import import normalize_raw_import, raw_import_arguments


RAW = {"raw": True, "language_id": "ARM:LE:32:v7", "image_base": "0x8000000",
       "compiler_spec": ""}


class RawImportOptionsTests(unittest.TestCase):
    def test_auto_is_unchanged(self):
        self.assertEqual({}, normalize_raw_import())
        self.assertEqual([], raw_import_arguments({}))

    def test_unsigned_addresses_are_canonical(self):
        for value, expected in (("0", "0x0"), ("00016", "0x10"), ("0XABCD", "0xabcd"),
                                ("18446744073709551615", "0xffffffffffffffff")):
            with self.subTest(value=value):
                result = normalize_raw_import(True, "ARM:LE:32:v7", value)
                self.assertEqual(expected, result["image_base"])
                self.assertEqual("", result["compiler_spec"])
                self.assertEqual(result, normalize_raw_import(**result))

    def test_native_language_variants_with_spaces_remain_one_token(self):
        language = "x86:LE:32:System Management Mode"
        options = normalize_raw_import(True, language, "0x1000", "default")
        self.assertEqual(["-loader", "BinaryLoader", "-processor", language,
                          "-loader-baseAddr", "0x1000", "-cspec", "default",
                          "-preScript", "GhydraRawImport.java", "0x1000"],
                         raw_import_arguments(options))

    def test_native_mixed_endian_language_remains_one_token(self):
        for language in ("ARM:LEBE:32:v7LEInstruction", "ARM:LEBE:32:v8LEInstruction"):
            with self.subTest(language=language):
                options = normalize_raw_import(True, language, "0x1000")
                arguments = raw_import_arguments(options)
                self.assertEqual(language, arguments[arguments.index("-processor") + 1])
                self.assertEqual(1, arguments.count(language))

    def test_native_default_compiler_is_not_overridden(self):
        self.assertNotIn("-cspec", raw_import_arguments(RAW))

    def test_orphan_options_are_rejected_even_when_empty(self):
        for field in ("language_id", "image_base", "compiler_spec"):
            for value in ("", "default"):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    normalize_raw_import(**{field: value})

    def test_invalid_raw_values_are_rejected(self):
        invalid = [{"raw": value} for value in (None, 0, 1, "true")]
        invalid += [{"language_id": value} for value in
                    (None, "", "ARM", "ARM:LE:32", "ARM: :32:v7", "ARM:LE:0:v7",
                     "ARM:LE:32:v7:extra",
                     "ARM:LE:x:v7", "-processor:LE:32:v7", "ARM:LE:32:v7\n",
                     "ARM:LE:32:tab\tmode", " ARM:LE:32:v7", 123)]
        invalid += [{"image_base": value} for value in
                    (None, "", "-1", "+1", " 1", "1 ", "0x", "0xgg", "1_000",
                     "0x10000000000000000", "18446744073709551616", 0, True)]
        invalid += [{"compiler_spec": value} for value in
                    (" ", "-postScript", "gcc\n", "gcc\x7f", 123)]
        for update in invalid:
            with self.subTest(update=update), self.assertRaises(ValueError):
                normalize_raw_import(**{**RAW, **update})


class RawRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = self.temp.name
        self.home = os.path.join(self.root, "ghidra")
        support = os.path.join(self.home, "support")
        os.makedirs(support)
        native_launcher = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
        with open(os.path.join(support, native_launcher), "w", encoding="utf-8") as handle:
            handle.write("")
        self.binary = os.path.join(self.root, "recognized.exe")
        with open(self.binary, "wb") as handle:
            handle.write(b"MZ\x00\x00raw bytes despite recognized magic")
        self.projects = os.path.join(self.root, "projects")
        os.makedirs(self.projects)
        self.state = mock.patch.dict(os.environ, {"GHYDRA_STATE_DIR": os.path.join(self.root, "state")})
        self.state.start()
        self.addCleanup(self.state.stop)

    def runner(self, options=None, **kwargs):
        return headless.HeadlessRunner(binary=self.binary, project_dir=self.projects,
                                       ghidra_home=self.home, **(RAW if options is None else options),
                                       **kwargs)

    def program(self, runner):
        index_dir = os.path.join(self.projects, runner.project_name + ".rep", "idata")
        os.makedirs(index_dir, exist_ok=True)
        with open(os.path.join(index_dir, "~index.dat"), "w", encoding="utf-8") as handle:
            handle.write("VERSION=1\n/\n 00000000:recognized.exe:abc\n")

    def test_raw_default_identity_separates_every_mapping_and_auto(self):
        auto = headless.default_project_name(self.binary)
        expected_hash = hashlib.sha256(json.dumps(RAW, sort_keys=True,
                                                  separators=(",", ":")).encode()).hexdigest()[:12]
        self.assertEqual(auto + "-raw-" + expected_hash, self.runner().project_name)
        names = {auto, self.runner().project_name}
        for field, value in (("language_id", "ARM:BE:32:v7"), ("image_base", "0x0"),
                             ("compiler_spec", "default")):
            names.add(self.runner({**RAW, field: value}).project_name)
        self.assertEqual(5, len(names))
        self.assertEqual(self.runner().project_name,
                         self.runner({**RAW, "image_base": "134217728"}).project_name)

    def test_recognized_magic_still_forces_binary_loader(self):
        command = self.runner().command()
        self.assertEqual(self.binary, command[command.index("-import") + 1])
        self.assertEqual("BinaryLoader", command[command.index("-loader") + 1])
        self.assertEqual(RAW["language_id"], command[command.index("-processor") + 1])
        self.assertEqual(RAW["image_base"], command[command.index("-loader-baseAddr") + 1])
        pre_script = command.index("-preScript")
        self.assertEqual(["GhydraRawImport.java", RAW["image_base"]],
                         command[pre_script + 1:pre_script + 3])
        self.assertLess(pre_script, command.index("-postScript"))
        self.assertNotIn("-cspec", command)
        self.assertNotIn("-loader", self.runner({}).command())
        self.assertNotIn("-preScript", self.runner({}).command())

    def test_java_launcher_receives_the_same_typed_options(self):
        utility = os.path.join(self.home, "Ghidra", "Framework", "Utility", "lib", "Utility.jar")
        os.makedirs(os.path.dirname(utility))
        with open(utility, "wb") as handle:
            handle.write(b"")
        with mock.patch.object(launcher, "vm_args", return_value=[]), \
                mock.patch.object(headless.HeadlessRunner, "resolve_java_home", return_value=self.home):
            command = self.runner({**RAW, "compiler_spec": "default"}).command()
        self.assertIn("ghidra.app.util.headless.AnalyzeHeadless", command)
        self.assertEqual("BinaryLoader", command[command.index("-loader") + 1])
        self.assertEqual("default", command[command.index("-cspec") + 1])
        self.assertLess(command.index("-preScript"), command.index("-postScript"))
        self.assertEqual("GhydraRawImport.java", command[command.index("-preScript") + 1])
        self.assertEqual(RAW["image_base"], command[command.index("-preScript") + 2])

    def test_raw_options_never_reach_process_mode(self):
        runner = self.runner()
        self.program(runner)
        headless.write_provenance(self.projects, runner.project_name, self.binary, **RAW)
        command = runner.command()
        self.assertIn("-process", command)
        self.assertNotIn("-loader", command)
        self.assertNotIn("-processor", command)
        self.assertNotIn("-import", command)
        self.assertNotIn("-preScript", command)

    def test_changed_bytes_reimport_with_the_same_mapping(self):
        runner = self.runner()
        self.program(runner)
        headless.write_provenance(self.projects, runner.project_name, self.binary, **RAW)
        with open(self.binary, "ab") as handle:
            handle.write(b"changed")
        command = runner.command()
        self.assertIn("-overwrite", command)
        self.assertIn("-loader", command)
        self.assertNotIn("-process", command)

    def test_existing_unproven_or_incompatible_project_fails_closed(self):
        runner = self.runner(project_name="explicit")
        self.program(runner)
        provenance = headless.provenance_path(self.projects, runner.project_name)
        for contents in (None, "not JSON", "[]", "{}", json.dumps({**RAW, "image_base": "0x0"})):
            if contents is not None:
                with open(provenance, "w", encoding="utf-8") as handle:
                    handle.write(contents)
            with self.subTest(contents=contents), self.assertRaises(headless.HeadlessError) as caught:
                runner.command()
            self.assertEqual("HEADLESS_RAW_PROJECT_MISMATCH", caught.exception.code)

    def test_auto_cannot_overwrite_a_raw_project(self):
        runner = self.runner(project_name="explicit")
        self.program(runner)
        headless.write_provenance(self.projects, runner.project_name, self.binary, **RAW)
        with self.assertRaises(headless.HeadlessError) as caught:
            self.runner({}, project_name="explicit").command()
        self.assertEqual("HEADLESS_RAW_PROJECT_MISMATCH", caught.exception.code)

    def test_other_source_path_cannot_reuse_raw_provenance(self):
        runner = self.runner()
        self.program(runner)
        headless.write_provenance(self.projects, runner.project_name, self.binary, **RAW)
        path = headless.provenance_path(self.projects, runner.project_name)
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        data["binary"] = os.path.join(self.root, "another.exe")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        with self.assertRaises(headless.HeadlessError):
            runner.command()

    def test_claimed_mapping_is_enforced_before_native_project_exists(self):
        first = self.runner(project_name="shared")
        headless.write_provenance(self.projects, first.project_name, self.binary, **RAW)
        for options in ({}, {**RAW, "image_base": "0x0"}):
            with self.subTest(options=options), self.assertRaises(headless.HeadlessError) as caught:
                self.runner(options, project_name="shared").command()
            self.assertEqual("HEADLESS_RAW_PROJECT_MISMATCH", caught.exception.code)

    def test_competing_fresh_claim_cannot_truncate_another_mapping(self):
        first_options = {**RAW, "image_base": "0x0"}
        first = self.runner(first_options, project_name="shared")
        second = self.runner(project_name="shared")
        # Both callers have validated a not-yet-created project.
        first.command()
        second.command()
        expected = {}

        def claim_first(_instance):
            headless.write_provenance(self.projects, first.project_name, self.binary, **first_options)
            with open(headless.provenance_path(self.projects, first.project_name), encoding="utf-8") as handle:
                expected.update(json.load(handle))

        with mock.patch.object(headless, "api_answers", return_value=False), \
                mock.patch.object(headless, "load_state", return_value=None), \
                mock.patch.object(headless, "save_state", side_effect=claim_first), \
                mock.patch.object(headless.subprocess, "Popen") as launch, \
                self.assertRaises(headless.HeadlessError) as caught:
            second.start()
        self.assertEqual("HEADLESS_RAW_PROJECT_MISMATCH", caught.exception.code)
        launch.assert_not_called()
        with open(headless.provenance_path(self.projects, first.project_name), encoding="utf-8") as handle:
            self.assertEqual(expected, json.load(handle))

    def test_project_appearing_after_initial_check_cannot_change_mapping(self):
        first_options = {**RAW, "image_base": "0x0"}
        second = self.runner(project_name="shared")
        original_check = second._check_import_mapping
        checked = False

        def publish_competitor_after_check(*args, **kwargs):
            nonlocal checked
            original_check(*args, **kwargs)
            if not checked:
                checked = True
                self.program(second)
                headless.write_provenance(self.projects, second.project_name,
                                          self.binary, **first_options)

        with mock.patch.object(headless, "api_answers", return_value=False), \
                mock.patch.object(headless, "load_state", return_value=None), \
                mock.patch.object(second, "_check_import_mapping",
                                  side_effect=publish_competitor_after_check), \
                mock.patch.object(second, "command", wraps=second.command) as command, \
                mock.patch.object(headless.subprocess, "Popen") as launch, \
                self.assertRaises(headless.HeadlessError) as caught:
            second.start()
        self.assertEqual("HEADLESS_RAW_PROJECT_MISMATCH", caught.exception.code)
        command.assert_not_called()
        launch.assert_not_called()
        with open(headless.provenance_path(self.projects, second.project_name), encoding="utf-8") as handle:
            self.assertEqual(first_options["image_base"], json.load(handle)["image_base"])

    def test_mapping_is_revalidated_immediately_before_native_launch(self):
        runner = self.runner(project_name="shared")
        first_options = {**RAW, "image_base": "0x0"}

        def replace_mapping_while_preparing_environment():
            headless.write_provenance(self.projects, runner.project_name, self.binary, **first_options)
            return {}

        with mock.patch.object(headless, "api_answers", return_value=False), \
                mock.patch.object(headless, "load_state", return_value=None), \
                mock.patch.object(runner, "environment",
                                  side_effect=replace_mapping_while_preparing_environment), \
                mock.patch.object(headless.subprocess, "Popen") as launch, \
                self.assertRaises(headless.HeadlessError) as caught:
            runner.start()
        self.assertEqual("HEADLESS_RAW_PROJECT_MISMATCH", caught.exception.code)
        launch.assert_not_called()

    def test_raw_symlink_roundtrip_uses_native_target_basename(self):
        alias = os.path.join(self.root, "alias.bin")
        os.symlink(self.binary, alias)
        raw_runner = headless.HeadlessRunner(binary=alias, project_dir=self.projects,
                                             ghidra_home=self.home, **RAW)
        self.assertEqual(self.binary, raw_runner.binary)
        self.assertEqual(self.runner().project_name, raw_runner.project_name)
        self.assertEqual(raw_runner.project_name, headless.default_project_name(alias, **RAW))
        self.program(raw_runner)
        headless.write_provenance(self.projects, raw_runner.project_name, raw_runner.binary, **RAW)
        command = raw_runner.command()
        self.assertEqual(os.path.basename(self.binary), command[command.index("-process") + 1])
        headless.save_state(raw_runner.instance)
        reopened = headless.HeadlessRunner.from_instance(headless.load_state(raw_runner.port))
        self.assertEqual(self.binary, reopened.binary)
        self.assertEqual(raw_runner.project_name, reopened.project_name)
        self.assertIn("-process", reopened.command())
        auto_runner = headless.HeadlessRunner(binary=alias, project_dir=self.projects,
                                              ghidra_home=self.home)
        self.assertEqual(alias, auto_runner.binary)

    def test_legacy_auto_project_without_provenance_keeps_overwrite_behavior(self):
        runner = self.runner({})
        self.program(runner)
        command = runner.command()
        self.assertIn("-overwrite", command)
        self.assertNotIn("-loader", command)

    def test_state_roundtrip_stop_reattachment_and_status_preserve_mapping(self):
        runner = self.runner()
        headless.save_state(runner.instance)
        restored = headless.load_state(runner.port)
        for key, value in RAW.items():
            self.assertEqual(value, restored.to_dict()[key])
        reattached = headless.HeadlessRunner.from_instance(restored)
        self.assertEqual(RAW, reattached.raw_options)
        self.assertEqual(runner.project_name, reattached.project_name)
        with mock.patch.object(headless, "process_alive", return_value=False), \
                mock.patch.object(headless, "api_answers", return_value=False):
            outcome = headless.status(runner.port)
        for key, value in RAW.items():
            self.assertEqual(value, outcome[key])
        self.assertNotIn("raw", headless.HeadlessInstance().to_dict())

    def test_successful_start_persists_provenance_only_after_ready(self):
        runner = self.runner()
        process = mock.Mock(pid=12345)
        with mock.patch.object(headless, "api_answers", return_value=False), \
                mock.patch.object(headless.subprocess, "Popen", return_value=process), \
                mock.patch.object(runner, "environment", return_value={}), \
                mock.patch.object(runner, "wait_ready") as ready:
            runner.start()
        ready.assert_called_once()
        with open(headless.provenance_path(self.projects, runner.project_name), encoding="utf-8") as handle:
            data = json.load(handle)
        for key, value in RAW.items():
            self.assertEqual(value, data[key])
        self.assertEqual(self.binary, data["binary"])

    def test_binary_rebuilt_during_wait_ready_aborts_and_preserves_retry_mapping(self):
        for options in (RAW, {}):
            with self.subTest(raw=bool(options)):
                runner = self.runner(options)
                # An existing valid sidecar must also be invalidated by the race.
                headless.write_provenance(self.projects, runner.project_name, self.binary, **options)
                self.program(runner)

                def rebuild(_timeout):
                    with open(self.binary, "ab") as handle:
                        handle.write(b" rebuilt during analysis")

                with mock.patch.object(headless, "api_answers", return_value=False), \
                        mock.patch.object(headless, "load_state", return_value=None), \
                        mock.patch.object(headless.subprocess, "Popen", return_value=mock.Mock(pid=12345)), \
                        mock.patch.object(runner, "environment", return_value={}), \
                        mock.patch.object(runner, "wait_ready", side_effect=rebuild), \
                        mock.patch.object(runner, "stop") as stop, \
                        self.assertRaises(headless.HeadlessError) as caught:
                    runner.start()
                self.assertEqual("HEADLESS_BINARY_CHANGED", caught.exception.code)
                stop.assert_called_once_with(timeout=5)
                with open(headless.provenance_path(self.projects, runner.project_name),
                          encoding="utf-8") as handle:
                    self.assertEqual({"binary": self.binary, **options}, json.load(handle))
                self.assertFalse(headless.project_is_current(
                    self.projects, runner.project_name, self.binary, **options))
                retry_command = runner.command()
                self.assertIn("-import", retry_command)
                self.assertIn("-overwrite", retry_command)
                if options:
                    incompatible = self.runner({**options, "image_base": "0x0"},
                                               project_name=runner.project_name)
                    with self.assertRaises(headless.HeadlessError) as mismatch:
                        incompatible.command()
                    self.assertEqual("HEADLESS_RAW_PROJECT_MISMATCH", mismatch.exception.code)

    def test_provenance_writer_persists_captured_identity_without_restat(self):
        runner = self.runner()
        captured = headless.binary_provenance(self.binary)
        with mock.patch.object(headless, "binary_provenance", side_effect=AssertionError("unexpected stat")):
            headless.write_provenance(self.projects, runner.project_name, self.binary,
                                      source_identity=captured, **RAW)
        with open(headless.provenance_path(self.projects, runner.project_name), encoding="utf-8") as handle:
            self.assertEqual({**captured, **RAW}, json.load(handle))

    def test_failed_start_does_not_claim_import_provenance(self):
        runner = self.runner()
        with mock.patch.object(headless, "api_answers", return_value=False), \
                mock.patch.object(headless.subprocess, "Popen", return_value=mock.Mock(pid=12345)), \
                mock.patch.object(runner, "environment", return_value={}), \
                mock.patch.object(runner, "wait_ready", side_effect=headless.HeadlessError("failed")), \
                mock.patch.object(runner, "stop"), self.assertRaises(headless.HeadlessError):
            runner.start()
        with open(headless.provenance_path(self.projects, runner.project_name), encoding="utf-8") as handle:
            self.assertEqual({"binary": self.binary, **RAW}, json.load(handle))

    def test_failed_first_import_leaving_empty_project_can_retry_same_mapping(self):
        runner = self.runner()

        def leave_empty_project(_timeout):
            with open(os.path.join(self.projects, runner.project_name + ".gpr"),
                      "w", encoding="utf-8") as handle:
                handle.write("")
            os.makedirs(os.path.join(self.projects, runner.project_name + ".rep"))
            raise headless.HeadlessError("native import failed")

        with mock.patch.object(headless, "api_answers", return_value=False), \
                mock.patch.object(headless, "load_state", return_value=None), \
                mock.patch.object(headless.subprocess, "Popen", return_value=mock.Mock(pid=12345)), \
                mock.patch.object(runner, "environment", return_value={}), \
                mock.patch.object(runner, "wait_ready", side_effect=leave_empty_project), \
                mock.patch.object(runner, "stop") as stop, self.assertRaises(headless.HeadlessError):
            runner.start()
        stop.assert_called_once_with(timeout=5)
        with open(headless.provenance_path(self.projects, runner.project_name), encoding="utf-8") as handle:
            self.assertEqual({"binary": self.binary, **RAW}, json.load(handle))
        self.assertFalse(headless.project_is_current(
            self.projects, runner.project_name, self.binary, **RAW))

        with open(self.binary, "wb") as handle:
            handle.write(b"valid replacement input at the same source path")
        retry = self.runner()
        with mock.patch.object(headless, "api_answers", return_value=False), \
                mock.patch.object(headless, "load_state", return_value=None), \
                mock.patch.object(headless.subprocess, "Popen", return_value=mock.Mock(pid=12346)) as launch, \
                mock.patch.object(retry, "environment", return_value={}), \
                mock.patch.object(retry, "wait_ready"):
            retry.start()
        self.assertIn("-import", launch.call_args.args[0])
        self.assertNotIn("-process", launch.call_args.args[0])
        self.assertTrue(headless.project_is_current(
            self.projects, retry.project_name, self.binary, **RAW))

    def test_invalid_options_fail_before_installation_or_repository_resolution(self):
        with mock.patch.object(headless, "find_ghidra_home") as find:
            for options in ({"language_id": RAW["language_id"]},
                            {"raw": True}, {**RAW, "repository_profile": "approved"}):
                with self.subTest(options=options), self.assertRaises(headless.HeadlessError):
                    headless.HeadlessRunner(**options)
            find.assert_not_called()
        with self.assertRaises(launcher.LauncherError):
            launcher.headless_command("missing", "missing", "projects", "p", "", 8192,
                                      empty=True, script="GhidraHeadlessServer", **RAW)
        with self.assertRaises(headless.HeadlessError):
            headless.build_command("launcher", "projects", "p", "", 8192, empty=True, **RAW)

    def test_raw_provenance_write_failure_aborts_the_started_run(self):
        runner = self.runner()
        with mock.patch.object(headless, "api_answers", return_value=False), \
                mock.patch.object(headless.subprocess, "Popen", return_value=mock.Mock(pid=12345)), \
                mock.patch.object(runner, "environment", return_value={}), \
                mock.patch.object(runner, "wait_ready"), \
                mock.patch.object(headless, "write_provenance",
                                  side_effect=headless.HeadlessError("cannot persist")), \
                mock.patch.object(runner, "stop") as stop, self.assertRaises(headless.HeadlessError):
            runner.start()
        stop.assert_called_once_with(timeout=5)


class RawSessionTests(unittest.TestCase):
    def test_open_store_reopen_and_close_preserve_exact_mapping(self):
        with tempfile.TemporaryDirectory() as root, \
                mock.patch.dict(os.environ, {"GHYDRA_STATE_DIR": root}):
            instance = headless.HeadlessInstance(binary=os.path.join(root, "image.bin"), pid=1234,
                                                 project_dir=os.path.join(root, "projects"),
                                                 project_name="raw-project", **RAW)
            runner = mock.Mock(instance=instance)
            runner.start.return_value = instance
            with mock.patch.object(sessions, "_build_runner", return_value=runner) as build:
                opened = sessions.open_session(instance.binary, name="raw-session", **RAW)
                for key, value in RAW.items():
                    self.assertEqual(value, build.call_args.kwargs[key])
                stored = sessions.get_session(opened.id)
                for key, value in RAW.items():
                    self.assertEqual(value, stored.to_dict()[key])
                stored.state = sessions.STATE_STOPPED
                sessions._save_store([stored])
                reopened = sessions.reopen_session(opened.id)
                self.assertEqual(instance.project_dir, build.call_args.kwargs["project_dir"])
                self.assertEqual(instance.project_name, build.call_args.kwargs["project_name"])
                for key, value in RAW.items():
                    self.assertEqual(value, build.call_args.kwargs[key])
                sessions.close_session(reopened.id)
                self.assertEqual(instance.project_dir, build.call_args.kwargs["project_dir"])
                self.assertEqual(instance.project_name, build.call_args.kwargs["project_name"])
                for key, value in RAW.items():
                    self.assertEqual(value, build.call_args.kwargs[key])
                runner.stop.assert_called_once()

    def test_repository_and_orphan_options_are_rejected_before_runner(self):
        with mock.patch.object(sessions, "_build_runner") as build:
            for options in ({"language_id": RAW["language_id"]},
                            {**RAW, "repository_profile": "approved"}):
                with self.subTest(options=options), self.assertRaises(sessions.SessionError):
                    sessions.open_session("image.bin", **options)
            build.assert_not_called()
        self.assertNotIn("raw", sessions.Session().to_dict())

    def test_session_runner_propagates_native_options(self):
        with mock.patch.object(headless, "HeadlessRunner") as runner:
            sessions._build_runner("image.bin", **RAW)
        for key, value in RAW.items():
            self.assertEqual(value, runner.call_args.kwargs[key])


class RawCliTests(unittest.TestCase):
    @staticmethod
    def context():
        formatter = mock.Mock()
        formatter.format_simple_result.side_effect = json.dumps
        formatter.format_error.side_effect = str
        return {"formatter": formatter}

    def test_headless_cli_propagates_named_native_options(self):
        instance = headless.HeadlessInstance(binary="image.exe", **RAW)
        runner = mock.Mock()
        runner.start.return_value = instance
        args = ["start", "image.exe", "--raw", "--language-id", RAW["language_id"],
                "--image-base", "0x08000000", "--compiler-spec", "default"]
        with mock.patch.object(headless_cli, "HeadlessRunner", return_value=runner) as constructor:
            result = CliRunner().invoke(headless_cli.headless, args, obj=self.context())
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIs(True, constructor.call_args.kwargs["raw"])
        self.assertEqual("default", constructor.call_args.kwargs["compiler_spec"])
        payload = json.loads(result.output)["result"]
        self.assertEqual("0x8000000", payload["image_base"])
        self.assertEqual("default", payload["compiler_spec"])

    def test_session_cli_propagates_named_native_options(self):
        opened = sessions.Session(name="raw", **RAW)
        args = ["open", "image.bin", "--raw", "--language-id", RAW["language_id"],
                "--image-base", RAW["image_base"], "--compiler-spec", "default"]
        with mock.patch.object(session_cli, "open_session", return_value=opened) as opening:
            result = CliRunner().invoke(session_cli.session, args, obj=self.context())
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIs(True, opening.call_args.kwargs["raw"])
        self.assertEqual(RAW["language_id"], opening.call_args.kwargs["language_id"])
        self.assertEqual(RAW["image_base"], opening.call_args.kwargs["image_base"])
        self.assertEqual("default", opening.call_args.kwargs["compiler_spec"])

    def test_cli_rejects_orphan_options_before_native_launch(self):
        with mock.patch.object(headless, "find_ghidra_home") as find:
            result = CliRunner().invoke(headless_cli.headless,
                                        ["start", "image.bin", "--image-base", "0x1000"],
                                        obj=self.context())
            self.assertEqual(1, result.exit_code)
            find.assert_not_called()
        result = CliRunner().invoke(session_cli.session,
                                    ["open", "image.bin", "--language-id", RAW["language_id"]],
                                    obj=self.context())
        self.assertEqual(1, result.exit_code)


if __name__ == "__main__":
    unittest.main()
