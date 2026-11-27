"""Structured raw imports through the standalone MCP consumers (no native run)."""

from contextlib import ExitStack
import inspect
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bridge_mcp_hydra as bridge
from ghydra import headless, sessions


LANGUAGE = "ARM:LE:32:Cortex"
RAW = {"raw": True, "language_id": LANGUAGE, "image_base": "0x8000000",
       "compiler_spec": ""}


class RawMcpTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.tmp = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.binary = self.tmp / "firmware.exe"
        # Recognized executable magic must not defeat an explicit BinaryLoader.
        self.binary.write_bytes(b"MZ" + bytes(range(32)))
        self.projects = self.tmp / "projects"
        self.projects.mkdir()
        self.home = self.tmp / "ghidra"
        utility = self.home / "Ghidra/Framework/Utility/lib/Utility.jar"
        utility.parent.mkdir(parents=True)
        utility.touch()
        self.stack.enter_context(mock.patch.dict(os.environ, {
            "GHYDRA_STATE_DIR": str(self.tmp / "state"),
            "GHIDRA_JAVA_OPTIONS": "", "GHIDRA_HEADLESS_JAVA_OPTIONS": "",
        }))
        for name, value in (("_headless_project_dir", str(self.projects)),
                            ("_headless_find_ghidra", str(self.home)),
                            ("_headless_find_java", str(self.tmp / "jdk")),
                            ("_headless_vmargs", [])):
            self.stack.enter_context(mock.patch.object(bridge, name, return_value=value))
        self.stack.enter_context(mock.patch.object(bridge, "register_instance"))
        self.stack.enter_context(mock.patch.object(bridge, "_headless_children", {}))
        self.process = mock.Mock(pid=43210)
        self.process.poll.return_value = None
        self.popen = self.stack.enter_context(
            mock.patch.object(bridge.subprocess, "Popen", return_value=self.process))

    def start(self, **options):
        with mock.patch.object(bridge, "_headless_api_answers", side_effect=[False, True]):
            return bridge._headless_start_raw(str(self.binary), **options)

    def command(self, **options):
        return bridge._headless_command(str(self.home), str(self.tmp / "jdk"),
                                        str(self.projects), "firmware", str(self.binary),
                                        8192, **options)

    def mark_program(self, project_name):
        directory = self.projects / (project_name + ".rep") / "idata"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "~index.dat").write_text(
            f"VERSION=1\n/\n 00000000:{self.binary.name}:abc\n", encoding="utf-8")

    def test_named_parameters_are_exposed_without_arg_passthrough(self):
        for name in ("headless_start", "session_open"):
            tool = bridge.mcp._tool_manager._tools[name]
            schema = tool.parameters["properties"]
            for field in RAW:
                self.assertIn(field, schema)
            signature = inspect.signature(getattr(bridge, name).__wrapped__)
            self.assertFalse(signature.parameters["raw"].default)
            self.assertNotIn("extra", signature.parameters)
            self.assertNotIn("args", signature.parameters)
            self.assertFalse(any(p.kind == inspect.Parameter.VAR_KEYWORD
                                 for p in signature.parameters.values()))

    def test_explicit_raw_forces_binary_loader_with_typed_flags(self):
        command = self.command(raw=True, language_id=LANGUAGE, image_base="134217728")
        self.assertIn("-import", command)
        self.assertEqual(command[command.index("-loader") + 1], "BinaryLoader")
        self.assertEqual(command[command.index("-processor") + 1], LANGUAGE)
        self.assertEqual(command[command.index("-loader-baseAddr") + 1], "0x8000000")
        pre_script = command.index("-preScript")
        self.assertEqual(command[pre_script + 1:pre_script + 3],
                         ["GhydraRawImport.java", "0x8000000"])
        self.assertLess(pre_script, command.index("-postScript"))
        self.assertNotIn("-cspec", command)
        command = self.command(**dict(RAW, compiler_spec="default"))
        self.assertEqual(command[command.index("-cspec") + 1], "default")

    def test_native_id_with_spaces_remains_one_argument(self):
        language = "x86:LE:32:System Management Mode"
        command = self.command(raw=True, language_id=language, image_base="0")
        self.assertEqual(command[command.index("-processor") + 1], language)
        self.assertEqual(command[command.index("-loader-baseAddr") + 1], "0x0")
        pre_script = command.index("-preScript")
        self.assertEqual(command[pre_script + 1:pre_script + 3],
                         ["GhydraRawImport.java", "0x0"])

    def test_default_auto_import_stays_unmodified(self):
        command = self.command()
        for flag in ("-loader", "-processor", "-loader-baseAddr", "-cspec", "-overwrite",
                     "-preScript"):
            self.assertNotIn(flag, command)
        result = self.start()
        self.assertTrue(result["success"], result)
        state = bridge._headless_load_state(8192)
        self.assertEqual(state["project_name"], "firmware")
        for key in RAW:
            self.assertNotIn(key, state)
        self.mark_program("firmware")
        self.assertTrue(self.start()["success"])
        self.assertIn("-process", self.popen.call_args.args[0])

    def test_invalid_options_fail_before_launch_or_async_task(self):
        invalid = [
            {"raw": True},
            {"raw": True, "language_id": LANGUAGE},
            {"raw": True, "image_base": "0"},
            {"language_id": LANGUAGE},
            {"image_base": "0x1000"},
            {"compiler_spec": "default"},
            dict(RAW, image_base="-1"),
            dict(RAW, image_base="0x10000000000000000"),
            dict(RAW, image_base="0x10 -postScript Evil"),
            dict(RAW, language_id="-postScript"),
            dict(RAW, language_id="ARM:LE:32:Cortex\n-postScript"),
            dict(RAW, compiler_spec="-scriptPath"),
            dict(RAW, compiler_spec="default\x00-postScript"),
            dict(RAW, raw="true"),
        ]
        with mock.patch.object(bridge, "_task_spawn") as spawn:
            for options in invalid:
                with self.subTest(options=options):
                    for consumer in (bridge.headless_start.__wrapped__,
                                     bridge.session_open.__wrapped__,
                                     bridge._headless_start_raw):
                        result = consumer(str(self.binary), **options)
                        self.assertFalse(result["success"], result)
                        self.assertEqual(result["error"]["code"], "HEADLESS_INVALID_ARGUMENT")
                    result = bridge.headless_start.__wrapped__(
                        str(self.binary), async_mode=True, **options)
                    self.assertFalse(result["success"], result)
            spawn.assert_not_called()
        self.popen.assert_not_called()

    def test_headless_wrapper_forwards_normalized_settings(self):
        outcome = {"success": True, "result": {}}
        with mock.patch.object(bridge, "_headless_start_raw", return_value=outcome) as start:
            self.assertIs(bridge.headless_start.__wrapped__(
                str(self.binary), raw=True, language_id=LANGUAGE,
                image_base="0X08000000"), outcome)
            self.assertEqual(start.call_args.kwargs, RAW)
        with mock.patch.object(bridge, "_task_spawn", return_value=outcome) as spawn, \
                mock.patch.object(bridge, "_headless_start_raw", return_value=outcome) as start:
            bridge.headless_start.__wrapped__(str(self.binary), async_mode=True, **RAW)
            spawn.call_args.kwargs["body"]()
            self.assertEqual(start.call_args.kwargs, RAW)

    def test_mapping_identity_and_provenance_match_cli(self):
        result = self.start(**RAW)
        self.assertTrue(result["success"], result)
        state = bridge._headless_load_state(8192)
        for key, value in RAW.items():
            self.assertEqual(state[key], value)
            self.assertEqual(result["result"][key], value)
        self.assertEqual(state["project_name"], headless.default_project_name(str(self.binary), **RAW))
        provenance = json.loads(Path(headless.provenance_path(
            str(self.projects), state["project_name"])).read_text())
        self.assertEqual(provenance, dict(headless.binary_provenance(str(self.binary)), **RAW))
        original = state["project_name"]
        for changed in (dict(RAW, image_base="0x9000000"),
                        dict(RAW, language_id="ARM:BE:32:Cortex"),
                        dict(RAW, compiler_spec="default")):
            self.assertTrue(self.start(**changed)["success"])
            self.assertNotEqual(bridge._headless_load_state(8192)["project_name"], original)
        other = self.tmp / "elsewhere" / self.binary.name
        other.parent.mkdir()
        other.write_bytes(self.binary.read_bytes())
        self.assertNotEqual(bridge._headless_raw_project_name(str(other), RAW), original)

    def test_current_raw_program_is_processed_without_import_flags(self):
        name = bridge._headless_raw_project_name(str(self.binary), RAW)
        self.mark_program(name)
        headless.write_provenance(str(self.projects), name, str(self.binary), **RAW)
        result = self.start(**RAW)
        self.assertTrue(result["success"], result)
        command = self.popen.call_args.args[0]
        self.assertIn("-process", command)
        for flag in ("-import", "-overwrite", "-loader", "-processor", "-loader-baseAddr",
                     "-preScript"):
            self.assertNotIn(flag, command)

    def test_changed_bytes_reimport_with_same_mapping_and_overwrite(self):
        name = bridge._headless_raw_project_name(str(self.binary), RAW)
        self.mark_program(name)
        headless.write_provenance(str(self.projects), name, str(self.binary), **RAW)
        self.binary.write_bytes(b"changed bytes")
        result = self.start(**RAW)
        self.assertTrue(result["success"], result)
        command = self.popen.call_args.args[0]
        self.assertIn("-import", command)
        self.assertIn("-overwrite", command)
        self.assertIn("-loader", command)
        self.assertEqual(command[command.index("-loader-baseAddr") + 1], "0x8000000")
        pre_script = command.index("-preScript")
        self.assertEqual(command[pre_script + 1:pre_script + 3],
                         ["GhydraRawImport.java", "0x8000000"])
        self.assertNotIn("-process", command)

    def test_existing_raw_project_without_matching_provenance_fails_closed(self):
        name = bridge._headless_raw_project_name(str(self.binary), RAW)
        self.mark_program(name)
        path = Path(headless.provenance_path(str(self.projects), name))
        for recorded in (None, "invalid json", [], {},
                         dict(RAW, image_base="0x9000000"),
                         dict(RAW, language_id="-postScript")):
            with self.subTest(recorded=recorded):
                if recorded is None:
                    if path.exists():
                        path.unlink()
                else:
                    path.write_text(recorded if isinstance(recorded, str)
                                    else json.dumps(recorded), encoding="utf-8")
                result = self.start(**RAW)
                self.assertFalse(result["success"], result)
                self.assertEqual(result["error"]["code"], "HEADLESS_RAW_PROJECT_MISMATCH")
        self.popen.assert_not_called()

    def test_auto_never_processes_a_recorded_raw_project(self):
        self.mark_program("firmware")
        headless.write_provenance(str(self.projects), "firmware", str(self.binary), **RAW)
        result = self.start()
        self.assertFalse(result["success"], result)
        self.assertEqual(result["error"]["code"], "HEADLESS_RAW_PROJECT_MISMATCH")
        self.popen.assert_not_called()

    def test_failed_launch_does_not_claim_successful_provenance(self):
        self.process.poll.return_value = 1
        result = self.start(**RAW)
        self.assertFalse(result["success"], result)
        name = bridge._headless_raw_project_name(str(self.binary), RAW)
        marker = Path(headless.provenance_path(str(self.projects), name))
        self.assertEqual(json.loads(marker.read_text()), {"binary": str(self.binary), **RAW})

    def test_first_failed_raw_start_can_retry_its_empty_owned_project(self):
        name = bridge._headless_raw_project_name(str(self.binary), RAW)
        sidecar = Path(headless.provenance_path(str(self.projects), name))
        marker = {"binary": str(self.binary), **RAW}

        def leave_empty_project(*args, **kwargs):
            self.assertEqual(json.loads(sidecar.read_text()), marker)
            (self.projects / (name + ".gpr")).touch()
            (self.projects / (name + ".rep")).mkdir()
            return self.process

        self.popen.side_effect = leave_empty_project
        self.process.poll.return_value = 1
        failed = self.start(**RAW)
        self.assertFalse(failed["success"], failed)
        self.assertEqual(failed["error"]["code"], "HEADLESS_DIED")
        self.assertEqual(json.loads(sidecar.read_text()), marker)
        self.popen.side_effect = None
        self.process.poll.return_value = None
        retried = self.start(**RAW)
        self.assertTrue(retried["success"], retried)
        command = self.popen.call_args.args[0]
        self.assertIn("-import", command)
        self.assertNotIn("-process", command)
        provenance = json.loads(sidecar.read_text())
        self.assertEqual(provenance["size"], self.binary.stat().st_size)
        self.assertEqual(provenance["mtime_ns"], self.binary.stat().st_mtime_ns)

    def test_session_settings_survive_cli_roundtrip_and_reopen(self):
        original = {"id": "old", "name": "cli-existing", "state": "stopped",
                    "extra": {"annotation": "preserve"}, **dict(RAW, image_base="0x1000")}
        bridge._sessions_save([original])
        with mock.patch.object(bridge, "_headless_start_raw", return_value={
                "success": True, "result": {
                    "pid": 43210, "project": "/display/only",
                    "project_dir": str(self.projects),
                    "project_name": "persisted-native-raw"}}) as start:
            opened = bridge.session_open.__wrapped__(
                str(self.binary), name="mcp-raw", raw=True,
                language_id=LANGUAGE, image_base="134217728")
        self.assertTrue(opened["success"], opened)
        self.assertEqual(start.call_args.kwargs, RAW)
        record = opened["result"]["session"]
        self.assertEqual(record["extra"]["project_dir"], str(self.projects))
        self.assertEqual(record["extra"]["project_name"], "persisted-native-raw")
        for key, value in RAW.items():
            self.assertEqual(record[key], value)
        self.assertEqual(bridge._sessions_load()[0], original)
        loaded = sessions._load_store()
        current = next(item for item in loaded if item.id == record["id"])
        current.state = "stopped"
        sessions._save_store(loaded)
        with mock.patch.dict(os.environ, {"HOME": str(self.tmp / "different-home")}), \
                mock.patch.object(sessions, "_build_runner") as build:
            build.return_value.start.return_value = mock.Mock(pid=98765)
            reopened = sessions.reopen_session(current.id)
            for key, value in RAW.items():
                self.assertEqual(build.call_args.kwargs[key], value)
            self.assertEqual(build.call_args.kwargs["project_dir"], str(self.projects))
            self.assertEqual(build.call_args.kwargs["project_name"], "persisted-native-raw")
        self.assertEqual(reopened.pid, 98765)
        with mock.patch.object(bridge, "_headless_process_alive", return_value=True):
            listed = bridge.session_list.__wrapped__()["result"]["sessions"]
        restored = next(item for item in listed if item["id"] == record["id"])
        for key, value in RAW.items():
            self.assertEqual(restored[key], value)
        self.assertEqual(listed[0]["extra"], original["extra"])

    def test_auto_session_omits_raw_fields(self):
        with mock.patch.object(bridge, "_headless_start_raw", return_value={
                "success": True, "result": {}}) as start:
            opened = bridge.session_open.__wrapped__(str(self.binary))
        self.assertTrue(opened["success"], opened)
        self.assertEqual(start.call_args.kwargs, {})
        for key in RAW:
            self.assertNotIn(key, opened["result"]["session"])

    def test_spaces_in_native_ids_never_expand_into_launcher_flags(self):
        language = "x86:LE:32:default -postScript Evil"
        compiler = "default -scriptPath /untrusted"
        command = self.command(raw=True, language_id=language, image_base="0",
                               compiler_spec=compiler)
        self.assertEqual(command[command.index("-processor") + 1], language)
        self.assertEqual(command[command.index("-cspec") + 1], compiler)
        self.assertEqual(command.count("-postScript"), 1)
        self.assertNotIn("-scriptPath", command)
        self.assertNotIn("Evil", command)

    def test_provenance_failure_is_reported_without_claiming_import_success(self):
        name = bridge._headless_raw_project_name(str(self.binary), RAW)
        self.mark_program(name)
        headless.write_provenance(str(self.projects), name, str(self.binary), **RAW)
        original_write = bridge._headless_write_raw_provenance

        def fail_ready_write(project_dir, project_name, source_identity, *, exclusive=False):
            if exclusive:
                return original_write(project_dir, project_name, source_identity, exclusive=True)
            raise OSError("read-only project directory")

        with mock.patch.object(bridge, "_headless_write_raw_provenance",
                               side_effect=fail_ready_write):
            result = self.start(**RAW)
        self.assertFalse(result["success"], result)
        self.assertEqual(result["error"]["code"], "HEADLESS_PROVENANCE")
        self.process.terminate.assert_called_once_with()
        self.process.wait.assert_called_once_with(timeout=20)
        self.assertEqual(bridge._headless_load_state(8192), {})

    def test_raw_rebuild_during_import_never_records_replacement_as_imported(self):
        name = bridge._headless_raw_project_name(str(self.binary), RAW)
        self.mark_program(name)
        headless.write_provenance(str(self.projects), name, str(self.binary), **RAW)
        provenance = Path(headless.provenance_path(str(self.projects), name))
        self.binary.write_bytes(b"version queued for import")
        before = self.binary.stat()

        def replace_binary(*args, **kwargs):
            self.binary.write_bytes(b"replaced during import")
            os.utime(self.binary, ns=(before.st_atime_ns, before.st_mtime_ns + 1))
            return self.process

        self.popen.side_effect = replace_binary
        with mock.patch.object(bridge, "_headless_write_raw_provenance",
                               wraps=bridge._headless_write_raw_provenance) as write:
            result = self.start(**RAW)
        self.assertFalse(result["success"], result)
        self.assertEqual(result["error"]["code"], "HEADLESS_BINARY_CHANGED")
        self.assertIn("-import", self.popen.call_args.args[0])
        marker = {"binary": str(self.binary), **RAW}
        self.assertEqual(write.call_args.args[2], marker)
        self.assertEqual(json.loads(provenance.read_text()), marker)
        self.process.terminate.assert_called_once_with()
        self.process.wait.assert_called_once_with(timeout=20)
        self.assertEqual(bridge._headless_load_state(8192), {})
        with self.assertRaises(ValueError):
            bridge._headless_import_plan(str(self.projects), name, str(self.binary),
                                         dict(RAW, image_base="0x9000000"))
        self.popen.side_effect = None
        retry = self.start(**RAW)
        self.assertTrue(retry["success"], retry)
        command = self.popen.call_args.args[0]
        self.assertIn("-import", command)
        self.assertIn("-overwrite", command)
        self.assertNotIn("-process", command)

    def test_raw_provenance_writer_receives_prelaunch_identity(self):
        captured = bridge._headless_binary_provenance(str(self.binary), RAW)
        with mock.patch.object(bridge, "_headless_write_raw_provenance",
                               wraps=bridge._headless_write_raw_provenance) as write:
            result = self.start(**RAW)
        self.assertTrue(result["success"], result)
        self.assertEqual(write.call_args.args[2], captured)

    def test_finished_owned_child_is_reaped_before_pid_liveness_probe(self):
        result = self.start(**RAW)
        self.assertTrue(result["success"], result)
        self.assertIs(bridge._headless_children[self.process.pid], self.process)
        self.process.poll.return_value = 0
        with mock.patch.object(bridge.os, "kill", return_value=None) as kill:
            self.assertFalse(bridge._headless_process_alive(self.process.pid))
        kill.assert_not_called()
        self.assertNotIn(self.process.pid, bridge._headless_children)

    def test_polite_stop_accepts_finished_child_without_forced_termination(self):
        self.assertTrue(self.start(**RAW)["success"])
        self.process.poll.return_value = 0
        with mock.patch.object(bridge, "_headless_process_is_ours", return_value=True), \
                mock.patch.object(bridge.requests, "post", return_value=mock.Mock(ok=True)), \
                mock.patch.object(bridge.os, "kill", return_value=None) as kill:
            stopped = bridge.headless_stop.__wrapped__(8192, timeout=1)
        self.assertTrue(stopped["success"], stopped)
        self.assertTrue(stopped["result"]["stopped"])
        self.assertNotIn(self.process.pid, bridge._headless_children)
        self.assertEqual(bridge._headless_load_state(8192), {})
        self.process.terminate.assert_not_called()
        kill.assert_not_called()

    def test_fresh_raw_marker_write_failure_does_not_launch_a_child(self):
        with mock.patch.object(bridge, "_headless_write_raw_provenance",
                               side_effect=OSError("read-only project directory")):
            failed = self.start(**RAW)
        self.assertFalse(failed["success"], failed)
        self.assertEqual(failed["error"]["code"], "HEADLESS_PROVENANCE")
        self.popen.assert_not_called()

    def test_raw_symlink_uses_native_target_name_and_reopens_same_project(self):
        alias = self.tmp / "alias.bin"
        alias.symlink_to(self.binary)
        with mock.patch.object(bridge, "_headless_api_answers", side_effect=[False, True]):
            first = bridge._headless_start_raw(str(alias), **RAW)
        self.assertTrue(first["success"], first)
        state = bridge._headless_load_state(8192)
        self.assertEqual(state["binary"], str(self.binary))
        self.assertEqual(state["project_name"],
                         headless.default_project_name(str(alias), **RAW))
        self.assertEqual(state["project_name"],
                         bridge._headless_raw_project_name(str(self.binary), RAW))
        self.assertEqual(self.popen.call_args.args[0][
            self.popen.call_args.args[0].index("-import") + 1], str(self.binary))
        self.mark_program(state["project_name"])
        with mock.patch.object(bridge, "_headless_api_answers", side_effect=[False, True]):
            reopened = bridge._headless_start_raw(str(alias), **RAW)
        self.assertTrue(reopened["success"], reopened)
        command = self.popen.call_args.args[0]
        self.assertEqual(command[command.index("-process") + 1], self.binary.name)

    def test_auto_symlink_path_and_legacy_project_name_are_unchanged(self):
        alias = self.tmp / "alias.bin"
        alias.symlink_to(self.binary)
        with mock.patch.object(bridge, "_headless_api_answers", side_effect=[False, True]):
            started = bridge._headless_start_raw(str(alias))
        self.assertTrue(started["success"], started)
        state = bridge._headless_load_state(8192)
        self.assertEqual(state["binary"], str(alias))
        self.assertEqual(state["project_name"], "alias")

    def test_raw_symlink_session_keeps_canonical_binary_and_native_label(self):
        alias = self.tmp / "alias.bin"
        alias.symlink_to(self.binary)
        with mock.patch.object(bridge, "_headless_start_raw", return_value={
                "success": True, "result": {
                    "project": str(self.projects / "native"),
                    "project_dir": str(self.projects), "project_name": "native"}}) as start:
            opened = bridge.session_open.__wrapped__(str(alias), **RAW)
        self.assertTrue(opened["success"], opened)
        self.assertEqual(start.call_args.args[0], str(self.binary))
        self.assertEqual(opened["result"]["session"]["binary"], str(self.binary))
        self.assertEqual(opened["result"]["session"]["name"], "firmware")

    def test_raw_marker_alone_rejects_foreign_mapping_or_source_without_truncation(self):
        name = bridge._headless_raw_project_name(str(self.binary), RAW)
        sidecar = Path(headless.provenance_path(str(self.projects), name))
        for marker in ({"binary": str(self.binary), **dict(RAW, image_base="0x9000000")},
                       {"binary": str(self.tmp / "foreign.bin"), **RAW}, {}):
            with self.subTest(marker=marker):
                sidecar.write_text(json.dumps(marker))
                before = sidecar.read_bytes()
                failed = self.start(**RAW)
                self.assertFalse(failed["success"], failed)
                self.assertEqual(failed["error"]["code"], "HEADLESS_RAW_PROJECT_MISMATCH")
                self.assertEqual(sidecar.read_bytes(), before)
        self.popen.assert_not_called()

    def test_exclusive_marker_claim_revalidates_a_concurrent_claim(self):
        name = bridge._headless_raw_project_name(str(self.binary), RAW)
        sidecar = Path(headless.provenance_path(str(self.projects), name))
        foreign = {"binary": str(self.tmp / "foreign.bin"), **RAW}
        original_write = bridge._headless_write_raw_provenance

        def competing_write(project_dir, project_name, source_identity, *, exclusive=False):
            self.assertTrue(exclusive)
            sidecar.write_text(json.dumps(foreign))
            return original_write(project_dir, project_name, source_identity, exclusive=exclusive)

        with mock.patch.object(bridge, "_headless_write_raw_provenance",
                               side_effect=competing_write):
            failed = self.start(**RAW)
        self.assertFalse(failed["success"], failed)
        self.assertEqual(failed["error"]["code"], "HEADLESS_RAW_PROJECT_MISMATCH")
        self.assertEqual(json.loads(sidecar.read_text()), foreign)
        self.popen.assert_not_called()

    def test_raw_claim_is_required_and_revalidated_immediately_before_launch(self):
        name = bridge._headless_raw_project_name(str(self.binary), RAW)
        sidecar = Path(headless.provenance_path(str(self.projects), name))
        original_command = bridge._headless_command
        foreign = {"binary": str(self.tmp / "foreign.bin"), **RAW}
        for mutation in ("remove", "replace"):
            with self.subTest(mutation=mutation):
                if sidecar.exists():
                    sidecar.unlink()

                def mutate_after_command(*args, **kwargs):
                    command = original_command(*args, **kwargs)
                    self.assertEqual(json.loads(sidecar.read_text()),
                                     {"binary": str(self.binary), **RAW})
                    if mutation == "remove":
                        sidecar.unlink()
                    else:
                        sidecar.write_text(json.dumps(foreign))
                    return command

                with mock.patch.object(bridge, "_headless_command",
                                       side_effect=mutate_after_command):
                    failed = self.start(**RAW)
                self.assertFalse(failed["success"], failed)
                self.assertEqual(failed["error"]["code"], "HEADLESS_RAW_PROJECT_MISMATCH")
        self.popen.assert_not_called()


class RawMcpProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def test_stdio_preserves_zero_decimal_and_hex_address_strings(self):
        from mcp.client.session import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        root = str(Path(__file__).resolve().parents[1])
        # Exercise actual MCP parsing, registered consumers, normalization and
        # shared session storage; only the native process launch is replaced.
        launcher = (
            f"import sys\nsys.path.insert(0, {root!r})\n"
            "import bridge_mcp_hydra as b\n"
            "def start(*args, **options):\n"
            "    with open(b.os.path.join(b._headless_state_dir(), 'launches'), 'a') as handle:\n"
            "        handle.write('launch\\n')\n"
            "    return {'success': True, 'result': "
            "{'pid': 12345, 'project': '/fixture/raw', **options}}\n"
            "b._headless_start_raw = start\n"
            "b.mcp.run(transport='stdio')\n"
        )
        with tempfile.TemporaryDirectory(prefix="ghydra-raw-mcp-test-") as home:
            parameters = StdioServerParameters(
                command=sys.executable, args=["-c", launcher],
                env={"HOME": home, "GHYDRA_STATE_DIR": home,
                     "GHYDRA_MCP_OUTPUT": "json", "GHYDRA_TELEMETRY": "0"})
            async with stdio_client(parameters) as (reader, writer):
                async with ClientSession(reader, writer) as client:
                    await client.initialize()
                    for index, (address, expected) in enumerate((
                            ("0", "0x0"), ("0x0", "0x0"),
                            ("134217728", "0x8000000"), ("0x08000000", "0x8000000"))):
                        for tool_name in ("headless_start", "session_open"):
                            with self.subTest(tool=tool_name, image_base=address):
                                arguments = {
                                    "binary": str(Path(home) / "firmware.bin"),
                                    "raw": True, "language_id": LANGUAGE,
                                    "image_base": address,
                                }
                                if tool_name == "session_open":
                                    arguments["name"] = f"raw-address-{index}"
                                response = await client.call_tool(tool_name, arguments=arguments)
                                self.assertFalse(response.isError, response)
                                text = "\n".join(part.text for part in response.content
                                                 if part.type == "text")
                                envelope = json.loads(text)
                                self.assertTrue(envelope["success"], envelope)
                                result = envelope["result"]
                                options = result["session"] if tool_name == "session_open" else result
                                self.assertIs(options["raw"], True)
                                self.assertEqual(options["language_id"], LANGUAGE)
                                self.assertEqual(options["image_base"], expected)
                                self.assertEqual(options["compiler_spec"], "")
                    launch_log = Path(home) / "launches"
                    launches_before = launch_log.read_text()
                    for raw in ("true", "false", "1", "0", "yes", "null", 1, 0, None):
                        for tool_name in ("headless_start", "session_open"):
                            with self.subTest(tool=tool_name, raw=raw):
                                response = await client.call_tool(tool_name, arguments={
                                    "binary": str(Path(home) / "firmware.bin"),
                                    "raw": raw, "language_id": LANGUAGE, "image_base": "0",
                                })
                                self.assertTrue(response.isError, response)
                                self.assertEqual(launch_log.read_text(), launches_before)


if __name__ == "__main__":
    unittest.main()
