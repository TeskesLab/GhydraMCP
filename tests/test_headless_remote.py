"""Repository lifecycle over prepared HTTP requests, without sockets or private stores."""
import contextlib
import itertools
import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

import requests
from requests.adapters import BaseAdapter

from ghydra import connections, headless, launcher, sessions


class RepositoryHTTPFixture(BaseAdapter):
    """An in-memory worker with real requests serialization and versioned program state."""

    def __init__(self):
        self.online = False
        self.permissions = ["read", "checkout", "checkin"]
        self.path = "/folder/program.exe"
        self.file = {"path": self.path, "name": "program.exe", "type": "file",
                     "version": 7, "latest_version": 7, "checked_out": False, "exclusive": False}
        self.prefix = []
        self.active = None
        self.dirty = False
        self.saved_changes = False
        self.checkins = []
        self.calls = []
        self.urls = []
        self.failures = {}
        self.save_result = None
        self.checkin_result = None
        self.refuse_stop = False

    def close(self):
        pass

    def send(self, request, **kwargs):
        self.urls.append(request.url)
        route = urlsplit(request.url)
        query = {key: value[0] for key, value in parse_qs(route.query).items()}
        body = json.loads(request.body) if request.body else None
        self.calls.append((request.method, route.path, query, body))
        status = 200
        result = {}
        error = None
        selection = body if body is not None else query
        if route.path == "/":
            status = 200 if self.online else 503
        elif not self.online:
            status, error = 503, "CONNECTION_FAILED"
        elif route.path in self.failures:
            status, error = self.failures[route.path]
        elif selection.get("profile") != "approved" and route.path != "/program/save":
            status, error = 403, "CONNECTION_PROFILE_INVALID"
        elif route.path == "/repositories":
            if "read" not in self.permissions:
                status, error = 403, "CONNECTION_PERMISSION_DENIED"
            else:
                result = {"profile": "approved", "permissions": self.permissions, "connected": True}
        elif route.path == "/repositories/files":
            assert query["path"] == "/folder"
            offset, limit = int(query["offset"]), int(query["limit"])
            entries = self.prefix + [{**self.file, "modified_since_checkout": self.saved_changes}]
            page = entries[offset:offset + limit]
            result = {"entries": page, "offset": offset, "count": len(page), "total": len(entries),
                      "has_more": offset + len(page) < len(entries)}
        elif route.path == "/repositories/checkout":
            assert body["path"] == self.path
            if "checkout" not in self.permissions:
                status, error = 403, "CONNECTION_PERMISSION_DENIED"
            elif self.file["checked_out"]:
                status, error = 409, "REPOSITORY_CONFLICT"
            else:
                assert body["exclusive"] is True
                self.file.update(checked_out=True, exclusive=True, version=self.file["latest_version"])
                result = dict(self.file)
        elif route.path == "/repositories/open":
            assert body["path"] == self.path
            writable = body["version"] == -1 and self.file["checked_out"]
            if body["version"] != -1:
                assert body["version"] > 0
            self.active = {"path": body["path"], "read_only": not writable,
                           "version": self.file["version"] if writable else body["version"]}
            result = {"profile": "approved", "opened": True, **self.active}
        elif route.path == "/program/save":
            assert query == {"workspace_only": "true"}
            if self.save_result is not None:
                result = dict(self.save_result)
            elif self.active is None:
                result = {"saved": False, "analyzer_owned": True}
            elif self.dirty:
                assert not self.active["read_only"]
                self.dirty = False
                self.saved_changes = True
                result = {"saved": True, "program": "program.exe", "detail": "saved"}
            else:
                result = {"saved": False, "program": "program.exe", "detail": "no unsaved changes"}
        elif route.path == "/repositories/checkin":
            assert body["path"] == self.path
            assert body["keep_checked_out"] is True
            assert body["comment"]
            if "checkin" not in self.permissions:
                status, error = 403, "CONNECTION_PERMISSION_DENIED"
            elif not self.saved_changes:
                status, error = 409, "REPOSITORY_CONFLICT"
            else:
                self.checkins.append(dict(body))
                self.saved_changes = False
                self.file["latest_version"] += 1
                self.file["version"] = self.file["latest_version"]
                result = (dict(self.checkin_result) if self.checkin_result is not None
                          else {**self.file, "checked_in": True})
        else:
            raise AssertionError("Unexpected HTTP request: " + request.method + " " + request.url)
        payload = ({"success": False, "error": {"code": error,
                    "message": "private-identity private-password /private/key"}} if error else
                   {"success": status == 200, "result": result})
        response = requests.Response()
        response.status_code = status
        response._content = json.dumps(payload).encode()
        response.headers["Content-Type"] = "application/json"
        response.request = request
        response.url = request.url
        return response

    def operations(self, route):
        return [call for call in self.calls if call[1] == route]


class RepositoryHeadlessTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.store = os.path.join(self.root, "unread-private-store")
        self.stack.enter_context(mock.patch.dict(os.environ, {
            "GHYDRA_STATE_DIR": os.path.join(self.root, "state"), "HOME": self.root}, clear=True))
        self.home = os.path.join(self.root, "ghidra")
        utility = os.path.join(self.home, "Ghidra", "Framework", "Utility", "lib")
        os.makedirs(utility)
        with open(os.path.join(utility, "Utility.jar"), "wb") as handle:
            handle.write(b"synthetic")
        self.http = RepositoryHTTPFixture()
        transport = requests.Session()
        transport.trust_env = False
        transport.mount("http://", self.http)
        self.stack.enter_context(mock.patch("requests.sessions.Session", return_value=transport))
        self.stack.enter_context(mock.patch.object(launcher, "vm_args", return_value=[]))
        self.stack.enter_context(mock.patch.object(launcher, "env_vars", return_value={}))
        self.stack.enter_context(mock.patch.object(headless.HeadlessRunner, "resolve_java_home", return_value=self.root))
        self.stack.enter_context(mock.patch.object(headless, "default_project_dir",
                                                   return_value=os.path.join(self.root, "projects")))
        self.flag = os.path.join(self.root, "stop")
        self.stack.enter_context(mock.patch.object(headless, "stop_file_path", return_value=self.flag))
        self.stack.enter_context(mock.patch.object(headless, "process_is_ours", return_value=True))
        self.stack.enter_context(mock.patch.object(connections, "load_profile",
                                                   side_effect=AssertionError("Python read private profile")))
        self.launch = self.stack.enter_context(mock.patch.object(subprocess, "Popen", side_effect=self.start_child))
        self.stack.enter_context(mock.patch.object(headless.HeadlessRunner, "_wait_for_exit", side_effect=self.stop_child))
        self.signal_pid = self.stack.enter_context(mock.patch.object(os, "kill"))
        self.signal_tree = self.stack.enter_context(mock.patch.object(subprocess, "run"))
        if hasattr(os, "killpg"):
            self.signal_group = self.stack.enter_context(mock.patch.object(os, "killpg"))

    def runner(self, **kwargs):
        options = dict(port=65421, ghidra_home=self.home, repository_profile="approved",
                       program="folder/program.exe", connections_dir=self.store)
        options.update(kwargs)
        return headless.HeadlessRunner(**options)

    def start_child(self, command, **kwargs):
        self.http.online = True
        project_dir, project_name = command[command.index("ghidra.app.util.headless.AnalyzeHeadless") + 1:][:2]
        with open(os.path.join(project_dir, project_name + ".gpr"), "w") as handle:
            handle.write("persistent empty native project")
        child = mock.Mock(pid=4567)
        child.poll.side_effect = lambda: None if self.http.online else 0
        return child

    def stop_child(self, pid, timeout):
        self.assertTrue(os.path.isfile(self.flag))
        if self.http.refuse_stop:
            return False
        os.remove(self.flag)
        self.http.online = False
        return True

    def assert_no_signals(self):
        self.signal_pid.assert_not_called()
        self.signal_tree.assert_not_called()
        if hasattr(self, "signal_group"):
            self.signal_group.assert_not_called()

    def test_empty_native_command_is_private_and_identity_is_stable(self):
        runner = self.runner()
        with mock.patch.object(runner, "program_in_project", side_effect=AssertionError("local index")):
            command = runner.command()
        for flag in ("-import", "-process", "-connect", "-p", "-keystore", "-readOnly", "-commit"):
            self.assertNotIn(flag, command)
        self.assertIn("-Dghydra.connections.dir=" + self.store, command)
        self.assertFalse(any("initial-profile" in item for item in command))
        self.assertIn(runner.project_dir, command)
        self.assertIn(runner.project_name, command)
        self.assertIn(headless.SCRIPT_NAME, command)
        self.assertEqual("", runner.instance.binary)
        self.assertEqual(runner.project_name, self.runner().project_name)
        self.assertNotEqual(runner.project_name, self.runner(program="folder/other.exe").project_name)
        self.assertNotEqual(runner.project_name, self.runner(repository_profile="another").project_name)
        headless.check_project_dir(runner.project_dir)

    def test_readonly_lifecycle_pages_to_exact_immutable_latest_snapshot(self):
        self.http.file.update(checked_out=True, exclusive=True, version=3)
        self.http.prefix = [{"path": "/folder/not-it-" + str(n), "name": "program.exe", "type": "file"}
                            for n in range(1000)]
        runner = self.runner()
        with mock.patch.object(headless, "write_provenance", side_effect=AssertionError("binary provenance")):
            instance = runner.start(timeout=1)
        self.assertEqual(7, self.http.active["version"])
        self.assertTrue(self.http.active["read_only"])
        self.assertEqual(["0", "1000"], [call[2]["offset"] for call in self.http.operations("/repositories/files")])
        self.assertEqual(7, self.http.operations("/repositories/open")[0][3]["version"])
        self.assertFalse(self.http.operations("/repositories/checkout"))
        args, kwargs = self.launch.call_args
        self.assertEqual(subprocess.DEVNULL, kwargs["stdin"])
        self.assertEqual(runner.project_dir, kwargs["cwd"])
        self.assertNotIn("--repository-worker", args[0])
        self.assertFalse(runner.stop())  # No changes needed saving; not a failed shutdown.
        self.assertIs(False, instance.repository_saved)
        self.assertIsNone(instance.checked_in)
        self.assertTrue(os.path.isfile(os.path.join(instance.project_dir, instance.project_name + ".gpr")))
        self.assertFalse(os.path.exists(headless.provenance_path(instance.project_dir, instance.project_name)))
        self.assertIsNone(headless.load_state(runner.port))
        self.assert_no_signals()

    def test_writable_stop_saves_then_checks_in_original_selection_and_keeps_checkout(self):
        runner = self.runner(writable=True, commit="Reviewed analysis")
        runner.start(timeout=1)
        self.assertTrue(self.http.file["exclusive"])
        self.assertFalse(self.http.active["read_only"])
        self.assertEqual(-1, self.http.operations("/repositories/open")[0][3]["version"])
        self.http.dirty = True
        attached = headless.HeadlessRunner.from_instance(headless.load_state(runner.port))
        self.assertTrue(attached.stop())
        self.assertTrue(attached.instance.repository_saved)
        self.assertTrue(attached.instance.checked_in)
        self.assertEqual({"profile": "approved", "path": self.http.path, "comment": "Reviewed analysis",
                          "keep_checked_out": True}, self.http.checkins[0])
        routes = [call[1] for call in self.http.calls]
        self.assertLess(routes.index("/program/save"), routes.index("/repositories/checkin"))
        self.assertTrue(self.http.file["checked_out"])
        self.assertTrue(self.http.file["exclusive"])
        self.assertEqual(8, self.http.file["latest_version"])
        self.assert_no_signals()

    def test_unchanged_writable_stop_does_not_publish_a_version(self):
        runner = self.runner(writable=True, commit="Reviewed analysis")
        runner.start(timeout=1)
        attached = headless.HeadlessRunner.from_instance(headless.load_state(runner.port))
        self.assertFalse(attached.stop())
        self.assertIs(False, attached.instance.checked_in)
        self.assertEqual([], self.http.checkins)
        self.assertEqual(7, self.http.file["latest_version"])
        self.assertTrue(self.http.file["checked_out"])
        self.assertTrue(self.http.file["exclusive"])
        self.assertIsNone(headless.load_state(runner.port))
        self.assert_no_signals()

    def test_writable_reuses_only_current_exclusive_local_checkout(self):
        self.http.file.update(checked_out=True, exclusive=True)
        runner = self.runner(writable=True, commit="Reviewed")
        runner.start(timeout=1)
        self.assertFalse(self.http.operations("/repositories/checkout"))
        self.assertFalse(self.http.active["read_only"])
        self.http.dirty = True
        runner.stop()

    def test_conflicting_or_stale_existing_checkout_is_not_overridden(self):
        for exclusive, version in ((False, 7), (True, 3)):
            with self.subTest(exclusive=exclusive, version=version):
                self.http.file.update(checked_out=True, exclusive=exclusive, version=version)
                runner = self.runner(writable=True, commit="Reviewed")
                with self.assertRaises(headless.HeadlessError) as caught:
                    runner.start(timeout=1)
                self.assertEqual("REPOSITORY_CONFLICT", caught.exception.code)
                self.assertFalse(self.http.operations("/repositories/checkout"))
                self.assertFalse(self.http.operations("/repositories/open"))
                self.assertIsNone(headless.load_state(runner.port))
        self.assert_no_signals()

    def test_explicit_write_intent_and_java_grants_are_both_required(self):
        for options in ({"writable": True}, {"commit": "Reviewed"}, {"writable": True, "commit": " "}):
            with self.subTest(options=options), self.assertRaises(headless.HeadlessError):
                self.runner(**options)
        for grants in (["read"], ["read", "checkout"], ["read", "checkin"]):
            with self.subTest(grants=grants):
                self.http.permissions = grants
                runner = self.runner(writable=True, commit="Reviewed")
                with self.assertRaises(headless.HeadlessError) as caught:
                    runner.start(timeout=1)
                self.assertEqual("CONNECTION_PERMISSION_DENIED", caught.exception.code)
                self.assertFalse(self.http.operations("/repositories/checkout"))
                self.assertFalse(self.http.operations("/repositories/checkin"))
        self.assert_no_signals()

    def test_checkout_conflict_is_reported_without_open_or_force(self):
        self.http.failures["/repositories/checkout"] = (409, "REPOSITORY_CONFLICT")
        with self.assertRaises(headless.HeadlessError) as caught:
            self.runner(writable=True, commit="Reviewed").start(timeout=1)
        self.assertEqual("REPOSITORY_CONFLICT", caught.exception.code)
        self.assertFalse(self.http.operations("/repositories/open"))
        self.assert_no_signals()

    def test_readonly_open_refuses_unconfirmed_or_nonpositive_latest_version(self):
        for version in (None, 0, -1, True, "7"):
            with self.subTest(version=version):
                self.http.file["latest_version"] = version
                with self.assertRaises(headless.HeadlessError):
                    self.runner().start(timeout=1)
                self.assertFalse(self.http.operations("/repositories/open"))
        self.assert_no_signals()

    def test_invalid_literal_programs_and_local_project_overrides_are_refused(self):
        for program in (None, "", "../program", "folder/../program", "folder//program", "-preScript",
                        "folder/-postScript", "*.exe", "program?", "a\\b", "a/%2e%2e/b", "//a", "a\nprogram"):
            with self.subTest(program=program), self.assertRaises(headless.HeadlessError):
                self.runner(program=program)
        for options in ({"binary": "local.bin"}, {"project_dir": self.root}, {"project_name": "local"}):
            with self.subTest(options=options), self.assertRaises(headless.HeadlessError):
                self.runner(**options)

    def test_reattached_save_or_checkin_failure_retains_worker_state_without_secrets(self):
        runner = self.runner(writable=True, commit="Reviewed")
        runner.start(timeout=1)
        self.http.dirty = True
        for route in ("/program/save", "/repositories/checkin"):
            with self.subTest(route=route):
                self.http.failures[route] = (409, "REPOSITORY_CONFLICT")
                attached = headless.HeadlessRunner.from_instance(headless.load_state(runner.port))
                with self.assertRaises(headless.HeadlessError) as caught:
                    attached.stop()
                self.assertEqual("HEADLESS_STOP_REFUSED", caught.exception.code)
                self.assertTrue(self.http.online)
                self.assertEqual(runner.instance.pid, headless.load_state(runner.port).pid)
                self.assertFalse(os.path.exists(self.flag))
                self.assertNotIn("private-password", str(caught.exception))
                del self.http.failures[route]
        self.assert_no_signals()

    def test_missing_save_confirmation_or_empty_bootstrap_save_never_counts_as_repository_save(self):
        runner = self.runner()
        runner.start(timeout=1)
        for result, expected in (({}, None), ({"saved": False, "analyzer_owned": True}, False)):
            with self.subTest(result=result):
                self.http.save_result = result
                with self.assertRaises(headless.HeadlessError):
                    headless.HeadlessRunner.from_instance(headless.load_state(runner.port)).stop()
                self.assertIs(expected, headless.load_state(runner.port).repository_saved)
                self.assertTrue(self.http.online)
        self.assert_no_signals()

    def test_missing_checkin_confirmation_remains_unknown_and_keeps_state(self):
        runner = self.runner(writable=True, commit="Reviewed")
        runner.start(timeout=1)
        self.http.dirty = True
        self.http.checkin_result = {}
        with self.assertRaises(headless.HeadlessError):
            runner.stop()
        self.assertIsNone(headless.load_state(runner.port).checked_in)
        self.assertTrue(self.http.online)
        self.assert_no_signals()

    def test_timeout_retains_state_and_retry_does_not_repeat_confirmed_checkin(self):
        runner = self.runner(writable=True, commit="Reviewed")
        runner.start(timeout=1)
        self.http.dirty = True
        self.http.refuse_stop = True
        with self.assertRaises(headless.HeadlessError) as caught:
            runner.stop(timeout=0)
        self.assertEqual("HEADLESS_STOP_REFUSED", caught.exception.code)
        self.assertTrue(headless.load_state(runner.port).checked_in)
        self.assertFalse(os.path.exists(self.flag))
        self.http.refuse_stop = False
        attached = headless.HeadlessRunner.from_instance(headless.load_state(runner.port))
        attached.stop()
        self.assertEqual(1, len(self.http.checkins))
        self.assertIsNone(headless.load_state(runner.port))
        self.assert_no_signals()

    def test_reattached_stop_publishes_external_http_save_after_confirmed_checkin_and_timeout(self):
        runner = self.runner(writable=True, commit="Reviewed")
        runner.start(timeout=1)
        self.http.dirty = True
        self.http.refuse_stop = True
        with self.assertRaises(headless.HeadlessError):
            runner.stop(timeout=0)
        self.assertTrue(headless.load_state(runner.port).checked_in)
        self.assertEqual(1, len(self.http.checkins))

        self.http.dirty = True
        saved = requests.post(runner.instance.url + "/program/save",
                              params={"workspace_only": "true"}, timeout=1)
        self.assertIs(True, saved.json()["result"]["saved"])
        self.assertFalse(self.http.dirty)
        self.http.prefix = [{"path": "/folder/another-program", "type": "file",
                             "modified_since_checkout": False} for _ in range(1000)]
        self.http.refuse_stop = False
        attached = headless.HeadlessRunner.from_instance(headless.load_state(runner.port))
        attached.stop()
        self.assertIs(False, attached.instance.repository_saved)
        self.assertIs(True, attached.instance.checked_in)
        self.assertEqual(2, len(self.http.checkins))
        self.assertEqual(9, self.http.file["latest_version"])
        self.assertEqual(["0", "1000"], [
            call[2]["offset"] for call in self.http.operations("/repositories/files")[-2:]])
        self.assertIsNone(headless.load_state(runner.port))
        self.assert_no_signals()

    def test_cached_checkin_cannot_be_reused_without_fresh_change_confirmation(self):
        runner = self.runner(writable=True, commit="Reviewed")
        runner.start(timeout=1)
        self.http.dirty = True
        self.http.refuse_stop = True
        with self.assertRaises(headless.HeadlessError):
            runner.stop(timeout=0)
        self.http.saved_changes = None  # Worker did not confirm the checkout's change state.
        attached = headless.HeadlessRunner.from_instance(headless.load_state(runner.port))
        with self.assertRaises(headless.HeadlessError) as caught:
            attached.stop(timeout=0)
        self.assertEqual("HEADLESS_STOP_REFUSED", caught.exception.code)
        self.assertIsNone(headless.load_state(runner.port).checked_in)
        self.assertEqual(1, len(self.http.checkins))
        self.assertTrue(self.http.online)
        self.assert_no_signals()

    def test_checkin_always_targets_original_approved_program_after_selection_changes(self):
        runner = self.runner(writable=True, commit="Original only")
        runner.start(timeout=1)
        self.http.saved_changes = True  # Original program was saved before selecting another.
        self.http.active = {"path": "/another/program", "read_only": False, "version": 1}
        self.http.dirty = True
        runner.stop()
        self.assertEqual(self.http.path, self.http.checkins[0]["path"])
        self.assertEqual("approved", self.http.checkins[0]["profile"])

    def test_private_store_is_never_read_or_exposed_in_command_environment_or_log(self):
        runner = self.runner()
        runner.start(timeout=1)
        command, options = self.launch.call_args.args[0], self.launch.call_args.kwargs
        visible = json.dumps({"command": command, "env": options["env"],
                              "state": headless.load_state(runner.port).to_dict()})
        with open(runner.instance.log, encoding="utf-8") as handle:
            visible += handle.read()
        for secret in ("private-identity", "private-password", "/private/key", "ghidra://", "credential_ref"):
            self.assertNotIn(secret, visible)
        self.assertFalse(os.path.exists(self.store))
        runner.stop()

    def test_failed_popen_releases_only_start_claim(self):
        self.launch.side_effect = OSError("synthetic launch failure")
        runner = self.runner()
        with self.assertRaises(headless.HeadlessError) as caught:
            runner.start(timeout=1)
        self.assertEqual("HEADLESS_LAUNCH", caught.exception.code)
        self.assertIsNone(headless.load_state(runner.port))
        self.assert_no_signals()

    def test_stale_pid_never_calls_repository_api_or_signals_other_process(self):
        runner = self.runner()
        runner.instance.pid = 4567
        with mock.patch.object(headless, "process_is_ours", return_value=False), \
                mock.patch.object(headless, "process_alive", return_value=True):
            self.assertFalse(runner.stop())
        self.assertEqual([], self.http.calls)
        self.assert_no_signals()

    def test_real_cli_start_and_reattached_stop_use_scoped_http(self):
        from click.testing import CliRunner
        from ghydra.cli.headless import headless as command

        cli = CliRunner()
        options = {"formatter": RepositoryCLITests.Formatter()}
        started = cli.invoke(command, [
            "start", "--repository-profile", "approved", "--program", "folder/program.exe",
            "--connections-dir", self.store, "--ghidra-home", self.home, "--port", "65421",
            "--writable", "--commit", "CLI-reviewed changes", "--timeout", "1"], obj=options)
        self.assertEqual(0, started.exit_code, started.output)
        self.assertFalse(json.loads(started.output)["result"]["read_only"])
        self.http.dirty = True
        stopped = cli.invoke(command, ["stop", "--port", "65421"], obj=options)
        self.assertEqual(0, stopped.exit_code, stopped.output)
        outcome = json.loads(stopped.output)["result"]
        self.assertIs(True, outcome["saved"])
        self.assertIs(True, outcome["checked_in"])
        self.assertFalse(outcome["confirmation_unknown"])
        self.assertEqual("CLI-reviewed changes", self.http.checkins[0]["comment"])
        self.assert_no_signals()


class BridgeProcessOwnershipTests(unittest.TestCase):
    def test_process_marker_also_requires_exact_worker_port(self):
        import bridge_mcp_hydra as bridge

        with mock.patch.object(subprocess, "run", return_value=mock.Mock(
                stdout="java GhidraHeadlessServer port=81920")):
            self.assertFalse(bridge._headless_process_is_ours(4567, port=8192))
            self.assertTrue(bridge._headless_process_is_ours(4567, port=81920))


class RepositoryBridgeLifecycleTests(unittest.TestCase):
    """The standalone MCP bridge consumes CLI state without importing its runner."""

    def setUp(self):
        import bridge_mcp_hydra as bridge

        self.bridge = bridge
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        root = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.stack.enter_context(mock.patch.dict(os.environ, {"GHYDRA_STATE_DIR": root}))
        self.stack.enter_context(mock.patch.object(bridge, "RAW_OUTPUT", True))
        self.http = RepositoryHTTPFixture()
        self.http.online = True
        self.http.file.update(checked_out=True, exclusive=True)
        self.http.active = {"path": self.http.path, "read_only": False, "version": 7}
        self.transport = requests.Session()
        self.transport.trust_env = False
        self.transport.mount("http://", self.http)
        self.stack.callback(self.transport.close)
        self.stack.enter_context(mock.patch.object(bridge, "_http_session", return_value=self.transport))
        self.stack.enter_context(mock.patch.object(
            headless.HeadlessRunner, "from_instance", side_effect=AssertionError("CLI runner imported")))
        self.stack.enter_context(mock.patch.object(
            connections, "load_profile", side_effect=AssertionError("Private profile read")))
        self.ours = self.stack.enter_context(
            mock.patch.object(bridge, "_headless_process_is_ours", return_value=True))
        self.stack.enter_context(mock.patch.object(
            bridge, "_headless_process_alive", side_effect=self.process_alive))
        self.stack.enter_context(mock.patch.object(
            bridge, "_headless_api_answers", side_effect=lambda *args: self.http.online))
        self.stack.enter_context(mock.patch.object(
            bridge.time, "time", side_effect=itertools.count(1000, 0.25).__next__))
        self.stack.enter_context(mock.patch.object(bridge.time, "sleep"))
        self.signal_pid = self.stack.enter_context(mock.patch.object(os, "kill"))
        self.signal_tree = self.stack.enter_context(mock.patch.object(subprocess, "run"))
        self.signal_group = (self.stack.enter_context(mock.patch.object(os, "killpg"))
                             if hasattr(os, "killpg") else None)
        self.instance = headless.HeadlessInstance(
            port=65421, host="worker.invalid", pid=4567, repository_profile="approved",
            program="folder/program.exe", writable=True, commit="Reviewed analysis")
        headless.save_state(self.instance)
        runner = mock.Mock(instance=self.instance)
        runner.start.return_value = self.instance
        with mock.patch.object(sessions, "_build_runner", return_value=runner):
            self.session = sessions.open_session(
                repository_profile="approved", program=self.instance.program, writable=True,
                commit=self.instance.commit, name="remote", port=self.instance.port)
        self.flag = bridge._headless_stop_file(self.instance.port)
        self.stack.enter_context(mock.patch.dict(
            bridge.active_instances, {self.instance.port: {"url": self.instance.url}}, clear=True))

    def process_alive(self, pid):
        self.assertEqual(self.instance.pid, pid)
        if os.path.isfile(self.flag) and not self.http.refuse_stop:
            os.remove(self.flag)
            self.http.online = False
        return self.http.online

    def close_session(self):
        return json.loads(self.bridge.session_close(self.session.id))

    def assert_retained(self, outcome):
        self.assertIs(False, outcome["success"])
        self.assertEqual("HEADLESS_STOP_REFUSED", outcome["error"]["code"])
        self.assertEqual(sessions.STATE_RUNNING, sessions.get_session(self.session.id).state)
        self.assertEqual(self.instance.pid, headless.load_state(self.instance.port).pid)
        self.assertTrue(self.http.online)
        self.assertIn(self.instance.port, self.bridge.active_instances)
        self.assertFalse(os.path.exists(self.flag))
        for private in ("private-identity", "private-password", "/private/key"):
            self.assertNotIn(private, json.dumps(outcome))
        self.signal_pid.assert_not_called()
        self.signal_tree.assert_not_called()
        if self.signal_group is not None:
            self.signal_group.assert_not_called()

    def test_cli_shared_session_saves_checks_in_then_stops(self):
        self.http.dirty = True
        outcome = self.close_session()
        self.assertIs(True, outcome["success"])
        result = outcome["result"]
        self.assertEqual("stopped", result["session"]["state"])
        self.assertEqual({"saved": True, "checked_in": True, "confirmation_unknown": False},
                         {key: result["session"]["extra"][key]
                          for key in ("saved", "checked_in", "confirmation_unknown")})
        self.assertIs(True, result["stopped"]["result"]["stopped"])
        self.assertEqual([
            ("POST", "/program/save", {"workspace_only": "true"}, None),
            ("GET", "/repositories/files", {"profile": "approved", "path": "/folder",
                                          "offset": "0", "limit": "1000"}, None),
            ("POST", "/repositories/checkin", {}, {
                "profile": "approved", "path": self.http.path,
                "comment": "Reviewed analysis", "keep_checked_out": True})], self.http.calls)
        self.assertTrue(all(urlsplit(url).hostname == self.instance.host for url in self.http.urls))
        self.assertIsNone(headless.load_state(self.instance.port))
        self.assertNotIn(self.instance.port, self.bridge.active_instances)
        self.assertIs(True, sessions.get_session(self.session.id).extra["checked_in"])
        self.ours.assert_called_once_with(self.instance.pid, port=self.instance.port)
        self.signal_pid.assert_not_called()
        self.signal_tree.assert_not_called()

    def test_consumer_text_reports_save_refusal_not_closed(self):
        self.http.failures["/program/save"] = (403, "CONNECTION_PERMISSION_DENIED")
        with mock.patch.object(self.bridge, "RAW_OUTPUT", False):
            text = self.bridge.session_close(self.session.id)
        self.assertIn("HEADLESS_STOP_REFUSED", text)
        self.assertNotIn("was closed", text)
        self.assertNotIn("private-password", text)
        self.assertEqual(sessions.STATE_RUNNING, sessions.get_session(self.session.id).state)

    def test_save_http_or_envelope_refusal_retains_cli_session(self):
        for status in (200, 403):
            with self.subTest(status=status):
                self.http.failures["/program/save"] = (status, "CONNECTION_PERMISSION_DENIED")
                self.assert_retained(self.close_session())
                self.assertIsNone(headless.load_state(self.instance.port).repository_saved)
                self.assertFalse(self.http.operations("/repositories/checkin"))

    def test_unconfirmed_or_analyzer_save_is_not_a_repository_save(self):
        for result, expected in (({}, None), ({"saved": False, "analyzer_owned": True}, False),
                                 ({"saved": "true"}, None)):
            with self.subTest(result=result):
                self.http.save_result = result
                self.assert_retained(self.close_session())
                self.assertIs(expected, headless.load_state(self.instance.port).repository_saved)
                self.assertFalse(self.http.operations("/repositories/checkin"))

    def test_checkin_http_or_envelope_refusal_retains_saved_checkout(self):
        for status in (200, 403, 409):
            with self.subTest(status=status):
                self.http.dirty = True
                self.http.failures["/repositories/checkin"] = (status, "REPOSITORY_CONFLICT")
                self.assert_retained(self.close_session())
                remembered = headless.load_state(self.instance.port)
                self.assertIs(True, remembered.repository_saved)
                self.assertIsNone(remembered.checked_in)
                self.assertTrue(self.http.saved_changes)

    def test_checkin_requires_explicit_boolean_confirmation(self):
        for result, expected in (({}, None), ({"checked_in": False}, False),
                                 ({"checked_in": "true"}, None)):
            with self.subTest(result=result):
                self.http.dirty = True
                self.http.checkin_result = result
                self.assert_retained(self.close_session())
                self.assertIs(expected, headless.load_state(self.instance.port).checked_in)

    def test_lost_checkin_response_is_not_retried_or_reported_as_stopped(self):
        self.http.dirty = True
        send = self.http.send

        def lose_checkin_response(request, **kwargs):
            response = send(request, **kwargs)
            if urlsplit(request.url).path == "/repositories/checkin":
                raise requests.Timeout("private-password /private/key")
            return response

        with mock.patch.object(self.http, "send", side_effect=lose_checkin_response):
            self.assert_retained(self.close_session())
        self.assertEqual(1, len(self.http.checkins))
        self.assertEqual(1, len(self.http.operations("/repositories/checkin")))
        self.assertIsNone(headless.load_state(self.instance.port).checked_in)

    def test_stop_timeout_retains_confirmation_and_retry_does_not_republish(self):
        self.http.dirty = True
        self.http.refuse_stop = True
        self.assert_retained(self.close_session())
        self.assertIs(True, headless.load_state(self.instance.port).checked_in)
        status = json.loads(self.bridge.headless_status(self.instance.port))
        self.assertIs(True, status["result"]["known"])
        self.assertIs(True, status["result"]["running"])
        self.http.refuse_stop = False
        self.assertIs(True, self.close_session()["success"])
        self.assertEqual(1, len(self.http.checkins))
        self.assertEqual(2, len(self.http.operations("/repositories/files")))

    def test_retry_fresh_metadata_publishes_external_saved_changes_across_pages(self):
        self.http.dirty = True
        self.http.refuse_stop = True
        self.assert_retained(self.close_session())
        # A later HTTP edit/save must invalidate the previous publication even
        # when this close's own save has no new in-memory changes to write.
        self.http.saved_changes = True
        self.http.prefix = [{"path": "/folder/other", "type": "file"} for _ in range(1000)]
        self.http.refuse_stop = False
        outcome = self.close_session()
        self.assertIs(True, outcome["success"])
        self.assertIs(False, outcome["result"]["session"]["extra"]["saved"])
        self.assertIs(True, outcome["result"]["session"]["extra"]["checked_in"])
        self.assertEqual(2, len(self.http.checkins))
        self.assertEqual(["0", "1000"], [
            call[2]["offset"] for call in self.http.operations("/repositories/files")[-2:]])

    def test_unknown_checkout_metadata_cannot_reuse_prior_confirmation(self):
        self.http.dirty = True
        self.http.refuse_stop = True
        self.assert_retained(self.close_session())
        self.http.saved_changes = None
        self.assert_retained(self.close_session())
        self.assertIsNone(headless.load_state(self.instance.port).checked_in)
        self.assertEqual(1, len(self.http.checkins))

    def test_checkin_targets_original_program_not_current_selection(self):
        self.http.active = {"path": "/another/program", "read_only": False, "version": 1}
        self.http.saved_changes = True
        self.http.dirty = True
        self.assertIs(True, self.close_session()["success"])
        self.assertEqual(self.http.path, self.http.checkins[0]["path"])

    def test_readonly_cli_session_saves_without_checkin(self):
        self.instance.writable = self.session.writable = False
        self.instance.commit = self.session.commit = None
        headless.save_state(self.instance)
        sessions._save_store([self.session])
        self.http.active["read_only"] = True
        outcome = self.close_session()
        self.assertIs(True, outcome["success"])
        self.assertIs(False, outcome["result"]["session"]["extra"]["saved"])
        self.assertIsNone(outcome["result"]["session"]["extra"]["checked_in"])
        self.assertFalse(self.http.operations("/repositories/checkin"))

    def test_missing_replaced_or_mismatched_worker_state_never_closes_cli_session(self):
        for key, value in (("pid", 9876), ("repository_profile", ""),
                           ("program", "folder/other"), ("commit", "Different approval")):
            with self.subTest(key=key):
                state = self.instance.to_dict()
                state[key] = value
                self.bridge._headless_save_state(self.instance.port, state)
                outcome = self.close_session()
                self.assertIs(False, outcome["success"])
                self.assertEqual("SESSION_NOT_RUNNING", outcome["error"]["code"])
                self.assertEqual(sessions.STATE_RUNNING, sessions.get_session(self.session.id).state)
                self.assertEqual(value, self.bridge._headless_load_state(self.instance.port)[key])
        self.bridge._headless_clear_state(self.instance.port)
        self.assertIs(False, self.close_session()["success"])
        self.assertFalse(self.http.calls)
        self.signal_pid.assert_not_called()
        self.signal_tree.assert_not_called()

    def test_unconfirmed_repository_worker_ownership_retains_live_session_without_http(self):
        self.ours.return_value = False
        self.assert_retained(self.close_session())
        self.assertEqual(self.instance.to_dict(), headless.load_state(self.instance.port).to_dict())
        self.assertFalse(self.http.calls)
        self.assertTrue(json.loads(self.bridge.headless_status(self.instance.port))["result"]["running"])

    def test_missing_repository_worker_pid_is_not_a_successful_close(self):
        self.instance.pid = self.session.pid = 0
        headless.save_state(self.instance)
        sessions._save_store([self.session])
        outcome = self.close_session()
        self.assertIs(False, outcome["success"])
        self.assertEqual("HEADLESS_STOP_REFUSED", outcome["error"]["code"])
        self.assertEqual(sessions.STATE_RUNNING, sessions.get_session(self.session.id).state)
        self.assertEqual(self.instance.to_dict(), headless.load_state(self.instance.port).to_dict())
        self.assertFalse(self.http.calls)
        self.ours.assert_not_called()
        self.signal_pid.assert_not_called()
        self.signal_tree.assert_not_called()

    def test_headless_stop_also_enforces_repository_save_and_checkin(self):
        self.http.dirty = True
        outcome = json.loads(self.bridge.headless_stop(self.instance.port))
        self.assertIs(True, outcome["success"])
        self.assertIs(True, outcome["result"]["saved"])
        self.assertIs(True, outcome["result"]["checked_in"])
        self.assertEqual(1, len(self.http.checkins))

    def test_save_timeout_or_malformed_response_retains_worker(self):
        with mock.patch.object(self.http, "send", side_effect=requests.Timeout("private-password")):
            outcome = self.close_session()
        self.assert_retained(outcome)
        response = requests.Response()
        response.status_code = 200
        response._content = b"private-password not JSON"
        with mock.patch.object(self.http, "send", return_value=response):
            outcome = self.close_session()
        self.assert_retained(outcome)
        self.assertIsNone(headless.load_state(self.instance.port).repository_saved)

    def test_stop_file_failure_retains_confirmed_checkout_and_session(self):
        self.http.dirty = True
        with mock.patch.object(os, "makedirs", side_effect=OSError("cannot create stop flag")):
            outcome = self.close_session()
        self.assert_retained(outcome)
        self.assertIs(True, headless.load_state(self.instance.port).checked_in)

    def test_local_session_close_preserves_polite_exit_and_truthful_save_status(self):
        self.session.repository_profile = ""
        self.session.program = ""
        self.session.writable = False
        self.session.commit = None
        sessions._save_store([self.session])
        self.bridge._headless_save_state(
            self.instance.port, {"port": self.instance.port, "pid": self.instance.pid})
        self.http.refuse_stop = True
        with mock.patch.object(requests, "post", return_value=mock.Mock(ok=False)):
            self.assert_retained(self.close_session())
            self.http.refuse_stop = False
            outcome = self.close_session()
        self.assertIs(True, outcome["success"])
        self.assertIs(True, outcome["result"]["stopped"]["result"]["stopped"])
        self.assertIs(False, outcome["result"]["stopped"]["result"]["saved"])
        self.assertEqual(sessions.STATE_STOPPED, sessions.get_session(self.session.id).state)
        self.signal_pid.assert_not_called()
        self.signal_tree.assert_not_called()

    def test_local_stop_timeout_is_not_a_success_and_never_signals(self):
        self.bridge._headless_save_state(
            self.instance.port, {"port": self.instance.port, "pid": self.instance.pid})
        self.http.refuse_stop = True
        response = mock.Mock(ok=False)
        with mock.patch.object(requests, "post", return_value=response):
            self.assert_retained(json.loads(self.bridge.headless_stop(self.instance.port)))


class RepositorySessionTests(unittest.TestCase):
    def test_remote_session_preserves_identity_and_reopens_with_current_store(self):
        with tempfile.TemporaryDirectory() as root, \
                mock.patch.dict(os.environ, {"GHYDRA_STATE_DIR": root}):
            instance = headless.HeadlessInstance(pid=1234, repository_profile="approved",
                                                 program="folder/program", port=65421)
            runner = mock.Mock(instance=instance)
            runner.start.return_value = instance
            with mock.patch.object(sessions, "_build_runner", return_value=runner) as build:
                opened = sessions.open_session(repository_profile="approved", program="folder/program",
                                               connections_dir="/private/store", name="remote", port=65421)
                self.assertEqual("approved", opened.repository_profile)
                self.assertEqual("folder/program", opened.program)
                self.assertNotIn("connections_dir", json.dumps(opened.to_dict()))
                opened.state = sessions.STATE_STOPPED
                sessions._save_store([opened])
                reopened = sessions.reopen_session(opened.id, connections_dir="/private/rotated", timeout=7)
                self.assertEqual(opened.id, reopened.id)
                self.assertEqual(sessions.STATE_RUNNING, reopened.state)
                self.assertEqual("/private/rotated", build.call_args.kwargs["connections_dir"])
                self.assertEqual("approved", build.call_args.kwargs["repository_profile"])
                self.assertEqual("folder/program", build.call_args.kwargs["program"])

    def test_failed_stop_leaves_session_running(self):
        with tempfile.TemporaryDirectory() as root, \
                mock.patch.dict(os.environ, {"GHYDRA_STATE_DIR": root}):
            instance = headless.HeadlessInstance(pid=1234, repository_profile="approved",
                                                 program="folder/program", port=65421)
            headless.save_state(instance)
            session = sessions.Session(id="remote", name="remote", pid=1234, port=65421,
                                       state=sessions.STATE_RUNNING, repository_profile="approved",
                                       program="folder/program")
            sessions._save_store([session])
            runner = mock.Mock(instance=instance)
            runner.stop.side_effect = headless.HeadlessError("Retained", code="HEADLESS_STOP_REFUSED")
            with mock.patch.object(headless.HeadlessRunner, "from_instance", return_value=runner):
                with self.assertRaises(sessions.SessionError) as caught:
                    sessions.close_session(session.id)
            self.assertEqual("HEADLESS_STOP_REFUSED", caught.exception.code)
            self.assertEqual(sessions.STATE_RUNNING, sessions.get_session(session.id).state)
            self.assertEqual(1234, headless.load_state(65421).pid)


class RepositoryCLITests(unittest.TestCase):
    class Formatter:
        @staticmethod
        def format_simple_result(payload):
            return json.dumps(payload)

        @staticmethod
        def format_error(error):
            return str(error)

    def test_cli_rejects_extra_native_arguments_and_password_options(self):
        from click.testing import CliRunner
        from ghydra.cli.headless import headless as command

        for arguments in (["--extra=-preScript"], ["--password", "secret"], ["--", "-preScript", "evil.java"]):
            with self.subTest(arguments=arguments), \
                    mock.patch("ghydra.cli.headless.HeadlessRunner") as constructor:
                result = CliRunner().invoke(
                    command, ["start", "--repository-profile", "approved", "--program", "program"] + arguments,
                    obj={"formatter": self.Formatter()})
                self.assertNotEqual(0, result.exit_code)
                constructor.assert_not_called()

    def test_stop_reports_unknown_confirmation_without_inventing_success(self):
        from click.testing import CliRunner
        from ghydra.cli.headless import headless as command

        instance = headless.HeadlessInstance(repository_profile="approved", program="program")
        runner = mock.Mock(instance=instance)
        runner.stop.return_value = False
        with mock.patch.object(headless, "load_state", return_value=instance), \
                mock.patch("ghydra.cli.headless.HeadlessRunner.from_instance", return_value=runner):
            result = CliRunner().invoke(command, ["stop"], obj={"formatter": self.Formatter()})
        self.assertEqual(0, result.exit_code, result.output)
        outcome = json.loads(result.output)["result"]
        self.assertIsNone(outcome["saved"])
        self.assertIsNone(outcome["checked_in"])
        self.assertTrue(outcome["confirmation_unknown"])


if __name__ == "__main__":
    unittest.main()
