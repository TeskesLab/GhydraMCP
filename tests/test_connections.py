"""Synthetic-only connection setup/storage regressions; no remote services."""
import json
import getpass
import multiprocessing
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from click.testing import CliRunner

from ghydra import connections as store
from ghydra.cli.connections import connections


SENTINEL = "DO_NOT_PRINT_worker_secret_7f129"


def _parallel_create(directory, profile_id):
    store.save_profile(profile_id, directory, kind="bsim", backend="postgresql",
                       endpoint="postgresql://db.example/corpus", auth="password",
                       permissions=["query"], credentials={"username": "reader", "password": SENTINEL})


@unittest.skipUnless(os.name == "posix", "secure worker profiles require POSIX")
class ConnectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = str(Path(self.temporary.name) / "worker")
        self.password = {"username": "reader", "password": SENTINEL}

    def save(self, profile_id="corpus", **changes):
        options = dict(kind="bsim", backend="postgresql", endpoint="postgresql://db.example:5432/corpus",
                       auth="password", permissions=["query"], credentials=self.password)
        options.update(changes)
        return store.save_profile(profile_id, self.directory, **options)

    def document(self, filename):
        return json.loads((Path(self.directory) / filename).read_text())

    def credential(self, profile_id="corpus"):
        reference = self.document("profiles.json")["profiles"][profile_id]["credential_ref"]
        return self.document("credentials.json")["credentials"][reference]

    def write_document(self, filename, document):
        path = Path(self.directory) / filename
        path.write_text(json.dumps(document))
        path.chmod(0o600)

    def assert_safe_failure(self, function, *args, **kwargs):
        with self.assertRaises(store.ConnectionError) as caught:
            function(*args, **kwargs)
        self.assertNotIn(SENTINEL, str(caught.exception))
        self.assertNotIn(SENTINEL, repr(caught.exception))
        return caught.exception

    def test_catalog_and_metadata_never_expose_identity_or_secret(self):
        self.save(credentials={"username": SENTINEL, "password": SENTINEL})
        metadata = store.load_profile("corpus", self.directory, kind="bsim", permission="query")
        catalog = store.catalog(self.directory)
        self.assertNotIn(SENTINEL, json.dumps([metadata, catalog]))
        self.assertEqual({"id", "kind", "backend", "permissions"}, set(catalog[0]))
        self.assertNotIn("credential_ref", metadata)
        self.assertNotIn("username", metadata)
        self.assertEqual(SENTINEL, self.credential()["password"])

    def test_private_files_directory_and_atomic_replacement_permissions(self):
        self.save()
        self.assertEqual(0o700, stat.S_IMODE(os.stat(self.directory).st_mode))
        for filename in ("profiles.json", "credentials.json", ".lock"):
            self.assertEqual(0o600, stat.S_IMODE(os.stat(Path(self.directory) / filename).st_mode))
        self.save(replace=True)
        self.assertEqual(0o600, stat.S_IMODE(os.stat(Path(self.directory) / "credentials.json").st_mode))
        self.assertFalse(list(Path(self.directory).glob(".tmp-*")))

    def test_permissions_and_kind_are_enforced(self):
        self.save()
        for kwargs in ({"permission": "ingest"}, {"permission": "checkin"}, {"kind": "ghidra"},
                       {"permission": []}, {"kind": []}):
            self.assert_safe_failure(store.load_profile, "corpus", self.directory, **kwargs)
        self.assert_safe_failure(store.load_profile, SENTINEL + "/..", self.directory)
        self.assert_safe_failure(store.load_profile, "absent", self.directory)

    def test_replacement_and_rotation_remove_all_old_secrets(self):
        self.save(default_bsim=True)
        original = self.document("profiles.json")["profiles"]["corpus"]["credential_ref"]
        result = store.rotate_credentials("corpus", self.directory,
                                          {"username": "new-reader", "password": "replacement"})
        self.assertNotIn(SENTINEL, json.dumps(result))
        self.assertNotIn(SENTINEL, (Path(self.directory) / "credentials.json").read_text())
        self.assertNotIn(original, self.document("credentials.json")["credentials"])
        self.assertEqual("corpus", self.document("profiles.json")["default_bsim"])
        self.save(replace=True, endpoint="postgresql://new.example/corpus",
                  credentials={"username": "other", "password": "third"})
        self.assertEqual({"username": "other", "password": "third"},
                         self.credential())
        store.remove_profile("corpus", self.directory)
        self.assertEqual([], store.catalog(self.directory))
        self.assertEqual({}, self.document("credentials.json")["credentials"])
        self.assertNotIn("default_bsim", self.document("profiles.json"))

    def test_default_bsim_kind_change_is_refused_without_corrupting_store(self):
        self.save(default_bsim=True)
        before = {name: self.document(name) for name in ("profiles.json", "credentials.json")}
        error = self.assert_safe_failure(
            self.save, replace=True, kind="ghidra", backend="ghidra",
            endpoint="ghidra://repo.example:13100/project", permissions=["read"])
        self.assertEqual("CONNECTION_PROFILE_INVALID", error.code)
        self.assertEqual(before, {name: self.document(name) for name in before})
        self.assertEqual("bsim", store.catalog(self.directory)[0]["kind"])
        store.rotate_credentials("corpus", self.directory,
                                 {"username": "reader", "password": "updated"})
        store.remove_profile("corpus", self.directory)
        self.assertEqual([], store.catalog(self.directory))

    def test_h2_pg_elastic_and_native_ghidra_profiles(self):
        self.save("local", backend="h2", endpoint="/srv/worker/corpus", auth="none", credentials=None,
                  permissions=["query", "ingest"])
        self.assertNotIn("credential_ref", self.document("profiles.json")["profiles"]["local"])
        self.assert_safe_failure(store.rotate_credentials, "local", self.directory, self.password)
        self.save("pg")
        self.save("elastic", backend="elasticsearch", endpoint="elastic://search.example:9200/corpus")
        self.save("elastic-tls", backend="elasticsearch", endpoint="https://search.example/corpus")
        self.save("native", kind="ghidra", backend="ghidra", endpoint="ghidra://repo.example:13100/project",
                  permissions=["read", "checkout", "checkin"])
        self.assertEqual(5, len(store.catalog(self.directory)))
        self.assert_safe_failure(self.save, "wrong", kind="ghidra")
        self.assert_safe_failure(self.save, "wrong", backend="h2", auth="password", endpoint="/srv/db")
        self.assert_safe_failure(self.save, "wrong", auth="ssh")
        self.assert_safe_failure(self.save, "wrong", permissions=["query", "query"])
        self.assert_safe_failure(self.save, "wrong", permissions=[])
        error = self.assert_safe_failure(self.save, "unsupported", backend="elasticsearch",
                                         endpoint="elastic://search.example/corpus", auth="pki")
        self.assertIn("password authentication only", str(error))

    def test_private_pki_and_ssh_identity_paths(self):
        identity_directory = Path(self.temporary.name) / "identity"
        identity_directory.mkdir(mode=0o700)
        key = identity_directory / "identity.p12"
        key.write_text("synthetic identity bytes")
        key.chmod(0o600)
        identity = {"username": "worker", "key_store": str(key), "key_store_password": SENTINEL}
        self.save("pg-pki", auth="pki", credentials=identity)
        self.assertNotIn(SENTINEL, json.dumps(store.load_profile("pg-pki", self.directory)))
        self.save("native-pki", kind="ghidra", backend="ghidra", endpoint="ghidra://repo.example/project",
                  permissions=["read"], auth="pki", credentials=identity)
        self.save("native-ssh", kind="ghidra", backend="ghidra", endpoint="ghidra://repo.example/project",
                  permissions=["read"], auth="ssh", credentials={**identity, "key_store_password": ""})
        self.assert_safe_failure(self.save, "encrypted-ssh", kind="ghidra", backend="ghidra",
                                 endpoint="ghidra://repo.example/project", permissions=["read"],
                                 auth="ssh", credentials=identity)
        key.chmod(0o644)
        self.assert_safe_failure(store.rotate_credentials, "pg-pki", self.directory, identity)
        key.chmod(0o600)
        link = identity_directory / "link"
        link.symlink_to(key)
        self.assert_safe_failure(self.save, "linked", auth="pki", credentials={**identity, "key_store": str(link)})

    def test_endpoint_injection_traversal_and_malformed_values(self):
        endpoints = [
            f"postgresql://user:{SENTINEL}@db.example/corpus", "postgresql://db.example/corpus?password=" + SENTINEL,
            "postgresql://db.example/corpus#" + SENTINEL, "postgresql://db.example/../corpus",
            "postgresql://db.example/%2e%2e", "postgresql://db.example/a%2fb", "postgresql://db.example/a/..",
            "postgresql://db.example:0/corpus", "postgresql://db.example:65536/corpus",
            "postgresql://db.example:bad/corpus", "postgresql://db.example:/corpus",
            "postgresql://-bad.example/corpus", "postgresql://db.example//corpus", "postgresql://db.example/corpus/",
            "postgresql://999.999.999.999/corpus", "postgresql://127.1/corpus",
            "postgresql://db.example/corpus\n" + SENTINEL, "postgresql://db.example/corpus;password=" + SENTINEL,
            "http://db.example/corpus", None, {}, [],
        ]
        for endpoint in endpoints:
            with self.subTest(endpoint=type(endpoint).__name__):
                self.assert_safe_failure(self.save, endpoint=endpoint)
        for endpoint in ("relative/db", "/srv/../db", "/srv/db;PASSWORD=" + SENTINEL, "/srv/%2e%2e"):
            self.assert_safe_failure(self.save, backend="h2", auth="none", credentials=None, endpoint=endpoint)
        for profile_id in ("../" + SENTINEL, "a/b", "ü", "", "a" * 65, {}):
            self.assert_safe_failure(self.save, profile_id)

    def test_unsafe_store_modes_symlinks_hardlinks_and_owner(self):
        self.save()
        for filename in ("profiles.json", "credentials.json", ".lock"):
            path = Path(self.directory) / filename
            path.chmod(0o644)
            self.assert_safe_failure(self.save, replace=True)
            path.chmod(0o600)
        Path(self.directory).chmod(0o755)
        self.assert_safe_failure(store.catalog, self.directory)
        Path(self.directory).chmod(0o700)
        for filename in ("profiles.json", "credentials.json", ".lock"):
            path = Path(self.directory) / filename
            backup = Path(self.temporary.name) / (filename + ".backup")
            path.rename(backup)
            path.symlink_to(backup)
            self.assert_safe_failure(self.save, replace=True)
            path.unlink()
            backup.rename(path)
        alias = Path(self.temporary.name) / "alias"
        alias.symlink_to(self.directory, target_is_directory=True)
        self.assert_safe_failure(store.catalog, str(alias))
        linked = Path(self.temporary.name) / "hardlink"
        os.link(Path(self.directory) / "profiles.json", linked)
        self.assert_safe_failure(store.catalog, self.directory)
        linked.unlink()
        with mock.patch.object(store.os, "geteuid", return_value=os.geteuid() + 10000):
            self.assert_safe_failure(store.catalog, self.directory)

    def test_malformed_and_secret_bearing_documents_fail_safely(self):
        self.save()
        path = Path(self.directory) / "profiles.json"
        original = path.read_text()
        for raw in (SENTINEL, '{"version":1,"version":1,"profiles":{}}',
                    json.dumps({"version": True, "profiles": {}}),
                    json.dumps({"version": 1, "profiles": {"x": {"password": SENTINEL}}}),
                    '[' * 2000 + SENTINEL):
            path.write_text(raw)
            self.assert_safe_failure(store.catalog, self.directory)
        path.write_text(original)
        (Path(self.directory) / "credentials.json").write_text(SENTINEL)
        self.assert_safe_failure(store.rotate_credentials, "corpus", self.directory, self.password)

    def test_two_operator_processes_do_not_lose_updates(self):
        self.save("initial")
        context = multiprocessing.get_context("spawn")
        processes = [context.Process(target=_parallel_create, args=(self.directory, name)) for name in ("one", "two")]
        for process in processes:
            process.start()
        for process in processes:
            process.join(15)
            if process.is_alive():
                process.terminate()
                process.join()
                self.fail("operator process failed to finish")
            self.assertEqual(0, process.exitcode)
        self.assertEqual({"initial", "one", "two"}, {p["id"] for p in store.catalog(self.directory)})

    def test_windows_fails_closed_with_deployment_instruction(self):
        with mock.patch.object(store.os, "name", "nt"):
            error = self.assert_safe_failure(store.catalog, self.directory)
        self.assertIn("isolated POSIX worker", str(error))

    def test_cli_never_accepts_secret_options_or_echoes_invalid_input(self):
        runner = CliRunner()
        for args in ([SENTINEL], ["create", SENTINEL, "--password", SENTINEL],
                     ["inspect", SENTINEL, SENTINEL], ["--password", SENTINEL]):
            result = runner.invoke(connections, ["--directory", self.directory, *args])
            self.assertNotEqual(0, result.exit_code)
            self.assertNotIn(SENTINEL, result.output)
        help_result = runner.invoke(connections, ["--directory", self.directory, "create", "--help"])
        self.assertEqual(0, help_result.exit_code)
        self.assertNotIn("--password", help_result.output)
        self.assertNotIn("--username", help_result.output)
        self.assertNotIn("--key-store", help_result.output)

    def test_cli_hidden_prompts_rotation_listing_and_no_env_secrets(self):
        runner = CliRunner()
        args = ["--directory", self.directory, "create", "corpus", "--kind", "bsim", "--backend", "postgresql",
                "--endpoint", "postgresql://db.example/corpus", "--auth", "password", "--permission", "query"]
        with mock.patch("ghydra.cli.connections._interactive"), mock.patch(
                "ghydra.cli.connections.click.prompt", side_effect=[SENTINEL, SENTINEL]) as prompt:
            result = runner.invoke(connections, args, env={"PASSWORD": "ignored"})
        self.assertEqual(0, result.exit_code, result.output)
        self.assertNotIn(SENTINEL, result.output)
        self.assertTrue(all(call.kwargs.get("hide_input") for call in prompt.call_args_list))
        for command in (["list"], ["inspect", "corpus"]):
            result = runner.invoke(connections, ["--directory", self.directory, *command])
            self.assertEqual(0, result.exit_code, result.output)
            self.assertNotIn(SENTINEL, result.output)
            self.assertNotIn("credential_ref", result.output)
        with mock.patch("ghydra.cli.connections._interactive"), mock.patch(
                "ghydra.cli.connections.click.prompt", side_effect=["replacement-reader", "replacement-password"]):
            result = runner.invoke(connections, ["--directory", self.directory, "rotate", "corpus"])
        self.assertEqual(0, result.exit_code, result.output)
        self.assertNotIn(SENTINEL, (Path(self.directory) / "credentials.json").read_text())
        with mock.patch("ghydra.cli.connections.sys.stdin.isatty", return_value=False):
            result = runner.invoke(connections, args)
        self.assertNotEqual(0, result.exit_code)
        self.assertIn("human interactive terminal", result.output)


    def test_hidden_input_never_falls_back_to_echo(self):
        import warnings
        from ghydra.cli.connections import _hidden_prompt

        def insecure_prompt(*args, **kwargs):
            warnings.warn("terminal cannot disable echo", getpass.GetPassWarning)
            self.fail("insecure fallback must never read input")

        with mock.patch("ghydra.cli.connections.click.prompt", side_effect=insecure_prompt):
            with self.assertRaises(Exception) as caught:
                _hidden_prompt("Worker password")
        self.assertIn("Secure hidden terminal", str(caught.exception))
        self.assertNotIn(SENTINEL, str(caught.exception))

    def test_failed_manifest_publication_preserves_old_identity(self):
        self.save()
        original_atomic = store._atomic

        def interrupt(fd, name, data):
            if name == "profiles.json":
                raise OSError("synthetic interruption " + SENTINEL)
            return original_atomic(fd, name, data)

        with mock.patch.object(store, "_atomic", side_effect=interrupt):
            self.assert_safe_failure(store.rotate_credentials, "corpus", self.directory,
                                     {"username": "new", "password": "replacement"})
        self.assertEqual(self.password, self.credential())
        store.rotate_credentials("corpus", self.directory, {"username": "new", "password": "replacement"})
        self.assertNotIn(SENTINEL, (Path(self.directory) / "credentials.json").read_text())

if __name__ == "__main__":
    unittest.main()
