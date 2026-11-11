"""Every command, and what it does when the instance is not there.

The `GhidraError` mistake in the target command's failure handler survived
because nothing drove the commands — the helpers were tested and the commands
were not. A handler that names a class it does not import raises a `NameError`
in the middle of reporting an error, and the user sees a traceback instead of
the reason.

This walks the whole Click tree, runs every leaf with nothing answering, and
asserts that **no command lets an exception out**. A command may answer 0 (it
did not need the instance) or 1 (it reported the failure); what it may not do is
crash.

Two things keep the walk honest and cheap:

* **the network is cut at the transport**, so no command waits for a socket to
  time out — the walk answered in 342 s before, and most of it was real
  connections to ports that are not there;
* **the walk runs in a temporary directory**, because a command that writes a
  file (the evidence export writes its bundle) must not write it into the
  repository.
"""

import os
import shutil
import socket
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ghydra.cli.main import cli  # noqa: E402
from ghydra.client.exceptions import GhidraConnectionError  # noqa: E402

#: A plausible value per option name. The point is not the value but that the
#: command gets far enough to reach its failure handling.
VALUES = {
    "address": "0x401000",
    "addresses": "0x401000",
    "name": "main",
    "new_name": "renamed",
    "old_name": "old",
    "length": "16",
    "size": "16",
    "count": "5",
    "value": "5",
    "type": "uint32_t",
    "data_type": "uint32_t",
    "category": "/custom",
    "field_name": "field",
    "field_type": "uint32_t",
    "struct_name": "MyStruct",
    "enum_name": "MyEnum",
    "union_name": "MyUnion",
    "datatype": "uint32_t",
    "format": "json",
    "output": "",
    "path": "",
    "file": "",
    "label": "label",
    "comment": "a comment",
    "signature": "int main(void)",
    "timeout": "5",
    "port": "8192",
    "max_functions": "1",
    "max_strings": "1",
    "depth": "1",
    "max_depth": "1",
    "limit": "5",
    "offset": "0",
    "query": "test",
    "goal": "what does this binary do",
    "source": "recv",
    "sink": "system",
    "kind": "overview",
    "match": "main",
    "tool": "GetAllRegisters",
    "arg": "a=1",
    "json_args": "{}",
    "id": "m1",
    "binary": "sample.exe",
    "new_type": "uint32_t",
    "new_comment": "a comment",
    "code": "0x401000",
    "memory": "0x401000",
    "reference": "0x401000",
    "to": "0x401000",
    "key": "a",
    "value_name": "a",
    "fields": "[]",
    "values": "{}",
    "width": "2",
    "height": "2",
    "address_space": "ram",
    "reason": "because",
    "phase": "1",
    "category_filter": "all",
    "command": "GetAllRegisters",
    "args": "",
}


def _value_for(option):
    name = option.name.replace("-", "_")
    return VALUES.get(name, VALUES.get(option.name, "1"))


def _leaves(command, path):
    """Every leaf command, with the options and arguments it needs."""
    subs = getattr(command, "commands", None)
    if not subs:
        yield path, command
        return
    for name, sub in sorted(subs.items()):
        yield from _leaves(sub, path + [name])


def _no_network():
    """Nothing answers, and nothing waits for an answer.

    The cut has to be at the **adapter**: the client talks through a
    `requests.Session`, so patching `requests.get` misses every call it makes —
    and the instance discovery builds a client of its own. The transport is
    where every one of them passes.
    """
    import requests

    def refused(*arguments, **keywords):
        raise requests.exceptions.ConnectionError("the network is cut in this test")

    def no_socket(*arguments, **keywords):
        raise OSError("the network is cut in this test")

    def no_dns(*arguments, **keywords):
        raise OSError("the network is cut in this test")

    return [
        mock.patch.object(requests.adapters.HTTPAdapter, "send", refused),
        mock.patch.object(requests, "get", refused),
        mock.patch.object(requests, "post", refused),
        mock.patch.object(requests, "request", refused),
        mock.patch.object(socket, "create_connection", no_socket),
        mock.patch.object(socket, "getaddrinfo", no_dns),
    ]


class CommandFailureTests(unittest.TestCase):
    """No command lets an exception out when nothing is serving."""

    def _invocation(self, path, command):
        """The arguments a leaf needs, so that it reaches its failure handling."""
        args = list(path)
        for param in command.params:
            if param.name in ("help",):
                continue
            if getattr(param, "is_flag", False):
                continue
            if param.required:
                if getattr(param, "opts", None) and param.opts[0].startswith("-"):
                    args.extend([param.opts[0], _value_for(param)])
                else:
                    args.append(_value_for(param))
        return args

    def _walk(self):
        """Every leaf command, run with nothing answering."""
        from click.testing import CliRunner

        class Failing:
            """The client that says the way a missing instance says it."""

            def _fail(self, *arguments, **keywords):
                raise GhidraConnectionError(
                    "no Ghidra instance is serving the API")

            get = post = patch = put = delete = _fail

            def __init__(self, host="127.0.0.1", port=8192, timeout=5,
                         dry_run=False, **keywords):
                self.host = host
                self.port = port
                self.timeout = timeout
                self.dry_run = dry_run
                self.base_url = f"http://{host}:{port}"
                self.session = None

        failures = []
        checked = 0
        runner = CliRunner()
        with mock.patch("ghydra.cli.main.GhidraHTTPClient", Failing):
            for path, command in _leaves(cli, []):
                args = self._invocation(path, command)
                result = runner.invoke(cli, args, catch_exceptions=True)
                checked += 1
                if result.exception is not None and not isinstance(
                        result.exception, SystemExit):
                    failures.append(
                        f"{' '.join(args)}: {type(result.exception).__name__}: "
                        f"{result.exception}")
        return checked, failures

    def test_no_command_crashes_when_nothing_is_serving(self):
        workspace = tempfile.mkdtemp(prefix="ghydra-cli-walk-")
        started = time.perf_counter()
        try:
            with mock.patch.dict(os.environ,
                                 {"GHYDRA_STATE_DIR": workspace}):
                patches = _no_network()
                for patcher in patches:
                    patcher.start()
                try:
                    with mock.patch("os.getcwd",
                                    return_value=workspace):
                        checked, failures = self._walk()
                finally:
                    for patcher in patches:
                        patcher.stop()
        finally:
            import shutil
            shutil.rmtree(workspace, ignore_errors=True)
        took = time.perf_counter() - started
        self.assertGreater(checked, 100, "the walk found almost no commands")
        self.assertEqual([], failures,
                         f"{len(failures)} command(s) let an exception out")
        # The walk used to take 342 s, almost all of it real connections to
        # ports that are not there.
        self.assertLess(took, 120.0,
                        f"the walk took {took:.0f}s; it is meant to be cheap")

    def test_the_walk_passes_on_a_machine_without_ghidra(self):
        """The CI has no Ghidra, and the failure it showed was here.

        `session open` fails while the runner is being **built** — the
        installation is looked for there — so the provider's error escaped the
        session layer on that machine and not on this one. The walk is run with
        the lookup failing, which is what the CI sees.
        """
        from ghydra.launcher import LauncherError

        def no_ghidra(*arguments, **keywords):
            raise LauncherError("no Ghidra installation found")

        workspace = tempfile.mkdtemp(prefix="ghydra-cli-walk-")
        try:
            with mock.patch.dict(os.environ,
                                 {"GHYDRA_STATE_DIR": workspace}):
                patches = _no_network()
                for patcher in patches:
                    patcher.start()
                try:
                    with mock.patch("os.getcwd", return_value=workspace):
                        with mock.patch("ghydra.launcher.find_ghidra_home",
                                        no_ghidra):
                            checked, failures = self._walk()
                finally:
                    for patcher in patches:
                        patcher.stop()
        finally:
            shutil.rmtree(workspace, ignore_errors=True)
        self.assertGreater(checked, 100)
        self.assertEqual([], failures,
                         f"{len(failures)} command(s) let an exception out "
                         "without an installation")

    def test_the_walk_reaches_every_command(self):
        """The guard above is only as good as the walk."""
        leaves = [path for path, _ in _leaves(cli, [])]
        self.assertGreater(len(leaves), 150)
        groups = {path[0] for path in leaves if path}
        self.assertEqual(set(cli.commands), groups)

    def test_the_walk_writes_nothing_into_the_repository(self):
        """A command that writes a file must not write it into the repository.

        The evidence export writes its bundle into the current directory, and the
        walk used to leave `default-evidence.json` and `default-evidence.md` in
        the repository root.
        """
        import shutil

        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        workspace = tempfile.mkdtemp(prefix="ghydra-cli-walk-")
        before = set(os.listdir(root))
        try:
            with mock.patch.dict(os.environ,
                                 {"GHYDRA_STATE_DIR": workspace}):
                patches = _no_network()
                for patcher in patches:
                    patcher.start()
                try:
                    with mock.patch("os.getcwd", return_value=workspace):
                        self._walk()
                finally:
                    for patcher in patches:
                        patcher.stop()
        finally:
            shutil.rmtree(workspace, ignore_errors=True)
        self.assertEqual(before, set(os.listdir(root)),
                         "the walk wrote into the repository")


if __name__ == "__main__":
    unittest.main()
