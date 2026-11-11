"""The evidence ledger and the sessions.

Neither needs Ghidra: the ledger is exercised on the files it reads and
writes, and the sessions on a fake runner that records what it was asked
to do. Nothing here touches the network either.
"""

import json
import os
import sys
import tempfile
import unittest

# The tests live in tests/; the code and the repository are one level up.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ghydra import evidence
from ghydra import headless
from ghydra import sessions


class _StateDirTestCase(unittest.TestCase):
    """A test that keeps its hands off the real state directory."""

    def setUp(self):
        """Point the state at a directory of its own."""
        self._previous = os.environ.get("GHYDRA_STATE_DIR")
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["GHYDRA_STATE_DIR"] = self._tmp.name

    def tearDown(self):
        """Give the state directory back."""
        if self._previous is None:
            os.environ.pop("GHYDRA_STATE_DIR", None)
        else:
            os.environ["GHYDRA_STATE_DIR"] = self._previous
        self._tmp.cleanup()


class EvidenceLedgerTests(_StateDirTestCase):
    """The findings: their ids, their addresses, and how they are found."""

    def test_the_first_finding_is_ev_0001(self):
        """The first finding of a ledger gets the first id."""
        ledger = evidence.Ledger.open("work")
        finding = ledger.add(kind="function", name="WinMain")
        self.assertEqual(finding.id, "EV-0001")

    def test_the_ids_increase(self):
        """Every finding gets the next id."""
        ledger = evidence.Ledger.open("work")
        ids = [ledger.add(kind="note", note=str(index)).id for index in range(4)]
        self.assertEqual(ids, ["EV-0001", "EV-0002", "EV-0003", "EV-0004"])

    def test_an_id_is_never_reused_after_a_removal(self):
        """A finding that is gone keeps its place in the history."""
        ledger = evidence.Ledger.open("work")
        ledger.add(kind="note", note="first")
        second = ledger.add(kind="note", note="second")
        self.assertTrue(ledger.remove(second.id))
        third = ledger.add(kind="note", note="third")
        self.assertEqual(third.id, "EV-0003")

    def test_an_id_is_never_reused_after_a_reload(self):
        """The counter is kept on disk, so a reload does not give it back."""
        ledger = evidence.Ledger.open("work")
        ledger.add(kind="note", note="first")
        ledger.add(kind="note", note="second")
        ledger.remove("EV-0002")
        again = evidence.Ledger.load("work")
        self.assertEqual(again.add(kind="note", note="third").id, "EV-0003")

    def test_an_unknown_kind_is_refused(self):
        """A kind that is not in the vocabulary does not go in."""
        ledger = evidence.Ledger.open("work")
        with self.assertRaises(evidence.EvidenceError) as caught:
            ledger.add(kind="sightseeing")
        self.assertEqual(caught.exception.code, "EVIDENCE_BAD_KIND")

    def test_the_known_kinds_are_accepted(self):
        """Every kind of the vocabulary is a finding."""
        ledger = evidence.Ledger.open("work")
        for kind in evidence.KINDS:
            self.assertEqual(ledger.add(kind=kind).kind, kind)

    def test_the_address_is_normalised(self):
        """An address is written one way, whatever way it came in."""
        ledger = evidence.Ledger.open("work")
        finding = ledger.add(kind="function", address="140001000")
        self.assertEqual(finding.address, "0x140001000")
        other = ledger.add(kind="function", address="0X140001000")
        self.assertEqual(other.address, "0x140001000")

    def test_an_address_that_is_not_a_number_is_kept(self):
        """An address that is not a number is left as it is."""
        ledger = evidence.Ledger.open("work")
        finding = ledger.add(kind="note", address="not an address")
        self.assertEqual(finding.address, "not an address")

    def test_the_findings_can_be_filtered_by_kind(self):
        """The kind narrows the list down."""
        ledger = evidence.Ledger.open("work")
        ledger.add(kind="function", name="one")
        ledger.add(kind="string", name="two")
        ledger.add(kind="function", name="three")
        found = ledger.list(kind="function")
        self.assertEqual([item.name for item in found], ["one", "three"])

    def test_the_findings_can_be_filtered_by_tag(self):
        """A tag picks the findings that carry it."""
        ledger = evidence.Ledger.open("work")
        ledger.add(kind="function", name="one", tags=["crypto"])
        ledger.add(kind="function", name="two", tags=["network", "crypto"])
        ledger.add(kind="function", name="three")
        found = ledger.list(tag="crypto")
        self.assertEqual([item.name for item in found], ["one", "two"])

    def test_the_findings_can_be_filtered_by_address(self):
        """The address picks the findings of one place."""
        ledger = evidence.Ledger.open("work")
        ledger.add(kind="function", address="140001000")
        ledger.add(kind="function", address="140002000")
        found = ledger.list(address="140001000")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].address, "0x140001000")

    def test_the_findings_can_be_filtered_by_query(self):
        """The query looks at the name, the note and the address."""
        ledger = evidence.Ledger.open("work")
        ledger.add(kind="function", name="WinMain")
        ledger.add(kind="note", note="the crypto is here")
        ledger.add(kind="data", address="0x140001000")
        self.assertEqual(len(ledger.list(query="winmain")), 1)
        self.assertEqual(len(ledger.list(query="crypto")), 1)
        self.assertEqual(len(ledger.list(query="0x140001000")), 1)

    def test_the_query_is_case_insensitive(self):
        """The query does not care how it was typed."""
        ledger = evidence.Ledger.open("work")
        ledger.add(kind="function", name="WinMain")
        self.assertEqual(len(ledger.list(query="WINMAIN")), 1)

    def test_the_ledger_round_trips_through_json(self):
        """What is written is what is read back."""
        ledger = evidence.Ledger.open("work")
        ledger.add(kind="function", address="140001000", name="WinMain",
                   note="the entry point", tags=["entry"], source="functions_get",
                   code="int main() {}", confidence="high")
        again = evidence.Ledger.load("work")
        self.assertEqual(len(again.findings), 1)
        finding = again.findings[0]
        self.assertEqual(finding.id, "EV-0001")
        self.assertEqual(finding.kind, "function")
        self.assertEqual(finding.address, "0x140001000")
        self.assertEqual(finding.name, "WinMain")
        self.assertEqual(finding.note, "the entry point")
        self.assertEqual(finding.tags, ["entry"])
        self.assertEqual(finding.source, "functions_get")
        self.assertEqual(finding.code, "int main() {}")
        self.assertEqual(finding.confidence, "high")

    def test_the_file_holds_the_ledger(self):
        """The file on disk is the ledger, in JSON."""
        ledger = evidence.Ledger.open("work")
        ledger.add(kind="note", note="hello")
        with open(evidence.ledger_path("work"), "r", encoding="utf-8") as handle:
            data = json.load(handle)
        self.assertEqual(data["name"], "work")
        self.assertEqual(len(data["findings"]), 1)
        self.assertIn("meta", data)
        self.assertIn("created_at", data)
        self.assertIn("updated_at", data)

    def test_a_missing_ledger_says_so(self):
        """A ledger that is not there is reported with its code."""
        with self.assertRaises(evidence.EvidenceError) as caught:
            evidence.Ledger.load("nothing")
        self.assertEqual(caught.exception.code, "EVIDENCE_NO_LEDGER")

    def test_opening_without_creating_does_not_make_a_ledger(self):
        """A ledger that is not there is not created behind the caller's back."""
        with self.assertRaises(evidence.EvidenceError) as caught:
            evidence.Ledger.open("nothing", create=False)
        self.assertEqual(caught.exception.code, "EVIDENCE_NO_LEDGER")
        self.assertFalse(os.path.exists(evidence.ledger_path("nothing")))

    def test_the_ledgers_are_listed_with_their_count(self):
        """The list says which ledgers are there and how full they are."""
        ledger = evidence.Ledger.open("work")
        ledger.add(kind="note")
        ledger.add(kind="note")
        evidence.Ledger.open("other")
        listed = {item["name"]: item for item in evidence.list_ledgers()}
        self.assertIn("work", listed)
        self.assertIn("other", listed)
        self.assertEqual(listed["work"]["findings"], 2)
        self.assertEqual(listed["other"]["findings"], 0)
        self.assertTrue(listed["work"]["path"].endswith("work.json"))

    def test_removing_a_finding_reports_whether_it_was_there(self):
        """Removing a finding that is not there is not a failure."""
        ledger = evidence.Ledger.open("work")
        finding = ledger.add(kind="note")
        self.assertTrue(ledger.remove(finding.id))
        self.assertFalse(ledger.remove(finding.id))

    def test_an_unknown_id_says_so(self):
        """A finding that is not in the ledger is reported with its code."""
        ledger = evidence.Ledger.open("work")
        with self.assertRaises(evidence.EvidenceError) as caught:
            ledger.get("EV-9999")
        self.assertEqual(caught.exception.code, "EVIDENCE_BAD_ID")

    def test_a_finding_is_found_by_any_spelling_of_its_id(self):
        """The id is the same finding however it is typed."""
        ledger = evidence.Ledger.open("work")
        finding = ledger.add(kind="note")
        self.assertEqual(ledger.get("ev-1").id, finding.id)
        self.assertEqual(ledger.get("EV-0001").id, finding.id)

    def test_the_confidence_defaults_to_medium(self):
        """A finding with nothing said about it is a medium one."""
        ledger = evidence.Ledger.open("work")
        self.assertEqual(ledger.add(kind="note").confidence, "medium")

    def test_the_ledger_lives_under_the_state_directory(self):
        """The ledger is a file in the state directory."""
        ledger = evidence.Ledger.open("work")
        self.assertTrue(evidence.ledger_path("work").startswith(
            os.environ["GHYDRA_STATE_DIR"]))
        self.assertTrue(os.path.isfile(evidence.ledger_path("work")))

    def test_a_name_that_is_a_path_is_refused(self):
        """A ledger name is a name, not a way out of the directory."""
        with self.assertRaises(evidence.EvidenceError):
            evidence.Ledger.open("../evil")


class EvidenceBundleTests(_StateDirTestCase):
    """The bundle: the ledger, written out for somebody else."""

    def _ledger(self):
        ledger = evidence.Ledger.open("work")
        ledger.add(kind="function", address="140001000", name="WinMain",
                   note="the entry point", tags=["entry"],
                   source="functions_get", code="int main() { return 0; }",
                   confidence="high")
        ledger.add(kind="vulnerability", address="140002000", name="copy",
                   note="a stack copy without a check", tags=["bug", "stack"],
                   source="https://127.0.0.1:8192", confidence="medium")
        return ledger

    def test_the_bundle_writes_two_files(self):
        """The bundle is a document and the data, side by side."""
        ledger = self._ledger()
        with tempfile.TemporaryDirectory() as tmp:
            paths = evidence.export_bundle(ledger, tmp)
            self.assertTrue(os.path.isfile(paths["markdown"]))
            self.assertTrue(os.path.isfile(paths["json"]))
            self.assertEqual(paths["findings"], 2)
            self.assertTrue(paths["markdown"].endswith("work-evidence.md"))
            self.assertTrue(paths["json"].endswith("work-evidence.json"))
            self.assertEqual(os.path.dirname(paths["markdown"]),
                             os.path.dirname(paths["json"]))

    def test_the_markdown_carries_every_id(self):
        """Every finding of the ledger is in the document."""
        ledger = self._ledger()
        text = evidence.render_bundle_markdown(ledger)
        for finding in ledger.findings:
            self.assertIn(finding.id, text)

    def test_the_markdown_has_the_summary_table(self):
        """The document says how many findings there are of each kind."""
        ledger = self._ledger()
        text = evidence.render_bundle_markdown(ledger)
        self.assertIn("## Summary", text)
        self.assertIn("function", text)
        self.assertIn("vulnerability", text)
        self.assertIn("Findings: 2", text)

    def test_the_markdown_carries_the_provenance_and_the_code(self):
        """What was recorded about a finding is in the document."""
        ledger = self._ledger()
        text = evidence.render_bundle_markdown(ledger, {"binary": "cmd.exe"})
        self.assertIn("functions_get", text)
        self.assertIn("https://127.0.0.1:8192", text)
        self.assertIn("int main() { return 0; }", text)
        self.assertIn("cmd.exe", text)

    def test_the_json_carries_the_findings(self):
        """The data of the bundle holds every finding."""
        ledger = self._ledger()
        with tempfile.TemporaryDirectory() as tmp:
            paths = evidence.export_bundle(ledger, tmp, binary="cmd.exe")
            with open(paths["json"], "r", encoding="utf-8") as handle:
                data = json.load(handle)
        self.assertEqual(data["count"], 2)
        self.assertEqual(data["binary"], "cmd.exe")
        self.assertEqual([item["id"] for item in data["findings"]],
                         ["EV-0001", "EV-0002"])

    def test_the_bundle_creates_the_directory(self):
        """The directory of the bundle is made when it is not there."""
        ledger = self._ledger()
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "out", "deeper")
            paths = evidence.export_bundle(ledger, target)
            self.assertTrue(os.path.isdir(target))
            self.assertTrue(os.path.isfile(paths["markdown"]))


class _FakeInstance:
    """The instance a fake run hands back."""

    def __init__(self, binary, port, pid=4242, project_dir="",
                 project_name="binary", host="127.0.0.1"):
        self.binary = binary
        self.port = port
        self.pid = pid
        self.project_dir = project_dir
        self.project_name = project_name
        self.host = host


class _FakeRunner:
    """A runner that records what it was asked to do."""

    def __init__(self, binary, port, ghidra_home="", java_home="", host="127.0.0.1"):
        self.binary = binary
        self.port = port
        self.calls = []
        self.instance = _FakeInstance(binary, port, host=host)

    def start(self, timeout=900):
        """Pretend to start the run."""
        self.calls.append(("start", timeout))
        return self.instance

    def stop(self, timeout=20):
        """Pretend to stop the run."""
        self.calls.append(("stop", timeout))
        return True


class SessionTests(_StateDirTestCase):
    """The sessions: the record and the running of a working context."""

    def setUp(self):
        """Install the fake runner and a process that is alive."""
        super().setUp()
        self.calls = []
        self.runners = []
        original = sessions._build_runner

        def fake(binary, port=sessions.DEFAULT_PORT, ghidra_home="",
                 java_home="", host="127.0.0.1"):
            self.calls.append({
                "binary": binary, "port": port,
                "ghidra_home": ghidra_home, "java_home": java_home,
            })
            runner = _FakeRunner(binary, port, ghidra_home, java_home, host)
            self.runners.append(runner)
            return runner

        sessions._build_runner = fake
        self.addCleanup(lambda: setattr(sessions, "_build_runner", original))

        self._alive = headless.process_alive
        headless.process_alive = lambda pid: True
        self.addCleanup(lambda: setattr(headless, "process_alive", self._alive))

    def test_the_sessions_file_is_under_the_state_directory(self):
        """The sessions are kept in the state directory."""
        self.assertTrue(sessions.sessions_path().startswith(
            os.environ["GHYDRA_STATE_DIR"]))
        self.assertTrue(sessions.sessions_path().endswith("sessions.json"))

    def test_a_session_round_trips_through_json(self):
        """What is written is what is read back."""
        session = sessions.Session(
            id="s-3f9a21c4", name="cmd", binary="C:\\bin\\cmd.exe",
            port=8192, provider="ghidra", state="running", pid=42,
            project="/projects/cmd", created_at=1.0, updated_at=2.0,
            extra={"host": "127.0.0.1"})
        again = sessions.Session.from_dict(session.to_dict())
        self.assertEqual(again.to_dict(), session.to_dict())

    def test_the_id_comes_from_the_name_and_the_moment(self):
        """The same name and the same moment give the same id."""
        first = sessions._session_id("cmd", 1700000000.0)
        second = sessions._session_id("cmd", 1700000000.0)
        other = sessions._session_id("cmd", 1700000001.0)
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)
        self.assertTrue(first.startswith("s-"))

    def test_a_provider_failure_is_translated_into_a_session_error(self):
        """The provider's error must not escape the layer that owns it.

        `HeadlessError` and `SessionError` are siblings, so the CLI's
        `except SessionError` did not catch it and the user saw a traceback
        instead of the reason.
        """
        def refuse(*arguments, **keywords):
            raise headless.HeadlessError("no such binary",
                                         code="HEADLESS_NO_FILE")

        original = sessions._build_runner
        sessions._build_runner = refuse
        self.addCleanup(lambda: setattr(sessions, "_build_runner", original))

        with self.assertRaises(sessions.SessionError) as caught:
            sessions.open_session("C:\\bin\\missing.exe", name="missing")
        self.assertEqual("HEADLESS_NO_FILE", caught.exception.code)
        self.assertIn("no such binary", str(caught.exception))

    def test_a_failure_while_building_the_runner_is_translated_too(self):
        """The installation is looked for while the runner is built.

        On a machine without Ghidra the failure comes from there and not from
        the run — and the CI has no Ghidra, so this is the path it takes.
        """
        def refuse(*arguments, **keywords):
            raise headless.HeadlessError(
                "no Ghidra installation found. Set GHIDRA_HOME, or pass "
                "--ghidra-home with the path of the installation.",
                code="HEADLESS_NO_LAUNCHER")

        original = sessions._build_runner
        sessions._build_runner = refuse
        self.addCleanup(lambda: setattr(sessions, "_build_runner", original))

        with self.assertRaises(sessions.SessionError) as caught:
            sessions.open_session("C:\\bin\\cmd.exe", name="cmd")
        self.assertEqual("HEADLESS_NO_LAUNCHER", caught.exception.code)
        self.assertIn("GHIDRA_HOME", str(caught.exception))

    def test_opening_a_session_starts_a_run(self):
        """Opening a session starts the run and remembers it."""
        session = sessions.open_session("C:\\bin\\cmd.exe", name="cmd")
        self.assertEqual(session.state, "running")
        self.assertEqual(session.name, "cmd")
        self.assertEqual(session.port, 8192)
        self.assertEqual(session.pid, 4242)
        self.assertEqual(session.provider, "ghidra")
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.runners[0].calls[0], ("start", 900))
        self.assertEqual(sessions.list_sessions()[0].id, session.id)

    def test_the_session_is_on_disk(self):
        """The session that was opened is remembered on disk."""
        session = sessions.open_session("C:\\bin\\cmd.exe", name="cmd")
        with open(sessions.sessions_path(), "r", encoding="utf-8") as handle:
            data = json.load(handle)
        self.assertEqual(len(data["sessions"]), 1)
        self.assertEqual(data["sessions"][0]["name"], "cmd")
        self.assertEqual(data["sessions"][0]["id"], session.id)

    def test_a_taken_name_is_refused(self):
        """Two sessions with one name are not allowed."""
        sessions.open_session("C:\\bin\\cmd.exe", name="cmd")
        with self.assertRaises(sessions.SessionError) as caught:
            sessions.open_session("C:\\bin\\other.exe", name="cmd")
        self.assertEqual(caught.exception.code, "SESSION_ALREADY")

    def test_the_name_defaults_to_the_binary(self):
        """The name of the binary is the name of the session."""
        session = sessions.open_session("C:\\bin\\cmd.exe")
        self.assertEqual(session.name, "cmd")

    def test_a_name_that_is_a_path_is_refused(self):
        """A session name is a name, not a path."""
        with self.assertRaises(sessions.SessionError) as caught:
            sessions.open_session("C:\\bin\\cmd.exe", name="../evil")
        self.assertEqual(caught.exception.code, "SESSION_BAD_NAME")

    def test_closing_a_session_stops_the_run(self):
        """Closing stops the run and says the session is stopped."""
        session = sessions.open_session("C:\\bin\\cmd.exe", name="cmd")
        closed = sessions.close_session(session.id)
        self.assertEqual(closed.state, "stopped")
        self.assertEqual(self.runners[-1].calls[-1], ("stop", 20))
        self.assertEqual(sessions.get_session(session.id).state, "stopped")

    def test_closing_a_stopped_session_says_so(self):
        """A session that is not running is not closed twice."""
        session = sessions.open_session("C:\\bin\\cmd.exe", name="cmd")
        sessions.close_session(session.id)
        with self.assertRaises(sessions.SessionError) as caught:
            sessions.close_session(session.id)
        self.assertEqual(caught.exception.code, "SESSION_NOT_RUNNING")

    def test_an_unknown_session_says_so(self):
        """A session that is not there is reported with its code."""
        with self.assertRaises(sessions.SessionError) as caught:
            sessions.get_session("s-nothing")
        self.assertEqual(caught.exception.code, "SESSION_NO_SUCH")
        with self.assertRaises(sessions.SessionError) as caught:
            sessions.close_session("s-nothing")
        self.assertEqual(caught.exception.code, "SESSION_NO_SUCH")

    def test_a_dead_session_is_marked_stopped(self):
        """A session whose process is gone is not running any more."""
        session = sessions.open_session("C:\\bin\\cmd.exe", name="cmd")
        headless.process_alive = lambda pid: False
        listed = sessions.list_sessions()
        self.assertEqual(listed[0].state, "stopped")
        with open(sessions.sessions_path(), "r", encoding="utf-8") as handle:
            data = json.load(handle)
        self.assertEqual(data["sessions"][0]["state"], "stopped")

    def test_touching_a_session_updates_the_moment(self):
        """Touching a session says that it was used just now."""
        session = sessions.open_session("C:\\bin\\cmd.exe", name="cmd")
        before = session.updated_at
        session.updated_at = 0.0
        touched = sessions.touch_session(session)
        self.assertGreater(touched.updated_at, before)
        self.assertEqual(sessions.get_session(session.id).updated_at,
                         touched.updated_at)

    def test_the_sessions_are_listed(self):
        """Every session that is known is in the list."""
        sessions.open_session("C:\\bin\\cmd.exe", name="cmd")
        sessions.open_session("C:\\bin\\other.exe", name="other")
        listed = sessions.list_sessions()
        self.assertEqual(len(listed), 2)
        self.assertEqual({item.name for item in listed}, {"cmd", "other"})

    def test_the_session_knows_where_it_is_served(self):
        """The session says the address of its instance."""
        session = sessions.open_session("C:\\bin\\cmd.exe", name="cmd")
        self.assertEqual(session.url, "http://127.0.0.1:8192")


if __name__ == "__main__":
    unittest.main(verbosity=2)
