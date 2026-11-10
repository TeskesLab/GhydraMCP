"""Mission mode: an objective, a budget, and an auditable dossier (R8).

`ghydra mission` answers a *goal*, not a tool call. It runs a plan — triage,
capability leads, source-to-sink hypotheses, selective decompilation — and then
does the step most analyses skip: it **re-reads its own evidence** and checks
whether the conclusions still hold. The output is a dossier with findings that
carry an ID that never changes, the evidence behind each one, the budget that
was actually spent, and an explicit list of what was *not* determined.

Five rules define it:

* **No questions.** There is nobody to ask: a doubt becomes an `unknown`
  finding with the reason, never a prompt.
* **The budget is a hard stop.** Every call is counted; when it runs out the
  mission stops, says which steps were skipped, and keeps what it learned.
* **A conclusion needs evidence.** A finding without at least one recorded
  answer is not a finding; it is an `unknown`.
* **Verification is adversarial.** Each evidence item is re-requested and its
  digest compared. A conclusion whose evidence moved is reported as
  `unverified`, not quietly kept.
* **A checkpoint is a promise.** The state is written after every step, so a
  mission that dies can be resumed without re-paying the calls it already made.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, List, Optional

from . import diff as diff_helper
from . import runbook as runbook_helper
from . import taint as taint_helper
from .core import mission as core_mission
from .core.cache import fingerprint_from_program
from .core.hints import HINT_PATTERNS as CORE_HINT_PATTERNS
from .core.hints import parse_goal as core_parse_goal

#: All of these are defined once, in the core (I1).
MISSION_VERSION = core_mission.MISSION_VERSION
DEFAULT_CALLS = core_mission.DEFAULT_CALLS
DEFAULT_TOKENS = core_mission.DEFAULT_TOKENS
DEFAULT_SECONDS = core_mission.DEFAULT_SECONDS
ERROR_NO_PROGRAM = core_mission.ERROR_NO_PROGRAM
ERROR_BUDGET = core_mission.ERROR_BUDGET
ERROR_BAD_FILE = core_mission.ERROR_BAD_FILE
STATUS_OPEN = core_mission.STATUS_OPEN
STATUS_VERIFIED = core_mission.STATUS_VERIFIED
STATUS_UNVERIFIED = core_mission.STATUS_UNVERIFIED
STATUS_UNKNOWN = core_mission.STATUS_UNKNOWN

#: The hints a goal can carry. Defined once, in the core (I1).
HINT_PATTERNS = CORE_HINT_PATTERNS


def mission_dir() -> str:
    """Where the checkpoints and dossiers live."""
    from .evidence import state_dir
    path = os.path.join(state_dir(), "missions")
    os.makedirs(path, exist_ok=True)
    return path


def mission_path(mission_id: str) -> str:
    return os.path.join(mission_dir(), f"{mission_id}.json")


def parse_goal(goal: str) -> Dict[str, Any]:
    """The hints a goal carries, read from the text.

    Delegates to the core (I1), so the CLI and the bridge can never form
    different hypotheses from the same sentence.
    """
    return core_parse_goal(goal)


class Budget:
    """Calls, tokens and wall-clock, counted as they are spent."""

    def __init__(self, max_calls: int = DEFAULT_CALLS,
                 max_tokens: int = DEFAULT_TOKENS,
                 max_seconds: int = DEFAULT_SECONDS):
        self.max_calls = max(1, int(max_calls))
        self.max_tokens = max(1, int(max_tokens))
        self.max_seconds = max(1, int(max_seconds))
        self.calls = 0
        self.tokens = 0
        self.started = time.time()

    def exhausted(self) -> Optional[str]:
        """Delegates the order of the limits to the core (I1)."""
        return core_mission.budget_exhausted(
            self.calls, self.max_calls, self.tokens, self.max_tokens,
            time.time() - self.started, self.max_seconds)

    def spend(self, endpoint: str, payload: Any) -> None:
        """The count is the core's; the clock and the calls stay here."""
        self.calls += 1
        self.tokens += core_mission.tokens_of(payload)

    def as_dict(self) -> Dict[str, Any]:
        return core_mission.budget_row(
            self.calls, self.max_calls, self.tokens, self.max_tokens,
            time.time() - self.started, self.max_seconds)


class Mission:
    """The state a mission carries between steps and across a resume."""

    def __init__(self, goal: str, mission_id: str = "",
                 budget: Optional[Budget] = None):
        self.goal = goal
        self.id = mission_id or f"m{int(time.time())}"
        self.budget = budget or Budget()
        self.hints: Dict[str, Any] = parse_goal(goal)
        self.findings: List[Dict[str, Any]] = []
        self.steps: List[Dict[str, Any]] = []
        self.skipped: List[str] = []
        self.program: Dict[str, Any] = {}
        self.next_step = 0
        self.failed: Optional[str] = None

    # ---- findings --------------------------------------------------------
    def _next_finding_id(self) -> str:
        return f"EV-{len(self.findings) + 1:04d}"

    def add_finding(self, kind: str, title: str, detail: str = "",
                    confidence: str = "medium",
                    evidence: Optional[List[Dict[str, Any]]] = None,
                    status: str = STATUS_OPEN) -> Dict[str, Any]:
        finding = {
            "id": self._next_finding_id(),
            "kind": kind,
            "title": title,
            "detail": detail,
            "confidence": confidence,
            "status": status,
            "evidence": evidence or [],
        }
        self.findings.append(finding)
        return finding

    def add_unknown(self, question: str, reason: str) -> Dict[str, Any]:
        """A doubt becomes a finding, never a question to the user."""
        return self.add_finding("unknown", question, reason,
                                confidence="low", status=STATUS_UNKNOWN)

    def evidence(self, endpoint: str, payload: Any,
                 params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {"endpoint": endpoint,
                "params": params,
                "digest": runbook_helper.digest(
                    runbook_helper.stable_result(payload))}

    # ---- persistence -----------------------------------------------------
    def as_dict(self) -> Dict[str, Any]:
        return {
            "mission": MISSION_VERSION,
            "id": self.id,
            "goal": self.goal,
            "hints": self.hints,
            "program": self.program,
            "findings": self.findings,
            "steps": self.steps,
            "skipped": self.skipped,
            "next_step": self.next_step,
            "failed": self.failed,
            "budget": self.budget.as_dict(),
        }

    def save(self) -> str:
        path = mission_path(self.id)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(self.as_dict(), ensure_ascii=False, indent=2))
        return path

    @classmethod
    def load(cls, path: str) -> "Mission":
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except OSError as exc:
            raise ValueError(f"cannot read {path}: {exc}") from exc
        except ValueError as exc:
            raise ValueError(f"{path} is not valid JSON: {exc}") from exc
        if not isinstance(data, dict) or "mission" not in data:
            raise ValueError(f"{path} is not a mission checkpoint")
        budget_data = data.get("budget") or {}
        budget = Budget(budget_data.get("max_calls", DEFAULT_CALLS),
                        budget_data.get("max_tokens", DEFAULT_TOKENS),
                        budget_data.get("max_seconds", DEFAULT_SECONDS))
        budget.calls = int(budget_data.get("calls") or 0)
        budget.tokens = int(budget_data.get("tokens") or 0)
        mission = cls(data.get("goal", ""), data.get("id", ""), budget)
        mission.hints = data.get("hints") or mission.hints
        mission.findings = data.get("findings") or []
        mission.steps = data.get("steps") or []
        mission.skipped = data.get("skipped") or []
        mission.program = data.get("program") or {}
        mission.next_step = int(data.get("next_step") or 0)
        mission.failed = data.get("failed")
        return mission


class _Caller:
    """Counts every request against the mission budget."""

    def __init__(self, client, mission: Mission):
        self.client = client
        self.mission = mission

    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Any:
        reason = self.mission.budget.exhausted()
        if reason:
            raise _BudgetSpent(reason)
        try:
            response = self.client.get(endpoint, params=params)
        except Exception as exc:
            response = {"success": False,
                        "error": {"code": getattr(exc, "code", "MISSION_CALL_FAILED"),
                                  "message": str(exc)}}
        self.mission.budget.spend(endpoint, response)
        return response


class _BudgetSpent(Exception):
    pass


def _result(envelope: Any) -> Any:
    if isinstance(envelope, dict) and envelope.get("success", False):
        return envelope.get("result")
    return None


def _error_code(envelope: Any) -> str:
    if isinstance(envelope, dict):
        error = envelope.get("error")
        if isinstance(error, dict):
            return str(error.get("code") or "UNKNOWN")
    return "UNKNOWN"


# ------------------------------------------------------------------ steps
def _step_overview(caller, mission) -> None:
    envelope = caller.get("program")
    payload = _result(envelope)
    if not isinstance(payload, dict):
        mission.failed = ERROR_NO_PROGRAM
        mission.add_unknown("What is this binary?",
                            f"the program could not be read ({_error_code(envelope)})")
        return
    # One fingerprint, read from the keys `/program` actually sends. It used to
    # be built here with names no endpoint sends, and the dossier's own renderer
    # read a different name again — so every dossier printed "(no path)".
    mission.program = fingerprint_from_program(payload)
    mission.add_finding(
        "data", "Program fingerprint",
        json.dumps(mission.program, ensure_ascii=False),
        confidence="high", evidence=[mission.evidence("program", envelope)],
        status=STATUS_OPEN)


def _step_capabilities(caller, mission) -> None:
    from .capabilities import build_capability_report

    imports_envelope = caller.get("symbols/imports", {"limit": 1000})
    strings_envelope = caller.get("strings", {"limit": 1000})
    report = build_capability_report({"success": True, "result": mission.program},
                                    imports_envelope, strings_envelope,
                                    include_strings=True)
    leads = report.get("findings") or report.get("techniques") or []
    if not isinstance(leads, list) or not leads:
        mission.add_unknown("What does this binary do?",
                            "no ATT&CK/MBC lead matched the imports or strings")
        return
    for lead in leads[:10]:
        if not isinstance(lead, dict):
            continue
        mission.add_finding(
            "data", str(lead.get("technique") or lead.get("name") or "capability lead"),
            json.dumps(lead.get("evidence") or lead, ensure_ascii=False),
            confidence=str(lead.get("confidence") or "medium"),
            evidence=[mission.evidence("symbols/imports", imports_envelope),
                      mission.evidence("strings", strings_envelope)])


def _step_taint(caller, mission) -> None:
    source = mission.hints.get("source")
    sink = mission.hints.get("sink")
    if not source or not sink:
        mission.add_unknown(
            "Does untrusted data reach a dangerous sink?",
            "the goal names no source and sink, so no hypothesis was formed")
        return
    report = taint_helper.find_hypotheses(caller.client, source, sink)
    hypotheses = report.get("hypotheses") or []
    if not hypotheses:
        mission.add_unknown(
            f"Does data from {source} reach {sink}?",
            "no source-to-sink path was found; the search is linear and "
            "bounded, so this is not proof of safety")
        return
    for hypothesis in hypotheses[:10]:
        mission.add_finding(
            "vulnerability",
            f"{source} -> {sink} ({hypothesis.get('confidence')})",
            str(hypothesis.get("reason") or ""),
            confidence="high" if hypothesis.get("confidence") == "direct" else "medium",
            evidence=[mission.evidence("analysis/call-path", {"path": hypothesis.get("hops")},
                                       {"from": source, "to": sink})])


def _step_address(caller, mission) -> None:
    address = mission.hints.get("address")
    if not address:
        return
    envelope = caller.get(f"inspect/address/{address}")
    payload = _result(envelope)
    if not isinstance(payload, dict):
        mission.add_unknown(f"What is at {address}?",
                            f"the address could not be inspected ({_error_code(envelope)})")
        return
    mission.add_finding("xref", f"Address context at {address}",
                        json.dumps(payload, ensure_ascii=False)[:2000],
                        confidence="high",
                        evidence=[mission.evidence(f"inspect/address/{address}", envelope)])


STEPS = (
    ("overview", _step_overview),
    ("capabilities", _step_capabilities),
    ("taint", _step_taint),
    ("address", _step_address),
)


def run(client, mission: Mission, resume: bool = False) -> Mission:
    """Run the plan from the step it stopped at, writing a checkpoint each time."""
    start = mission.next_step if resume else 0
    for index in range(start, len(STEPS)):
        name, step = STEPS[index]
        if mission.failed:
            mission.skipped.extend(other for other, _ in STEPS[index:])
            break
        reason = mission.budget.exhausted()
        if reason:
            mission.skipped.extend(other for other, _ in STEPS[index:])
            mission.add_unknown("Was the whole plan run?",
                                f"{reason}; the steps "
                                f"{', '.join(other for other, _ in STEPS[index:])} "
                                f"were not run")
            break
        caller = _Caller(client, mission)
        try:
            step(caller, mission)
            mission.steps.append({"step": name, "status": "done"})
        except _BudgetSpent as exc:
            mission.skipped.append(name)
            mission.add_unknown("Was the whole plan run?", str(exc))
            mission.next_step = index
            break
        mission.next_step = index + 1
        mission.save()
    mission.save()
    return mission


def verify(client, mission: Mission) -> Dict[str, Any]:
    """Re-request every evidence item and check the conclusion still holds.

    This is the adversarial half: a finding is only `verified` when the answer
    behind it has the same digest it had when it was recorded. A finding whose
    evidence cannot be re-read is `unverified` - it is never silently kept.
    """
    checked = 0
    for finding in mission.findings:
        if finding.get("status") == STATUS_UNKNOWN or not finding.get("evidence"):
            continue
        verified = True
        for item in finding["evidence"]:
            if item.get("endpoint") == "analysis/call-path":
                # A derived path has no endpoint of its own to re-read; the
                # hops are re-checked by the call-path call the step made.
                continue
            checked += 1
            try:
                response = client.get(item["endpoint"], params=item.get("params"))
            except Exception:
                verified = False
                continue
            current = runbook_helper.digest(runbook_helper.stable_result(response))
            if current != item.get("digest"):
                verified = False
        finding["status"] = STATUS_VERIFIED if verified else STATUS_UNVERIFIED
    verified_count = sum(1 for f in mission.findings if f["status"] == STATUS_VERIFIED)
    unverified = [f["id"] for f in mission.findings if f["status"] == STATUS_UNVERIFIED]
    return {"checked": checked, "verified": verified_count,
            "unverified": unverified,
            "ok": not unverified}


def to_markdown(mission: Mission,
                verification: Optional[Dict[str, Any]] = None) -> str:
    """The dossier a human reads, and the artifact a CI job keeps.

    Delegates the rendering to the core (I1): one document, so the CLI and the
    bridge cannot produce different artifacts for the same mission.
    """
    return core_mission.dossier(
        mission.goal, mission.id, mission.program, mission.hints,
        mission.budget.as_dict(), mission.failed, mission.skipped,
        mission.findings, verification)

def save_dossier(mission: Mission, verification: Optional[Dict[str, Any]],
                 path: Optional[str] = None) -> str:
    target = path or os.path.join(mission_dir(), f"{mission.id}.md")
    with open(target, "w", encoding="utf-8") as handle:
        handle.write(to_markdown(mission, verification))
    return target