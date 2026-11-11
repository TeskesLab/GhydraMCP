"""The evidence ledger: the findings that outlive the session.

Reverse engineering is a long activity: hours of analysis, dozens of findings,
and the findings are what the work is actually for. Until now there was
nowhere to put one - a note about a function, a string, an xref - so they
lived in the analyst's head and died with the shell that opened them.

The ledger is that place. Every finding gets a stable id (``EV-0001``), a
kind, an address, a note, tags, and the provenance of where it was seen: the
tool that saw it, the instance that answered, the report it came from. The
ids are never reused, so a finding that is referred to in a conversation, in
a ticket or in another report still means the same thing tomorrow.

The ledger is a plain JSON file under the state directory, so it can be read
without this program, and the work can be handed over: ``export_bundle``
writes the findings out twice, as Markdown for a human to read and as JSON
for a program to read.

Nothing here needs Ghidra: the ledger is a book of notes, and the notes are
whatever the caller says they are.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from . import state as state_paths
from .markdown import markdown_table

# The kinds a finding can have. A finding that does not fit any of them is
# a "custom" one - the list is a vocabulary, not a cage.
KINDS = ("function", "string", "xref", "data", "note", "vulnerability", "custom")

# How sure the finding is.
CONFIDENCES = ("high", "medium", "low")

# The shape of an id: EV-0001, EV-0002, ...
ID_PREFIX = "EV-"
ID_WIDTH = 4


class EvidenceError(Exception):
    """A failure with a machine-readable code."""

    def __init__(self, message: str, code: str = "EVIDENCE_ERROR") -> None:
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------------ helpers


def ledger_dir() -> str:
    """Where the ledgers live: ``<state>/evidence``."""
    directory = os.path.join(state_paths.state_dir(), "evidence")
    os.makedirs(directory, exist_ok=True)
    return directory


def _check_name(name: str) -> str:
    """The name of a ledger, checked.

    The name is a file name, so it is not a path: a ledger called
    ``../config`` would be a way out of the directory.
    """
    text = str(name or "").strip()
    if not text:
        raise EvidenceError("the ledger needs a name")
    if text in (".", "..") or "/" in text or "\\" in text:
        raise EvidenceError(f"a ledger name is not a path: {name!r}")
    return text


def ledger_path(name: str) -> str:
    """Where the file of a ledger lives."""
    return os.path.join(ledger_dir(), f"{_check_name(name)}.json")


def normalize_address(address: str) -> str:
    """The address, the way it is written everywhere else.

    A Ghidra address is a hexadecimal number, so ``140001000`` and
    ``0x140001000`` are the same place and are written the same way:
    lower case, with the ``0x``. An address that is not a number at all -
    a label, a space, a reference - is kept as it is.
    """
    text = str(address or "").strip()
    if not text:
        return ""
    candidate = text[2:] if text[:2].lower() == "0x" else text
    if not candidate:
        return text
    try:
        value = int(candidate, 16)
    except ValueError:
        return text
    if value < 0:
        return text
    return f"0x{value:x}"


def _normalize_id(finding_id: str) -> str:
    """The id of a finding, the way it is written.

    ``ev-1``, ``EV-1`` and ``EV-0001`` are the same finding: the id is
    padded to four digits, so the answer does not depend on how it was
    typed.
    """
    text = str(finding_id or "").strip().upper()
    if not text:
        return ""
    if text.startswith(ID_PREFIX):
        text = text[len(ID_PREFIX):]
    if text.isdigit():
        return f"{ID_PREFIX}{int(text):0{ID_WIDTH}d}"
    return f"{ID_PREFIX}{text}"


def _next_id_of(findings: List["Finding"], stored: Any = None) -> int:
    """The id that comes next.

    The counter is the highest id ever issued, so an id is never given out
    twice - not even when the finding that had it was removed, and not
    even when the ledger was written to disk and read back.
    """
    highest = 0
    for finding in findings:
        text = str(getattr(finding, "id", "") or "")
        if text.startswith(ID_PREFIX):
            tail = text[len(ID_PREFIX):]
            if tail.isdigit():
                highest = max(highest, int(tail))
    try:
        stored_value = int(stored)
    except (TypeError, ValueError):
        stored_value = 0
    return max(highest + 1, stored_value, 1)


# ----------------------------------------------------------------- findings


@dataclass
class Finding:
    """One thing that was seen, and what was seen about it."""

    id: str
    kind: str
    address: str = ""
    name: str = ""
    note: str = ""
    tags: List[str] = field(default_factory=list)
    source: str = ""
    code: str = ""
    confidence: str = "medium"
    created_at: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        data = data or {}
        tags = data.get("tags") or []
        if isinstance(tags, str):
            tags = [tags]
        try:
            created_at = float(data.get("created_at") or 0.0)
        except (TypeError, ValueError):
            created_at = 0.0
        return cls(
            id=str(data.get("id") or ""),
            kind=str(data.get("kind") or "note"),
            address=normalize_address(data.get("address") or ""),
            name=str(data.get("name") or ""),
            note=str(data.get("note") or ""),
            tags=[str(tag) for tag in tags],
            source=str(data.get("source") or ""),
            code=str(data.get("code") or ""),
            confidence=str(data.get("confidence") or "medium"),
            created_at=created_at,
        )


# ------------------------------------------------------------------ ledger


class Ledger:
    """A book of findings, kept on disk.

    The ledger writes itself: every change is saved, so a finding that was
    added is a finding that is there, whatever the caller does next.
    """

    def __init__(self,
                 name: str,
                 findings: Optional[List[Any]] = None,
                 meta: Optional[Dict[str, Any]] = None) -> None:
        self.name = _check_name(name)
        self.findings: List[Finding] = [
            item if isinstance(item, Finding) else Finding.from_dict(item)
            for item in (findings or [])
        ]
        self.meta: Dict[str, Any] = dict(meta or {})
        now = time.time()
        self.created_at = now
        self.updated_at = now
        self._next_id = _next_id_of(self.findings)

    # -- the file ------------------------------------------------------

    @classmethod
    def open(cls, name: str, create: bool = True) -> "Ledger":
        """The ledger with that name, opened.

        A ledger that is there is read back; one that is not is created,
        unless the caller says otherwise.
        """
        name = _check_name(name)
        if os.path.isfile(ledger_path(name)):
            return cls.load(name)
        if not create:
            raise EvidenceError(
                f"no ledger named {name!r}", code="EVIDENCE_NO_LEDGER")
        ledger = cls(name)
        ledger.save()
        return ledger

    @classmethod
    def load(cls, name: str) -> "Ledger":
        """The ledger with that name, read from disk."""
        name = _check_name(name)
        path = ledger_path(name)
        if not os.path.isfile(path):
            raise EvidenceError(
                f"no ledger named {name!r}", code="EVIDENCE_NO_LEDGER")
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError) as exc:
            raise EvidenceError(
                f"the ledger {name!r} could not be read: {exc}",
                code="EVIDENCE_NO_FILE",
            ) from None
        if not isinstance(data, dict):
            raise EvidenceError(
                f"the ledger {name!r} is not a ledger",
                code="EVIDENCE_NO_FILE",
            )
        return cls.from_dict(data)

    def save(self) -> str:
        """Write the ledger, and say where it went."""
        path = ledger_path(self.name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.updated_at = time.time()
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=2, ensure_ascii=False)
        return path

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "next_id": self._next_id,
            "meta": dict(self.meta),
            "findings": [finding.to_dict() for finding in self.findings],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Ledger":
        data = data or {}
        ledger = cls(
            name=str(data.get("name") or ""),
            findings=data.get("findings") or [],
            meta=data.get("meta") or {},
        )
        try:
            ledger.created_at = float(data.get("created_at") or ledger.created_at)
        except (TypeError, ValueError):
            pass
        try:
            ledger.updated_at = float(data.get("updated_at") or ledger.updated_at)
        except (TypeError, ValueError):
            pass
        ledger._next_id = _next_id_of(ledger.findings, data.get("next_id"))
        return ledger

    # -- the findings --------------------------------------------------

    def add(self,
            kind: str,
            address: str = "",
            name: str = "",
            note: str = "",
            tags: Optional[List[str]] = None,
            source: str = "",
            code: str = "",
            confidence: str = "medium") -> Finding:
        """Add a finding, and give it the next id.

        The id is the promise of the ledger: ``EV-0001`` means the same
        thing in every file that mentions it, forever.
        """
        kind = str(kind or "").strip().lower()
        if kind not in KINDS:
            raise EvidenceError(
                f"unknown kind: {kind!r}. The kinds are: {', '.join(KINDS)}",
                code="EVIDENCE_BAD_KIND",
            )
        level = str(confidence or "medium").strip().lower()
        if level not in CONFIDENCES:
            level = "medium"
        if isinstance(tags, str):
            tags = [tags]
        finding = Finding(
            id=self._issue_id(),
            kind=kind,
            address=normalize_address(address),
            name=str(name or ""),
            note=str(note or ""),
            tags=[str(tag) for tag in (tags or [])],
            source=str(source or ""),
            code=str(code or ""),
            confidence=level,
            created_at=time.time(),
        )
        self.findings.append(finding)
        self.updated_at = finding.created_at
        self.save()
        return finding

    def _issue_id(self) -> str:
        number = self._next_id
        self._next_id = number + 1
        return f"{ID_PREFIX}{number:0{ID_WIDTH}d}"

    def get(self, finding_id: str) -> Finding:
        """The finding with that id."""
        key = _normalize_id(finding_id)
        for finding in self.findings:
            if finding.id == key:
                return finding
        raise EvidenceError(
            f"no finding {finding_id!r} in the ledger {self.name!r}",
            code="EVIDENCE_BAD_ID",
        )

    def remove(self, finding_id: str) -> bool:
        """Remove the finding with that id.

        The id is not given out again: the counter remembers it, so the
        finding that is gone keeps its place in the history.
        """
        key = _normalize_id(finding_id)
        for index, finding in enumerate(self.findings):
            if finding.id == key:
                del self.findings[index]
                self.save()
                return True
        return False

    def list(self,
             kind: str = "",
             tag: str = "",
             address: str = "",
             query: str = "") -> List[Finding]:
        """The findings that match, in the order they were found.

        The filters are combined: a finding has to pass all of them to be
        in the list. The query is a case-insensitive substring of the name,
        the note and the address.
        """
        wanted_kind = str(kind or "").strip().lower()
        wanted_tag = str(tag or "").strip().lower()
        wanted_address = normalize_address(address) if address else ""
        needle = str(query or "").strip().lower()

        out: List[Finding] = []
        for finding in self.findings:
            if wanted_kind and finding.kind.lower() != wanted_kind:
                continue
            if wanted_tag and wanted_tag not in [t.lower() for t in finding.tags]:
                continue
            if wanted_address and finding.address != wanted_address:
                continue
            if needle:
                haystack = " ".join(
                    (finding.name, finding.note, finding.address)).lower()
                if needle not in haystack:
                    continue
            out.append(finding)
        return out


def list_ledgers() -> List[Dict[str, Any]]:
    """The ledgers that are there, with how many findings each holds."""
    out: List[Dict[str, Any]] = []
    try:
        names = sorted(os.listdir(ledger_dir()))
    except OSError:
        return out
    for entry in names:
        if not entry.endswith(".json"):
            continue
        path = os.path.join(ledger_dir(), entry)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        out.append({
            "name": str(data.get("name") or os.path.splitext(entry)[0]),
            "path": path,
            "findings": len(data.get("findings") or []),
            "updated_at": data.get("updated_at", 0.0),
        })
    return out


# ------------------------------------------------------------------ bundle


def _fence_language(kind: str) -> str:
    """The language of the fenced block of a finding."""
    return "c" if kind in ("function", "vulnerability") else "text"


def render_bundle_markdown(ledger: Ledger, meta: Optional[Dict[str, Any]] = None) -> str:
    """The ledger as a document a human reads.

    The header says what the ledger is about, the summary says how many
    findings there are of each kind, and every finding gets its own
    section with everything that was recorded about it.
    """
    meta = dict(meta or {})
    findings = list(ledger.findings)
    generated = time.time()

    out: List[str] = []
    out.append(f"# {ledger.name} - evidence ledger\n")
    out.append(f"- Ledger: `{ledger.name}`")
    binary = meta.get("binary")
    if binary:
        out.append(f"- Binary: `{binary}`")
    out.append(f"- Date: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(generated))}")
    out.append(f"- Findings: {len(findings)}")
    out.append(f"- Created: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ledger.created_at))}")
    out.append(f"- Updated: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ledger.updated_at))}")
    for key, value in meta.items():
        if key == "binary":
            continue
        out.append(f"- {key}: {value}")
    out.append("")

    out.append("## Summary\n")
    counts = [(kind, sum(1 for f in findings if f.kind == kind))
              for kind in KINDS]
    counts = [(kind, count) for kind, count in counts if count]
    out.append(markdown_table(["Kind", "How many"], [[kind, count] for kind, count in counts]))
    out.append("")

    out.append("## The findings\n")
    for finding in findings:
        out.append(f"### {finding.id} - {finding.kind}\n")
        out.append(f"- **Name**: {finding.name or '-'}")
        out.append(f"- **Address**: {('`' + finding.address + '`') if finding.address else '-'}")
        out.append(f"- **Tags**: {', '.join(finding.tags) if finding.tags else '-'}")
        out.append(f"- **Provenance**: {finding.source or '-'}")
        out.append(f"- **Confidence**: {finding.confidence}")
        out.append(f"- **Seen**: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(finding.created_at))}")
        out.append("")
        if finding.note:
            out.append(finding.note)
            out.append("")
        if finding.code:
            out.append(f"```{_fence_language(finding.kind)}")
            out.append(finding.code.rstrip())
            out.append("```")
            out.append("")

    return "\n".join(out)


def export_bundle(ledger: Ledger,
                  output: Optional[str] = None,
                  binary: str = "",
                  meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Write the ledger out twice, and say where the files went.

    The two files are the same findings in two shapes: the Markdown is what
    a human reads, the JSON is what a program reads. They sit next to each
    other, so the pair travels together.
    """
    directory = os.path.abspath(os.path.expanduser(output)) if output else os.getcwd()
    os.makedirs(directory, exist_ok=True)

    meta = dict(meta or {})
    if binary:
        meta.setdefault("binary", binary)

    stem = f"{ledger.name}-evidence"
    markdown_path = os.path.join(directory, f"{stem}.md")
    json_path = os.path.join(directory, f"{stem}.json")

    with open(markdown_path, "w", encoding="utf-8") as handle:
        handle.write(render_bundle_markdown(ledger, meta))

    payload = {
        "name": ledger.name,
        "generated_at": time.time(),
        "binary": meta.get("binary", ""),
        "meta": meta,
        "count": len(ledger.findings),
        "findings": [finding.to_dict() for finding in ledger.findings],
    }
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)

    return {
        "markdown": markdown_path,
        "json": json_path,
        "findings": len(ledger.findings),
    }
