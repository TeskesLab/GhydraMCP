"""The sessions: a named working context that outlives the shell that opened it.

A headless run is a running Ghidra that serves the API for one binary. The
run survives the command that started it, but it does not say *what* it is:
the binary, the port, the project - nothing that says "this is the session
where I was looking at the crypto".

A session is that naming. It is a record of a working context - the binary,
the port that serves it, the provider, the state - kept in the state
directory, so "the session" survives the shell, the terminal and the day.
Opening one starts a headless run and remembers it; closing one stops the
run and says that it is stopped.

A session whose process is gone is marked stopped on its own: the state is
what the run did, and a run that died is a run that is not running any
more.

Nothing here needs Ghidra to be installed - only to open a session.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from . import state as state_paths
from .launcher import binary_name

# The port the first instance binds.
DEFAULT_PORT = 8192

# The states a session can be in.
STATE_RUNNING = "running"
STATE_STOPPED = "stopped"

# The provider of the session. There is only one for now.
PROVIDER_GHIDRA = "ghidra"


class SessionError(Exception):
    """A failure with a machine-readable code."""

    def __init__(self, message: str, code: str = "SESSION_ERROR") -> None:
        super().__init__(message)
        self.code = code


@dataclass
class Session:
    """A named working context."""

    id: str = ""
    name: str = ""
    binary: str = ""
    port: int = DEFAULT_PORT
    provider: str = PROVIDER_GHIDRA
    state: str = STATE_STOPPED
    pid: int = 0
    project: str = ""
    created_at: float = 0.0
    updated_at: float = 0.0
    extra: Dict[str, Any] = field(default_factory=dict)
    repository_profile: str = ""
    program: str = ""
    writable: bool = False
    commit: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Session":
        data = data or {}
        known = {name for name in cls.__dataclass_fields__}
        values = {key: value for key, value in data.items() if key in known}
        if not isinstance(values.get("extra"), dict):
            values["extra"] = {}
        try:
            values["port"] = int(values.get("port") or DEFAULT_PORT)
        except (TypeError, ValueError):
            values["port"] = DEFAULT_PORT
        try:
            values["pid"] = int(values.get("pid") or 0)
        except (TypeError, ValueError):
            values["pid"] = 0
        for stamp in ("created_at", "updated_at"):
            try:
                values[stamp] = float(values.get(stamp) or 0.0)
            except (TypeError, ValueError):
                values[stamp] = 0.0
        return cls(**values)

    @property
    def url(self) -> str:
        """Where the session is served."""
        host = (self.extra or {}).get("host") or "127.0.0.1"
        return f"http://{host}:{int(self.port)}"


# ------------------------------------------------------------------ store


def sessions_path() -> str:
    """Where the sessions are kept."""
    return os.path.join(state_paths.state_dir(), "sessions.json")


def _load_store() -> List[Session]:
    """The sessions that are on disk."""
    try:
        with open(sessions_path(), "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    entries = data.get("sessions") or []
    return [Session.from_dict(item) for item in entries if isinstance(item, dict)]


def _save_store(sessions: List[Session]) -> str:
    """Write the sessions down, and say where they went."""
    path = sessions_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = {"sessions": [session.to_dict() for session in sessions]}
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
    return path


def _session_id(name: str, created_at: float) -> str:
    """The id of a session.

    It comes from the name and the moment the session was made, so it is
    the same id in every command, in every restart, and two sessions with
    the same name are still two different sessions.
    """
    digest = hashlib.sha256(f"{name}:{created_at:.6f}".encode("utf-8")).hexdigest()
    return f"s-{digest[:8]}"


def _check_name(name: str) -> str:
    """The name of a session, checked.

    The name is a name, not a path.
    """
    text = str(name or "").strip()
    if not text:
        raise SessionError("the session needs a name", code="SESSION_BAD_NAME")
    if "/" in text or "\\" in text:
        raise SessionError(
            f"a session name is not a path: {name!r}", code="SESSION_BAD_NAME")
    return text


# --------------------------------------------------------------- the runner


def _build_runner(binary: str,
                  port: int = DEFAULT_PORT,
                  ghidra_home: str = "",
                  java_home: str = "",
                  host: str = "127.0.0.1",
                  repository_profile: Optional[str] = None,
                  program: Optional[str] = None,
                  connections_dir: Optional[str] = None,
                  writable: bool = False, commit: Optional[str] = None):
    """The headless runner that serves a session.

    The runner is built here and nowhere else, so a caller that wants a
    different one - a fake, in the tests - has a single place to change.
    """
    from .headless import HeadlessRunner

    return HeadlessRunner(
        binary=binary,
        port=port,
        ghidra_home=ghidra_home or None,
        java_home=java_home or None,
        host=host,
        repository_profile=repository_profile, program=program,
        connections_dir=connections_dir, writable=writable, commit=commit,
    )


# -------------------------------------------------------------- the sessions


def list_sessions() -> List[Session]:
    """The sessions that are known.

    A session whose process is gone is marked stopped, and the file is
    brought up to date: the state on disk is the state of the world.
    """
    from .headless import process_alive

    sessions = _load_store()
    changed = False
    for session in sessions:
        if session.state != STATE_RUNNING:
            continue
        if process_alive(session.pid):
            continue
        session.state = STATE_STOPPED
        session.updated_at = time.time()
        changed = True
    if changed:
        _save_store(sessions)
    return sessions


def get_session(session_id: str) -> Session:
    """The session with that id."""
    key = str(session_id or "").strip()
    for session in _load_store():
        if session.id == key:
            return session
    raise SessionError(f"no session {key!r}", code="SESSION_NO_SUCH")


def touch_session(session: Session) -> Session:
    """Say that the session was used just now."""
    session.updated_at = time.time()
    sessions = _load_store()
    for index, item in enumerate(sessions):
        if item.id == session.id:
            sessions[index] = session
            break
    else:
        sessions.append(session)
    _save_store(sessions)
    return session


def open_session(binary: str = "",
                 name: str = "",
                 port: int = DEFAULT_PORT,
                 ghidra_home: str = "",
                 java_home: str = "",
                 timeout: int = 900,
                 provider: str = PROVIDER_GHIDRA,
                 repository_profile: Optional[str] = None,
                 program: Optional[str] = None,
                 connections_dir: Optional[str] = None,
                 writable: bool = False,
                 commit: Optional[str] = None) -> Session:
    """Open a session: start the run, and remember it.

    The name is the name of the binary, unless the caller gives one. A
    name that is already taken is refused: two sessions with one name are
    two answers to one question.
    """
    if not binary and not repository_profile:
        raise SessionError("no binary or repository profile to open", code="SESSION_BAD_NAME")
    if not repository_profile:
        binary = os.path.abspath(os.path.expanduser(binary))
    if not name:
        name = os.path.splitext(binary_name((program or "") if repository_profile else binary))[0] or "program"
    name = _check_name(name)

    sessions = _load_store()
    for session in sessions:
        if session.name == name:
            raise SessionError(
                f"the name {name!r} is already taken by the session {session.id}",
                code="SESSION_ALREADY",
            )

    # The provider's failure is translated into this layer's taxonomy: the code
    # it carries is kept, so the reason is still machine-readable, and the
    # caller has one type to handle instead of two.
    #
    # The whole provider interaction is inside the guard, not only the start:
    # building the runner is where the installation is looked for, so on a
    # machine without Ghidra the failure comes from the constructor and not
    # from the run.
    runner_options = {}
    if repository_profile:
        runner_options = dict(repository_profile=repository_profile, program=program,
                              connections_dir=connections_dir, writable=writable, commit=commit)
    try:
        runner = _build_runner(binary, port=port, ghidra_home=ghidra_home,
                               java_home=java_home, **runner_options)
        instance = runner.start(timeout=timeout)
    except Exception as exc:
        from .headless import HeadlessError

        if isinstance(exc, HeadlessError):
            raise SessionError(str(exc),
                               code=getattr(exc, "code", "SESSION_ERROR")) from exc
        if isinstance(exc, SessionError):
            raise
        raise

    now = time.time()
    project_dir = str(getattr(instance, "project_dir", "") or "")
    project_name = str(getattr(instance, "project_name", "") or "")
    session = Session(
        id=_session_id(name, now),
        name=name,
        binary=str(getattr(instance, "binary", binary) or binary),
        port=int(getattr(instance, "port", port) or port),
        provider=provider or PROVIDER_GHIDRA,
        state=STATE_RUNNING,
        pid=int(getattr(instance, "pid", 0) or 0),
        project=os.path.join(project_dir, project_name) if project_dir else project_name,
        created_at=now,
        updated_at=now,
        repository_profile=repository_profile or "",
        program=str(getattr(instance, "program", "") or ""),
        writable=writable,
        commit=commit,
        extra={
            "ghidra_home": ghidra_home,
            "java_home": java_home,
            "host": str(getattr(instance, "host", "127.0.0.1") or "127.0.0.1"),
        },
    )
    sessions.append(session)
    _save_store(sessions)
    return session


def close_session(session_id: str, timeout: int = 20) -> Session:
    """Close a session: stop the run, and say that it is stopped.

    A session that is not running is not closed twice - the run is either
    there or it is not, and the record says which.
    """
    session = get_session(session_id)
    if session.state != STATE_RUNNING:
        raise SessionError(
            f"the session {session.id} is not running", code="SESSION_NOT_RUNNING")

    extra = session.extra or {}
    if session.repository_profile:
        from .headless import HeadlessRunner, load_state
        remembered = load_state(session.port)
        if remembered is None or remembered.pid != session.pid:
            raise SessionError("The repository worker state is unavailable.",
                               code="SESSION_NOT_RUNNING")
        runner = HeadlessRunner.from_instance(remembered)
    else:
        runner = _build_runner(
            session.binary,
            port=session.port,
            ghidra_home=str(extra.get("ghidra_home") or ""),
            java_home=str(extra.get("java_home") or ""),
        )
    instance = getattr(runner, "instance", None)
    if instance is not None:
        try:
            instance.pid = session.pid
        except (AttributeError, TypeError):
            pass
    from .headless import HeadlessError
    try:
        runner.stop(timeout=timeout)
    except HeadlessError as exc:
        raise SessionError(str(exc), code=exc.code) from exc
    if session.repository_profile:
        session.extra["saved"] = runner.instance.repository_saved
        session.extra["checked_in"] = runner.instance.checked_in
        session.extra["confirmation_unknown"] = (
            runner.instance.repository_saved is None or runner.instance.checked_in is None)

    session.state = STATE_STOPPED
    session.updated_at = time.time()
    sessions = _load_store()
    for index, item in enumerate(sessions):
        if item.id == session.id:
            sessions[index] = session
            break
    else:
        sessions.append(session)
    _save_store(sessions)
    return session


def reopen_session(session_id: str, connections_dir: Optional[str] = None,
                   timeout: int = 900) -> Session:
    """Restart a stopped context; scoped Java operations resolve current credentials."""
    session = get_session(session_id)
    if session.state == STATE_RUNNING:
        raise SessionError("The session is already running.", code="SESSION_ALREADY")
    extra = session.extra or {}
    options = {}
    if session.repository_profile:
        options = dict(repository_profile=session.repository_profile, program=session.program,
                       connections_dir=connections_dir, writable=session.writable,
                       commit=session.commit)
    try:
        runner = _build_runner(session.binary, port=session.port,
                               ghidra_home=extra.get("ghidra_home", ""),
                               java_home=extra.get("java_home", ""), **options)
        instance = runner.start(timeout=timeout)
    except Exception as exc:
        from .headless import HeadlessError
        if isinstance(exc, HeadlessError):
            raise SessionError(str(exc), code=exc.code) from None
        raise
    session.pid = instance.pid
    session.state = STATE_RUNNING
    session.updated_at = time.time()
    for key in ("saved", "checked_in", "confirmation_unknown"):
        session.extra.pop(key, None)
    stored = _load_store()
    _save_store([session if item.id == session.id else item for item in stored])
    return session
