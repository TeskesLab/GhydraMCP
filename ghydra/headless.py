"""The headless GhydraMCP: the same API, with nobody watching.

The CodeBrowser plugin serves the GhydraMCP REST API from a window a human is
looking at. A headless Ghidra run can serve the very same API: the binary is
imported, analysed, and the API answers for that analysis - with no window
and nobody watching.

The headless run is Ghidra's own ``analyzeHeadless``, with one extra script
that starts the server and keeps the run alive. The script lives in the
extension, so the server it starts is the same server the CodeBrowser plugin
starts: the same resources, the same decompiler service, the same middleware.

What is different is what is behind them. The CodeBrowser has a
ProgramManager, a tool and a UI; the headless run has one fixed program and
one fixed project, and the endpoints that need the UI answer 503 rather than
pretending to work.

The launcher is cross-platform. The Ghidra installation is found through
``GHIDRA_HOME`` or in the places Ghidra is usually installed, the launcher
script is ``support/analyzeHeadless`` on POSIX and ``analyzeHeadless.bat`` on
Windows, and the state is kept under ``~/.ghydra`` so a run survives the shell
that started it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from . import launcher as ghidra_launcher
from .launcher import LauncherError, binary_name
from . import state as state_paths

# The port the first instance binds. The bridge scans 8192-8201 on its own.
DEFAULT_PORT = 8192

# The script that starts the server and keeps the headless run alive.
SCRIPT_NAME = "GhidraHeadlessServer"

# What tells a headless run apart from any other process: the script name
# travels in the command line of the launcher and of the JVM it starts, so
# a process that does not carry it is not ours.
OWNERSHIP_MARKER = SCRIPT_NAME

ENV_GHIDRA_HOME = "GHIDRA_HOME"
ENV_JAVA_HOME = "JAVA_HOME"

# The line the script prints when the server is up.
READY_MARKER = "[GhydraMCP] HEADLESS READY"

# How long to wait for the API to answer. An analysis of a big binary takes
# minutes, so the default is generous; the wait ends early when the run dies.
DEFAULT_TIMEOUT = 900

# The poll interval while waiting.
POLL_INTERVAL = 0.25


class HeadlessError(Exception):
    """A failure with a machine-readable code."""

    def __init__(self, message: str, code: str = "HEADLESS_ERROR") -> None:
        super().__init__(message)
        self.code = code


@dataclass
class HeadlessInstance:
    """A headless run, as it is remembered between commands."""

    port: int = DEFAULT_PORT
    host: str = "127.0.0.1"
    pid: int = 0
    binary: str = ""
    project_dir: str = ""
    project_name: str = ""
    ghidra_home: str = ""
    java_home: str = ""
    log: str = ""
    started_at: float = 0.0
    # The port is claimed before the child is launched, so a start that
    # arrives at the same time as another one finds the port taken. The
    # token says which runner made the claim.
    reserved: bool = False
    token: str = ""
    repository_profile: str = ""
    program: str = ""
    writable: bool = False
    commit: Optional[str] = None
    repository_saved: Optional[bool] = None
    checked_in: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HeadlessInstance":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in (data or {}).items() if k in known})

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"


def state_path(port: int) -> str:
    """The file that remembers the run on a port."""
    return os.path.join(state_paths.state_dir(), f"headless-{int(port)}.json")


def log_path(port: int) -> str:
    """The file that holds the output of the run."""
    return os.path.join(state_paths.state_dir(), f"headless-{int(port)}.log")


def stop_file_path(port: int) -> str:
    """The file the launcher leaves behind to stop the run.

    The headless script watches for it and returns when it appears: the
    headless analyzer then saves the program and closes the project, and the
    project is left unlocked. Killing the process instead would leave the
    lock file behind, and the next run would refuse to open the project.
    """
    directory = os.environ.get("GHYDRA_STATE_DIR") or os.path.join(os.path.expanduser("~"), ".ghidra")
    return os.path.join(directory, f"headless-{int(port)}.stop")


def clear_stop_flag(port: int) -> None:
    """Remove the stop flag, if there is one.

    A run that was killed before the script could see the flag leaves it
    behind, and the next run on that port would stop as soon as it starts.
    """
    try:
        os.remove(stop_file_path(port))
    except OSError:
        pass


# The launcher speaks its own codes; the headless runner speaks its own.
# The mapping keeps a caller of the runner from having to know that the
# finding came from the launcher.
_HEADLESS_CODES = {
    "LAUNCHER_NO_GHIDRA": "HEADLESS_NO_GHIDRA",
    "LAUNCHER_NO_JDK": "HEADLESS_NO_JDK",
    "LAUNCHER_NO_UTILITY": "HEADLESS_NO_UTILITY",
}


def candidate_homes() -> List[str]:
    """The places Ghidra is usually installed."""
    return ghidra_launcher.candidate_homes()


def find_ghidra_home(explicit: Optional[str] = None) -> str:
    """Where the Ghidra installation is.

    The explicit path wins over ``GHIDRA_HOME``, and both win over the places
    Ghidra is usually installed.
    """
    try:
        return ghidra_launcher.find_ghidra_home(explicit, candidates=candidate_homes())
    except LauncherError as exc:
        raise HeadlessError(str(exc), code=_HEADLESS_CODES.get(exc.code, exc.code)) from None


def launcher_for(ghidra_home: str) -> str:
    """The headless launcher of an installation.

    Ghidra ships two of them: ``analyzeHeadless`` is the shell script, and
    ``analyzeHeadless.bat`` is the Windows one. Both are in ``support``.
    """
    support = os.path.join(ghidra_home, "support")
    names = ["analyzeHeadless.bat", "analyzeHeadless"] if os.name == "nt" \
        else ["analyzeHeadless", "analyzeHeadless.bat"]
    for name in names:
        candidate = os.path.join(support, name)
        if os.path.isfile(candidate):
            return candidate
    raise HeadlessError(
        f"no headless launcher in {support}. The installation looks incomplete.",
        code="HEADLESS_NO_LAUNCHER",
    )


def slug_for(binary: str) -> str:
    """A project name for a binary: the file name, without the extension."""
    name = binary_name(binary)
    stem = os.path.splitext(name)[0]
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", stem).strip("_") or "binary"
    return cleaned


def default_project_name(binary: str) -> str:
    """The project of a binary: its name, and a mark of where it came from.

    Ghidra identifies a program by its file name, so two binaries with the
    same name in different directories are two programs that cannot live in
    the same project - and the second one would be served the first one, with
    the analysis of a file nobody asked about. The mark is a short digest of
    the absolute path: it tells the two apart, and it keeps the name of the
    binary readable.
    """
    absolute = os.path.abspath(os.path.expanduser(binary))
    digest = hashlib.sha256(os.path.normcase(absolute).encode("utf-8")).hexdigest()[:8]
    return f"{slug_for(absolute)}-{digest}"


def default_project_dir() -> str:
    """Where the projects live when the caller does not say.

    It is Ghidra's own convention - ``ghidra_projects`` in the home
    directory - and not something under ``~/.ghidra``: Ghidra refuses a
    project path with an element that starts with a dot, and ``.ghidra`` is
    exactly that.
    """
    return os.path.join(os.path.expanduser("~"), "ghidra_projects")


def check_project_dir(path: str) -> None:
    """Whether Ghidra will accept the project directory.

    A path element that starts with a dot is refused by Ghidra
    ("Path element starting with '.' is not permitted"), which rules out
    anything under a dotted directory such as ``~/.ghidra``.
    """
    absolute = os.path.abspath(path)
    drive, tail = os.path.splitdrive(absolute)
    parts = [part for part in tail.replace("\\", "/").split("/") if part]
    for part in parts:
        if part.startswith("."):
            raise HeadlessError(
                f"Ghidra refuses a project path with an element that starts with "
                f"a dot: {absolute}. Use a plain directory, such as "
                f"{default_project_dir()}.",
                code="HEADLESS_BAD_PROJECT_DIR",
            )


def project_index(project_dir: str, project_name: str) -> str:
    """The index of the files in a project.

    Ghidra keeps it as plain text: one line per file, with the name of the
    file and the id of its content. It is what says whether a program is
    already in the project.
    """
    path = os.path.join(project_dir, f"{project_name}.rep", "idata", "~index.dat")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def project_has_program(project_dir: str, project_name: str, program: str) -> bool:
    """Whether the program is already in the project.

    Importing a program that is already there fails, and the run ends
    without ever reaching the script that starts the server. When the
    program is there, the run has to process it instead of importing it.
    """
    name = binary_name(program)
    index = project_index(project_dir, project_name)
    if not index:
        return False
    return f":{name}:" in index


def project_content_written_since(project_dir: str, project_name: str,
                                  since: float) -> bool:
    """Whether the content of the program in the project was written after a moment.

    The answer to "is the analysis in the project?" is the project itself.
    Ghidra keeps the content of a program under `<project>.rep/idata/`, in a
    file whose name starts with "db." - a new one for every save - and the
    headless analyzer writes it when the script returns.

    The files that a save writes while it is in progress do not count: their
    name starts with "tmp", and they are there whether the save finished or
    not.
    """
    root = os.path.join(project_dir, f"{project_name}.rep", "idata")
    for base, _dirs, files in os.walk(root):
        for name in files:
            if not name.startswith("db."):
                continue
            try:
                if os.path.getmtime(os.path.join(base, name)) >= since:
                    return True
            except OSError:
                continue
    return False


def provenance_path(project_dir: str, project_name: str) -> str:
    """The file that remembers which binary a project was built from."""
    return os.path.join(project_dir, f"{project_name}.ghydra.json")


def binary_provenance(binary: str) -> Dict[str, Any]:
    """What the binary on disk looks like right now."""
    try:
        info = os.stat(binary)
    except OSError:
        return {}
    return {
        "binary": os.path.abspath(binary),
        "size": int(info.st_size),
        "mtime": int(info.st_mtime),
        # The time with the sub-second part: a rebuild that happens inside
        # the same second leaves the same size and the same second, and the
        # project would serve the old bytes while Kuna reads the new file.
        "mtime_ns": int(info.st_mtime_ns),
    }


def write_provenance(project_dir: str, project_name: str, binary: str) -> None:
    """Remember the binary the project is being built from."""
    try:
        with open(provenance_path(project_dir, project_name), "w",
                  encoding="utf-8") as handle:
            json.dump(binary_provenance(binary), handle, indent=2)
    except OSError:
        pass


def project_is_current(project_dir: str, project_name: str, binary: str) -> bool:
    """Whether the program in the project is the binary that is on disk now.

    A binary that was rebuilt has the same name and the same path, and the
    program that is in the project is the old one - so a run would analyse
    the stored copy again and the addresses would be the ones of a file
    that is not there any more.
    """
    try:
        with open(provenance_path(project_dir, project_name), "r",
                  encoding="utf-8") as handle:
            recorded = json.load(handle)
    except (OSError, ValueError):
        # Nothing was recorded, so nothing is known: the binary is imported
        # again, and the project holds the bytes that are there now.
        return False
    now = binary_provenance(binary)
    if not now:
        return False
    # The sidecar of a run that was made before the sub-second precision
    # was kept carries only the second: it is compared as it is, and the
    # binary is imported again - which is the safe answer.
    if "mtime_ns" in recorded and "mtime_ns" in now:
        return (recorded.get("size") == now.get("size")
                and recorded.get("mtime_ns") == now.get("mtime_ns"))
    return (recorded.get("size") == now.get("size")
            and recorded.get("mtime") == now.get("mtime"))


def build_command(
    launcher: str,
    project_dir: str,
    project_name: str,
    binary: str,
    port: int,
    process: bool = False,
    overwrite: bool = False,
    extra: Optional[List[str]] = None,
    empty: bool = False,
) -> List[str]:
    """The command that starts the headless run.

    ``-process`` re-analyses a program that is already in the project;
    ``-import`` puts a new one in. The script runs after the analysis and
    stays in the run, so the run serves the API until it is stopped.

    ``-overwrite`` replaces the program that is in the project with the file
    that is on disk now - which is what a rebuilt binary needs.
    """
    command = [launcher, project_dir, project_name]
    if process:
        command += ["-process", binary_name(binary)]
    elif not empty:
        command += ["-import", binary]
        if overwrite:
            command += ["-overwrite"]
    command += ["-postScript", SCRIPT_NAME, f"port={int(port)}"]
    if extra:
        command += list(extra)
    return command


def port_is_open(host: str, port: int, timeout: float = 0.5) -> bool:
    """Whether something is listening on the port."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def free_port(host: str, start: int, attempts: int = 256) -> int:
    """The first port that nothing is serving on, from ``start`` upwards.

    It is what a second run uses when the first port is taken: the port
    that was asked for is kept when it is free, and the next one is used
    when it is not.
    """
    for offset in range(max(1, int(attempts))):
        candidate = int(start) + offset
        if not port_is_open(host, candidate):
            return candidate
    raise HeadlessError(
        f"no free port between {start} and {int(start) + int(attempts) - 1}",
        code="HEADLESS_NO_PORT",
    )


def api_answers(host: str, port: int, timeout: float = 5.0) -> bool:
    """Whether the API answers on the port.

    The root is the cheapest endpoint that proves the server is up: it is
    served before anything else has to be read from the program.
    """
    import requests

    try:
        response = requests.get(f"http://{host}:{int(port)}/", timeout=timeout)
    except Exception:
        return False
    return response.status_code == 200


def load_state(port: int) -> Optional[HeadlessInstance]:
    """The run remembered for a port, if there is one."""
    path = state_path(port)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return HeadlessInstance.from_dict(json.load(handle))
    except (OSError, ValueError):
        return None


def save_state(instance: HeadlessInstance) -> None:
    """Remember a run."""
    with open(state_path(instance.port), "w", encoding="utf-8") as handle:
        json.dump(instance.to_dict(), handle, indent=2)


def clear_state(port: int) -> None:
    """Forget a run."""
    try:
        os.remove(state_path(port))
    except OSError:
        pass


# How long a claim of a port stays valid. The claim is written right before
# the child is launched, so a start that arrives a moment later finds the
# port taken; one that finds a claim much later finds a claim that nobody
# took up.
RESERVATION_TTL = 60.0


def reservation_is_live(port: int) -> bool:
    """Whether the claim of a port is one that was taken up.

    The claim is written immediately before the child is launched, so it is
    young for a moment and then it is the state of a live run. A claim that
    nobody took up - the process died between the claim and the launch - is
    older than that, and the port is free again.
    """
    try:
        age = time.time() - os.path.getmtime(state_path(port))
    except OSError:
        return False
    return age < RESERVATION_TTL


def process_command_line(pid: int) -> str:
    """The command line of a process, or an empty string.

    It is what tells a headless run apart from any other process: a PID on
    its own says nothing, because the operating system reuses them.
    """
    if not pid:
        return ""
    try:
        if os.name == "nt":
            command = (
                "Get-CimInstance Win32_Process -Filter "
                f"'ProcessId={int(pid)}' | Select-Object -ExpandProperty CommandLine"
            )
            output = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
                capture_output=True, text=True, timeout=30,
            ).stdout or ""
        else:
            output = subprocess.run(
                ["ps", "-p", str(int(pid)), "-o", "command="],
                capture_output=True, text=True, timeout=30,
            ).stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""
    return output.strip()


def live_processes() -> List[tuple]:
    """The processes of this machine, with their command lines.

    It is what tells a Ghidra that has a project open from a Ghidra that is
    gone: the lock file of a project carries no owner that can be read.
    """
    out: List[tuple] = []
    try:
        if os.name == "nt":
            command = (
                "Get-CimInstance Win32_Process | "
                "Select-Object ProcessId,CommandLine | "
                "ForEach-Object { \"$($_.ProcessId)|$($_.CommandLine)\" }"
            )
            output = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
                capture_output=True, text=True, timeout=30,
            ).stdout or ""
            for line in output.splitlines():
                pid_text, _, command_line = line.partition("|")
                try:
                    out.append((int(pid_text.strip()), command_line.strip()))
                except ValueError:
                    continue
        else:
            output = subprocess.run(
                ["ps", "-eo", "pid=,args="],
                capture_output=True, text=True, timeout=30,
            ).stdout or ""
            for line in output.splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) < 2:
                    continue
                try:
                    out.append((int(parts[0]), parts[1]))
                except ValueError:
                    continue
    except (OSError, subprocess.SubprocessError):
        return out
    return out


def process_is_ours(pid: int, marker: str = SCRIPT_NAME,
                    port: Optional[int] = None) -> bool:
    """Whether the process is the headless run this launcher started.

    A run that crashed leaves its state file behind, and the operating
    system hands its PID to somebody else. Signalling that process would
    stop something that has nothing to do with the analysis, so the command
    line is read and the process is only ours when it carries the marker of
    the headless script.

    The port is part of the answer too: the PID of a crashed run can be
    handed to another run of the same script - on another port, with another
    project - and stopping that one would kill a live analysis.
    """
    if not pid:
        return False
    command = process_command_line(pid)
    if not command:
        return False
    lowered = command.lower()
    if marker.lower() not in lowered:
        return False
    if port is not None:
        # The port is a token of its own: "port=8192" is not "port=81920".
        if not re.search(rf"port={int(port)}(?!\d)", lowered):
            return False
    return True


def process_alive(pid: int) -> bool:
    """Whether the process of a run is still there."""
    if not pid:
        return False
    if os.name == "nt":
        try:
            output = subprocess.run(
                ["tasklist", "/FI", f"PID eq {int(pid)}", "/NH"],
                capture_output=True, text=True, timeout=10,
            ).stdout or ""
        except (OSError, subprocess.SubprocessError):
            return False
        return str(pid) in output
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _repository_program(program: Optional[str]) -> str:
    """Accept one literal repository program, never a native pattern or option."""
    text = program or ""
    if text.startswith("/"):
        text = text[1:]
    parts = text.split("/")
    if (not text or any(not p or p in (".", "..") or p.startswith("-") for p in parts)
            or any(c in text for c in "\\*?%:#")
            or any(ord(c) < 32 or ord(c) == 127 for c in text)):
        raise HeadlessError("Specify one literal repository program path.",
                            code="CONNECTION_PROFILE_INVALID")
    return text


class HeadlessRunner:
    """A headless run: started, waited for, and stopped again.

    The run is detached from the shell that starts it, so it outlives the
    command that launched it and another command can find it afterwards.
    """

    def __init__(
        self,
        binary: str = "",
        port: int = DEFAULT_PORT,
        project_dir: Optional[str] = None,
        project_name: Optional[str] = None,
        ghidra_home: Optional[str] = None,
        java_home: Optional[str] = None,
        host: str = "127.0.0.1",
        configured_java_homes: Optional[List[str]] = None,
        repository_profile: Optional[str] = None,
        program: Optional[str] = None,
        connections_dir: Optional[str] = None,
        writable: bool = False,
        commit: Optional[str] = None,
    ) -> None:
        self.repository_profile = repository_profile or ""
        self.program = _repository_program(program) if self.repository_profile else ""
        if self.repository_profile and (binary or project_dir or project_name):
            raise HeadlessError("Repository mode cannot use a binary or local project.",
                                code="CONNECTION_PROFILE_INVALID")
        if not self.repository_profile and (program or writable or commit is not None):
            raise HeadlessError("Repository options require a repository profile.",
                                code="CONNECTION_PROFILE_REQUIRED")
        if self.repository_profile and (writable != (commit is not None) or
                                       (commit is not None and
                                        (not commit.strip() or len(commit) > 4096 or
                                         any(ord(c) < 32 for c in commit)))):
            raise HeadlessError("Repository writes require --writable and a commit comment.",
                                code="CONNECTION_PERMISSION_DENIED")
        directory = connections_dir or os.environ.get("GHYDRA_CONNECTIONS_DIR", "")
        self.connections_dir = os.path.abspath(os.path.expanduser(directory)) if directory else ""
        self.writable = bool(writable)
        self.commit = commit
        self.binary = "" if self.repository_profile else os.path.abspath(os.path.expanduser(binary))
        self.port = int(port)
        if not 1 <= self.port <= 65535:
            # The port is refused here, before anything is started: the
            # script would fall back to 8192, and the wait would keep
            # polling a port that cannot be bound.
            raise HeadlessError(
                f"{self.port} is not a port: it has to be between 1 and 65535.",
                code="HEADLESS_BAD_PORT",
            )
        self.host = host
        self.ghidra_home = find_ghidra_home(ghidra_home)
        # What the caller asked for, and what the machine has. They are
        # kept apart: an explicit JDK that is too old is an error, while an
        # environment that points at one that is too old is only a place
        # the search did not stop.
        self.requested_java_home = java_home or ""
        self.java_home = java_home or os.environ.get(ENV_JAVA_HOME, "")
        self.configured_java_homes = list(configured_java_homes or [])
        if self.repository_profile:
            identity = json.dumps([self.repository_profile, self.program], separators=(",", ":"))
            digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
            self.project_name = "repository-" + digest
            self.project_dir = os.path.join(default_project_dir(), "repository-workers")
        elif project_dir:
            self.project_dir = os.path.abspath(os.path.expanduser(project_dir))
        else:
            self.project_dir = default_project_dir()
        if not self.repository_profile:
            self.project_name = project_name or default_project_name(self.binary)
        self.process: Optional[subprocess.Popen] = None
        self.instance = HeadlessInstance(
            port=self.port,
            host=self.host,
            binary=self.binary,
            project_dir=self.project_dir,
            project_name=self.project_name,
            ghidra_home=self.ghidra_home,
            java_home=self.java_home,
            log=log_path(self.port),
            started_at=time.time(),
            repository_profile=self.repository_profile,
            program=self.program,
            writable=self.writable,
            commit=self.commit,
        )

    # -- the command ---------------------------------------------------

    def project_exists(self) -> bool:
        """Whether the project is already there."""
        marker = os.path.join(self.project_dir, f"{self.project_name}.gpr")
        return os.path.isfile(marker)

    def program_in_project(self) -> bool:
        """Whether the program is already in the project."""
        return project_has_program(self.project_dir, self.project_name, self.binary)

    def resolve_java_home(self) -> str:
        """The JDK the analysis runs on.

        It is found when it is needed rather than when the runner is built,
        because a run that only has to talk to an instance that is already
        serving does not need a JDK at all.

        The JDK that is too old for the installation is not used: the
        installation's own VM arguments carry flags that only the newer JVMs
        take, and the run would die with a message about a flag instead of
        about the JDK.
        """
        required = ghidra_launcher.required_jdk_major(self.ghidra_home)

        if self.requested_java_home:
            version = ghidra_launcher.java_version(self.requested_java_home)
            if version and required and version[0] < required:
                raise HeadlessError(
                    f"the JDK that was asked for ({self.requested_java_home}) is a "
                    f"JDK {version[0]}, and this Ghidra asks for a JDK {required} "
                    "or newer",
                    code="HEADLESS_NO_JDK",
                )
            self.java_home = self.requested_java_home
            return self.java_home

        try:
            found = ghidra_launcher.find_java_home(
                ghidra_home=self.ghidra_home,
                required_major=required,
                configured=self.configured_java_homes,
            )
        except LauncherError as exc:
            raise HeadlessError(str(exc), code=exc.code) from None
        self.java_home = found
        return found

    def command(self) -> List[str]:
        """The command that starts the run.

        A program that is already in the project is processed again; one
        that is not is imported. Importing a program that is already there
        fails, and the run never reaches the script that starts the server.

        The command is the JVM invocation the launcher makes, not the
        launcher itself: the Windows launcher asks "press any key to
        continue" when it fails, because it cannot tell a double-click from
        a shell - and a launcher that was started by another program is
        exactly the case it cannot handle. It also sends the output of the
        run somewhere else, and the log of the run is the only place the
        reason for a failure is.
        """
        empty = bool(self.repository_profile)
        process = not empty and self.program_in_project()
        current = process and project_is_current(
            self.project_dir, self.project_name, self.binary)
        overwrite = process and not current
        utility = os.path.join(
            self.ghidra_home, "Ghidra", "Framework", "Utility", "lib", "Utility.jar")
        if empty or os.path.isfile(utility):
            java = self.resolve_java_home()
            try:
                return ghidra_launcher.headless_command(
                    self.ghidra_home,
                    java,
                    self.project_dir,
                    self.project_name,
                    self.binary,
                    self.port,
                    process=current,
                    overwrite=overwrite,
                    script=SCRIPT_NAME,
                    script_args=[f"port={self.port}"],
                    empty=empty,
                    connections_dir=self.connections_dir or None,
                    repository_profile=self.repository_profile or None,
                )
            except LauncherError as exc:
                raise HeadlessError(str(exc), code=exc.code) from None
        return build_command(
            launcher_for(self.ghidra_home),
            self.project_dir,
            self.project_name,
            self.binary,
            self.port,
            process=current,
            overwrite=overwrite,
            empty=empty,
        )

    def _repository_request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        """Call the worker using only opaque selection data; never echo native errors."""
        import requests

        try:
            response = getattr(requests, method)(self.instance.url + path, timeout=30, **kwargs)
            payload = response.json()
        except Exception:
            raise HeadlessError("The repository worker request could not be confirmed.",
                                code="CONNECTION_FAILED") from None
        if not response.ok or not isinstance(payload, dict) or payload.get("success") is not True:
            error = payload.get("error") if isinstance(payload, dict) else None
            code = error.get("code") if isinstance(error, dict) else None
            if not isinstance(code, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", code):
                code = "CONNECTION_FAILED"
            raise HeadlessError("The repository worker refused the operation.", code=code)
        result = payload.get("result")
        if not isinstance(result, dict):
            raise HeadlessError("The repository worker response was not confirmed.",
                                code="CONNECTION_FAILED")
        return result

    def _repository_entry(self) -> Dict[str, Any]:
        """Read fresh metadata for exactly the originally approved program."""
        path = "/" + self.program
        folder = path.rpartition("/")[0] or "/"
        offset = 0
        while True:
            page = self._repository_request(
                "get", "/repositories/files",
                params={"profile": self.repository_profile, "path": folder,
                        "offset": offset, "limit": 1000})
            entries = page.get("entries")
            if not isinstance(entries, list):
                raise HeadlessError("The repository listing was not confirmed.", code="CONNECTION_FAILED")
            entry = next((row for row in entries if isinstance(row, dict)
                          and row.get("path") == path and row.get("type") == "file"), None)
            if entry is not None:
                return entry
            if not page.get("has_more"):
                raise HeadlessError("The approved repository program was not found.",
                                    code="REPOSITORY_NOT_FOUND")
            if not entries:
                raise HeadlessError("The repository listing did not advance.", code="CONNECTION_FAILED")
            offset += len(entries)

    def _open_repository(self) -> None:
        """Browse the approved folder and activate a snapshot or exclusive checkout."""
        selection = {"profile": self.repository_profile}
        status = self._repository_request("get", "/repositories", params=selection)
        permissions = status.get("permissions")
        if self.writable and (not isinstance(permissions, list)
                              or not {"checkout", "checkin"}.issubset(permissions)):
            raise HeadlessError("Repository writes require checkout and check-in grants.",
                                code="CONNECTION_PERMISSION_DENIED")
        entry = self._repository_entry()
        path = "/" + self.program
        if self.writable:
            if entry.get("checked_out") is True:
                if entry.get("exclusive") is not True:
                    raise HeadlessError("The existing local checkout is not exclusive.",
                                        code="REPOSITORY_CONFLICT")
                if entry.get("version") != entry.get("latest_version"):
                    raise HeadlessError("The existing checkout is not the latest repository version.",
                                        code="REPOSITORY_CONFLICT")
            else:
                checkout = self._repository_request(
                    "post", "/repositories/checkout",
                    json={**selection, "path": path, "exclusive": True})
                if checkout.get("checked_out") is not True or checkout.get("exclusive") is not True:
                    raise HeadlessError("Exclusive checkout was not confirmed.",
                                        code="REPOSITORY_CONFLICT")
            version = -1
        else:
            version = entry.get("latest_version")
            if type(version) is not int or version < 1:
                raise HeadlessError("The latest repository version was not confirmed.",
                                    code="CONNECTION_FAILED")
        opened = self._repository_request(
            "post", "/repositories/open", json={**selection, "path": path, "version": version})
        if (opened.get("opened") is not True
                or opened.get("read_only") is not (not self.writable)):
            raise HeadlessError("The requested repository access mode was not confirmed.",
                                code="CONNECTION_PERMISSION_DENIED")

    def _save_repository(self) -> bool:
        """Persist the active workspace; this never publishes a repository version."""
        self.instance.repository_saved = None
        try:
            result = self._repository_request(
                "post", "/program/save", params={"workspace_only": "true"})
        except HeadlessError:
            save_state(self.instance)
            return False
        value = result.get("saved")
        self.instance.repository_saved = value if type(value) is bool else None
        if value is True:
            self.instance.checked_in = None
        save_state(self.instance)
        return value is True or (value is False and result.get("detail") == "no unsaved changes")

    def _checkin_repository(self) -> None:
        """Publish only the originally approved selection, retaining its open checkout."""
        previously_confirmed = self.instance.checked_in is True
        self.instance.checked_in = None
        save_state(self.instance)
        entry = self._repository_entry()
        modified = entry.get("modified_since_checkout")
        if modified is False:
            self.instance.checked_in = previously_confirmed
            save_state(self.instance)
            return
        if modified is not True:
            raise HeadlessError("The repository checkout's saved changes were not confirmed.",
                                code="HEADLESS_STOP_REFUSED")
        try:
            result = self._repository_request(
                "post", "/repositories/checkin",
                json={"profile": self.repository_profile, "path": "/" + self.program,
                      "comment": self.commit, "keep_checked_out": True})
        except HeadlessError:
            save_state(self.instance)
            raise
        value = result.get("checked_in")
        self.instance.checked_in = value if type(value) is bool else None
        save_state(self.instance)
        if value is not True:
            raise HeadlessError("Repository check-in was not confirmed.",
                                code="HEADLESS_STOP_REFUSED")

    @classmethod
    def from_instance(cls, instance: HeadlessInstance) -> "HeadlessRunner":
        """Reattach for stop without opening a repository or loading credentials."""
        runner = cls(binary=instance.binary, port=instance.port,
                     project_dir=None if instance.repository_profile else instance.project_dir or None,
                     project_name=None if instance.repository_profile else instance.project_name or None,
                     ghidra_home=instance.ghidra_home, java_home=instance.java_home,
                     host=instance.host, repository_profile=instance.repository_profile or None,
                     program=instance.program or None, writable=instance.writable,
                     commit=instance.commit)
        runner.project_dir = instance.project_dir or runner.project_dir
        runner.project_name = instance.project_name or runner.project_name
        runner.instance = instance
        return runner

    def environment(self) -> Dict[str, str]:
        """The environment the run gets.

        ``JAVA_HOME`` is passed through: Ghidra 12 needs a JDK 21 or newer,
        and the machine's default is often an older one. The variables the
        installation asks for are added too - they come from Ghidra's own
        ``launch.properties``, and the launcher is what would have set them.
        """
        env = dict(os.environ)
        if self.java_home:
            env[ENV_JAVA_HOME] = self.java_home
        try:
            for key, value in ghidra_launcher.env_vars(
                    self.ghidra_home, self.java_home).items():
                env.setdefault(key, value)
        except Exception:
            pass
        return env

    # -- the run -------------------------------------------------------

    def start(self, timeout: int = DEFAULT_TIMEOUT) -> HeadlessInstance:
        """Start the run and wait for the API to answer.

        The output of the run goes to a log file: the analysis is long and
        the reasons it failed are in there.
        """
        if not self.repository_profile and not os.path.isfile(self.binary):
            raise HeadlessError(
                f"no such binary: {self.binary}", code="HEADLESS_NO_FILE")

        # A port that is already served is not this run's port. Starting
        # anyway would make the wait accept the server that is already
        # there, and the command would report a run that never bound the
        # port - and that dies on its own a moment later.
        if api_answers(self.host, self.port):
            raise HeadlessError(
                f"something is already serving the API on {self.host}:{self.port}. "
                "Stop it first, or start this one on another port.",
                code="HEADLESS_PORT_IN_USE")

        # A run that is still going is this port's run, even when it has not
        # bound the API yet - it is analysing. Starting a second one would
        # overwrite the state of the first, and the first would be left
        # running with nothing remembering it.
        #
        # The claim of the port is part of it: the port is claimed before
        # the child is launched, so two starts that arrive together cannot
        # both find the port free and both launch an analyzer.
        remembered = load_state(self.port)
        if remembered is not None:
            if remembered.reserved and reservation_is_live(self.port):
                raise HeadlessError(
                    f"a headless run is already being started on port {self.port}. "
                    "Stop it first, or start this one on another port.",
                    code="HEADLESS_ALREADY_RUNNING")
            if remembered.pid and process_is_ours(remembered.pid, port=self.port):
                raise HeadlessError(
                    f"a headless run is already there on port {self.port} "
                    f"(pid {remembered.pid}). Stop it first, or start this one "
                    "on another port.",
                    code="HEADLESS_ALREADY_RUNNING")

        check_project_dir(self.project_dir)
        os.makedirs(self.project_dir, exist_ok=True)
        command = self.command()
        # A stop flag that a killed run left behind would stop this one as
        # soon as it starts.
        clear_stop_flag(self.port)

        # The port is claimed before the child is launched. Two starts that
        # arrive together would both find the port free, and both would
        # launch an analyzer: the one that binds the API first answers both
        # waits, and the state file ends up naming the loser - so one report
        # can combine the Ghidra data of one binary with the Kuna data of
        # another.
        self.instance.token = uuid.uuid4().hex
        self.instance.reserved = True
        save_state(self.instance)

        handle = open(self.instance.log, "a", encoding="utf-8", errors="replace")
        handle.write(f"\n=== {time.strftime('%Y-%m-%d %H:%M:%S')} "
                     f"{'repository worker' if self.repository_profile else ' '.join(command)}\n")
        handle.flush()

        kwargs: Dict[str, Any] = {
            "stdout": handle,
            "stderr": subprocess.STDOUT,
            "stdin": subprocess.DEVNULL,
            "cwd": self.project_dir,
            "env": self.environment(),
        }
        if os.name == "nt":
            kwargs["creationflags"] = (subprocess.CREATE_NEW_PROCESS_GROUP
                                       | getattr(subprocess, "DETACHED_PROCESS", 0))
        else:
            kwargs["start_new_session"] = True

        try:
            self.process = subprocess.Popen(command, **kwargs)
        except OSError as exc:
            self._release_claim()
            raise HeadlessError(
                f"could not start the headless run: {exc}",
                code="HEADLESS_LAUNCH",
            ) from None
        finally:
            handle.close()

        self.instance.pid = self.process.pid
        self.instance.reserved = False
        save_state(self.instance)
        try:
            self.wait_ready(timeout)
            if self.repository_profile:
                self._open_repository()
        except HeadlessError:
            self._abort_start = True
            try:
                self.stop(timeout=5)
            finally:
                self._abort_start = False
            raise
        # The provenance is written when the run is serving: the binary is
        # only in the project when the import reached that point. A run that
        # failed before it - an unexecutable launcher, a project that would
        # not open - must not leave the sidecar of a binary that is not in
        # the project, or the next run would analyse the old bytes again.
        if not self.repository_profile:
            write_provenance(self.project_dir, self.project_name, self.binary)
        return self.instance

    def wait_ready(self, timeout: int = DEFAULT_TIMEOUT) -> None:
        """Wait for the API to answer, or for the run to die."""
        deadline = time.time() + max(1, int(timeout))
        while time.time() < deadline:
            if self.process is not None and self.process.poll() is not None:
                raise HeadlessError(
                    f"the headless run ended before the API came up. "
                    f"See {self.instance.log}",
                    code="HEADLESS_DIED",
                )
            if api_answers(self.host, self.port):
                return
            time.sleep(POLL_INTERVAL)
        raise HeadlessError(
            f"the API did not answer on {self.host}:{self.port} within {timeout}s. "
            f"See {self.instance.log}",
            code="HEADLESS_TIMEOUT",
        )

    def save(self) -> bool:
        """Ask the server to save the program.

        The headless analyzer saves when the script returns, and the script
        never returns - so the save is asked for over the API before the run
        is stopped.

        A refused or failed save is not a save: the answer is checked, and
        the caller is told the truth instead of a promise.
        """
        if self.repository_profile:
            return self._save_repository()
        if not api_answers(self.host, self.port):
            return False
        import requests

        try:
            response = requests.post(
                f"http://{self.host}:{self.port}/program/save",
                timeout=30)
        except Exception as exc:
            self._note(f"the save request failed: {exc}")
            return False
        if not response.ok:
            self._note(f"the server refused the save: {response.status_code} {response.text[:200]}")
            return False
        return True

    def _note(self, message: str) -> None:
        """Write a line into the log of the run."""
        try:
            with open(self.instance.log, "a", encoding="utf-8", errors="replace") as handle:
                handle.write(f"[ghydra] {message}\n")
        except OSError:
            pass

    def stop(self, timeout: int = 20) -> bool:
        """Stop the run, and let it save the analysis on its way out.

        The stop file asks the script to drain requests, release selections,
        and close its project. Normal shutdown never signals the worker.
        Only failed-start cleanup may terminate its owned child.

        A process that is not ours is left alone: the state of a run that
        died is stale, and the PID it carries may belong to something else
        entirely by now.
        """
        saved = False
        pid = self.instance.pid or (self.process.pid if self.process else 0)
        if not pid:
            # A start that was refused before the child was launched has no
            # PID of its own: the state on disk belongs to another run, and
            # erasing it would leave that run untracked - so the next start
            # would walk past the guard that remembers it.
            self._clear_own_state()
            return False

        if not process_is_ours(pid, port=self.port):
            # The run is gone, or the PID belongs to somebody else by now.
            # A run that is dead cannot hold the project: the lock it left
            # behind is stale, and every later start would refuse the
            # project because of it. A live PID that is not ours is left
            # alone - its lock may belong to a real owner.
            if not process_alive(pid):
                self._drop_stale_lock()
            self._clear_own_state()
            return False

        aborting = getattr(self, "_abort_start", False)
        if not aborting:
            saved = self.save()
            if self.repository_profile:
                if not saved:
                    raise HeadlessError("The active repository workspace could not be saved; the worker remains available.",
                                        code="HEADLESS_STOP_REFUSED")
                if self.writable:
                    try:
                        self._checkin_repository()
                    except HeadlessError:
                        raise HeadlessError("Repository check-in was not confirmed; the worker remains available.",
                                            code="HEADLESS_STOP_REFUSED") from None

        flag = stop_file_path(self.port)
        asked = time.time()
        try:
            os.makedirs(os.path.dirname(flag), exist_ok=True)
            with open(flag, "w", encoding="utf-8") as handle:
                handle.write(str(asked))
        except OSError:
            flag = ""

        if flag and self._wait_for_exit(pid, timeout):
            self._clear_own_state()
            if self.repository_profile:
                return self.instance.repository_saved is True
            if not saved:
                # The API save was refused, and in a headless run that is
                # what the analyzer does: the program is inside the
                # transaction of the script that serves the API, and the
                # analyzer saves it when the script returns - which is what
                # the polite stop is for. The project says whether it did:
                # the content of the program was written after the stop was
                # asked for.
                saved = project_content_written_since(
                    self.project_dir, self.project_name, asked)
                if saved:
                    self._note("the api save was refused; the analyzer saved "
                               "the program when the script returned")
            return saved

        if not getattr(self, "_abort_start", False):
            clear_stop_flag(self.port)
            raise HeadlessError("The worker has not finished stopping; its process and state were retained.",
                                code="HEADLESS_STOP_REFUSED")

        if os.name == "nt":
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(pid), "/T", "/F"],
                    capture_output=True, timeout=timeout,
                )
            except (OSError, subprocess.SubprocessError):
                pass
        else:
            try:
                if self.repository_profile and os.getpgid(int(pid)) == int(pid):
                    os.killpg(int(pid), signal.SIGTERM)
                else:
                    os.kill(int(pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            deadline = time.time() + timeout
            while time.time() < deadline and not self._child_exited(pid):
                time.sleep(POLL_INTERVAL)
            if not self._child_exited(pid):
                try:
                    if self.repository_profile and os.getpgid(int(pid)) == int(pid):
                        os.killpg(int(pid), signal.SIGKILL)
                    else:
                        os.kill(int(pid), signal.SIGKILL)
                except OSError:
                    pass
        self._drop_stale_lock()
        # The run was killed before it could see the flag, so the flag is
        # still there - and the next run on this port would stop as soon as
        # it starts.
        self._clear_own_state()
        return saved

    def _clear_own_state(self) -> None:
        """Erase the state of this run, and only of this run.

        A start that was refused before the child was launched has no PID of
        its own, and the state on disk belongs to another run: erasing it
        would leave that run untracked, and the next start would walk past
        the guard that remembers it. A runner that stops a run it found
        erases the state only while it is still the state of that run.
        """
        pid = self.instance.pid or (self.process.pid if self.process else 0)
        if not pid:
            return
        remembered = load_state(self.port)
        if remembered is not None and remembered.pid and remembered.pid != pid:
            return
        clear_stop_flag(self.port)
        clear_state(self.port)

    def _release_claim(self) -> None:
        """Give the port back, when the child never came up.

        The claim of the port is only ours while the token on disk is the
        one this runner wrote: a start that came later has its own claim,
        and that one is not ours to erase.
        """
        remembered = load_state(self.port)
        if remembered is not None and remembered.token and remembered.token != self.instance.token:
            return
        clear_state(self.port)

    def _lock_has_live_owner(self) -> bool:
        """Whether another Ghidra has the project open.

        The lock carries no owner that can be read, so the answer comes from
        the processes: a live Ghidra that has the project open holds the
        lock, and taking that lock away would let a second analyzer open
        the same project beside it - and the project would be written by
        two of them.
        """
        marker = os.path.normcase(os.path.abspath(self.project_dir))
        marker = marker.replace("\\", "/").lower()
        for pid, command_line in live_processes():
            if pid == self.instance.pid:
                continue
            if not command_line:
                continue
            lowered = command_line.replace("\\", "/").lower()
            if "ghidra" not in lowered:
                continue
            if marker in lowered:
                return True
        return False

    def _drop_stale_lock(self) -> None:
        """Remove the lock of a project whose owner was killed.

        Ghidra writes a lock file when it opens a project and removes it
        when it closes it. A run that was killed leaves the lock behind, and
        the next run refuses to open the project.

        The lock is only removed when nothing else holds the project: a
        CodeBrowser that has it open holds the lock too, and that one
        belongs to a live process - the run that died was refused the
        project in the first place because of it.
        """
        if self._lock_has_live_owner():
            return
        for name in (f"{self.project_name}.lock", f"{self.project_name}.lock~"):
            path = os.path.join(self.project_dir, name)
            try:
                if os.path.isfile(path):
                    os.remove(path)
            except OSError:
                pass

    def _wait_for_exit(self, pid: int, timeout: int) -> bool:
        """Whether the run ended on its own, within the timeout.

        When the child is ours, it is polled rather than looked for: polling
        reaps it, and a reaped child is gone - while a child that was never
        reaped stays a zombie, and a zombie is still a process that
        ``kill(pid, 0)`` finds alive.
        """
        deadline = time.time() + max(1, int(timeout))
        while time.time() < deadline:
            if self._child_exited(pid):
                return True
            time.sleep(POLL_INTERVAL)
        return self._child_exited(pid)

    def _child_exited(self, pid: int) -> bool:
        """Whether the process is gone, reaping it when it is ours."""
        if self.process is not None and self.process.pid == pid:
            return self.process.poll() is not None
        return not process_alive(pid)


def status(port: int = DEFAULT_PORT, host: str = "127.0.0.1") -> Dict[str, Any]:
    """What is known about the run on a port."""
    instance = load_state(port)
    if instance is None:
        return {
            "port": int(port),
            "running": False,
            "known": False,
            "api": api_answers(host, port),
        }
    alive = process_alive(instance.pid)
    return {
        "port": int(port),
        "running": alive,
        "known": True,
        "api": api_answers(host, port),
        "pid": instance.pid,
        "binary": instance.binary,
        "project_dir": instance.project_dir,
        "project_name": instance.project_name,
        "log": instance.log,
        "started_at": instance.started_at,
        "url": instance.url,
        "repository_profile": instance.repository_profile,
        "program": instance.program or instance.binary,
        "read_only": bool(instance.repository_profile and not instance.writable),
        "saved": instance.repository_saved,
        "checked_in": instance.checked_in,
    }

