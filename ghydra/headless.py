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

import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

# The port the first instance binds. The bridge scans 8192-8201 on its own.
DEFAULT_PORT = 8192

# The script that starts the server and keeps the headless run alive.
SCRIPT_NAME = "GhidraHeadlessServer"

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

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HeadlessInstance":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in (data or {}).items() if k in known})

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"


def state_dir() -> str:
    """Where the state lives: ``~/.ghydra``."""
    base = os.environ.get("GHYDRA_STATE_DIR")
    if not base:
        base = os.path.join(os.path.expanduser("~"), ".ghidra")
    os.makedirs(base, exist_ok=True)
    return base


def state_path(port: int) -> str:
    """The file that remembers the run on a port."""
    return os.path.join(state_dir(), f"headless-{int(port)}.json")


def log_path(port: int) -> str:
    """The file that holds the output of the run."""
    return os.path.join(state_dir(), f"headless-{int(port)}.log")


def stop_file_path(port: int) -> str:
    """The file the launcher leaves behind to stop the run.

    The headless script watches for it and returns when it appears: the
    headless analyzer then saves the program and closes the project, and the
    project is left unlocked. Killing the process instead would leave the
    lock file behind, and the next run would refuse to open the project.
    """
    return os.path.join(os.path.expanduser("~"), ".ghidra", f"headless-{int(port)}.stop")


def candidate_homes() -> List[str]:
    """The places Ghidra is usually installed."""
    home = os.path.expanduser("~")
    candidates: List[str] = []
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA", "")
        program = os.environ.get("ProgramFiles", r"C:\Program Files")
        if local:
            candidates.append(os.path.join(local, "Programs", "Ghidra"))
        if program:
            candidates.append(os.path.join(program, "Ghidra"))
        candidates.append(os.path.join(home, "scoop", "apps", "ghidra", "current"))
        candidates.append(os.path.join(home, "ghidra"))
    else:
        candidates.extend([
            "/opt/ghidra",
            "/usr/local/ghidra",
            "/usr/share/ghidra",
            os.path.join(home, "ghidra"),
            os.path.join(home, "opt", "ghidra"),
        ])
    return candidates


def find_ghidra_home(explicit: Optional[str] = None) -> str:
    """Where the Ghidra installation is.

    The explicit path wins over ``GHIDRA_HOME``, and both win over the places
    Ghidra is usually installed.
    """
    for candidate in (explicit, os.environ.get(ENV_GHIDRA_HOME)):
        if candidate and os.path.isdir(candidate):
            return os.path.abspath(candidate)
    for candidate in candidate_homes():
        if os.path.isdir(candidate):
            return os.path.abspath(candidate)
    raise HeadlessError(
        "no Ghidra installation found. Set GHIDRA_HOME, or pass --ghidra-home "
        "with the path of the installation.",
        code="HEADLESS_NO_GHIDRA",
    )


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
    name = os.path.basename(binary)
    stem = os.path.splitext(name)[0]
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", stem).strip("_") or "binary"
    return cleaned


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
    name = os.path.basename(program)
    index = project_index(project_dir, project_name)
    if not index:
        return False
    return f":{name}:" in index


def build_command(
    launcher: str,
    project_dir: str,
    project_name: str,
    binary: str,
    port: int,
    process: bool = False,
    extra: Optional[List[str]] = None,
) -> List[str]:
    """The command that starts the headless run.

    ``-process`` re-analyses a program that is already in the project;
    ``-import`` puts a new one in. The script runs after the analysis and
    stays in the run, so the run serves the API until it is stopped.
    """
    command = [launcher, project_dir, project_name]
    if process:
        command += ["-process", os.path.basename(binary)]
    else:
        command += ["-import", binary]
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


def process_is_ours(pid: int, marker: str = SCRIPT_NAME) -> bool:
    """Whether the process is the headless run this launcher started.

    A run that crashed leaves its state file behind, and the operating
    system hands its PID to somebody else. Signalling that process would
    stop something that has nothing to do with the analysis, so the command
    line is read and the process is only ours when it carries the marker of
    the headless script.
    """
    if not pid:
        return False
    command = process_command_line(pid)
    if not command:
        return False
    return marker.lower() in command.lower()


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


class HeadlessRunner:
    """A headless run: started, waited for, and stopped again.

    The run is detached from the shell that starts it, so it outlives the
    command that launched it and another command can find it afterwards.
    """

    def __init__(
        self,
        binary: str,
        port: int = DEFAULT_PORT,
        project_dir: Optional[str] = None,
        project_name: Optional[str] = None,
        ghidra_home: Optional[str] = None,
        java_home: Optional[str] = None,
        host: str = "127.0.0.1",
    ) -> None:
        self.binary = os.path.abspath(os.path.expanduser(binary))
        self.port = int(port)
        self.host = host
        self.ghidra_home = find_ghidra_home(ghidra_home)
        self.java_home = java_home or os.environ.get(ENV_JAVA_HOME, "")
        self.project_name = project_name or slug_for(self.binary)
        if project_dir:
            self.project_dir = os.path.abspath(os.path.expanduser(project_dir))
        else:
            self.project_dir = default_project_dir()
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
        )

    # -- the command ---------------------------------------------------

    def project_exists(self) -> bool:
        """Whether the project is already there."""
        marker = os.path.join(self.project_dir, f"{self.project_name}.gpr")
        return os.path.isfile(marker)

    def program_in_project(self) -> bool:
        """Whether the program is already in the project."""
        return project_has_program(self.project_dir, self.project_name, self.binary)

    def command(self) -> List[str]:
        """The command that starts the run.

        A program that is already in the project is processed again; one
        that is not is imported. Importing a program that is already there
        fails, and the run never reaches the script that starts the server.
        """
        launcher = launcher_for(self.ghidra_home)
        return build_command(
            launcher,
            self.project_dir,
            self.project_name,
            self.binary,
            self.port,
            process=self.program_in_project(),
        )

    def environment(self) -> Dict[str, str]:
        """The environment the run gets.

        ``JAVA_HOME`` is passed through: Ghidra 12 needs a JDK 21 or newer,
        and the machine's default is often an older one.
        """
        env = dict(os.environ)
        if self.java_home:
            env[ENV_JAVA_HOME] = self.java_home
        return env

    # -- the run -------------------------------------------------------

    def start(self, timeout: int = DEFAULT_TIMEOUT) -> HeadlessInstance:
        """Start the run and wait for the API to answer.

        The output of the run goes to a log file: the analysis is long and
        the reasons it failed are in there.
        """
        if not os.path.isfile(self.binary):
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

        check_project_dir(self.project_dir)
        os.makedirs(self.project_dir, exist_ok=True)
        command = self.command()

        handle = open(self.instance.log, "a", encoding="utf-8", errors="replace")
        handle.write(f"\n=== {time.strftime('%Y-%m-%d %H:%M:%S')} "
                     f"{' '.join(command)}\n")
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
            raise HeadlessError(
                f"could not start the headless run: {exc}",
                code="HEADLESS_LAUNCH",
            ) from None
        finally:
            handle.close()

        self.instance.pid = self.process.pid
        save_state(self.instance)
        self.wait_ready(timeout)
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
        """
        if not api_answers(self.host, self.port):
            return False
        import requests

        try:
            requests.post(f"http://{self.host}:{self.port}/program/save", timeout=30)
        except Exception:
            return False
        return True

    def stop(self, timeout: int = 20) -> bool:
        """Stop the run, and let it save the analysis on its way out.

        The stop file is the polite way: the script returns, the analyzer
        saves the program and closes the project. The kill is the fallback
        for a run that does not come back.

        A process that is not ours is left alone: the state of a run that
        died is stale, and the PID it carries may belong to something else
        entirely by now.
        """
        saved = self.save()
        pid = self.instance.pid or (self.process.pid if self.process else 0)
        if not pid:
            clear_state(self.port)
            return saved

        if not process_is_ours(pid):
            clear_state(self.port)
            return saved

        flag = stop_file_path(self.port)
        try:
            os.makedirs(os.path.dirname(flag), exist_ok=True)
            with open(flag, "w", encoding="utf-8") as handle:
                handle.write(str(time.time()))
        except OSError:
            flag = ""

        if flag and self._wait_for_exit(pid, timeout):
            clear_state(self.port)
            return True

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
                os.kill(int(pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            deadline = time.time() + timeout
            while time.time() < deadline and not self._child_exited(pid):
                time.sleep(POLL_INTERVAL)
            if not self._child_exited(pid):
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except OSError:
                    pass
        self._drop_stale_lock()
        clear_state(self.port)
        return saved

    def _drop_stale_lock(self) -> None:
        """Remove the lock of a project whose owner was killed.

        Ghidra writes a lock file when it opens a project and removes it
        when it closes it. A run that was killed leaves the lock behind, and
        the next run refuses to open the project. The lock carries no PID,
        so there is no way to tell a live owner from a dead one - which is
        why the lock is only removed here, right after the kill.
        """
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
    }
