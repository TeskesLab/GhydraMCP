"""Prepare a Ghidra instance that the live suites can run against.

Two things stand between a developer and the live suites, and both are
dialogues:

**The "New Plugins Found!" dialogue.** Ghidra asks, once per tool, whether the
plugins of a newly installed extension should be configured — and the answer is
not kept: the tools' state carries no ``<EXTENSIONS>`` element, so the
dialogue comes back every time the CodeBrowser is opened. The state is written
by hand here: one ``<EXTENSION NAME="…"/>`` per installed extension, in the
tool's own XML. The front end's state is ``FrontEndTool.xml`` in the user
directory; the CodeBrowser's is the ``RUNNING_TOOL`` block of the project's
``projectState``.

**The program.** The cursor endpoints (``/address`` and ``/function``) answer
for the program the CodeBrowser has open, so a CodeBrowser with no program
answers 503 and the tests that cover them skip. Ghidra's own *GhidraGo*
interface opens a program in a running Ghidra — the request is a URL, and the
sender writes it to a file the running instance watches. That is how the
program gets open without a human touching the window.

The script does both, and prints the port of the instance that serves the
program — which is not always the first one: Ghidra gives the first port to
whoever asks first, and a CodeBrowser opened for a program lands on the next
free one.

    python scripts/prepare_ghidra_instance.py --ghidra-home <path> \\
        --project <path.gpr> --binary <path> [--port 8192]
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from typing import List, Optional, Tuple

#: The element Ghidra reads the known extensions from.
EXTENSIONS = "EXTENSIONS"
EXTENSION = "EXTENSION"
NAME = "NAME"
ENCODED_NAME = "ENCODED_NAME"

#: The name the extension is known by — the `name=` of its extension.properties.
DEFAULT_EXTENSION_NAME = "Ghydra"


def _jdk(ghidra_home: str) -> Optional[str]:
    """The JDK Ghidra itself would use.

    The installation knows its own answer — ``LaunchSupport -jdk_home -save``
    — and it is better than the one on the PATH: the launcher refuses a JDK
    that is too old, and the path holds whichever was installed last.
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if root not in sys.path:
        sys.path.insert(0, root)
    try:
        from ghydra.launcher import find_java_home
    except ImportError:
        return os.environ.get("JAVA_HOME") or None
    try:
        return find_java_home(ghidra_home=ghidra_home)
    except Exception:
        return os.environ.get("JAVA_HOME") or None


def _read(path: str) -> Optional[ET.ElementTree]:
    if not os.path.isfile(path):
        return None
    try:
        return ET.parse(path)
    except ET.ParseError:
        return None


def seed_extension(path: str, parent_tag: str, extension_name: str) -> bool:
    """Record the extension in a tool's state, so the dialogue stays away.

    The state is a small XML element: the tools that Ghidra writes it into are
    the front end (its own file in the user directory) and the CodeBrowser
    (the block of the project's state).
    """
    tree = _read(path)
    if tree is None:
        return False
    root = tree.getroot()
    parents = [element for element in root.iter() if element.tag == parent_tag]
    if not parents:
        return False
    changed = False
    for parent in parents:
        extensions = parent.find(EXTENSIONS)
        if extensions is None:
            extensions = ET.SubElement(parent, EXTENSIONS)
            changed = True
        known = {child.get(NAME) or child.get(ENCODED_NAME)
                 for child in extensions.findall(EXTENSION)}
        if extension_name not in known:
            child = ET.SubElement(extensions, EXTENSION)
            child.set(NAME, extension_name)
            changed = True
    if changed:
        tree.write(path, encoding="UTF-8", xml_declaration=True)
    return changed


def user_directory(ghidra_home: str) -> Optional[str]:
    """The directory Ghidra keeps its per-user state in."""
    root = os.environ.get("APPDATA")
    if not root:
        return None
    base = os.path.join(root, "ghidra")
    if not os.path.isdir(base):
        return None
    candidates = sorted(os.listdir(base))
    for name in reversed(candidates):
        candidate = os.path.join(base, name)
        if os.path.isdir(candidate) and name.startswith("ghidra_"):
            return candidate
    return None


def project_state(project: str) -> Optional[str]:
    """The file the project's tools' state is in."""
    if not project.endswith(".gpr"):
        return None
    repository = project[:-4] + ".rep"
    candidate = os.path.join(repository, "projectState")
    return candidate if os.path.isfile(candidate) else None


def http_get(url: str, timeout: float = 5.0) -> Optional[Tuple[int, str]]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as answer:
            return answer.getcode(), answer.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")
    except Exception:
        return None


def instances_with_a_program(first: int, last: int) -> List[int]:
    """The ports of the instances that have a program open.

    The ports are asked in parallel: a port that is not served waits for the
    whole timeout, and ten of them in a row would make the wait for the
    program minutes long.
    """
    from concurrent.futures import ThreadPoolExecutor

    def probe(port: int) -> Optional[int]:
        answer = http_get(f"http://127.0.0.1:{port}/program", timeout=3)
        return port if answer and answer[0] == 200 else None

    with ThreadPoolExecutor(max_workers=min(16, last - first + 1)) as pool:
        answers = list(pool.map(probe, range(first, last + 1)))
    return [port for port in answers if port is not None]


def send_ghidra_go(ghidra_home: str, project: str, binary: str) -> bool:
    """Ask the running Ghidra to open the program, through GhidraGo.

    GhidraGo is a launchable of the installation, not a program with a `main`:
    Ghidra's own launcher starts it, with the Ghidra class loader and the
    installation's jars. The launcher script cannot be used here — it refuses a
    redirected input ("Input redirection is not supported, exiting the process
    immediately"), and a script that runs without a console has one — so the
    invocation is made here, the way the launcher makes it.

    The sender writes the URL to a file the running instance watches, so the
    request does not wait for the program to be open.
    """
    java_home = _jdk(ghidra_home)
    if not java_home:
        return False
    java = os.path.join(java_home, "bin", "java.exe")
    if not os.path.isfile(java):
        java = os.path.join(java_home, "bin", "java")
    jars = []
    for base, _directories, files in os.walk(ghidra_home):
        for name in files:
            if name.endswith(".jar") and os.sep + "lib" + os.sep in base:
                jars.append(os.path.join(base, name))
    if not jars:
        return False
    directory = os.path.dirname(project)
    name = os.path.basename(project)
    if name.endswith(".gpr"):
        name = name[:-4]
    url = f"ghidra:/{directory}/{name}?/{os.path.basename(binary)}"
    command = [
        java,
        "-Djava.system.class.loader=ghidra.GhidraClassLoader",
        f"-Dghidra.install.dir={ghidra_home}",
        "-cp", ";".join(jars),
        "ghidra.Ghidra", "ghidra.GhidraGo", url,
    ]
    try:
        with open(os.path.join(tempfile.gettempdir(), "ghydra-go.log"),
                  "a", encoding="utf-8") as log:
            console = _console_input()
            if console is None:
                result = subprocess.run(command, stdout=log, stderr=log,
                                        timeout=120)
            else:
                result = subprocess.run(command, stdin=console, stdout=log,
                                        stderr=log, timeout=120)
            if console is not None:
                console.close()
    except Exception:
        return False
    return result.returncode == 0


def _console_input():
    """The console's input, for the launcher.

    Ghidra's applications refuse a redirected input — "Input redirection is not
    supported, exiting the process immediately" — and a script that runs
    without a console has one. The console is opened by name on Windows, so
    the launcher sees the console it expects.
    """
    if os.name != "nt":
        return None
    try:
        return open("CONIN$", "rb")
    except OSError:
        return None


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra-home", required=True,
                        help="the Ghidra installation")
    parser.add_argument("--project", required=True,
                        help="the project the CodeBrowser opens")
    parser.add_argument("--binary", required=True,
                        help="the program the CodeBrowser opens")
    parser.add_argument("--extension", default=DEFAULT_EXTENSION_NAME,
                        help="the name of the extension (default: %(default)s)")
    parser.add_argument("--port", type=int, default=8192,
                        help="the first port of the instance range")
    parser.add_argument("--last-port", type=int, default=8201,
                        help="the last port of the instance range")
    parser.add_argument("--no-start", action="store_true",
                        help="only seed the state; do not start anything")
    arguments = parser.parse_args(argv)

    # 1. The dialogue: the extension is recorded as known in both tools.
    directory = user_directory(arguments.ghidra_home)
    if directory:
        front_end = os.path.join(directory, "FrontEndTool.xml")
        if seed_extension(front_end, "TOOL", arguments.extension):
            print(f"  seeded {front_end}")
    state = project_state(arguments.project)
    if state:
        if seed_extension(state, "RUNNING_TOOL", arguments.extension):
            print(f"  seeded {state}")

    if arguments.no_start:
        print("  the state is ready; the instance was not started")
        return 0

    # 2. The program: the running instance opens it, through GhidraGo.
    if not instances_with_a_program(arguments.port, arguments.last_port):
        print("  asking the running Ghidra to open the program")
        send_ghidra_go(arguments.ghidra_home, arguments.project,
                       arguments.binary)
    for _ in range(30):
        time.sleep(4)
        serving = instances_with_a_program(arguments.port, arguments.last_port)
        if serving:
            print(f"  the program is served on port {serving[0]}")
            print(f"  run the suites with GHYDRAMCP_TEST_PORT={serving[0]}")
            return 0
    print("  no instance answers with a program; is Ghidra running with "
          "the project open?", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
