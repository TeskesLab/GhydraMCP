"""The Ghidra installation, the JDK it needs, and the command that starts it.

Ghidra ships two launchers: ``analyzeHeadless`` (POSIX) and
``analyzeHeadless.bat`` (Windows). Both are batch/shell wrappers around the
same JVM invocation, and both have two habits that get in the way of a tool
that wants to run in the background:

* the Windows one asks "press any key to continue" when it fails, because it
  cannot tell a double-click from a shell - and a launcher that was started
  by another program is exactly the case it cannot handle;
* the output of the run goes wherever the JVM's console goes, which is not
  necessarily the file the caller asked for.

So this module does not call the launcher. It builds the JVM invocation
itself, the way the launcher does:

    java <the VM arguments of the installation> \\
         -cp <Utility.jar> ghidra.Ghidra \\
         ghidra.app.util.headless.AnalyzeHeadless <the arguments>

The VM arguments come from Ghidra's own ``LaunchSupport``, which reads
``support/launch.properties`` - so they are the ones the installation was
built for, and not a copy that drifts. The same tool is what finds the JDK:
``LaunchSupport <install> -jdk_home -save`` answers with a JDK the
installation supports, which is how a machine with three JDKs ends up
running the right one without anybody configuring anything.

The JDK search is layered, and the layers are in the order of how explicit
the decision is: what the caller asked for, what the configuration file
says, what the environment says, what Ghidra itself would use, and finally
the usual places a JDK is installed.
"""

from __future__ import annotations

import glob
import os
import re
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

# Where Ghidra keeps its per-user state. The extension lives in the
# "Extensions" directory of this tree, and that is where it has to be for
# Ghidra to load it.
ENV_STATE_DIR = "GHYDRA_STATE_DIR"

# The Ghidra home: the directory that holds "Ghidra", "support" and
# "docs".
ENV_GHIDRA_HOME = "GHIDRA_HOME"

# The JDK. Ghidra 11.x wants a JDK 21 and Ghidra 12.2 wants a JDK 25, so the
# version that the installation asks for is read from its own properties
# rather than guessed.
ENV_JAVA_HOME = "JAVA_HOME"

# The headless analyzer's own heap default, and the two flags it uses to
# keep the GC and the JIT compiler from taking a thread per core. A headless
# run is usually one of many, and the analyzer is not the only thing on the
# machine.
HEADLESS_MAXMEM = "2G"
HEADLESS_VMARGS = ("-XX:ParallelGCThreads=2", "-XX:CICompilerCount=2")

# The JVM options the caller may add, the same names Ghidra's own launcher
# uses.
ENV_JAVA_OPTIONS = "GHIDRA_JAVA_OPTIONS"
ENV_HEADLESS_JAVA_OPTIONS = "GHIDRA_HEADLESS_JAVA_OPTIONS"
ENV_MAXMEM = "GHIDRA_MAXMEM"
ENV_HEADLESS_MAXMEM = "GHIDRA_HEADLESS_MAXMEM"


class LauncherError(Exception):
    """A failure with a machine-readable code."""

    def __init__(self, message: str, code: str = "LAUNCHER_ERROR") -> None:
        super().__init__(message)
        self.code = code


# --------------------------------------------------------------- the paths


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


def find_ghidra_home(explicit: Optional[str] = None,
                     candidates: Optional[List[str]] = None) -> str:
    """Where the Ghidra installation is.

    The explicit path wins over ``GHIDRA_HOME``, and both win over the
    places Ghidra is usually installed. The places may be given, so that a
    caller can decide where to look.
    """
    for candidate in (explicit, os.environ.get(ENV_GHIDRA_HOME)):
        if candidate and os.path.isdir(candidate):
            return os.path.abspath(candidate)
    for candidate in (candidates if candidates is not None else candidate_homes()):
        if os.path.isdir(candidate):
            return os.path.abspath(candidate)
    raise LauncherError(
        "no Ghidra installation found. Set GHIDRA_HOME, or pass --ghidra-home "
        "with the path of the installation.",
        code="LAUNCHER_NO_GHIDRA",
    )


def read_properties(path: str) -> Dict[str, str]:
    """The key/value pairs of a Java properties file.

    Only what Ghidra's own properties files use: ``key=value``, ``#``
    comments and continuation lines. A malformed line is skipped rather than
    fatal - a properties file is configuration, not a contract.
    """
    out: Dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                line = raw.strip()
                if not line or line.startswith("#") or line.startswith("!"):
                    continue
                if "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                if key:
                    out[key] = value.strip()
    except OSError:
        return {}
    return out


def application_properties(ghidra_home: str) -> Dict[str, str]:
    """The properties of the installation itself."""
    path = os.path.join(ghidra_home, "Ghidra", "application.properties")
    return read_properties(path)


def ghidra_version(ghidra_home: str) -> str:
    """The version of the installation, e.g. ``12.2``."""
    return application_properties(ghidra_home).get("application.version", "")


def required_jdk_major(ghidra_home: str) -> Optional[int]:
    """The JDK the installation needs.

    Ghidra says it in its own properties: ``application.java.min`` is the
    oldest JDK that works, and ``application.java.max`` the newest one that
    is supported. Ghidra 11.x asks for a JDK 21 and Ghidra 12.2 for a JDK
    25, and the difference matters: the VM arguments of the installation
    carry flags that only the newer JVMs take.
    """
    properties = application_properties(ghidra_home)
    for key in ("application.java.min", "application.java.max"):
        value = properties.get(key, "")
        if value:
            try:
                return int(value)
            except ValueError:
                continue
    return None


def release_name(ghidra_home: str) -> str:
    """The native release name, such as PUBLIC or NIX."""
    return application_properties(ghidra_home).get("application.release.name", "")


# ------------------------------------------------------------------- the JDK


def binary_name(path: str) -> str:
    """The name of the file a path points at, with either separator.

    A Windows path handed to a POSIX machine is still a path with a file
    name at the end, so the backslash is a separator there too - and Ghidra
    identifies a program by that name.
    """
    normalized = str(path).replace("\\", os.sep).replace("/", os.sep)
    return os.path.basename(normalized)


def java_binary(java_home: str) -> str:
    """The java executable of a JDK."""
    name = "java.exe" if os.name == "nt" else "java"
    return os.path.join(java_home, "bin", name)


def java_version(java_home: str) -> Optional[Tuple[int, int]]:
    """The version of a JDK, as ``(major, minor)``.

    It is read from the ``release`` file the JDK ships, and not by running
    the JVM: the file is there, it is fast, and running a JVM to find out
    which JVM it is would be silly.
    """
    if not java_home:
        return None
    release = os.path.join(java_home, "release")
    try:
        with open(release, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError:
        return None
    match = re.search(r'JAVA_VERSION="?(\d+)(?:\.(\d+))?', text)
    if not match:
        return None
    major = int(match.group(1))
    minor = int(match.group(2) or 0)
    return major, minor


def any_java() -> Optional[str]:
    """A java to run Ghidra's own tools with.

    It does not have to be the right one - it only has to run Java code, so
    that Ghidra's ``LaunchSupport`` can find the right one.
    """
    home = os.environ.get(ENV_JAVA_HOME, "")
    if home and os.path.isfile(java_binary(home)):
        return java_binary(home)
    found = shutil.which("java")
    return found


def _jdk_candidates() -> List[str]:
    """The places a JDK is usually installed."""
    home = os.path.expanduser("~")
    patterns: List[str] = []
    if os.name == "nt":
        program = os.environ.get("ProgramFiles", r"C:\Program Files")
        local = os.environ.get("LOCALAPPDATA", "")
        if program:
            patterns.append(os.path.join(program, "Eclipse Adoptium", "jdk-*"))
            patterns.append(os.path.join(program, "Java", "jdk-*"))
            patterns.append(os.path.join(program, "Microsoft", "jdk-*"))
            patterns.append(os.path.join(program, "Zulu", "zulu*"))
        if local:
            patterns.append(os.path.join(local, "Programs", "Eclipse Adoptium", "jdk-*"))
        patterns.append(os.path.join(home, ".jdks", "*"))
        patterns.append(os.path.join(home, "scoop", "apps", "temurin*", "current"))
        patterns.append(os.path.join(home, "scoop", "apps", "openjdk*", "current"))
        patterns.append(os.path.join(home, "scoop", "apps", "microsoft-openjdk*", "current"))
    else:
        patterns.extend([
            "/usr/lib/jvm/*",
            "/usr/java/*",
            "/opt/java/*",
            "/Library/Java/JavaVirtualMachines/*/Contents/Home",
            os.path.join(home, ".jdks", "*"),
            os.path.join(home, ".sdkman", "candidates", "java", "*"),
        ])
    found: List[str] = []
    for pattern in patterns:
        for path in sorted(glob.glob(pattern)):
            if os.path.isfile(java_binary(path)):
                found.append(path)
    return found


def _launch_support_jdk(ghidra_home: str) -> Optional[str]:
    """The JDK Ghidra itself would use.

    ``LaunchSupport`` reads the installation's own properties and answers
    with a JDK that satisfies them - and with the one the user chose, when
    the user chose one. That answer is better than any search: it is the
    installation's own opinion about what it runs on.
    """
    java = any_java()
    support = os.path.join(ghidra_home, "support", "LaunchSupport.jar")
    if not java or not os.path.isfile(support):
        return None
    try:
        output = subprocess.run(
            [java, "-cp", support, "LaunchSupport", ghidra_home, "-jdk_home", "-save"],
            capture_output=True, text=True, timeout=120,
        ).stdout or ""
    except (OSError, subprocess.SubprocessError):
        return None
    for line in output.splitlines():
        candidate = line.strip()
        if candidate and os.path.isfile(java_binary(candidate)):
            return os.path.abspath(candidate)
    return None


def find_java_home(explicit: Optional[str] = None,
                   ghidra_home: Optional[str] = None,
                   required_major: Optional[int] = None,
                   configured: Optional[List[str]] = None) -> str:
    """The JDK to run Ghidra with.

    The layers, in the order of how explicit the decision is:

    1. what the caller asked for;
    2. what the configuration file says;
    3. ``JAVA_HOME``;
    4. the JDK Ghidra itself would use;
    5. the places a JDK is usually installed.

    A JDK that is older than the installation asks for is not used - the
    installation's VM arguments carry flags that only the newer JVMs take,
    and the run would die with a message about a flag rather than about the
    JDK. When the caller asked for a specific one and it is too old, that is
    an error rather than a silent substitution.
    """
    # What the caller asked for is an order, not a hint: if that JDK is older
    # than the installation asks for, the answer is an error and not a
    # substitution. Every other layer is a place the search may stop.
    if explicit and os.path.isdir(explicit):
        version = java_version(explicit)
        if version is not None and required_major and version[0] < required_major:
            raise LauncherError(
                f"the JDK that was asked for ({explicit}) is JDK {version[0]}, "
                f"and this Ghidra asks for JDK {required_major} or newer. Its "
                "VM arguments carry flags that only the newer JVMs take, so "
                "the run would die with a message about a flag rather than "
                "about the JDK. Point at a newer one.",
                code="LAUNCHER_NO_JDK")

    layers: List[Tuple[str, str]] = []
    if explicit:
        layers.append(("the requested JDK", explicit))
    for entry in configured or []:
        if entry:
            layers.append(("the configuration file", entry))
    if os.environ.get(ENV_JAVA_HOME):
        layers.append((ENV_JAVA_HOME, os.environ[ENV_JAVA_HOME]))

    if ghidra_home:
        chosen = _launch_support_jdk(ghidra_home)
        if chosen:
            layers.append(("Ghidra's own choice", chosen))

    for path in _jdk_candidates():
        layers.append(("an installed JDK", path))

    rejected: List[str] = []
    for origin, path in layers:
        if not path or not os.path.isdir(path):
            continue
        version = java_version(path)
        if version is None:
            continue
        if required_major and version[0] < required_major:
            rejected.append(
                f"{path} ({origin}, JDK {version[0]}) needs JDK {required_major} or newer")
            continue
        return os.path.abspath(path)

    if rejected:
        raise LauncherError(
            "no JDK is new enough for this Ghidra. The installation asks for a "
            f"JDK {required_major} or newer, and what was found is not: "
            + "; ".join(rejected),
            code="LAUNCHER_NO_JDK",
        )
    raise LauncherError(
        "no JDK found. Set JAVA_HOME, put one in the configuration file "
        '("java_home"), or pass --java-home.',
        code="LAUNCHER_NO_JDK",
    )


# --------------------------------------------------------- the Ghidra tools


def launch_support(ghidra_home: str, java_home: str, *args: str) -> List[str]:
    """What Ghidra's own ``LaunchSupport`` answers.

    It is the tool the launchers use to read ``launch.properties``: the VM
    arguments, the environment variables, and the JDK the installation
    supports. Asking it is better than reading the properties file here,
    because it applies the rules - the platform suffixes, the overrides -
    that the file describes.
    """
    java = java_binary(java_home)
    support = os.path.join(ghidra_home, "support", "LaunchSupport.jar")
    if not os.path.isfile(support):
        return []
    try:
        result = subprocess.run(
            [java, "-cp", support, "LaunchSupport", ghidra_home, *args],
            capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    return [line for line in (result.stdout or "").splitlines() if line.strip()]


def vm_args(ghidra_home: str, java_home: str) -> List[str]:
    """The VM arguments of the installation."""
    return [line.strip() for line in launch_support(ghidra_home, java_home, "-vmargs")
            if line.strip()]


def env_vars(ghidra_home: str, java_home: str) -> Dict[str, str]:
    """The environment variables the installation asks for."""
    out: Dict[str, str] = {}
    for line in launch_support(ghidra_home, java_home, "-envvars"):
        key, separator, value = line.partition("=")
        if separator and key.strip():
            out[key.strip()] = value.strip()
    return out


def _split_options(value: str) -> List[str]:
    """The options of an environment variable, as a list.

    The options are separated by spaces, and a path with spaces in it is
    quoted - the same way the launchers read them.
    """
    return [part for part in re.split(r"\s+", value.strip()) if part]


def headless_command(ghidra_home: str, java_home: str, project_dir: str,
                     project_name: str, binary: str, port: int,
                     process: bool = False, overwrite: bool = False,
                     extra: Optional[List[str]] = None,
                     maxmem: Optional[str] = None, script: str = "",
                     script_args: Optional[List[str]] = None,
                     empty: bool = False,
                     connections_dir: Optional[str] = None,
                     repository_profile: Optional[str] = None) -> List[str]:
    """The command that starts a headless run.

    It is the JVM invocation the launcher makes, with the same arguments:
    the installation's VM arguments, the headless heap and thread flags, and
    the analyzer class.

    ``-process`` re-analyses a program that is already in the project and
    ``-import`` puts a new one in - importing a program that is already
    there fails, and the run never reaches the script that starts the
    server.

    ``empty`` runs the script once without importing or processing a binary.
    ``script_args`` supplies the script arguments. The script keeps the run
    alive while it serves the API.
    """
    if empty and (not script or binary or process or overwrite):
        raise LauncherError("Empty project runs require a script and no binary operation.",
                            code="LAUNCHER_INVALID_ARGUMENT")
    if repository_profile and (not empty or extra or script != "GhidraHeadlessServer"):
        raise LauncherError("Repository workers require the fixed empty-project bootstrap.",
                            code="CONNECTION_PERMISSION_DENIED")
    java = java_binary(java_home)
    utility = os.path.join(ghidra_home, "Ghidra", "Framework", "Utility", "lib", "Utility.jar")
    if not os.path.isfile(utility):
        raise LauncherError(
            f"no Utility.jar in {utility}. The installation looks incomplete.",
            code="LAUNCHER_NO_UTILITY",
        )

    heap = maxmem or os.environ.get(ENV_HEADLESS_MAXMEM) \
        or os.environ.get(ENV_MAXMEM) or HEADLESS_MAXMEM

    command: List[str] = [java]
    command += vm_args(ghidra_home, java_home)
    command.append(f"-Xmx{heap}")
    command += list(HEADLESS_VMARGS)
    for name in (ENV_JAVA_OPTIONS, ENV_HEADLESS_JAVA_OPTIONS):
        value = os.environ.get(name, "")
        if value.strip():
            command += _split_options(value)
    # The stop file lives in the home directory of the user, and the script
    # looks for it with "user.home" - so the two have to agree.
    command.append(f"-Duser.home={os.path.expanduser('~')}")
    if connections_dir:
        command.append(f"-Dghydra.connections.dir={connections_dir}")
    command += ["-cp", utility, "ghidra.Ghidra",
                "ghidra.app.util.headless.AnalyzeHeadless"]
    command += [project_dir, project_name]
    if process:
        command += ["-process", binary_name(binary)]
    elif not empty:
        command += ["-import", binary]
        if overwrite:
            # Replace an existing program with the rebuilt binary.
            command += ["-overwrite"]
    if script:
        command += ["-postScript", script]
        command += list(script_args or [])
    if extra:
        command += list(extra)
    return command


# -------------------------------------------------------------- the extension


def user_settings_dir() -> str:
    """Where Ghidra keeps the per-user state.

    The layout is Ghidra's own: ``<settings>/ghidra/ghidra_<version>_<release>``.
    """
    if os.name == "nt":
        base = os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Roaming")
        return os.path.join(base, "ghidra")
    if sys.platform == "darwin":
        return os.path.join(os.path.expanduser("~"), "Library", "Application Support", "ghidra")
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = xdg if xdg else os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "ghidra")


def settings_version_dir(ghidra_home: str = "") -> str:
    """The version directory of the settings.

    It is ``ghidra_<version>_<release>``, and the version comes from the
    installation when there is one - otherwise the newest directory that is
    there.
    """
    root = user_settings_dir()
    version = ghidra_version(ghidra_home) if ghidra_home else ""
    release = release_name(ghidra_home) if ghidra_home else ""
    if version:
        name = f"ghidra_{version}"
        if release:
            name += f"_{release}"
        return os.path.join(root, name)
    try:
        entries = sorted(
            entry for entry in os.listdir(root)
            if entry.startswith("ghidra_") and os.path.isdir(os.path.join(root, entry))
        )
    except OSError:
        return root
    if entries:
        return os.path.join(root, entries[-1])
    return root


def extension_dir(ghidra_home: str = "") -> str:
    """Where the GhydraMCP extension has to be installed.

    Ghidra loads the extensions of the user from the "Extensions"
    directory of the settings directory - not from the installation, and
    not from ``ghidra.extensions.dir``.
    """
    return os.path.join(settings_version_dir(ghidra_home), "Extensions", "Ghydra")


def extension_status(ghidra_home: str = "") -> Dict[str, Any]:
    """Whether the extension is installed, and whether it fits.

    The extension declares the version of Ghidra it was built for, and Ghidra
    refuses to load an extension that was built for another version - so the
    two are compared here.
    """
    out: Dict[str, Any] = {
        "directory": extension_dir(ghidra_home),
        "installed": False,
        "version": "",
        "expected_version": ghidra_version(ghidra_home) if ghidra_home else "",
        "matches": None,
    }
    directory = out["directory"]
    properties = os.path.join(directory, "extension.properties")
    if not os.path.isfile(properties):
        return out
    out["installed"] = True
    values = read_properties(properties)
    out["version"] = values.get("ghidraVersion", "")
    if out["expected_version"] and out["version"]:
        out["matches"] = out["version"] == out["expected_version"]
    return out
