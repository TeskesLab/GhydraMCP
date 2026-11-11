"""The doctor: is this machine ready, and what is missing.

Every one of these tools has a way to fail that is discovered late. The
Ghidra installation is somewhere else than the environment says. The JDK is
older than the installation asks for, and the run dies with a message about
a JVM flag instead of about the JDK. The extension is built for another
version of Ghidra, so Ghidra does not load it and the API is simply not
there. The port is taken by something else. The project directory has an
element that starts with a dot, and Ghidra refuses to open it.

The doctor looks at all of that at once, before a single analysis is
started, and says what is wrong in words that name the fix. A check that
fails is never a dead end: it carries a hint, and the hint is the command
that solves it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import kuna as kuna_helper
from . import launcher as ghidra_launcher
from . import x64dbg as x64dbg_helper
from .config.defaults import GhidraConfig
from .headless import (
    HeadlessError,
    api_answers,
    check_project_dir,
    default_project_dir,
    port_is_open,
)

STATUS_OK = "ok"
STATUS_WARN = "warn"
STATUS_FAIL = "fail"

# The order the checks are reported in: what has to be there before
# anything else can work, and what only matters when it is used.
CHECK_ORDER = (
    "ghidra",
    "jdk",
    "extension",
    "config",
    "port",
    "project",
    "api",
    "kuna",
    "x64dbg",
)


@dataclass
class Check:
    """One thing that was looked at, and what came of it."""

    name: str
    status: str
    detail: str
    hint: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "hint": self.hint,
        }


@dataclass
class Report:
    """Every check, and the verdict."""

    checks: List[Check] = field(default_factory=list)

    def add(self, check: Check) -> Check:
        self.checks.append(check)
        return check

    @property
    def failures(self) -> List[Check]:
        return [check for check in self.checks if check.status == STATUS_FAIL]

    @property
    def warnings(self) -> List[Check]:
        return [check for check in self.checks if check.status == STATUS_WARN]

    @property
    def ok(self) -> bool:
        return not self.failures

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "checks": [check.to_dict() for check in self.checks],
            "failures": len(self.failures),
            "warnings": len(self.warnings),
        }


# ------------------------------------------------------------- the checks


def check_ghidra(explicit: str = "") -> Check:
    """The Ghidra installation."""
    try:
        home = ghidra_launcher.find_ghidra_home(explicit or None)
    except ghidra_launcher.LauncherError as exc:
        return Check(
            "ghidra", STATUS_FAIL, str(exc),
            "Set GHIDRA_HOME, or put \"ghidra_home\" in ~/.ghydra/config.json.",
        )

    version = ghidra_launcher.ghidra_version(home)
    utility = os.path.join(home, "Ghidra", "Framework", "Utility", "lib", "Utility.jar")
    if not os.path.isfile(utility):
        return Check(
            "ghidra", STATUS_WARN,
            f"{home} has no Utility.jar, so the headless runner has to use the "
            "launcher script - and the launcher script asks 'press any key' "
            "when it fails",
            "The installation looks like a source tree rather than a release.",
        )
    return Check(
        "ghidra", STATUS_OK,
        f"{home}" + (f" (version {version})" if version else ""),
    )


def check_jdk(ghidra_home: str = "", configured: Optional[List[str]] = None) -> Check:
    """The JDK the installation runs on."""
    required = ghidra_launcher.required_jdk_major(ghidra_home) if ghidra_home else None
    try:
        home = ghidra_launcher.find_java_home(
            ghidra_home=ghidra_home or None,
            required_major=required,
            configured=configured,
        )
    except ghidra_launcher.LauncherError as exc:
        return Check(
            "jdk", STATUS_FAIL, str(exc),
            "Install a JDK and point at it: \"java_home\" in "
            "~/.ghydra/config.json, or JAVA_HOME.",
        )

    version = ghidra_launcher.java_version(home)
    text = f"{home}" + (f" (JDK {version[0]}.{version[1]})" if version else "")
    if required and version and version[0] < required:
        return Check(
            "jdk", STATUS_FAIL,
            f"{text} - the installation asks for a JDK {required} or newer",
            "The VM arguments of the installation carry flags that only the "
            "newer JVMs take.",
        )
    if required:
        text += f", and the installation asks for {required} or newer"
    return Check("jdk", STATUS_OK, text)


def check_extension(ghidra_home: str = "") -> Check:
    """The extension, and whether it fits the installation."""
    status = ghidra_launcher.extension_status(ghidra_home)
    if not status.get("installed"):
        return Check(
            "extension", STATUS_FAIL,
            f"not installed in {status.get('directory')}",
            "Install the extension there: the jar, extension.properties and "
            "the Module.manifest, in the directory Ghidra loads from.",
        )
    if status.get("matches") is False:
        return Check(
            "extension", STATUS_FAIL,
            f"built for Ghidra {status.get('version')}, and the installation is "
            f"{status.get('expected_version')} - Ghidra will not load it",
            "Rebuild the extension for this version of Ghidra.",
        )
    return Check(
        "extension", STATUS_OK,
        f"installed in {status.get('directory')} (Ghidra {status.get('version')})",
    )


def check_config(config: GhidraConfig, path: str = "") -> Check:
    """The configuration file, and what is missing from it."""
    details: List[str] = []
    hints: List[str] = []
    if path:
        details.append(path)
    if not config.ghidra_home:
        hints.append('"ghidra_home": "<path>"')
    if not config.java_home:
        hints.append('"java_home": "<path>"')
    if not hints:
        return Check("config", STATUS_OK, ", ".join(details) or "the defaults")
    return Check(
        "config", STATUS_WARN,
        (", ".join(details) + " - " if details else "") +
        "the paths of Ghidra and of the JDK are not written down, so they "
        "have to be found every time",
        "Add " + " and ".join(hints) + " to it.",
    )


def check_port(host: str, port: int) -> Check:
    """The port the API is served on."""
    if api_answers(host, port):
        return Check("port", STATUS_OK, f"{host}:{port} is serving the API")
    if port_is_open(host, port):
        return Check(
            "port", STATUS_WARN,
            f"{host}:{port} is taken by something that is not the Ghidra API",
            "Another Ghidra instance may be starting, or something else took "
            "the port.",
        )
    return Check("port", STATUS_OK, f"{host}:{port} is free")


def check_project(project_dir: str = "") -> Check:
    """The directory the Ghidra projects live in."""
    directory = os.path.abspath(os.path.expanduser(project_dir or default_project_dir()))
    try:
        check_project_dir(directory)
    except HeadlessError as exc:
        return Check(
            "project", STATUS_FAIL, str(exc),
            "Ghidra refuses a project path with an element that starts with "
            "a dot. Use a plain directory, such as " + default_project_dir(),
        )
    if not os.path.isdir(directory):
        return Check(
            "project", STATUS_OK,
            f"{directory} does not exist yet - it is created when it is needed",
        )
    if not os.access(directory, os.W_OK):
        return Check(
            "project", STATUS_FAIL, f"{directory} cannot be written to",
            "The projects of Ghidra have to be written to.",
        )
    # A project that is locked has a run that has it open. The next run of
    # the same binary will refuse to open it, and the reason it gives is
    # about a lock file rather than about the run that holds it.
    # Ghidra leaves a `<name>.lock` and a `<name>.lock~` behind, and they are
    # one project: the run that holds it and the copy it made of the lock. Listing
    # both told the user a project was locked twice.
    locked = set()
    try:
        for name in os.listdir(directory):
            if name.endswith(".lock~"):
                locked.add(name[:-len(".lock~")])
            elif name.endswith(".lock"):
                locked.add(name[:-len(".lock")])
    except OSError:
        locked = set()
    if locked:
        return Check(
            "project", STATUS_WARN,
            f"{directory} - the "
            f"{'project' if len(locked) == 1 else 'projects'} "
            f"{', '.join(sorted(locked))} "
            f"{'is' if len(locked) == 1 else 'are'} locked, "
            "so a run has them open",
            "Stop the run that has it (ghydra headless status), or wait for it. "
            "A lock left by a run that was killed is removed by the next stop.",
        )
    return Check("project", STATUS_OK, directory)


def check_api(host: str, port: int) -> Check:
    """An instance that answers."""
    if api_answers(host, port):
        return Check("api", STATUS_OK, f"an instance is serving on {host}:{port}")
    return Check(
        "api", STATUS_WARN,
        f"nothing is serving on {host}:{port}",
        "That is normal - a headless run starts one when it is needed: "
        "\"ghydra headless start <binary>\".",
    )


def check_kuna(config: GhidraConfig) -> Check:
    """The Kuna decompiler."""
    section = {"enabled": config.kuna_enabled, "path": config.kuna_path}
    if not kuna_helper.is_enabled(section):
        return Check(
            "kuna", STATUS_WARN,
            "the Kuna integration is off",
            "It is an elevation of privilege - it runs a program on the "
            'machine - so it is off by default. Turn it on with '
            '"kuna": {"enabled": true} in ~/.ghydra/config.json.',
        )
    binary = kuna_helper.find_binary(section)
    if not binary:
        return Check(
            "kuna", STATUS_FAIL,
            "the integration is on, but the kuna executable was not found",
            'Point at it with "kuna": {"path": "<path>"} in '
            "~/.ghydra/config.json.",
        )
    return Check("kuna", STATUS_OK, binary)


def check_x64dbg(config: GhidraConfig) -> Check:
    """The x64dbg MCP server."""
    section = {
        "host": config.x64dbg_host,
        "port": config.x64dbg_port,
        "token": config.x64dbg_token,
        "path": config.x64dbg_path,
    }
    settings = x64dbg_helper.resolve_config(section)
    if not settings.get("token"):
        return Check(
            "x64dbg", STATUS_WARN,
            "no bearer token for the x64dbg MCP server",
            'The token cannot be guessed: the plugin writes it to its own '
            'mcp_config.json. Run "ghydra x64dbg setup" to find it and write '
            "the configuration.",
        )
    instance = x64dbg_helper.discover(section)
    if instance is None:
        return Check(
            "x64dbg", STATUS_WARN,
            f"the token is there, but nothing answered on {settings.get('host')}"
            f":{settings.get('port')}",
            "Start x64dbg with the plugin loaded.",
        )
    if instance.get("unauthorized"):
        return Check(
            "x64dbg", STATUS_FAIL,
            "the x64dbg MCP server rejected the token",
            'Run "ghydra x64dbg setup" to read the token the plugin wrote.',
        )
    return Check(
        "x64dbg", STATUS_OK,
        f"serving on {instance.get('host')}:{instance.get('port')}",
    )


# ------------------------------------------------------------- the report


def run_checks(config: Optional[GhidraConfig] = None,
               host: str = "127.0.0.1", port: int = 8192,
               ghidra_home: str = "", java_home: str = "",
               project_dir: str = "") -> Report:
    """Every check, in the order they matter."""
    config = config or GhidraConfig()
    report = Report()

    ghidra = check_ghidra(ghidra_home or config.ghidra_home)
    report.add(ghidra)

    # The installation that was found is the one the other checks ask
    # about: the JDK it needs and the version of the extension it loads
    # are both properties of that installation.
    home = ghidra_home or config.ghidra_home
    if not home:
        try:
            home = ghidra_launcher.find_ghidra_home(None)
        except ghidra_launcher.LauncherError:
            home = ""

    configured = [path for path in (java_home, config.java_home) if path]
    report.add(check_jdk(home, configured))

    report.add(check_extension(home))
    report.add(check_config(config, str(_config_path())))
    report.add(check_port(host, port))
    report.add(check_project(project_dir))
    report.add(check_api(host, port))
    report.add(check_kuna(config))
    report.add(check_x64dbg(config))

    ordered = sorted(report.checks, key=lambda check: (
        CHECK_ORDER.index(check.name) if check.name in CHECK_ORDER else 99))
    report.checks = ordered
    return report


def _config_path() -> str:
    """Where the configuration file is."""
    try:
        from .config.config_manager import ConfigManager
        return str(ConfigManager.CONFIG_FILE)
    except Exception:
        return os.path.join(os.path.expanduser("~"), ".ghydra", "config.json")


def render_text(report: Report) -> str:
    """The report, as a human reads it."""
    marks = {STATUS_OK: "ok", STATUS_WARN: "warn", STATUS_FAIL: "FAIL"}
    lines: List[str] = []
    for check in report.checks:
        lines.append(f"[{marks.get(check.status, check.status):>4}] {check.name}: {check.detail}")
        if check.hint and check.status != STATUS_OK:
            lines.append(f"         -> {check.hint}")
    if report.failures:
        lines.append("")
        lines.append(f"{len(report.failures)} problem(s) and "
                     f"{len(report.warnings)} warning(s).")
    else:
        lines.append("")
        lines.append("Everything works." if not report.warnings else
                     f"Everything works, with {len(report.warnings)} warning(s).")
    return "\n".join(lines)
