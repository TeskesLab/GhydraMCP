"""Build the Ghidra extension without Maven.

Maven is not installed on this machine, and the extension has to be rebuilt
often enough that "install Maven" is not an answer. The merge itself is
`scripts/make_uberjar.py` — this script finds the dependency jars, compiles the
sources, calls that script, and lays out the extension directory exactly as
`src/assembly/ghidra-extension.xml` describes it.

The version that goes into `extension.properties` is the one of the
installation the extension is built for: Ghidra refuses to load an extension
whose `ghidraVersion` does not match the installation it is found in.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Sequence

#: The repository's root, so the script works from anywhere.
ROOT = Path(__file__).resolve().parent.parent

#: Where the dependency jars live in the local Maven repository.
M2 = Path(os.environ.get("USERPROFILE", str(Path.home()))) / ".m2" / "repository"

#: The runtime dependencies that are merged into the jar: Javalin and its
#: transitives, SLF4J, and the annotations Kotlin's signatures refer to.
#: Gson is `provided` (Ghidra supplies it) and the Ghidra module jars in
#: `lib/` are `system`-scoped, so neither is merged.
RUNTIME_JARS = (
    "io/javalin/javalin/6.3.0/javalin-6.3.0.jar",
    "org/eclipse/jetty/jetty-server/11.0.23/jetty-server-11.0.23.jar",
    "org/eclipse/jetty/jetty-util/11.0.23/jetty-util-11.0.23.jar",
    "org/eclipse/jetty/jetty-io/11.0.23/jetty-io-11.0.23.jar",
    "org/eclipse/jetty/jetty-http/11.0.23/jetty-http-11.0.23.jar",
    "org/eclipse/jetty/jetty-servlet/11.0.23/jetty-servlet-11.0.23.jar",
    "org/eclipse/jetty/jetty-security/11.0.23/jetty-security-11.0.23.jar",
    "org/eclipse/jetty/jetty-webapp/11.0.23/jetty-webapp-11.0.23.jar",
    "org/eclipse/jetty/jetty-xml/11.0.23/jetty-xml-11.0.23.jar",
    "org/eclipse/jetty/toolchain/jetty-jakarta-servlet-api/5.0.2/jetty-jakarta-servlet-api-5.0.2.jar",
    # Javalin registers its websocket plugin at startup, so these are not
    # optional: without them the server dies with a NoClassDefFoundError
    # before it answers anything.
    "org/eclipse/jetty/websocket/websocket-jetty-server/11.0.23/websocket-jetty-server-11.0.23.jar",
    "org/eclipse/jetty/websocket/websocket-jetty-api/11.0.23/websocket-jetty-api-11.0.23.jar",
    "org/eclipse/jetty/websocket/websocket-jetty-common/11.0.23/websocket-jetty-common-11.0.23.jar",
    "org/eclipse/jetty/websocket/websocket-core-server/11.0.23/websocket-core-server-11.0.23.jar",
    "org/eclipse/jetty/websocket/websocket-core-common/11.0.23/websocket-core-common-11.0.23.jar",
    "org/eclipse/jetty/websocket/websocket-servlet/11.0.23/websocket-servlet-11.0.23.jar",
    "org/jetbrains/kotlin/kotlin-stdlib/1.9.25/kotlin-stdlib-1.9.25.jar",
    "org/jetbrains/kotlin/kotlin-stdlib-jdk7/1.9.25/kotlin-stdlib-jdk7-1.9.25.jar",
    "org/jetbrains/kotlin/kotlin-stdlib-jdk8/1.9.25/kotlin-stdlib-jdk8-1.9.25.jar",
    "org/slf4j/slf4j-api/2.0.16/slf4j-api-2.0.16.jar",
    "org/slf4j/slf4j-simple/2.0.9/slf4j-simple-2.0.9.jar",
    "org/jetbrains/annotations/13.0/annotations-13.0.jar",
)

#: The dependencies that are needed to compile but are not merged: Gson is
#: `provided`, and Ghidra supplies it at runtime.
COMPILE_ONLY_JARS = (
    "com/google/code/gson/gson/2.10.1/gson-2.10.1.jar",
)


class BuildError(Exception):
    """A build that could not be done, with the reason a reader can act on."""


def ghidra_version(ghidra_home: Path) -> str:
    """The version of the installation the extension is built for."""
    properties = ghidra_home / "Ghidra" / "application.properties"
    if not properties.is_file():
        raise BuildError(
            f"{properties} is not there: {ghidra_home} is not a Ghidra "
            "installation")
    for line in properties.read_text(encoding="utf-8").splitlines():
        if line.startswith("application.version="):
            return line.split("=", 1)[1].strip()
    raise BuildError(f"application.version is not in {properties}")


def find_jar(relative: str) -> Path:
    """One jar in the local Maven repository."""
    path = M2 / relative
    if not path.is_file():
        raise BuildError(
            f"{path} is not there. The dependency is needed to build the "
            "extension, and Maven is not installed to fetch it.")
    return path


def compile_sources(classes: Path, classpath: Sequence[Path]) -> int:
    """Every `.java` under `src/main/java`, compiled into `classes`."""
    sources = sorted((ROOT / "src" / "main" / "java").rglob("*.java"))
    if not sources:
        raise BuildError("there are no Java sources to compile")
    classes.mkdir(parents=True, exist_ok=True)
    command = [
        "javac", "-nowarn", "-encoding", "UTF-8",
        "-d", str(classes),
        "-cp", os.pathsep.join(str(entry) for entry in classpath),
        *[str(source) for source in sources],
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise BuildError("javac failed:\n" + (result.stderr or result.stdout))
    return len(sources)


def merge_jar(classes: Path, deps: Path, out_jar: Path) -> None:
    """The uberjar, through the script that already does the merge."""
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "make_uberjar.py"),
         str(classes), str(deps), str(out_jar)],
        capture_output=True, text=True)
    if result.returncode != 0:
        raise BuildError("the merge failed:\n"
                         + (result.stderr or result.stdout))
    print("  " + result.stdout.strip())


def assemble(out: Path, ghidra_version_string: str, jar: Path) -> None:
    """The extension directory, as `src/assembly/ghidra-extension.xml` says."""
    resources = ROOT / "src" / "main" / "resources"
    if out.exists():
        shutil.rmtree(out)
    (out / "lib").mkdir(parents=True)
    (out / "ghidra_scripts").mkdir(parents=True)

    properties = (resources / "extension.properties").read_text(
        encoding="utf-8").replace("${ghidra.version}", ghidra_version_string)
    (out / "extension.properties").write_text(properties, encoding="utf-8")

    manifest = resources / "Module.manifest"
    (out / "Module.manifest").write_text(
        manifest.read_text(encoding="utf-8") if manifest.is_file() else "",
        encoding="utf-8")

    scripts = resources / "ghidra_scripts"
    if scripts.is_dir():
        shutil.copytree(scripts, out / "ghidra_scripts", dirs_exist_ok=True)

    shutil.copy2(jar, out / "lib" / "Ghydra.jar")


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra-home", required=True,
                        help="the Ghidra installation the extension is for")
    parser.add_argument("--out", default=str(ROOT / "build" / "extension"),
                        help="where the extension directory is assembled")
    parser.add_argument("--work", default=None,
                        help="where the build happens (a temporary directory "
                             "by default)")
    parser.add_argument("--keep-work", action="store_true",
                        help="leave the build directory behind")
    arguments = parser.parse_args(argv)

    home = Path(arguments.ghidra_home)
    version = ghidra_version(home)
    print(f"Ghidra {version} at {home}")

    work = Path(arguments.work) if arguments.work else Path(
        tempfile.mkdtemp(prefix="ghydra-extension-"))
    work.mkdir(parents=True, exist_ok=True)
    try:
        classes = work / "classes"
        deps = work / "deps"
        deps.mkdir(parents=True, exist_ok=True)

        runtime = [find_jar(relative) for relative in RUNTIME_JARS]
        for jar in runtime:
            shutil.copy2(jar, deps / jar.name)

        ghidra_jars = sorted((ROOT / "lib").glob("*.jar"))
        if not ghidra_jars:
            raise BuildError(f"there are no jars in {ROOT / 'lib'}")
        compile_only = [find_jar(relative) for relative in COMPILE_ONLY_JARS]

        classpath = ghidra_jars + runtime + compile_only
        count = compile_sources(classes, classpath)
        print(f"  compiled {count} source file(s)")

        jar = work / "Ghydra.jar"
        merge_jar(classes, deps, jar)
        print(f"  Ghydra.jar: {jar.stat().st_size} bytes")

        out = Path(arguments.out)
        assemble(out, version, jar)
        print(f"  the extension is in {out}")
        return 0
    except BuildError as error:
        print(f"the build failed: {error}", file=sys.stderr)
        return 1
    finally:
        if arguments.keep_work or arguments.work:
            print(f"  the build directory is in {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
