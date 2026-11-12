"""Run isolated native connection regressions, including a private fixture Ghidra Server.

Run Maven first. Native fixtures live outside Maven's pure unit-test classpath so
surrogate BSim classes can never shadow the real feature in ordinary unit tests.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra-home", required=True, type=Path)
    parser.add_argument("--java-home", type=Path)
    parser.add_argument("--junit-jar", type=Path)
    parser.add_argument("--hamcrest-jar", type=Path)
    args = parser.parse_args(argv)
    install = args.ghidra_home.resolve()
    if not (install / "Ghidra" / "application.properties").is_file():
        parser.error("--ghidra-home must name an installed Ghidra")
    java = args.java_home / "bin" / "java" if args.java_home else shutil.which("java")
    javac = args.java_home / "bin" / "javac" if args.java_home else shutil.which("javac")
    junit = args.junit_jar or Path.home() / ".m2/repository/junit/junit/4.13.2/junit-4.13.2.jar"
    hamcrest = args.hamcrest_jar or Path.home() / ".m2/repository/org/hamcrest/hamcrest-core/1.3/hamcrest-core-1.3.jar"
    maven = shutil.which("mvn")
    if not java or not javac or not maven or not junit.is_file() or not hamcrest.is_file():
        parser.error("Install Maven and a compatible JDK, then run mvn test or pass explicit JDK/JUnit/Hamcrest paths")
    if not (ROOT / "target/classes").is_dir():
        parser.error("Run mvn test first to compile the plugin")
    jars = sorted((install / "Ghidra").glob("**/lib/*.jar"))
    sources = sorted((ROOT / "src/test/native/java").rglob("*.java"))
    with tempfile.TemporaryDirectory(prefix="ghydra-native-connections-") as temporary:
        home = Path(temporary)
        classes = home / "classes"
        classes.mkdir()
        dependency_file = home / "dependencies.txt"
        subprocess.run([maven, "-q", "dependency:build-classpath",
                        f"-Dmdep.outputFile={dependency_file}"],
                       cwd=ROOT, check=True, timeout=120)
        dependencies = [Path(item) for item in dependency_file.read_text(encoding="utf-8").strip().split(os.pathsep)
                        if item and not Path(item).is_relative_to(ROOT / "lib")]
        classpath = os.pathsep.join(map(str, [ROOT / "target/classes", *dependencies, *jars, junit, hamcrest]))
        # Never load operator credentials/settings or unrelated agent secrets in tests.
        environment = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL", "TMPDIR") if key in os.environ}
        environment["HOME"] = str(home)
        environment["GHYDRA_STATE_DIR"] = str(home / "state")
        subprocess.run([str(javac), "-encoding", "UTF-8", "-cp", classpath,
                        "-d", str(classes), *map(str, sources)],
                       check=True, cwd=ROOT, env=environment, timeout=120)
        result = subprocess.run([str(java), "-Djava.awt.headless=true", f"-Duser.home={home}",
                                 "-cp", str(classes) + os.pathsep + classpath,
                                 "eu.starsong.ghidra.NativeConnectionTests", str(install)],
                                cwd=ROOT, env=environment, timeout=300)
        return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
