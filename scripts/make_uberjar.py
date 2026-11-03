"""Merge the compiled classes and the runtime dependencies into one jar.

The Maven build shades Javalin, Jetty, SLF4J and Kotlin into Ghydra.jar. This
script does the same thing without Maven, for the machines that have no Maven
and only a JDK.

    python scripts/make_uberjar.py <classes-dir> <lib-dir> <out.jar>
"""

from __future__ import annotations

import os
import sys
import zipfile

# Signatures are per jar and do not survive the merge.
SKIP_PREFIXES = ("META-INF/",)


def _skip(name: str) -> bool:
    if name in ("META-INF/MANIFEST.MF",):
        return True
    if name.startswith("META-INF/") and name.endswith((".SF", ".RSA", ".DSA", ".EC")):
        return True
    return False


def _merge_services(entries, sources):
    """The service files are lists of provider classes; they are concatenated."""
    merged = {}
    for jar in sources:
        with zipfile.ZipFile(jar) as src:
            for name in src.namelist():
                if not name.startswith("META-INF/services/"):
                    continue
                body = src.read(name).decode("utf-8", "replace")
                merged.setdefault(name, []).append(body)
    for name, bodies in merged.items():
        lines = []
        for body in bodies:
            lines.extend(line.strip() for line in body.splitlines() if line.strip())
        entries[name] = ("\n".join(lines) + "\n").encode("utf-8")


def main(argv):
    if len(argv) != 4:
        print(__doc__)
        return 2
    classes_dir, lib_dir, out_jar = argv[1], argv[2], argv[3]

    jars = []
    if os.path.isdir(lib_dir):
        for name in sorted(os.listdir(lib_dir)):
            if name.endswith(".jar"):
                jars.append(os.path.join(lib_dir, name))

    entries = {}
    with zipfile.ZipFile(out_jar, "w", zipfile.ZIP_DEFLATED) as out:
        # The compiled classes come first: they win over a same-named entry
        # in a dependency.
        for root, _dirs, files in os.walk(classes_dir):
            for name in files:
                path = os.path.join(root, name)
                arc = os.path.relpath(path, classes_dir).replace(os.sep, "/")
                if _skip(arc):
                    continue
                with open(path, "rb") as handle:
                    entries[arc] = handle.read()
        for jar in jars:
            with zipfile.ZipFile(jar) as src:
                for info in src.infolist():
                    if info.is_dir() or _skip(info.filename):
                        continue
                    if info.filename in entries:
                        continue
                    entries[info.filename] = src.read(info.filename)
        _merge_services(entries, jars)
        for name, body in entries.items():
            out.writestr(name, body)

    print(f"{out_jar}: {len(entries)} entries, {len(jars)} dependencies merged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
