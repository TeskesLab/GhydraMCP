"""Generate `GHYDRA_ERRORS.md`: every error code, where it is raised, what it says.

An error code is a contract — a client branches on it, a test asserts it, and the
troubleshooting guide explains it. A hand-written list of a hundred of them is
wrong within a release, so this one is **generated**:

    python scripts/gen_errors_doc.py            # write the document
    python scripts/gen_errors_doc.py --check    # fail when it is stale

Two sources, because the two sides carry codes differently:

* **Java** answers with `Response.error(ctx, port, "CODE", "message")` — a literal
  code (a guard enforces that) and usually a literal message, which is the human
  explanation;
* **Python** raises with a code and defines it as a constant or passes it inline;
  both are found, and the document says where.

A code that appears in neither is not listed: this document describes what the
code says, not what somebody once wrote in a ticket.
"""

from __future__ import annotations

import argparse
import glob
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = os.path.join(ROOT, "docs")
DOCUMENT = os.path.join(DOCS, "GHYDRA_ERRORS.md")

JAVA_PATTERN = re.compile(
    r'Response\.error\([^,]+,[^,]+,\s*"([A-Z0-9_]+)",\s*(?:"([^"]{0,120})"|([A-Za-z_][\w.]*))')
JAVA_STATUS = re.compile(r'ctx\.status\((\d{3})\)')
JAVA_EXCEPTION_PATTERN = re.compile(
    r'new (?:ConnectionException|RepositoryException)\(\s*"([A-Z0-9_]+)",\s*(\d{3}),\s*"([^"]{0,240})"')
PYTHON_PATTERNS = (
    re.compile(r'"code":\s*"([A-Z][A-Z0-9_]+)"'),
    re.compile(r'code="([A-Z][A-Z0-9_]+)"'),
    re.compile(r'ERROR_[A-Z0-9_]*\s*=\s*"([A-Z][A-Z0-9_]+)"'),
    re.compile(r'"code"\s*:\s*"([A-Z][A-Z0-9_]+)"'),
    re.compile(r'(?:_fail|ConnectionError)\(\s*"([A-Z][A-Z0-9_]+)"'),
)

#: Strings that look like codes and are not (values, header names, versions).
NOT_CODES = {
    "API_VERSION", "REQUIRED_API_VERSION", "PLUGIN_VERSION", "BRIDGE_VERSION",
    "DEFAULT_PORT", "ACCEPT", "CONTENT_TYPE", "APPLICATION_JSON", "UTF_8",
    "GHYDRA_JSON", "GHYDRA_MCP_OUTPUT", "API_JSON", "TEXT_PLAIN",
}


#: Prefixes that name a subsystem. A prefix with two or more codes is one of
#: these by evidence; a prefix with a single code is a word (`BAD`, `NO`, `READ`)
#: and belongs with the generic codes.
DOMAIN_PREFIXES = {
    "ANALYSIS", "ASSERTION", "BSIM", "CACHE", "DIFF", "DOCTOR", "EVIDENCE",
    "FLEET", "FUNCTION", "HEADLESS", "KUNA", "MISSION", "REPORT", "RUNBOOK",
    "SCRIPTS", "SESSION", "SNAPSHOT", "TASK", "TELEMETRY", "TOOL", "X64DBG",
    "CONNECTION", "REPOSITORY",
}

#: Where the generic codes are shown, and what the section says.
GENERIC_TITLE = "Generic — the shape every client branches on"


def _families(codes: dict) -> dict:
    """Group the codes by subsystem; everything else goes to `generic`."""
    families: dict = {}
    for code, entry in codes.items():
        prefix = code.split("_")[0]
        key = prefix if prefix in DOMAIN_PREFIXES else "generic"
        families.setdefault(key, {})[code] = entry
    return families


def collect_java() -> dict:
    """{code: {where, message, status}} from the Java resources and middleware."""
    codes: dict = {}
    for path in sorted(glob.glob(os.path.join(ROOT, "src/main/java/**/*.java"),
                                 recursive=True)):
        relative = os.path.relpath(path, ROOT).replace(os.sep, "/")
        with io.open(path, encoding="utf-8") as handle:
            text = handle.read()
        for match in JAVA_PATTERN.finditer(text):
            code = match.group(1)
            if code in NOT_CODES:
                continue
            line = text.count("\n", 0, match.start()) + 1
            message = match.group(2) or ""
            # The status is set on the line just above the response, when it is
            # set at all.
            window = text[max(0, match.start() - 400):match.start()]
            statuses = JAVA_STATUS.findall(window)
            codes.setdefault(code, {
                "where": f"`{relative}:{line}`",
                "message": message.strip() or ("(computed)" if match.group(3) else ""),
                "status": statuses[-1] if statuses else "",
                "side": "Java",
            })
        for match in JAVA_EXCEPTION_PATTERN.finditer(text):
            code, status, message = match.groups()
            line = text.count("\n", 0, match.start()) + 1
            codes.setdefault(code, {
                "where": f"`{relative}:{line}`", "message": message.strip(),
                "status": status, "side": "Java",
            })
    return codes


def collect_python() -> dict:
    """{code: {where}} from the bridge and the CLI package."""
    codes: dict = {}
    candidates = []
    candidates.append(os.path.join(ROOT, "bridge_mcp_hydra.py"))
    for pattern in ("ghydra/*.py", "ghydra/cli/*.py", "ghydra/client/*.py"):
        candidates.extend(sorted(glob.glob(os.path.join(ROOT, pattern))))
    for path in candidates:
        relative = os.path.relpath(path, ROOT).replace(os.sep, "/")
        with io.open(path, encoding="utf-8") as handle:
            text = handle.read()
        for pattern in PYTHON_PATTERNS:
            for match in pattern.finditer(text):
                code = match.group(1)
                if code in NOT_CODES:
                    continue
                line = text.count("\n", 0, match.start()) + 1
                codes.setdefault(code, {
                    "where": f"`{relative}:{line}`",
                    "message": "",
                    "status": "",
                    "side": "Python",
                })
    return codes


def render() -> str:
    java = collect_java()
    python = collect_python()
    both = dict(java)
    for code, entry in python.items():
        both.setdefault(code, entry)
    families = _families(both)

    lines = [
        "# Error codes",
        "",
        "Every error code the plugin and the clients answer with, where it is raised",
        "and what it means. **Generated** from the source by",
        "`scripts/gen_errors_doc.py`; a test fails when it drifts.",
        "",
        f"**{len(both)} codes** in {len(families)} families. A code is a contract: a",
        "client branches on it, a test asserts it, and",
        "[GHYDRA_TROUBLESHOOTING.md](GHYDRA_TROUBLESHOOTING.md) explains the ones a",
        "user meets.",
        "",
        "| Column | Meaning |",
        "| --- | --- |",
        "| Code | the machine-readable value |",
        "| Side | where it is produced (`Java` = the server, `Python` = CLI/bridge) |",
        "| Status | the HTTP status the server answers with, when it sets one |",
        "| Says | the message the server sends with it, when it is a literal |",
        "| Raised at | the file and line that produces it |",
        "",
    ]
    order = sorted(family for family in families if family != "generic")
    if "generic" in families:
        order.append("generic")
    for family in order:
        codes = families[family]
        if family == "generic":
            lines.append(f"## {GENERIC_TITLE}")
        else:
            lines.append(f"## {family}")
        lines.append("")
        lines.append(f"`{len(codes)}` code(s): "
                     + ", ".join(f"`{name}`" for name in sorted(codes)))
        lines.append("")
        lines.append("| Code | Side | Status | Says | Raised at |")
        lines.append("| --- | --- | --- | --- | --- |")
        for code in sorted(codes):
            entry = codes[code]
            message = entry["message"].replace("|", "\\|") or "—"
            lines.append(f"| `{code}` | {entry['side']} | {entry['status'] or '—'} | "
                         f"{message} | {entry['where']} |")
        lines.append("")
    lines.append("## Regenerating")
    lines.append("")
    lines.append("```bash")
    lines.append("python scripts/gen_errors_doc.py           # rewrite this document")
    lines.append("python scripts/gen_errors_doc.py --check   # fail when it is stale")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="fail when the document is stale")
    arguments = parser.parse_args(argv)
    rendered = render()
    current = ""
    if os.path.exists(DOCUMENT):
        with io.open(DOCUMENT, encoding="utf-8") as handle:
            current = handle.read()
    if arguments.check:
        if rendered != current:
            print("stale: GHYDRA_ERRORS.md does not match the source. "
                  "Run: python scripts/gen_errors_doc.py", file=sys.stderr)
            return 1
        print("ok: the error reference is current")
        return 0
    if rendered == current:
        print("ok: nothing to update")
        return 0
    with io.open(DOCUMENT, "w", encoding="utf-8", newline="") as handle:
        handle.write(rendered)
    print(f"wrote {DOCUMENT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())