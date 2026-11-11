"""Markdown rendering shared by analysis reports and evidence bundles."""

from typing import Any, List


def markdown_table(headers: List[str], rows: List[List[Any]]) -> str:
    """Render an aligned table, or the empty-result marker."""
    if not rows:
        return "_nothing_\n"
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(str(cell)))
    out = ["| " + " | ".join(str(h).ljust(widths[i]) for i, h in enumerate(headers)) + " |"]
    out.append("|" + "|".join("-" * (widths[i] + 2) for i in range(len(headers))) + "|")
    for row in rows:
        out.append("| " + " | ".join(str(c).ljust(widths[i]) for i, c in enumerate(row)) + " |")
    return "\n".join(out) + "\n"
