"""Table-based output formatter using rich library."""

import io
import os
import sys
from typing import Any, Dict

from rich import box
from rich.console import Console, Group
from rich.markup import escape
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.tree import Tree

from .base import BaseFormatter


def _page_total(data: Dict[str, Any]) -> int | None:
    """How many items there are, when the answer is one page of more.

    A page that is not the whole list has to say so: "Callers (100)" reads
    as "there are 100" when there are two hundred and fifty.
    """
    meta = data.get("meta")
    if not isinstance(meta, dict):
        return None
    total = meta.get("total")
    if not isinstance(total, int) or total < 0:
        return None
    return total


def _page_note(data: Dict[str, Any], items: list) -> str:
    """The note that says the list is one page of a longer one."""
    total = _page_total(data)
    if total is None or total <= len(items):
        return ""
    return (f"There are {total} in total - this page holds {len(items)}. "
            f"Ask for the rest with --offset and --limit.")


class TableFormatter(BaseFormatter):
    """Formatter that outputs rich terminal tables and formatted text.

    Uses the rich library to create attractive terminal output with
    tables, syntax highlighting, and colors.
    """

    def __init__(self, use_colors: bool = True):
        """Initialize table formatter.

        Args:
            use_colors: Enable colored output
        """
        # Only colorize when stdout is a real terminal. The old force_terminal=use_colors
        # leaked ANSI codes into piped output, corrupting programmatic/agent parsing of hex
        # addresses. Auto-detect the TTY so default output is agent-clean without --no-color,
        # and honor the NO_COLOR convention (https://no-color.org).
        self._use_colors = use_colors and not os.environ.get("NO_COLOR") and sys.stdout.isatty()
        self.console = Console(
            color_system="auto" if self._use_colors else None,
            force_terminal=self._use_colors or None,
        )

    def _capture(self, renderable) -> str:
        """Capture rich renderable output to string.

        Args:
            renderable: Rich renderable object

        Returns:
            Captured string output
        """
        buffer = io.StringIO()
        # Mirror the main console's color decision (TTY-aware) so captured output is
        # plain when stdout is piped.
        temp_console = Console(
            file=buffer,
            color_system="auto" if self._use_colors else None,
            force_terminal=self._use_colors or None,
        )
        temp_console.print(renderable, soft_wrap=True)
        return buffer.getvalue().rstrip()

    def format_functions_list(self, data: Dict[str, Any]) -> str:
        """Format function list as table."""
        result = data.get("result", [])

        # Get total count from metadata
        metadata = data.get("metadata", {})
        total = metadata.get("size", len(result))
        offset = metadata.get("offset", 0)
        limit = metadata.get("limit", len(result))

        if not result:
            return self._capture("[yellow]No functions found[/yellow] (0 total)")

        table = Table(title=f"Functions ({total} total)", show_lines=False)
        table.add_column("Address", style="cyan", no_wrap=True)
        table.add_column("Name", style="green")
        table.add_column("Signature", style="yellow", overflow="fold")

        for fn in result:
            table.add_row(
                fn.get("address", "?"),
                fn.get("name", "?"),
                fn.get("signature", "")[:100]
            )

        # Add pagination info if showing subset
        if total > len(result):
            table.caption = f"Showing {offset + 1}-{offset + len(result)} of {total}"

        return self._capture(table)

    def format_function_info(self, data: Dict[str, Any]) -> str:
        """Format single function info."""
        result = data.get("result", {})

        if not result:
            return self._capture("[yellow]No function info available[/yellow]")

        lines = [
            f"[cyan]Address:[/cyan] {result.get('address', '?')}",
            f"[cyan]Name:[/cyan] {result.get('name', '?')}",
            f"[cyan]Signature:[/cyan] {result.get('signature', '?')}",
        ]

        if result.get("entryPoint"):
            lines.append(f"[cyan]Entry Point:[/cyan] {result['entryPoint']}")

        if result.get("thunk"):
            lines.append(f"[cyan]Thunk:[/cyan] {result['thunk']}")

        panel = Panel("\n".join(lines), title="Function Info", border_style="blue")
        return self._capture(panel)

    def format_decompiled_code(self, data: Dict[str, Any]) -> str:
        """Format decompiled code with syntax highlighting."""
        result = data.get("result", {})
        code = (result.get("decompiled") or result.get("decompilation")
                or result.get("ccode") or result.get("decompiled_text", ""))
        retry_recommended = bool(result.get("retry_recommended"))
        suggested_timeout = result.get("suggested_timeout_seconds")
        message = result.get("message")
        decompile_error = result.get("decompile_error")

        advisory_lines = []
        if retry_recommended:
            if message:
                advisory_lines.append(f"// {message}")
            if suggested_timeout:
                advisory_lines.append(f"// Suggested timeout: {suggested_timeout}s")
            if decompile_error:
                advisory_lines.append(f"// Decompiler error: {decompile_error}")

        if advisory_lines:
            advisory_text = "\n".join(advisory_lines)
            if code:
                if advisory_text.lower() not in code.lower():
                    code = f"{code.rstrip()}\n\n{advisory_text}"
            else:
                code = advisory_text

        if not code:
            return self._capture("[red]No decompiled code available[/red]")

        code = code.strip()

        syntax = Syntax(
            code,
            "c",
            theme="monokai",
            line_numbers=True,
            word_wrap=False
        )

        return self._capture(syntax)

    def format_disassembly(self, data: Dict[str, Any]) -> str:
        """Format disassembly listing."""
        result = data.get("result", {})
        instructions = result.get("instructions", [])

        if not instructions:
            return self._capture("[red]No disassembly available[/red]")

        func_info = result.get("function", {})
        title = func_info.get("name", "Disassembly")
        total = result.get("totalInstructions", len(instructions))

        lines = []
        for instr in instructions:
            addr = instr.get("address", "?")
            bytez = instr.get("bytes", "")
            mnemonic = instr.get("mnemonic", "?")
            operands = instr.get("operands", "")
            lines.append(f"{addr}  {bytez:<20s} {mnemonic:<8s} {operands}")

        disasm_text = "\n".join(lines)

        header = f"[cyan]{title}[/cyan] ({total} instructions)\n"
        return self._capture(header) + "\n" + disasm_text

    def format_memory(self, data: Dict[str, Any]) -> str:
        """Format memory as hex dump."""
        result = data.get("result", {})
        addr = result.get("address", "???")
        # Javalin server sends "hex" (continuous string); older builds sent
        # "hexBytes" (space-separated pairs).
        hex_bytes = result.get("hex") or result.get("hexBytes") or ""

        if not hex_bytes:
            return self._capture("[red]No memory data available[/red]")

        lines = [f"[cyan]Memory at 0x{addr}:[/cyan]\n"]

        if " " in hex_bytes.strip():
            byte_pairs = hex_bytes.split()
        else:
            cleaned = hex_bytes.strip()
            byte_pairs = [cleaned[i:i+2] for i in range(0, len(cleaned), 2)]

        for i in range(0, len(byte_pairs), 16):
            chunk = byte_pairs[i:i+16]

            # Address offset
            offset = f"{i:08x}"

            # Hex part - format each byte with fixed width
            hex_part = " ".join(f"{bp:>2}" for bp in chunk)

            # ASCII part
            ascii_part = ""
            for bp in chunk:
                try:
                    b = int(bp, 16)
                    ascii_part += chr(b) if 32 <= b < 127 else "."
                except:
                    ascii_part += "?"

            lines.append(f"[dim]{offset}[/dim]  {hex_part:<48}  [dim]{ascii_part}[/dim]")

        return self._capture("\n".join(lines))

    def format_xrefs(self, data: Dict[str, Any]) -> str:
        """Format cross-references as table."""
        result = data.get("result", {})
        references = result.get("references", []) if isinstance(result, dict) else result

        if not references:
            return self._capture("[yellow]No cross-references found[/yellow]")

        table = Table(title="Cross-References", show_lines=False)
        table.add_column("From", style="cyan", no_wrap=True)
        table.add_column("To", style="green", no_wrap=True)
        table.add_column("Type", style="yellow")
        table.add_column("From Function", style="dim")

        for xref in references:
            # XrefDto uses fromAddress/toAddress/fromFunction; accept legacy names.
            from_func = xref.get("fromFunction") or ""
            if not from_func and isinstance(xref.get("from_function"), dict):
                from_func = xref["from_function"].get("name", "")
            table.add_row(
                xref.get("fromAddress") or xref.get("from_addr", "?"),
                xref.get("toAddress") or xref.get("to_addr", "?"),
                xref.get("refType", "?"),
                from_func
            )

        return self._capture(table)

    def format_xrefs_by_name(self, data: Dict[str, Any]) -> str:
        """Format the references to a symbol name."""
        result = data.get("result", {})
        if not isinstance(result, dict):
            return self._capture("[yellow]No references found[/yellow]")

        symbols = result.get("symbols") or []
        references = result.get("references") or []
        total = result.get("total", len(references))
        label = escape(str(result.get("name") or "?"))

        lines = [f"[cyan]References to '{label}'[/cyan] [dim]({len(references)} of {total})[/dim]"]

        for symbol in symbols:
            if not isinstance(symbol, dict):
                continue
            lines.append(f"  [green]{escape(str(symbol.get('name', '?')))}[/green]  "
                         f"{escape(str(symbol.get('address', '')))}  "
                         f"[dim]{escape(str(symbol.get('type', '')))}[/dim]")

        if references:
            table = Table(show_lines=False)
            table.add_column("From", style="cyan", no_wrap=True)
            table.add_column("To", style="green", no_wrap=True)
            table.add_column("Type", style="yellow")
            table.add_column("From Function", style="dim")

            for xref in references:
                if not isinstance(xref, dict):
                    continue
                from_func = xref.get("fromFunction") or ""
                if not from_func and isinstance(xref.get("from_function"), dict):
                    from_func = xref["from_function"].get("name", "")
                table.add_row(
                    escape(str(xref.get("fromAddress") or xref.get("from_addr", "?"))),
                    escape(str(xref.get("toAddress") or xref.get("to_addr", "?"))),
                    escape(str(xref.get("refType", "?"))),
                    escape(str(from_func)),
                )

            lines.append(self._capture(table))
        else:
            lines.append("  [dim](no references)[/dim]")

        return self._capture("\n".join(lines))

    def format_batch_decompile(self, data: Dict[str, Any]) -> str:
        """Format a batch decompilation."""
        items = data.get("result", [])
        if not isinstance(items, list) or not items:
            return self._capture("[yellow]No decompilation results returned[/yellow]")

        done = [i for i in items if isinstance(i, dict) and i.get("success")]
        failed = [i for i in items if isinstance(i, dict) and not i.get("success")]

        blocks = []
        for item in done:
            name = escape(str(item.get("functionName") or item.get("function_name") or "?"))
            address = escape(str(item.get("functionAddress") or item.get("function_address") or ""))
            code = (item.get("decompilation") or "").strip()
            header = f"[cyan]{name}[/cyan]  [dim]{address}[/dim]"
            if not code:
                blocks.append(header + "\n[yellow](no code)[/yellow]")
                continue
            syntax = Syntax(code, "c", theme="monokai", line_numbers=True, word_wrap=False)
            blocks.append(Group(header, syntax))

        summary = f"[cyan]Batch decompile[/cyan] [dim]({len(done)} of {len(items)} succeeded)[/dim]"
        output = self._capture(summary)
        if blocks:
            output += "\n" + self._capture(Group(*blocks))

        if failed:
            rows = []
            for item in failed:
                name = escape(str(item.get("functionName") or item.get("function_name") or "?"))
                reason = escape(str(item.get("errorMessage") or item.get("error_message") or "unknown error"))
                rows.append(f"  {name}: {reason}")
            output += "\n" + self._capture("[red]Failed:[/red]\n" + "\n".join(rows))

        return output

    def format_address_context(self, data: Dict[str, Any]) -> str:
        """Format what an address holds."""
        result = data.get("result", {})
        if not isinstance(result, dict):
            return self._capture("[yellow]No address context returned[/yellow]")

        address = escape(str(result.get("address", "?")))
        space = escape(str(result.get("addressSpace", "?")))
        lines = [f"[cyan]Address {address}[/cyan] [dim]({space})[/dim]"]

        symbol = result.get("symbol") or {}
        if symbol:
            lines.append(f"  [green]symbol:[/green]   {escape(str(symbol.get('name', '?')))}"
                         f" [dim]({escape(str(symbol.get('type', '')))})[/dim]")

        function = result.get("function") or {}
        if function:
            lines.append(f"  [green]function:[/green] {escape(str(function.get('name', '?')))}"
                         f"  {escape(str(function.get('address', '')))}")
            signature = function.get("signature")
            if signature:
                lines.append(f"               [dim]{escape(str(signature))}[/dim]")

        instruction = result.get("instruction") or {}
        if instruction:
            lines.append(f"  [green]code:[/green]     {escape(str(instruction.get('address', '')))}"
                         f"  {escape(str(instruction.get('bytes', '')))}"
                         f"  {escape(str(instruction.get('mnemonic', '')))}"
                         f"  {escape(str(instruction.get('operands', '')))}")

        data_item = result.get("data") or {}
        if data_item:
            label = escape(str(data_item.get("label") or ""))
            lines.append(f"  [green]data:[/green]     {escape(str(data_item.get('dataType', '?')))}"
                         f"  [dim]len={escape(str(data_item.get('length', '?')))}[/dim]  {label}")

        comment = result.get("comment")
        if comment:
            lines.append(f"  [green]comment:[/green]  {escape(str(comment))}")

        eol_comment = result.get("eolComment")
        if eol_comment:
            lines.append(f"  [green]eol:[/green]      {escape(str(eol_comment))}")

        xrefs_to = result.get("xrefsTo") or []
        xrefs_from = result.get("xrefsFrom") or []

        lines.append(f"  [green]referenced by[/green] [dim]({len(xrefs_to)})[/dim]")
        for xref in xrefs_to:
            if isinstance(xref, dict):
                lines.append("    " + self._xref_line(xref))

        lines.append(f"  [green]references[/green]     [dim]({len(xrefs_from)})[/dim]")
        for xref in xrefs_from:
            if isinstance(xref, dict):
                lines.append("    " + self._xref_line(xref))

        return self._capture("\n".join(lines))

    def _xref_line(self, xref: Dict[str, Any]) -> str:
        """One cross-reference, as a line of text."""
        from_addr = escape(str(xref.get("fromAddress") or xref.get("from_addr", "?")))
        to_addr = escape(str(xref.get("toAddress") or xref.get("to_addr", "")))
        ref_type = escape(str(xref.get("refType", "?")))
        from_func = xref.get("fromFunction") or ""
        if isinstance(from_func, dict):
            from_func = from_func.get("name", "")

        line = f"{from_addr}"
        if to_addr:
            line += f" -> {to_addr}"
        line += f"  {ref_type}"
        if from_func:
            line += f"  [dim]from {escape(str(from_func))}[/dim]"
        return line

    def format_call_path(self, data: Dict[str, Any]) -> str:
        """Format a call path."""
        result = data.get("result", {})
        if not isinstance(result, dict):
            return self._capture("[yellow]No call path returned[/yellow]")

        source = result.get("from") or {}
        target = result.get("to") or {}
        source_name = escape(str(source.get("name", "?")))
        target_name = escape(str(target.get("name", "?")))

        if not result.get("found"):
            reason = escape(str(result.get("reason") or "no path found"))
            return self._capture(f"[yellow]No call path from {source_name} to {target_name}:[/yellow] {reason}")

        path = result.get("path") or []
        lines = [f"[cyan]Call path from {source_name} to {target_name}[/cyan] "
                 f"[dim]({result.get('depth', '?')} hop(s), "
                 f"{result.get('visited', '?')} function(s) explored)[/dim]"]

        for index, fn in enumerate(path):
            if not isinstance(fn, dict):
                continue
            name = escape(str(fn.get("name", "?")))
            address = escape(str(fn.get("address", "")))
            prefix = "  " if index == 0 else "[green]->[/green] "
            lines.append(f"  {prefix}{name}  [dim]{address}[/dim]")

        return self._capture("\n".join(lines))

    def format_callers(self, data: Dict[str, Any]) -> str:
        """Format the callers of a function as a table."""
        items = data.get("result", [])
        if not isinstance(items, list) or not items:
            return self._capture("[yellow]Nobody calls it[/yellow]")

        title = f"Callers ({len(items)})"
        total = _page_total(data)
        if total is not None and total > len(items):
            title += f" of {total}"

        table = Table(title=title, show_lines=False)
        table.add_column("Name", style="green")
        table.add_column("Address", style="cyan", no_wrap=True)
        table.add_column("Signature", style="yellow", overflow="fold")

        for item in items:
            if not isinstance(item, dict):
                continue
            table.add_row(
                escape(str(item.get("name", "?"))),
                escape(str(item.get("address", "?"))),
                escape(str(item.get("signature", ""))),
            )

        note = _page_note(data, items)
        if note:
            return self._capture(Group(table, note))

        return self._capture(table)

    def format_callees(self, data: Dict[str, Any]) -> str:
        """Format the callees of a function as a table."""
        items = data.get("result", [])
        if not isinstance(items, list) or not items:
            return self._capture("[yellow]It calls nothing[/yellow]")

        title = f"Callees ({len(items)})"
        total = _page_total(data)
        if total is not None and total > len(items):
            title += f" of {total}"

        table = Table(title=title, show_lines=False)
        table.add_column("Name", style="green")
        table.add_column("Address", style="cyan", no_wrap=True)
        table.add_column("Signature", style="yellow", overflow="fold")

        for item in items:
            if not isinstance(item, dict):
                continue
            table.add_row(
                escape(str(item.get("name", "?"))),
                escape(str(item.get("address", "?"))),
                escape(str(item.get("signature", ""))),
            )

        note = _page_note(data, items)
        if note:
            return self._capture(Group(table, note))

        return self._capture(table)

    def format_function_analysis(self, data: Dict[str, Any]) -> str:
        """Format everything known about one function."""
        result = data.get("result", {})
        if not isinstance(result, dict):
            return self._capture("[yellow]Nothing to analyse[/yellow]")

        function = result.get("function") or {}
        lines = [f"[cyan]{escape(str(function.get('name', '?')))}[/cyan]  "
                 f"[dim]{escape(str(function.get('address', '')))}[/dim]"]

        signature = function.get("signature")
        if signature:
            lines.append(f"  [dim]{escape(str(signature))}[/dim]")

        code = result.get("decompilation")
        syntax = None
        if code:
            syntax = Syntax(str(code).strip(), "c", theme="monokai",
                            line_numbers=True, word_wrap=False)
        else:
            reason = result.get("decompileError")
            lines.append("")
            lines.append(f"[yellow](no decompilation{f': {escape(str(reason))}' if reason else ''})[/yellow]")

        for label, key in (("Callers", "callers"), ("Callees", "callees"), ("References", "xrefs")):
            items = result.get(key) or []
            lines.append("")
            lines.append(f"[green]{label}[/green] [dim]({len(items)})[/dim]")
            for item in items:
                if not isinstance(item, dict):
                    continue
                if key == "xrefs":
                    lines.append("    " + self._xref_line(item))
                else:
                    lines.append(f"    {escape(str(item.get('name', '?')))}"
                                 f"  [dim]{escape(str(item.get('address', '')))}[/dim]")

        # The relations are part of the answer even when the decompilation
        # worked, so the code is rendered after them and not instead of them.
        if syntax is not None:
            return self._capture(Group("\n".join(lines), syntax))

        return self._capture("\n".join(lines))

    def format_overview(self, data: Dict[str, Any]) -> str:
        """Format the overview of the loaded binary."""
        result = data.get("result", {})
        if not isinstance(result, dict):
            return self._capture("[yellow]No overview available[/yellow]")

        program = result.get("program") or {}
        statistics = result.get("statistics") or {}

        lines = [f"[cyan]{escape(str(program.get('name', '?')))}[/cyan]"]
        if program.get("path"):
            lines.append(f"  path:     {escape(str(program['path']))}")
        lines.append(f"  language: {escape(str(program.get('language', '?')))}")
        lines.append(f"  base:     {escape(str(program.get('imageBase', '?')))}")

        counts = []
        for label, key in (("functions", "functions"), ("symbols", "symbols"),
                           ("imports", "imports"), ("blocks", "memoryBlocks")):
            value = statistics.get(key)
            if value is not None:
                counts.append(f"{value} {label}")
        if counts:
            lines.append(f"  holds:    {escape(', '.join(counts))}")

        segments = result.get("segments") or []
        if segments:
            table = Table(title=f"Segments ({len(segments)})", show_lines=False)
            table.add_column("Name", style="green", no_wrap=True)
            table.add_column("Start", style="cyan", no_wrap=True)
            table.add_column("End", style="cyan", no_wrap=True)
            table.add_column("Size", style="yellow", justify="right")

            for segment in segments:
                if not isinstance(segment, dict):
                    continue
                table.add_row(
                    escape(str(segment.get("name", "?"))),
                    escape(str(segment.get("start", "?"))),
                    escape(str(segment.get("end", "?"))),
                    escape(str(segment.get("size", "?"))),
                )
            lines.append("")
            lines.append(self._capture(table))

        imports = result.get("imports") or []
        if imports:
            lines.append("")
            lines.append(f"[green]Imports[/green] [dim]({len(imports)})[/dim]")
            for item in imports:
                if isinstance(item, dict):
                    lines.append(f"  {escape(str(item.get('name', '?')))}")

        return self._capture("\n".join(lines))

    def format_scalars(self, data: Dict[str, Any]) -> str:
        """Format scalar search results as table."""
        results = data.get("result", [])
        meta = data.get("meta", {}) or {}

        if not results:
            if meta.get("scanTruncated"):
                return self._capture("[yellow]No scalars found[/yellow] (scan truncated; "
                                     "narrow with --in-function or a more specific value)")
            return self._capture("[yellow]No scalars found[/yellow]")

        offset = meta.get("offset", 0)
        table = Table(title=f"Scalars ({offset + 1}-{offset + len(results)})", show_lines=False)
        table.add_column("Address", style="cyan", no_wrap=True)
        table.add_column("Value", style="green", no_wrap=True)
        table.add_column("Op", style="dim", no_wrap=True)
        table.add_column("Instruction", style="yellow", overflow="fold")
        table.add_column("In Function", style="white")
        table.add_column("Calls", style="magenta")

        for s in results:
            table.add_row(
                s.get("address", "?"),
                s.get("hexValue", str(s.get("value", "?"))),
                str(s.get("operandIndex", "")),
                s.get("instruction", ""),
                s.get("inFunction") or "-",
                s.get("toFunction") or "",
            )

        output = self._capture(table)
        if meta.get("scanTruncated"):
            output += "\n" + self._capture("[yellow]Scan truncated to keep the UI responsive; "
                                           "results may be incomplete - narrow with --in-function "
                                           "or a more specific value.[/yellow]")
        return output

    def format_data_list(self, data: Dict[str, Any]) -> str:
        """Format data items list as table."""
        result = data.get("result", [])

        if not result:
            return self._capture("[yellow]No data items found[/yellow]")

        table = Table(title=f"Data Items ({len(result)} items)", show_lines=False)
        table.add_column("Address", style="cyan", no_wrap=True)
        table.add_column("Name", style="green")
        table.add_column("Type", style="yellow")
        table.add_column("Value", style="white", overflow="fold")

        for item in result:
            value = item.get("value", "")
            if isinstance(value, str) and len(value) > 50:
                value = value[:47] + "..."

            table.add_row(
                item.get("address", "?"),
                item.get("label") or item.get("name", ""),  # DataDto field is 'label'
                item.get("dataType", "?"),
                str(value)
            )

        return self._capture(table)

    def format_strings_list(self, data: Dict[str, Any]) -> str:
        """Format strings list as table."""
        result = data.get("result", [])

        if not result:
            return self._capture("[yellow]No strings found[/yellow]")

        table = Table(title=f"Strings ({len(result)} items)", show_lines=False)
        table.add_column("Address", style="cyan", no_wrap=True)
        table.add_column("Value", style="green", overflow="fold")

        for string in result:
            value = string.get("value", "")
            if len(value) > 80:
                value = value[:77] + "..."

            table.add_row(
                string.get("address", "?"),
                value
            )

        return self._capture(table)

    def format_structs_list(self, data: Dict[str, Any]) -> str:
        """Format structs list as table."""
        result = data.get("result", [])

        if not result:
            return self._capture("[yellow]No structs found[/yellow]")

        table = Table(title=f"Structs ({len(result)} items)", show_lines=False)
        table.add_column("Name", style="cyan")
        table.add_column("Size", style="yellow", justify="right")
        table.add_column("Fields", style="green", justify="right")

        for struct in result:
            table.add_row(
                struct.get("name", "?"),
                str(struct.get("size", 0)),
                str(struct.get("fieldCount", 0))
            )

        return self._capture(table)

    def format_struct_info(self, data: Dict[str, Any]) -> str:
        """Format struct info with fields as tree."""
        result = data.get("result", {})

        if not result:
            return self._capture("[yellow]No struct info available[/yellow]")

        tree = Tree(f"[cyan]{result.get('name', '?')}[/cyan] (size: {result.get('size', 0)})")

        fields = result.get("fields", [])
        for field in fields:
            field_str = (
                f"[green]{field.get('name', '?')}[/green] "
                f"[yellow]{field.get('type', '?')}[/yellow] "
                f"@ offset {field.get('offset', 0)}"
            )
            tree.add(field_str)

        return self._capture(tree)

    def format_project_info(self, data: Dict[str, Any]) -> str:
        """Format project info as panel."""
        result = data.get("result", {})

        if not result:
            return self._capture("[yellow]No project info available[/yellow]")

        lines = [
            f"[cyan]Name:[/cyan] {result.get('name', '?')}",
            f"[cyan]Location:[/cyan] {result.get('location', '?')}",
        ]

        if result.get("fileCount") is not None:
            lines.append(f"[cyan]File Count:[/cyan] {result['fileCount']}")

        panel = Panel("\n".join(lines), title="Project Info", border_style="blue")
        return self._capture(panel)

    def format_instances_list(self, data: Dict[str, Any]) -> str:
        """Format instances list as table."""
        instances = data.get("instances", [])

        if not instances:
            return self._capture("[yellow]No Ghidra instances found[/yellow]")

        table = Table(title=f"Ghidra Instances ({len(instances)} found)", show_lines=False)
        table.add_column("Port", style="cyan", justify="right")
        table.add_column("URL", style="blue")
        table.add_column("Project", style="green")
        table.add_column("File", style="yellow")

        for inst in instances:
            table.add_row(
                str(inst.get("port", "?")),
                inst.get("url", "?"),
                inst.get("project", "-"),
                inst.get("file", "-")
            )

        return self._capture(table)

    def format_capabilities(self, data: Dict[str, Any]) -> str:
        """Format the capability negotiation payload as a panel."""
        result = data.get("result", data)
        if not isinstance(result, dict):
            return self._capture(str(result))

        lines = [
            f"[cyan]Plugin:[/cyan] {result.get('plugin_version', '?')}",
            f"[cyan]API:[/cyan] {result.get('api_version', '?')}",
            f"[cyan]Ghidra:[/cyan] {result.get('ghidra_version', 'unknown')}",
            f"[cyan]Java:[/cyan] {result.get('java_version', 'unknown')}",
            f"[cyan]Headless:[/cyan] {result.get('headless', False)}",
        ]
        features = result.get("features") or {}
        if features:
            on = ", ".join(sorted(k for k, v in features.items() if v)) or "none"
            off = ", ".join(sorted(k for k, v in features.items() if not v)) or "none"
            lines.append(f"[cyan]Features on:[/cyan] {on}")
            lines.append(f"[cyan]Features off:[/cyan] {off}")
        limits = result.get("limits") or {}
        if limits:
            lines.append("[cyan]Limits:[/cyan] " + ", ".join(
                f"{k}={v}" for k, v in sorted(limits.items())))

        return self._capture(Panel("\n".join(lines), title="Capabilities",
                                   border_style="blue"))

    def format_capabilities_summary(self, data: Dict[str, Any]) -> str:
        """Format a ranked capability triage as a table + evidence lines."""
        result = data.get("result", data)
        if not isinstance(result, dict):
            return self._capture(str(result))
        findings = result.get("findings") or []
        summary = result.get("summary") or {}

        table = Table(title="Capability Triage", show_lines=False)
        table.add_column("Confidence", style="yellow", justify="left")
        table.add_column("ID", style="cyan")
        table.add_column("Technique", style="green")
        table.add_column("Score", style="magenta", justify="right")
        table.add_column("Evidence", style="white")

        for finding in findings:
            evidence = ", ".join(
                f"{item.get('kind')}:{item.get('name')}"
                for item in (finding.get("evidence") or [])[:2]) or "-"
            table.add_row(
                str(finding.get("confidence", "?")),
                str(finding.get("id", "?")),
                str(finding.get("name", "?")),
                str(finding.get("score", 0)),
                evidence,
            )

        footer = (
            f"Scanned {summary.get('imports_scanned', 0)} imports / "
            f"{summary.get('strings_scanned', 0)} strings against "
            f"{summary.get('rules', 0)} rules. "
            + str(result.get("method", ""))
        )
        if not findings:
            footer += "  No known technique patterns matched."
        rendered = self._capture(table)
        return rendered + "\n" + footer

    def format_simple_result(self, data: Dict[str, Any]) -> str:
        """Format simple success/info response."""
        result = data.get("result", {})

        if isinstance(result, str):
            return self._capture(f"[green]{result}[/green]")

        if isinstance(result, dict) and "message" in result:
            return self._capture(f"[green]{result['message']}[/green]")

        if isinstance(result, list):
            if not result:
                return self._capture("[green]Success[/green] (no items)")
            rows = []
            for item in result:
                if isinstance(item, dict):
                    rows.append(", ".join(f"{k}: {v}" for k, v in item.items() if k != "_links"))
                else:
                    rows.append(str(item))
            return self._capture("\n".join(rows))

        lines = []
        for key, value in result.items():
            if key not in ("_links",):
                lines.append(f"[cyan]{key}:[/cyan] {value}")

        if lines:
            return self._capture("\n".join(lines))

        return self._capture("[green]Success[/green]")

    def format_classes_list(self, data: Dict[str, Any]) -> str:
        """Format classes list as table."""
        result = data.get("result", [])

        if not result:
            return self._capture("[yellow]No classes found[/yellow]")

        table = Table(title=f"Classes ({len(result)} items)", show_lines=False)
        table.add_column("Name", style="cyan")
        table.add_column("Namespace", style="dim")

        for item in result:
            table.add_row(
                item.get("simpleName", item.get("name", "?")),
                item.get("namespace", "")
            )

        return self._capture(table)

    def format_symbols_list(self, data: Dict[str, Any]) -> str:
        """Format symbols list as table."""
        result = data.get("result", [])

        if not result:
            return self._capture("[yellow]No symbols found[/yellow]")

        table = Table(title=f"Symbols ({len(result)} items)", show_lines=False)
        table.add_column("Address", style="cyan", no_wrap=True)
        table.add_column("Type", style="yellow")
        table.add_column("Name", style="green")

        for item in result:
            primary = " *" if item.get("isPrimary") else ""
            table.add_row(
                item.get("address", "?"),
                item.get("type", "?"),
                item.get("name", "?") + primary
            )

        return self._capture(table)

    def format_segments_list(self, data: Dict[str, Any]) -> str:
        """Format segments list as table."""
        result = data.get("result", [])

        if not result:
            return self._capture("[yellow]No segments found[/yellow]")

        table = Table(title=f"Segments ({len(result)} items)", show_lines=False)
        table.add_column("Name", style="cyan")
        table.add_column("Start", style="green", no_wrap=True)
        table.add_column("End", style="green", no_wrap=True)
        table.add_column("Size", style="yellow", justify="right")
        table.add_column("Perms", style="white")
        table.add_column("Init", style="dim")

        for seg in result:
            # MemoryBlockDto serializes isRead/isWrite/isExecute/isInitialized.
            perms = ""
            perms += "R" if seg.get("isRead", seg.get("readable")) else "-"
            perms += "W" if seg.get("isWrite", seg.get("writable")) else "-"
            perms += "X" if seg.get("isExecute", seg.get("executable")) else "-"
            init = "init" if seg.get("isInitialized", seg.get("initialized")) else "uninit"
            table.add_row(
                seg.get("name", "?"),
                seg.get("start", "?"),
                seg.get("end", "?"),
                str(seg.get("size", 0)),
                perms,
                init
            )

        return self._capture(table)

    def format_namespaces_list(self, data: Dict[str, Any]) -> str:
        """Format namespaces list as table."""
        result = data.get("result", [])

        if not result:
            return self._capture("[yellow]No namespaces found[/yellow]")

        table = Table(title=f"Namespaces ({len(result)} items)", show_lines=False)
        table.add_column("Name", style="cyan")

        for item in result:
            name = item if isinstance(item, str) else item.get("name", "?")
            table.add_row(name)

        return self._capture(table)

    def format_variables_list(self, data: Dict[str, Any]) -> str:
        """Format variables list as table."""
        result = data.get("result", [])

        if not result:
            return self._capture("[yellow]No variables found[/yellow]")

        table = Table(title=f"Variables ({len(result)} items)", show_lines=False)
        table.add_column("Address", style="cyan", no_wrap=True)
        table.add_column("Scope", style="yellow")
        table.add_column("Type", style="green")
        table.add_column("Name", style="white")
        table.add_column("Function", style="dim")

        for v in result:
            table.add_row(
                v.get("address", "?"),
                v.get("type", "?"),
                v.get("dataType", "?"),
                v.get("name", "?"),
                v.get("function", "")
            )

        return self._capture(table)

    def format_datatypes_list(self, data: Dict[str, Any]) -> str:
        """Format datatypes list as table."""
        result = data.get("result", [])

        if not result:
            return self._capture("[yellow]No data types found[/yellow]")

        table = Table(title=f"Data Types ({len(result)} items)", show_lines=False)
        table.add_column("Kind", style="yellow")
        table.add_column("Name", style="cyan")
        table.add_column("Size", style="green", justify="right")
        table.add_column("Category", style="dim")

        for dt in result:
            table.add_row(
                dt.get("kind", "?"),
                dt.get("name", "?"),
                str(dt.get("length", 0)),
                dt.get("category", "/")
            )

        return self._capture(table)

    def format_callgraph(self, data: Dict[str, Any]) -> str:
        """Format analysis callgraph as a readable tree with summary.

        Server shape: {root: {name, address, ...}, depth, direction,
                       callers: [{function: {...}, callers: [...]}],
                       callees: [{function: {...}, callees: [...]}]}
        """
        result = data.get("result", {})
        if not isinstance(result, dict) or not isinstance(result.get("root"), dict):
            return self._capture("[yellow]No call graph data available[/yellow]")

        root = result["root"]
        root_name = root.get("name", "?")
        root_addr = root.get("address", "")
        depth = result.get("depth")

        summary = self._capture(
            f"[cyan]Call Graph[/cyan] for {root_name} ({root_addr})"
            + (f" depth={depth}" if depth is not None else "")
        )

        def build_tree(title: str, nodes, child_key: str) -> str:
            tree = Tree(f"[cyan]{title}[/cyan]")

            def add_nodes(parent, items, level=0, budget=None):
                if budget is None:
                    budget = [200]
                if not isinstance(items, list):
                    return
                for node in items:
                    if budget[0] <= 0:
                        parent.add("[dim]...[/dim]")
                        return
                    if not isinstance(node, dict):
                        continue
                    fn = node.get("function", {})
                    label = f"{fn.get('name', '?')} ({fn.get('address', '?')})"
                    child = parent.add(f"[green]{label}[/green]")
                    budget[0] -= 1
                    add_nodes(child, node.get(child_key), level + 1, budget)

            add_nodes(tree, nodes)
            return self._capture(tree)

        parts = [summary]
        callers = result.get("callers")
        if callers is not None:
            parts.append(build_tree(f"Callers ({len(callers)})", callers, "callers")
                         if callers else self._capture("[yellow]No callers[/yellow]"))
        callees = result.get("callees")
        if callees is not None:
            parts.append(build_tree(f"Callees ({len(callees)})", callees, "callees")
                         if callees else self._capture("[yellow]No callees[/yellow]"))

        return "\n".join(parts)

    def format_dataflow(self, data: Dict[str, Any]) -> str:
        """Format analysis dataflow output."""
        result = data.get("result", {})
        if not isinstance(result, dict):
            return self._capture("[yellow]No data flow data available[/yellow]")

        steps = result.get("steps", [])
        if not isinstance(steps, list):
            steps = []

        table = Table(title="Data Flow", show_lines=False)
        table.add_column("Step", style="cyan", justify="right")
        table.add_column("Address", style="green", no_wrap=True)
        table.add_column("Instruction", style="white", overflow="fold")
        table.add_column("Function", style="dim")
        table.add_column("Refs", style="yellow", justify="right")

        for i, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                continue
            # Server steps carry instruction text + containing function + references.
            table.add_row(
                str(i),
                str(step.get("address", step.get("to", step.get("from", "?")))),
                str(step.get("instruction", step.get("description", step.get("label", "")))),
                str(step.get("function", "")),
                str(step.get("reference_count", len(step.get("references", []))))
            )

        header = []
        for key in ("start_address", "address", "direction", "max_steps", "truncated"):
            if key in result:
                header.append(f"[cyan]{key}:[/cyan] {result.get(key)}")

        if not table.rows:
            return self._capture("\n".join(header) if header else "[yellow]No data flow steps found[/yellow]")

        header_text = self._capture("\n".join(header)) if header else ""
        body = self._capture(table)
        return f"{header_text}\n{body}".strip()

    def format_x64dbg(self, data: Dict[str, Any]) -> str:
        """Format an x64dbg MCP server result.

        Args:
            data: Result with 'kind' (what was requested) and 'data' (the
                  payload returned by the x64dbg plugin)

        Returns:
            Formatted string output
        """
        kind = data.get("kind", "")
        payload = data.get("data", {})
        if not isinstance(payload, dict):
            payload = {}

        if kind == "status":
            lines = [
                f"[cyan]x64dbg MCP server:[/cyan] reachable at "
                f"{escape(str(payload.get('host')))}:{payload.get('port')}",
                f"[cyan]Tools:[/cyan] {payload.get('tools', 0)}",
            ]
            modules = payload.get("modules") or []
            if modules:
                lines.append(f"[cyan]Modules ({len(modules)}):[/cyan]")
                for module in modules:
                    lines.append(
                        f"  {hex(module.get('base', 0))}  {hex(module.get('size', 0))}  "
                        f"{escape(str(module.get('path')))}"
                    )
            else:
                lines.append("[cyan]Modules:[/cyan] none loaded (no debug session?)")
            if payload.get("debug_state"):
                lines.append(f"[cyan]State:[/cyan] {escape(str(payload['debug_state']))}")
            return self._capture("\n".join(lines))

        if kind == "tools":
            tools = payload.get("tools") or []
            lines = [f"[cyan]x64dbg tools ({payload.get('count', len(tools))}):[/cyan]", ""]
            for tool in tools:
                description = str(tool.get("description") or "").split("\n")[0]
                if len(description) > 110:
                    description = description[:107] + "..."
                lines.append(f"  [cyan]{escape(str(tool.get('name')))}[/cyan]")
                if description:
                    lines.append(f"    {escape(description)}")
            lines.append("")
            lines.append("Call one with: ghydra x64dbg call <name> --arg value")
            return self._capture("\n".join(lines))

        if kind == "call":
            # The plugin's own text carries a "[state]" marker, and Rich reads
            # a bracketed word as a style: without the escape the marker is
            # swallowed and the agent loses the line it needs.
            return self._capture(
                f"[cyan]{escape(str(payload.get('tool')))}[/cyan]\n\n"
                f"{escape(str(payload.get('text', '')))}"
            )

        if kind == "target":
            return self._capture("\n".join([
                "[cyan]Ghidra and x64dbg agree on this binary:[/cyan]",
                f"  Binary:      {escape(str(payload.get('binary')))}",
                f"  Image base:  {hex(payload.get('image_base') or 0)}  (Ghidra, in the file)",
                f"  Module base: {hex(payload.get('module_base') or 0)}  (x64dbg, in the process)",
                f"  Delta:       {hex(payload.get('delta') or 0)}",
                "",
                "runtime = static - image_base + module_base",
            ]))

        if kind in ("breakpoint_at", "go_to"):
            lines = [
                f"[cyan]{'Breakpoint set at' if kind == 'breakpoint_at' else 'Runtime address'}[/cyan] "
                f"{escape(str(payload.get('runtime_address')))} "
                f"(static {escape(str(payload.get('static_address')))})",
                f"  Binary: {escape(str(payload.get('binary')))}",
            ]
            if payload.get("image_base"):
                lines.append(f"  Image base:  {payload.get('image_base')}")
                lines.append(f"  Module base: {payload.get('module_base')}")
            text = payload.get("text")
            if text:
                lines.append("")
                # The plugin's own text, escaped for the same reason as above.
                lines.append(escape(str(text)))
            return self._capture("\n".join(lines))

        return self._capture(str(payload))

    def format_kuna(self, data: Dict[str, Any]) -> str:
        """Format a Kuna decompiler result.

        Args:
            data: Result with 'kind' (what was requested) and 'data' (the
                  payload returned by Kuna)

        Returns:
            Formatted string output
        """
        kind = data.get("kind", "")
        payload = data.get("data", {})
        if not isinstance(payload, dict):
            payload = {}

        if kind == "status":
            state = "enabled" if payload.get("enabled") else "disabled"
            # The version and the path come from the outside world: square
            # brackets are rich markup, and rich eats "[kuna 1.988]" whole if
            # the whole group is not escaped.
            lines = [
                f"[cyan]Kuna integration:[/cyan] {state} "
                f"(opt-in via {payload.get('source', 'unknown')})",
                f"[cyan]Binary:[/cyan] {escape(str(payload.get('binary') or 'not found'))}"
                + (f"  {escape('[' + str(payload.get('version')) + ']')}"
                   if payload.get("version") else ""),
                f"[cyan]Config:[/cyan] {escape(str(payload.get('config_file', '')))}",
                f"[cyan]Work:[/cyan] {escape(str(payload.get('work_dir', '')))}",
            ]
            exports = payload.get("exports") or []
            if exports:
                lines.append("")
                lines.append(f"[cyan]Exports on disk ({len(exports)}):[/cyan]")
                for export in exports:
                    streaming = "  (streaming)" if export.get("streaming") else ""
                    lines.append(
                        f"  {export.get('digest')}  "
                        f"{export.get('functions', 0)} functions  "
                        f"{escape(str(export.get('binary') or 'unknown binary'))}{streaming}"
                    )
                    lines.append(
                        f"    kuna://export/{export.get('digest')}/index.jsonl"
                    )
            return self._capture("\n".join(lines))

        if kind == "summary":
            summary = payload.get("summary", {}) or {}
            entry = summary.get("entry") or {}
            main = summary.get("main") or {}
            lines = [
                f"[cyan]Binary:[/cyan] {payload.get('binary', '?')}",
                f"[cyan]Functions:[/cyan] {payload.get('count', '?')} "
                f"(total {payload.get('total', '?')})",
            ]
            if entry:
                lines.append(
                    f"[cyan]Entry:[/cyan] {entry.get('name')} @ {entry.get('address_hex')}"
                )
            if main:
                lines.append(
                    f"[cyan]Main:[/cyan] {main.get('name')} @ {main.get('address_hex')}"
                )
            lines.append(
                f"[cyan]Reachable:[/cyan] {summary.get('reachable_from_entry', '?')} from entry"
            )
            lines.append(f"[cyan]No callers:[/cyan] {summary.get('no_callers', '?')}")
            lines.append(f"[cyan]Code bytes:[/cyan] {summary.get('code_bytes', '?')}")

            buckets = summary.get("size_buckets") or []
            if buckets:
                lines.append("")
                lines.append("[cyan]Size buckets:[/cyan]")
                for bucket in buckets:
                    lines.append(
                        f"  {str(bucket.get('bucket', '?')):>10}  {bucket.get('count', 0)}"
                    )

            largest = summary.get("largest") or []
            if largest:
                lines.append("")
                lines.append("[cyan]Largest functions:[/cyan]")
                for fn in largest[:10]:
                    lines.append(
                        f"  {fn.get('name', '?'):<28} {fn.get('size', 0):>7} bytes"
                        f"  @ {fn.get('address_hex', '?')}"
                    )

            return self._capture("\n".join(lines))

        if kind == "functions":
            functions = payload.get("functions", []) or []
            total = payload.get("total", len(functions))
            offset = payload.get("offset", 0)
            if not functions:
                return self._capture("[yellow]No functions found[/yellow]")

            table = Table(title=f"Functions ({total} total)", show_lines=False, box=box.ASCII)
            table.add_column("Address", style="cyan", no_wrap=True)
            table.add_column("Name", style="green")
            table.add_column("Size", style="yellow", justify="right")

            for fn in functions:
                table.add_row(
                    str(fn.get("address_hex", "?")),
                    escape(str(fn.get("name", "?"))),
                    str(fn.get("size", 0)),
                )

            if total > len(functions):
                table.caption = f"Showing {offset + 1}-{offset + len(functions)} of {total}"

            return self._capture(table)

        if kind == "decompile":
            functions = payload.get("functions") or []
            if not functions:
                return self._capture("[yellow]No decompiled function available[/yellow]")
            fn = functions[0]
            code = (fn.get("code") or "").strip()
            header = (
                f"{fn.get('name', '?')} @ {fn.get('address_hex', '?')} "
                f"({fn.get('size', 0)} bytes)"
            )
            if not code:
                return self._capture(f"{header}\n\n[yellow]No code returned[/yellow]")
            syntax = Syntax(code, "c", theme="monokai", line_numbers=True, word_wrap=False)
            return f"{self._capture(header)}\n{self._capture(syntax)}"

        if kind == "disassemble":
            target = payload.get("target") or {}
            instructions = payload.get("instructions", []) or []
            if not instructions:
                return self._capture("[yellow]No instructions returned[/yellow]")

            table = Table(
                title=(
                    f"Disassembly of {target.get('name', '?')} "
                    f"({payload.get('start_hex', '?')}-{payload.get('end_hex', '?')})"
                ),
                show_lines=False,
                box=box.ASCII,
            )
            table.add_column("Address", style="cyan", no_wrap=True)
            table.add_column("Bytes", style="dim", no_wrap=True)
            table.add_column("Instruction", style="white")

            for instruction in instructions:
                table.add_row(
                    str(instruction.get("address_hex", "?")),
                    str(instruction.get("bytes", "")),
                    escape(str(instruction.get("text", ""))),
                )

            return self._capture(table)

        if kind == "read":
            rows = payload.get("rows", []) or []
            if not rows:
                return self._capture("[yellow]No bytes returned[/yellow]")
            lines = [
                f"[cyan]Bytes at[/cyan] {payload.get('start_hex', '?')} "
                f"({payload.get('bytes', 0)} bytes)",
                "",
            ]
            for row in rows:
                lines.append(
                    f"  {str(row.get('address_hex', '?')):<18} "
                    f"{str(row.get('bytes', '')):<34} {row.get('ascii', '')}"
                )
            return self._capture("\n".join(lines))

        if kind == "strings":
            strings = payload.get("strings", []) or []
            total = payload.get("count", len(strings))
            if not strings:
                return self._capture("[yellow]No strings matched[/yellow]")

            table = Table(title=f"Strings matching /{payload.get('filter', '')}/",
                          show_lines=False, box=box.ASCII)
            table.add_column("Address", style="cyan", no_wrap=True)
            table.add_column("Text", style="white", overflow="fold")
            table.add_column("Section", style="dim")
            table.add_column("Xrefs", style="yellow", justify="right")

            for entry in strings:
                table.add_row(
                    str(entry.get("address_hex", "?")),
                    escape(str(entry.get("text", "")).replace("\n", "\\n")),
                    str(entry.get("section", "?")),
                    str(entry.get("xrefs_count", 0)),
                )

            if total > len(strings):
                table.caption = f"Showing {len(strings)} of {total}"

            return self._capture(table)

        if kind == "crypto":
            constants = payload.get("constants", []) or []
            if not constants:
                return self._capture("[yellow]No crypto constants found[/yellow]")

            table = Table(title=f"Crypto constants ({len(constants)})",
                          show_lines=False, box=box.ASCII)
            table.add_column("Algorithm", style="cyan", no_wrap=True)
            table.add_column("Name", style="white", overflow="fold")
            table.add_column("Address", style="green", no_wrap=True)
            table.add_column("Section", style="dim")

            for entry in constants:
                table.add_row(
                    str(entry.get("algorithm", "?")),
                    escape(str(entry.get("name", ""))),
                    str(entry.get("address_hex", "?")),
                    str(entry.get("section", "?")),
                )

            return self._capture(table)

        if kind == "xrefs":
            target = payload.get("target") or {}
            xrefs = payload.get("xrefs", []) or []
            if not xrefs:
                return self._capture("[yellow]No cross-references found[/yellow]")

            table = Table(
                title=(
                    f"Cross-references {payload.get('direction', '?')} "
                    f"{target.get('name', '?')} ({len(xrefs)})"
                ),
                show_lines=False,
                box=box.ASCII,
            )
            table.add_column("Address", style="cyan", no_wrap=True)
            table.add_column("Kind", style="yellow", no_wrap=True)
            table.add_column("Instruction", style="white")

            for xref in xrefs:
                table.add_row(
                    str(xref.get("address_hex", "?")),
                    str(xref.get("kind", "?")),
                    escape(str(xref.get("instruction", ""))),
                )

            return self._capture(table)

        if kind == "unpack":
            output = payload.get("output", payload.get("unpacked", payload.get("path", "?")))
            return self._capture(
                f"[cyan]Unpacked[/cyan] {payload.get('binary', '?')}\n"
                f"[cyan]Output:[/cyan] {output}"
            )

        if kind == "export":
            reused = payload.get("reused")
            lines = [
                f"[cyan]{'Reused' if reused else 'Exported'}[/cyan] "
                f"{escape(str(payload.get('binary', '?')))}",
                f"[cyan]Dir:[/cyan] {escape(str(payload.get('dir', '?')))}",
                f"[cyan]Functions:[/cyan] {payload.get('functions', 0)} "
                f"({payload.get('failed', 0)} failed)",
            ]
            if reused:
                lines.append(
                    "[cyan]The export was already there:[/cyan] the binary was not analysed again"
                )
            for failure in payload.get("failures", []) or []:
                lines.append(
                    f"  [red]ERROR[/red] {failure.get('name', '?')}: {failure.get('error')}"
                )
            return self._capture("\n".join(lines))

        if kind == "export-read":
            functions = payload.get("functions")
            if functions is not None:
                table = Table(title=f"Exported functions ({payload.get('total', len(functions))})",
                              show_lines=False, box=box.ASCII)
                table.add_column("Address", style="cyan", no_wrap=True)
                table.add_column("Name", style="green")
                table.add_column("Size", style="yellow", justify="right")

                for record in functions:
                    table.add_row(
                        str(record.get("addr", "?")),
                        escape(str(record.get("name", "?"))),
                        str(record.get("size", 0)),
                    )

                return self._capture(table)

            header = f"{payload.get('artifact', '?')} for {payload.get('function') or 'export'}"
            return self._capture(f"{header}\n\n{payload.get('text', '')}")

        return self._capture(str(payload))

    def format_error(self, error: Exception) -> str:
        """Format error message."""
        from ..client.exceptions import GhidraAPIError

        if isinstance(error, GhidraAPIError):
            return f"[red]Error [{error.code}]:[/red] {error.message}"

        return f"[red]Error:[/red] {str(error)}"
