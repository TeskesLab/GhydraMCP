"""Base formatter interface for output formatting."""

from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseFormatter(ABC):
    """Abstract base class for output formatters.

    All formatters must implement these methods to handle different
    types of API responses and format them appropriately.
    """

    @abstractmethod
    def format_functions_list(self, data: Dict[str, Any]) -> str:
        """Format function list response.

        Args:
            data: API response data containing function list

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_function_info(self, data: Dict[str, Any]) -> str:
        """Format single function info response.

        Args:
            data: API response data containing function details

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_decompiled_code(self, data: Dict[str, Any]) -> str:
        """Format decompiled code response.

        Args:
            data: API response data containing decompiled code

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_disassembly(self, data: Dict[str, Any]) -> str:
        """Format disassembly response.

        Args:
            data: API response data containing disassembly

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_memory(self, data: Dict[str, Any]) -> str:
        """Format memory read response.

        Args:
            data: API response data containing memory bytes

        Returns:
            Formatted string output (typically hex dump)
        """
        pass

    @abstractmethod
    def format_xrefs(self, data: Dict[str, Any]) -> str:
        """Format cross-references list response.

        Args:
            data: API response data containing xrefs

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_xrefs_by_name(self, data: Dict[str, Any]) -> str:
        """Format the references to a symbol name.

        Args:
            data: API response data with the symbols and their references

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_batch_decompile(self, data: Dict[str, Any]) -> str:
        """Format a batch decompilation.

        Args:
            data: API response data with one entry per target

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_address_context(self, data: Dict[str, Any]) -> str:
        """Format what an address holds.

        Args:
            data: API response data with the address context

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_call_path(self, data: Dict[str, Any]) -> str:
        """Format a call path.

        Args:
            data: API response data with the path or the reason there is none

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_callers(self, data: Dict[str, Any]) -> str:
        """Format the callers of a function.

        Args:
            data: API response data with the calling functions

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_callees(self, data: Dict[str, Any]) -> str:
        """Format the callees of a function.

        Args:
            data: API response data with the called functions

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_function_analysis(self, data: Dict[str, Any]) -> str:
        """Format everything known about one function.

        Args:
            data: API response data with the function and its relations

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_overview(self, data: Dict[str, Any]) -> str:
        """Format the overview of the loaded binary.

        Args:
            data: API response data with the program, the segments and the imports

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_data_list(self, data: Dict[str, Any]) -> str:
        """Format data items list response.

        Args:
            data: API response data containing data items

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_strings_list(self, data: Dict[str, Any]) -> str:
        """Format strings list response.

        Args:
            data: API response data containing strings

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_structs_list(self, data: Dict[str, Any]) -> str:
        """Format structs list response.

        Args:
            data: API response data containing structs

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_struct_info(self, data: Dict[str, Any]) -> str:
        """Format single struct info response.

        Args:
            data: API response data containing struct details

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_project_info(self, data: Dict[str, Any]) -> str:
        """Format project info response.

        Args:
            data: API response data containing project details

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_instances_list(self, data: Dict[str, Any]) -> str:
        """Format instances list response.

        Args:
            data: API response data containing instances

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_capabilities(self, data: Dict[str, Any]) -> str:
        """Format a capability negotiation response.

        Args:
            data: API response with versions, feature flags and limits

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_context_pack(self, data: Dict[str, Any]) -> str:
        """Format a budgeted context-pack dossier (R3).

        Args:
            data: The pack — sections, citations, omissions, token counts

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_capabilities_summary(self, data: Dict[str, Any]) -> str:
        """Format a ranked capability triage (ATT&CK/MBC-style leads).

        Args:
            data: Report with scan counts, ranked findings and evidence

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_simple_result(self, data: Dict[str, Any]) -> str:
        """Format simple success/info response.

        Args:
            data: API response data

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_kuna(self, data: Dict[str, Any]) -> str:
        """Format a Kuna decompiler result.

        Args:
            data: Result with 'kind' (what was requested) and 'data' (the
                  payload returned by Kuna)

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_x64dbg(self, data: Dict[str, Any]) -> str:
        """Format an x64dbg MCP server result.

        Args:
            data: Result with 'kind' (what was requested) and 'data' (the
                  payload returned by the x64dbg plugin)

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_callgraph(self, data: Dict[str, Any]) -> str:
        """Format the call graph of a function.

        Args:
            data: API response data

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_classes_list(self, data: Dict[str, Any]) -> str:
        """Format the class listing.

        Args:
            data: API response data

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_dataflow(self, data: Dict[str, Any]) -> str:
        """Format the data flow of a function.

        Args:
            data: API response data

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_datatypes_list(self, data: Dict[str, Any]) -> str:
        """Format the data type listing.

        Args:
            data: API response data

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_namespaces_list(self, data: Dict[str, Any]) -> str:
        """Format the namespace listing.

        Args:
            data: API response data

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_scalars(self, data: Dict[str, Any]) -> str:
        """Format the scalar search.

        Args:
            data: API response data

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_segments_list(self, data: Dict[str, Any]) -> str:
        """Format the segment listing.

        Args:
            data: API response data

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_symbols_list(self, data: Dict[str, Any]) -> str:
        """Format the symbol listing.

        Args:
            data: API response data

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_variables_list(self, data: Dict[str, Any]) -> str:
        """Format the variable listing of a function.

        Args:
            data: API response data

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_error(self, error: Exception) -> str:
        """Format error message.

        Args:
            error: Exception to format

        Returns:
            Formatted error string
        """
        pass

    @abstractmethod
    def format_connections(self, data: Dict[str, Any]) -> str:
        """Format the safe worker profile catalog."""
        pass

    @abstractmethod
    def format_repository(self, data: Dict[str, Any]) -> str:
        """Format native repository status, files, or an operation outcome."""
        pass

    @abstractmethod
    def format_bsim_comparison(self, data: Dict[str, Any]) -> str:
        """Format a selected-match diff and its non-mutating change preview."""
        pass

    @abstractmethod
    def format_bsim_prepare_apply(self, data: Dict[str, Any]) -> str:
        """Format the complete unapplied native preview and explicit apply token."""
        pass

    @abstractmethod
    def format_bsim_apply_match(self, data: Dict[str, Any]) -> str:
        """Format the native outcome of an explicit prepared-match application."""
        pass
