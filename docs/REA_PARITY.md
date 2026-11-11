# REA parity

The point of this file is the **exact** catalogue of the REA, not an impression
of it. The REA is installed here (`rea-agents`), so the list was asked of the
server itself over MCP `tools/list` — 139 tools in version 6.0.0, and the
"170 tools" figure belongs to a later release.

The names are not comparable one by one: the REA says *procedure* where Ghidra
says *function*, and it spreads its tools over platforms Ghidra itself
already understands. So the comparison below is by **capability**.

## The scope of this pull request

This pull request carries **only the parity work**: the four native gaps and the
four composed calls. The rows below that mention the format identification
(`inspect_target`), the evidence ledger (`evidence_*`) and the working sessions
(`session_*`) describe work that lives elsewhere and is **not** part of this
pull request — they are marked as such where they appear.

## What the REA has, and where GhydraMCP stands

| Area | REA | GhidraMCP | Gap |
| --- | --- | --- | --- |
| Native reverse engineering | `procedure_*`, `read_bytes`, `xrefs`, `address_*` (about 40 tools) | `functions_*`, `data_*`, `xrefs_*`, `symbols_*`, `segments_*`, `memory_*`, `comments_*` | covered |
| Composed workflows | `get_call_graph`, `batch_decompile`, `analyze_function`, `trace_call_path`, `binary_overview`, `find_xrefs_to_name` | `analysis_get_callgraph`, `analysis_get_dataflow`, `analysis_run`, `functions_decompile`, `functions_get_cfg`, `functions_batch_decompile`, `analysis_trace_call_path`, `xrefs_find_by_name`, `functions_analyze`, `programs_overview`, `analysis_callers`, `analysis_callees` | **closed** (the four gaps below) |
| Apple | `inspect_macho`, `inspect_plist`, `decode_interface_builder`, `inspect_keyed_archive`, `inspect_asset_catalog`, `trace_dylib_resolution`, `get_objc_classes`, `analyze_swift_types`, `demangle_swift` | the format identification is not in this pull request | Ghidra reads these; the REA adds dedicated engines |
| Managed (.NET) | `inspect_managed_artifact`, `inspect_managed_members`, `compare_managed_members`, `import_managed_reconstruction` | — | out of scope for a Ghidra plugin |
| Android | `inspect_android_package`, `search_android_classes`, `inspect_android_class`, `inspect_android_method`, `trace_android_references` | — | out of scope |
| Artifacts and firmware | `inspect_binary_layout`, `inspect_artifact`, `extract_artifact`, `inspect_evm_interface`, `inspect_recorded_crash`, `inspect_firmware_regions`, `extract_firmware` | — | identification lands separately; deep parsers not |
| Web, Electron, JavaScript | about 30 tools | — | out of scope |
| Evidence | `export_evidence_bundle`, `get_evidence_bundle`, `list_unknowns`, `record_unknown`, `verify_unknown_resolution` | the evidence ledger is not in this pull request | covered elsewhere, under another name |
| Sessions | `open_binary`, `close_binary`, `binary_session`, `get_navigation_context`, `inspect_address_context` | `ui_get_current_address`, `inspect_address` | **closed** (`inspect_address_context`) |
| Process capture | `capture_process_scenario`, `compare_process_captures` | — | the x64dbg integration is the neighbour of this |

## The gaps that are worth closing

Four of them are native, cheap and answer a question an agent asks all the
time. The rest of the REA's breadth comes from engines for Apple, Android,
web and .NET — Ghidra already understands those formats, and the REA is not
bringing a better Ghidra to them.

**All four are closed.** Each one exists on the three surfaces — the REST
API, the MCP bridge and the CLI — and `test_rea_parity.py` proves they agree.

1. **`batch_decompile`** — the REA decompiles a list of functions in one call.
   GhidraMCP has `functions_decompile` for one at a time, and `kuna_decompile`
   for one binary. A list in, a list out, is what a triage pass needs.
   → `POST /functions/decompile-batch`, `functions_batch_decompile`,
   `ghydra functions decompile-batch --targets '["main","0x401000"]'`.
   A target that resolves to nothing comes back as a failed entry, so one
   wrong name does not cost the batch.
2. **`find_xrefs_to_name`** — the REA finds the references to a *name*. The
   GhidraMCP xrefs are addressed by address, so the agent has to resolve the
   name first and then ask again.
   → `GET /xrefs/to-name/{name}`, `xrefs_find_by_name`,
   `ghydra xrefs find-by-name strlen`. A bare name matches every namespace;
   a qualified one (`NS::foo`) matches that namespace.
3. **`inspect_address_context`** — one call that says what an address is:
   the function it sits in, the data it holds, the references to it, the
   comment on it. GhidraMCP has the pieces, and the agent pays four calls.
   → `GET /inspect/address/{address}`, `inspect_address`,
   `ghydra inspect-address 0x140001008`. The answer holds the symbol, the
   containing function, the data, the instruction, both comments and the
   references on both sides.
4. **`trace_call_path`** — the REA answers "how does A reach B". The
   GhidraMCP has the call graph, which is the graph, not the path.
   → `GET /analysis/call-path?from=&to=`, `analysis_trace_call_path`,
   `ghydra analysis trace-call-path --from main --to strcmp`. The path
   returned is the shortest one Ghidra knows about, and the answer says how
   many functions were explored when there is none.

## The composed calls that came out of the comparison

Comparing the two catalogues tool by tool, rather than by area, found four more that the REA has
and this project did not. Two of them were in the REST API since 3.0.0 and were never exposed on
the other two surfaces; the other two are compositions of what was already there.

| REA | Bridge tool | CLI | What it composes |
| --- | --- | --- | --- |
| `procedure_callers` | `analysis_callers` | `ghydra analysis callers ADDR` | `GET /analysis/callers/{address}` |
| `procedure_callees` | `analysis_callees` | `ghydra analysis callees ADDR` | `GET /analysis/callees/{address}` |
| `analyze_function` | `functions_analyze` | `ghydra functions analyze --address ADDR` | the function, its decompilation, its callers, its callees and its references |
| `binary_overview` | `programs_overview` | `ghydra analysis overview` | the program, its segments, its counts and its imports |

### What is still not covered, and why

- **`list_bookmarks`** — Ghidra has bookmarks of its own, and the API does not expose them. The
  project's answer to the same question is the **evidence ledger**, which gives every finding an ID
  that never changes and never collides, and exports as a bundle. It is the stronger of the two,
  and it lives outside this pull request.
- **`resolve_native_call_targets`** — resolving the target of an *indirect* call needs the
  decompiler's p-code, not the reference manager. The call graph resolves what it can.
- **`list_classes`, `list_objc_*`, `inspect_*` (Apple, Android, .NET, web)** — Ghidra reads those
  formats; the REA brings dedicated engines for them. A Ghidra plugin does not become a better
  Ghidra by shipping a second analyser.

## The full catalogue

Taken from the server itself, `tools/list` on `rea-agents` 6.0.0:

```
annotate_native_function, inspect_native_load_image, inspect_native_data_type,
inspect_native_instruction, resolve_native_call_targets, address_name, comment,
current_address, current_procedure, current_document, goto_address,
inline_comment, list_bookmarks, list_documents, list_names, list_procedures,
list_segments, list_strings, next_address, prev_address, procedure_address,
procedure_assembly, procedure_callees, procedure_callers, procedure_info,
read_function_instructions, read_bytes, address_to_file_offset,
procedure_references, procedure_pseudo_code, resolve_containing_procedure,
search_procedures, search_strings, set_address_name, set_addresses_names,
set_bookmark, set_comment, set_current_document, set_inline_comment,
unset_bookmark, xrefs, trace_native_values, inspect_native_dispatch_metadata,
get_objc_classes, get_objc_protocols, batch_decompile, get_call_graph,
analyze_swift_types, find_xrefs_to_name, binary_overview, analyze_function,
inspect_native_api, trace_feature, trace_call_path, trace_native_ui_action,
observe_native_ui, capture_native_ui_scenario, observe_native_calls,
inspect_macho, inspect_signature, inspect_plist, list_architectures,
demangle_swift, inspect_artifact, extract_artifact, decode_interface_builder,
inspect_keyed_archive, inspect_asset_catalog, trace_dylib_resolution,
inspect_managed_artifact, inspect_managed_members,
inspect_managed_native_boundaries, compare_managed_members,
verify_managed_native_boundaries, import_managed_reconstruction,
project_managed_application_graph, inspect_android_package,
search_android_classes, inspect_android_class, inspect_android_method,
trace_android_references, inspect_binary_layout, inspect_evm_interface,
inspect_recorded_crash, inspect_firmware_regions, extract_firmware,
export_web_scripts, list_browser_targets, inspect_web_page,
analyze_web_bundle, observe_web_session, discover_webmcp_tools,
compare_web_captures, capture_web_screenshot, compare_web_screenshots,
capture_browser_scenario, list_electron_targets, inspect_electron_page,
analyze_javascript_application, reconcile_javascript_runtime,
capture_electron_scenario, list_javascript_runtime_targets,
observe_javascript_runtime, trace_application_feature, trace_javascript_semantics,
compare_application_versions, compare_source_to_bundle,
compare_javascript_export_shapes, build_reconstruction_obligation_ledger,
evaluate_reconstruction_coverage, project_android_application_graph,
project_apple_application_graph, trace_web_module_imports, trace_web_source_location,
observe_web_execution, inspect_web_event_listeners, inspect_web_network_capture,
recover_javascript_sources, open_binary, close_binary, binary_session,
export_evidence_bundle, import_evidence_bundle, get_evidence_bundle,
capture_process_scenario, compare_process_captures, compare_artifacts,
compare_functions, compare_bundles, find_changed_behavior, build_call_path,
correlate_static_and_runtime, verify_reconstruction, list_unknowns,
record_unknown, update_unknown, verify_unknown_resolution,
get_navigation_context, inspect_address_context
```
