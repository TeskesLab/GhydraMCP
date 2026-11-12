"""Explicit selected-match comparison, preparation and application across workers."""
from urllib.parse import quote

from .client.exceptions import GhidraAPIError
from .client.http_client import GhidraHTTPClient
from .core.bsim_compare import BSimComparisonError, compare_match


def compare_selected_match(client, match_id, reference_profile, reference_port,
                           profile=None, max_code_lines=1000):
    """Compare an exact query row; neither worker changes its active program.

    Native instruction evidence accompanies C/signature/types; the shared core
    aligns detached listings without importing programs across worker boundaries.

    Args:
        client: The configured target HTTP client.
        match_id: Opaque ID returned by the target worker's BSim query.
        reference_profile: Approved repository profile on the reference worker.
        reference_port: Reference worker's HTTP port, on the target client's host.
        profile: The BSim profile that produced the selected row.
        max_code_lines: Maximum decompiled lines per function, 1..10000.

    Returns:
        dict: Comparison envelope, including an explicitly non-mutating preview.
    """
    if (type(reference_port) is not int or not 1 <= reference_port <= 65535
            or type(max_code_lines) is not int or not 1 <= max_code_lines <= 10000
            or not reference_profile):
        raise GhidraAPIError("Select a repository profile, valid reference port and line limit.",
                             "BSIM_COMPARISON_INVALID")
    endpoint = f"bsim/matches/{quote(match_id, safe='')}"
    params = {"profile": profile} if profile else {}
    source = client.get(endpoint, params={**params, "max_code_lines": max_code_lines})
    payload = source.get("result", {})
    selection = payload.get("selection", {})
    match = selection.get("match", {})
    if not match.get("reference_available"):
        raise GhidraAPIError("The selected match has no usable repository reference.",
                             "BSIM_REFERENCE_UNAVAILABLE")
    reference_client = GhidraHTTPClient(host=client.host, port=reference_port,
        timeout=client.timeout, session=client.session, dry_run=client.dry_run)
    reference = reference_client.get("repositories/inspect-match", params={
        "profile": reference_profile, "match_id": match_id,
        "repository_url": match.get("repository_url"),
        "executable_md5": match.get("executable_md5"),
        "address": match.get("address"), "function": match.get("function"),
        "max_code_lines": max_code_lines})
    validation = client.get(endpoint + "/validate", params=params)
    if validation.get("result", {}).get("valid") is not True:
        raise GhidraAPIError("The source selection is no longer valid.", "BSIM_MATCH_STALE")
    try:
        result = compare_match(selection, payload.get("target", {}), reference.get("result", {}))
    except BSimComparisonError as exc:
        raise GhidraAPIError(str(exc), exc.code) from None
    result["reference_port"] = reference_port
    return {**source, "result": result}


def prepare_selected_match(client, match_id, reference_profile, reference_port, profile=None):
    """Prepare a native signature/type preview for an exact selected query row.

    The reference worker exports readonly native evidence; the target validates
    and retains it under an opaque token. Neither operation applies changes.
    """
    if (type(reference_port) is not int or not 1 <= reference_port <= 65535
            or not reference_profile):
        raise GhidraAPIError("Select a repository profile and valid reference port.",
                             "BSIM_APPLY_INVALID")
    endpoint = f"bsim/matches/{quote(match_id, safe='')}"
    params = {"profile": profile} if profile else {}
    source = client.get(endpoint + "/selection", params=params)
    match = source.get("result", {}).get("selection", {}).get("match", {})
    if not match.get("reference_available"):
        raise GhidraAPIError("The selected match has no usable repository reference.",
                             "BSIM_REFERENCE_UNAVAILABLE")
    if client.dry_run:
        return {"success": True, "dry_run": True, "result":
                f"Dry run: would export the selected reference via profile "
                f"{reference_profile!r} on port {reference_port}, then POST "
                f"{endpoint}/prepare-apply. No export, preview or apply token requested."}
    reference_client = GhidraHTTPClient(host=client.host, port=reference_port,
        timeout=client.timeout, session=client.session, dry_run=client.dry_run)
    reference = reference_client.get("repositories/export-match", params={
        "profile": reference_profile, "match_id": match_id,
        "repository_url": match.get("repository_url"),
        "executable_md5": match.get("executable_md5"),
        "address": match.get("address"), "function": match.get("function"),
        "version": -1})
    return client.post(endpoint + "/prepare-apply", params=params,
                       json_data={"reference": reference["result"]})


def apply_selected_match(client, match_id, apply_token, profile=None):
    """Explicitly apply only the native prepared token, never requery a match."""
    if not isinstance(apply_token, str) or not apply_token.strip():
        raise GhidraAPIError("Supply the token from a fresh prepare-apply preview.",
                             "BSIM_APPLY_INVALID")
    return client.post(f"bsim/matches/{quote(match_id, safe='')}/apply",
                       params={"profile": profile} if profile else {},
                       json_data={"apply_token": apply_token})
