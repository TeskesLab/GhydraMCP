"""Human-only profile setup. No secrets in options, environment or output."""
from functools import wraps
import getpass
import json
import sys
import warnings

import click

from .. import connections as store
from ..client.exceptions import GhidraError
from ..utils import rich_echo


class _SafeArguments:
    def parse_args(self, ctx, args):
        try:
            return super().parse_args(ctx, args)
        except click.ClickException:
            # Click normally includes invalid/unexpected values in its errors.
            raise click.UsageError("Invalid connection command arguments.", ctx) from None


class _Command(_SafeArguments, click.Command):
    pass


class _Group(_SafeArguments, click.Group):
    command_class = _Command

    def resolve_command(self, ctx, args):
        try:
            return super().resolve_command(ctx, args)
        except click.ClickException:
            raise click.UsageError("Invalid connection command arguments.", ctx) from None


def _safe(function):
    @wraps(function)
    def invoke(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except store.ConnectionError as exc:
            raise click.ClickException(str(exc)) from None
        except (OSError, ValueError, TypeError, RuntimeError):
            raise click.ClickException("Connection administration failed safely.") from None
    return invoke


def _interactive():
    if not sys.stdin.isatty():
        raise click.ClickException("Credential setup requires a human interactive terminal; use an isolated worker account.")

def _hidden_prompt(label, **options):
    # getpass otherwise falls back to echoing input when terminal protection
    # fails. Turn its warning into a hard failure before fallback reads anything.
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            return click.prompt(label, hide_input=True, **options)
        except getpass.GetPassWarning:
            raise click.ClickException("Secure hidden terminal input is unavailable.") from None



def _credentials(auth):
    if auth == "none":
        return None
    _interactive()
    # Explicit calls, never @password_option: there must be no secret option or
    # auto-environment equivalent. Even identity and identity-file paths are hidden.
    result = {"username": _hidden_prompt("Worker username")}
    if auth == "password":
        result["password"] = _hidden_prompt("Worker password", confirmation_prompt=True)
    elif auth in ("pki", "ssh"):
        result["key_store"] = _hidden_prompt("Private identity file (absolute path)")
        result["key_store_password"] = (_hidden_prompt("Identity store password",
                                                     confirmation_prompt=True, default="", show_default=False)
                                         if auth == "pki" else "")
    else:
        raise click.ClickException("Invalid authentication method.")
    return result


def _shown(value):
    click.echo(json.dumps(value, indent=2, ensure_ascii=True))


@click.group(cls=_Group)
@click.option("--directory", allow_from_autoenv=False,
              help="Explicit absolute private worker directory; no config discovery.")
@click.pass_context
@_safe
def connections(ctx, directory):
    """Out-of-band operator administration (never an MCP provisioning tool)."""
    ctx.ensure_object(dict)
    ctx.obj["connections_directory"] = directory
    if ctx.invoked_subcommand != "list" and not directory:
        raise click.UsageError("--directory is required for out-of-band operator administration.")


def _profile_options(command):
    for option in reversed([
        click.argument("profile_id"),
        click.option("--kind", required=True, allow_from_autoenv=False, help="bsim or ghidra"),
        click.option("--backend", required=True, allow_from_autoenv=False, help="h2, postgresql, elasticsearch or ghidra"),
        click.option("--endpoint", required=True, allow_from_autoenv=False, help="Approved credential-free native URL or absolute H2 path"),
        click.option("--auth", required=True, allow_from_autoenv=False, help="none, password, pki or ssh (backend-specific)"),
        click.option("--permission", "permissions", multiple=True, required=True, allow_from_autoenv=False,
                     help="Repeat for each query/ingest or read/checkout/checkin grant"),
        click.option("--default-bsim", is_flag=True, allow_from_autoenv=False,
                     help="Select this BSim profile as the worker default"),
    ]):
        command = option(command)
    return command


def _save(ctx, profile_id, *, replace, **options):
    # Validate all public arguments BEFORE requesting secrets. The temporary ref
    # only validates the shape; the store generates an unguessable reference.
    profile = {k: options[k] for k in ("kind", "backend", "endpoint", "auth")}
    profile["permissions"] = list(options["permissions"])
    if profile["auth"] != "none":
        profile["credential_ref"] = "validation"
    store._profile(profile_id, profile)
    _interactive()
    store.save_profile(profile_id, ctx.obj["connections_directory"],
                               credentials=_credentials(options["auth"]), replace=replace, **options)
    # Do not echo supplied IDs/endpoints on setup or rotation success.
    click.echo("Connection profile saved.")


@connections.command("create")
@_profile_options
@click.pass_context
@_safe
def create(ctx, profile_id, **options):
    """Create an approved endpoint and prompt for credentials without echo."""
    _save(ctx, profile_id, replace=False, **options)


@connections.command("update")
@_profile_options
@click.pass_context
@_safe
def update(ctx, profile_id, **options):
    """Replace all metadata AND credentials (no old secret fields are retained)."""
    _save(ctx, profile_id, replace=True, **options)


@connections.command("rotate")
@click.argument("profile_id")
@click.pass_context
@_safe
def rotate(ctx, profile_id):
    """Replace only credentials, preserving approved endpoint and grants."""
    _interactive()
    directory = ctx.obj["connections_directory"]
    profile = store.load_profile(profile_id, directory)
    store.rotate_credentials(profile_id, directory, _credentials(profile["auth"]))
    click.echo("Connection credentials rotated.")


@connections.command("remove")
@click.argument("profile_id")
@click.pass_context
@_safe
def remove(ctx, profile_id):
    """Remove an endpoint and its credentials without contacting its server."""
    _interactive()
    store.remove_profile(profile_id, ctx.obj["connections_directory"])
    click.echo("Connection profile removed.")


@connections.command("list")
@click.pass_context
@_safe
def list_profiles(ctx):
    """List approved worker IDs remotely, or inspect an operator's explicit store."""
    directory = ctx.obj["connections_directory"]
    if directory:
        _shown(store.catalog(directory))
        return
    try:
        response = ctx.obj["client"].get("connections")
        click.echo(ctx.obj["formatter"].format_connections(response))
    except GhidraError as exc:
        rich_echo(ctx.obj["formatter"].format_error(exc), err=True)
        ctx.exit(1)


@connections.command("inspect")
@click.argument("profile_id")
@click.pass_context
@_safe
def inspect_profile(ctx, profile_id):
    """Inspect approved metadata; never print credential references or values."""
    _shown(store.load_profile(profile_id, ctx.obj["connections_directory"]))
