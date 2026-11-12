"""Out-of-band worker profile administration; never import into MCP provisioning.

No implicit directory/config/environment lookup. Public readers return metadata only.
POSIX record locks coordinate with the worker JVM's FileChannel locks.
"""
from __future__ import annotations

from contextlib import contextmanager
import ipaddress
import json
import os
import re
import secrets
import stat
import threading
from urllib.parse import urlsplit


class ConnectionError(ValueError):
    """A stable, credential-free failure suitable for operator output."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z", re.ASCII)
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z", re.ASCII)
_HOST_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z", re.ASCII)
_PERMISSIONS = {"bsim": {"query", "ingest"}, "ghidra": {"read", "checkout", "checkin"}}
_AUTHS = {"h2": {"none"}, "postgresql": {"password", "pki"},
          "elasticsearch": {"password"}, "ghidra": {"password", "ssh", "pki"}}
_LIMIT = 1024 * 1024
_MUTEX = threading.RLock()


def _fail(code="CONNECTION_PROFILE_INVALID", message="Invalid connection profile."):
    raise ConnectionError(code, message) from None


def _identifier(value):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        _fail()
    return value


def _plain(value, *, empty=False):
    if (not isinstance(value, str) or len(value) > 65536 or
            (not empty and not value) or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        _fail("CONNECTION_AUTH_REQUIRED", "Invalid worker credentials.")
    return value


def _absolute(value):
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 4096:
        _fail()
    if any(ord(c) < 32 or ord(c) == 127 for c in value) or any(c in value for c in "\\;?#%"):
        _fail()
    parts = value.split("/")[1:]
    if not parts or any(p in ("", ".", "..") for p in parts):
        _fail()
    return parts


def _endpoint(backend, endpoint):
    if backend == "h2":
        _absolute(endpoint)
        return endpoint
    if (not isinstance(endpoint, str) or len(endpoint) > 4096 or
            not endpoint.isascii() or any(ord(c) <= 32 or ord(c) == 127 for c in endpoint) or
            any(c in endpoint for c in "\\%@?#")):
        _fail()
    try:
        url = urlsplit(endpoint)
        port = url.port
        host = url.hostname
    except (ValueError, TypeError):
        _fail()
    schemes = {"postgresql": {"postgresql"}, "elasticsearch": {"elastic", "https"},
               "ghidra": {"ghidra"}}
    if (url.scheme not in schemes[backend] or not host or url.username is not None or
            url.password is not None or url.query or url.fragment or
            (port is not None and not 1 <= port <= 65535) or url.netloc.endswith(":")):
        _fail()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if (len(host) > 253 or all(c in "0123456789." for c in host) or
                not all(_HOST_LABEL.fullmatch(x) for x in host.split("."))):
            _fail()
    path = url.path.split("/")
    if len(path) != 2 or not _NAME.fullmatch(path[1]) or path[1] in (".", ".."):
        _fail()
    return endpoint


def _profile(profile_id, value):
    _identifier(profile_id)
    if not isinstance(value, dict):
        _fail()
    required = {"kind", "backend", "endpoint", "auth", "permissions"}
    if not required <= value.keys() or value.keys() - required - {"credential_ref"}:
        _fail()
    kind, backend, auth = value["kind"], value["backend"], value["auth"]
    if backend == "elasticsearch" and auth == "pki":
        _fail("CONNECTION_PROFILE_INVALID", "Native Elasticsearch profiles support password authentication only.")
    if (not isinstance(kind, str) or kind not in _PERMISSIONS or
            not isinstance(backend, str) or backend not in _AUTHS or
            (kind == "ghidra") != (backend == "ghidra") or
            not isinstance(auth, str) or auth not in _AUTHS[backend]):
        _fail()
    grants = value["permissions"]
    if (not isinstance(grants, list) or not grants or
            any(not isinstance(p, str) or p not in _PERMISSIONS[kind] for p in grants) or
            len(set(grants)) != len(grants)):
        _fail()
    _endpoint(backend, value["endpoint"])
    if auth == "none":
        if value.get("credential_ref") not in (None, ""):
            _fail()
    else:
        _identifier(value.get("credential_ref"))
    return dict(value)


def _metadata(profile_id, profile, *, catalog=False):
    keys = ("kind", "backend", "permissions") if catalog else (
        "kind", "backend", "endpoint", "auth", "permissions")
    result = {"id": profile_id, **{k: profile[k] for k in keys}}
    result["permissions"] = list(result["permissions"])
    return result


def _check_owner(st, *, directory=False, ancestor=False):
    uid = os.geteuid()
    mode = stat.S_IMODE(st.st_mode)
    if ancestor:
        # Root-owned sticky /tmp is safe against replacement by other users.
        if (st.st_uid not in (0, uid) or
                (mode & 0o022 and not (st.st_uid == 0 and mode & stat.S_ISVTX))):
            _fail("CONNECTION_STORE_UNSAFE", "Unsafe worker store protection.")
    elif st.st_uid != uid or mode != (0o700 if directory else 0o600):
        _fail("CONNECTION_STORE_UNSAFE", "Unsafe worker store protection.")
    if not directory and not ancestor and (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1):
        _fail("CONNECTION_STORE_UNSAFE", "Unsafe worker store protection.")


def _directory_fd(directory, *, create=False):
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        _fail("CONNECTION_STORE_UNSAFE", "Secure profiles require an isolated POSIX worker; Windows ACL support is unavailable.")
    try:
        value = os.fspath(directory)
        parts = _absolute(value)
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for index, part in enumerate(parts):
                final = index == len(parts) - 1
                _check_owner(os.fstat(fd), directory=True, ancestor=True)
                if final and create:
                    try:
                        os.mkdir(part, 0o700, dir_fd=fd)
                    except FileExistsError:
                        pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
                _check_owner(os.fstat(fd), directory=True, ancestor=not final)
            return fd
        except BaseException:
            os.close(fd)
            raise
    except ConnectionError:
        raise
    except (OSError, TypeError, ValueError):
        _fail("CONNECTION_STORE_UNSAFE", "Cannot securely open the worker store.")


def _file_fd(directory_fd, name, *, create=False):
    flags = os.O_RDWR if create else os.O_RDONLY
    flags |= os.O_NOFOLLOW | os.O_NONBLOCK
    if create:
        flags |= os.O_CREAT
    fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
    try:
        _check_owner(os.fstat(fd))
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def _store(directory, *, write=False):
    # POSIX record locks are process-scoped, so threads also need this mutex.
    with _MUTEX:
        fd = _directory_fd(directory, create=write)
        lock = None
        try:
            import fcntl
            lock = _file_fd(fd, ".lock", create=write)
            fcntl.lockf(lock, fcntl.LOCK_EX if write else fcntl.LOCK_SH)
            yield fd
        except ConnectionError:
            raise
        except (OSError, ValueError, TypeError, UnicodeError):
            _fail("CONNECTION_STORE_UNSAFE", "Cannot securely access the worker store.")
        finally:
            if lock is not None:
                os.close(lock)
            os.close(fd)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail()
        result[key] = value
    return result


def _read(fd, name, *, missing=None):
    try:
        handle = _file_fd(fd, name)
    except FileNotFoundError:
        if missing is not None:
            return missing
        _fail("CONNECTION_PROFILE_NOT_FOUND", "Connection store is not initialized.")
    try:
        size = os.fstat(handle).st_size
        if size > _LIMIT:
            _fail()
        with os.fdopen(handle, "rb", closefd=False) as stream:
            raw = stream.read(_LIMIT + 1)
        if len(raw) > _LIMIT:
            _fail()
        return json.loads(raw, object_pairs_hook=_pairs)
    except (ValueError, UnicodeError, RecursionError):
        _fail()
    finally:
        os.close(handle)


def _manifest(fd, *, new=False):
    data = _read(fd, "profiles.json", missing={"version": 1, "profiles": {}} if new else None)
    if (not isinstance(data, dict) or data.keys() - {"version", "profiles", "default_bsim"} or
            type(data.get("version")) is not int or data["version"] != 1 or
            not isinstance(data.get("profiles"), dict) or len(data["profiles"]) > 1024):
        _fail()
    data["profiles"] = {key: _profile(key, p) for key, p in data["profiles"].items()}
    default = data.get("default_bsim")
    if default is not None and (not isinstance(default, str) or default not in data["profiles"] or
                                data["profiles"][default]["kind"] != "bsim"):
        _fail()
    return data


def _credential_document(fd, *, new=False):
    data = _read(fd, "credentials.json", missing={"version": 1, "credentials": {}} if new else None)
    if (not isinstance(data, dict) or set(data) != {"version", "credentials"} or
            type(data.get("version")) is not int or data["version"] != 1 or
            not isinstance(data.get("credentials"), dict) or len(data["credentials"]) > 1025):
        _fail()
    for key, entry in data["credentials"].items():
        _identifier(key)
        if (not isinstance(entry, dict) or not entry or
                entry.keys() - {"username", "password", "key_store", "key_store_password"}):
            _fail()
        for field, value in entry.items():
            _plain(value, empty=field == "key_store_password")
    return data


def _credentials(profile, entry):
    auth = profile["auth"]
    if auth == "none":
        if entry is not None and entry != {}:
            _fail()
        return {}
    fields = {"username", "password"} if auth == "password" else {
        "username", "key_store", "key_store_password"}
    if not isinstance(entry, dict) or set(entry) != fields:
        _fail("CONNECTION_AUTH_REQUIRED", "Worker credentials are missing or invalid.")
    result = {k: _plain(v, empty=k == "key_store_password") for k, v in entry.items()}
    if auth == "ssh" and result["key_store_password"]:
        _fail("CONNECTION_AUTH_REQUIRED", "Encrypted SSH keys are not supported by the native headless client.")
    if auth in ("ssh", "pki"):
        parts = _absolute(result["key_store"])
        parent = "/" + "/".join(parts[:-1])
        # Identity files must also be private, not just the JSON store.
        key_dir = _directory_fd(parent)
        try:
            key = _file_fd(key_dir, parts[-1])
            os.close(key)
        except OSError:
            _fail("CONNECTION_STORE_UNSAFE", "Cannot securely open the worker identity file.")
        finally:
            os.close(key_dir)
    return result


def _selected(manifest, profile_id, kind=None, permission=None):
    _identifier(profile_id)
    if kind is not None and (not isinstance(kind, str) or kind not in _PERMISSIONS):
        _fail()
    profile = manifest["profiles"].get(profile_id)
    if profile is None:
        _fail("CONNECTION_PROFILE_NOT_FOUND", "Connection profile was not found.")
    if kind is not None and profile["kind"] != kind:
        _fail()
    if permission is not None and (not isinstance(permission, str) or permission not in profile["permissions"]):
        _fail("CONNECTION_PERMISSION_DENIED", "Connection permission is not granted.")
    return profile


def load_profile(profile_id, directory, kind=None, permission=None):
    """Read approved nonsecret metadata, optionally enforcing kind and a grant."""
    with _store(directory) as fd:
        profile = _selected(_manifest(fd), profile_id, kind, permission)
        return _metadata(profile_id, profile)


def catalog(directory):
    """Return id/kind/backend/permissions only, never identities or endpoints."""
    with _store(directory) as fd:
        data = _manifest(fd)
        return [_metadata(key, data["profiles"][key], catalog=True) for key in sorted(data["profiles"])]


def _atomic(fd, name, data):
    encoded = json.dumps(data, ensure_ascii=True, separators=(",", ":")) + "\n"
    if len(encoded.encode("utf-8")) > _LIMIT:
        _fail()
    # Check existing destination, not just the replacement, to fail on tampering.
    try:
        existing = _file_fd(fd, name)
    except FileNotFoundError:
        pass
    else:
        os.close(existing)
    temporary = ".tmp-" + secrets.token_hex(16)
    handle = None
    try:
        handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=fd)
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, "w", encoding="utf-8", closefd=False) as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(handle)
        os.rename(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        if handle is not None:
            os.close(handle)
        try:
            os.unlink(temporary, dir_fd=fd)
        except FileNotFoundError:
            pass


def _prune(manifest, credentials):
    used = {p.get("credential_ref") for p in manifest["profiles"].values()}
    credentials["credentials"] = {k: v for k, v in credentials["credentials"].items() if k in used}


def save_profile(profile_id, directory, *, kind, backend, endpoint, auth, permissions,
                 credentials=None, replace=False, default_bsim=False):
    """Human administration only. Credentials must originate from hidden prompts.

    Replacing a profile also replaces all of its credentials; nothing is merged.
    """
    if type(replace) is not bool or type(default_bsim) is not bool:
        _fail()
    profile = {"kind": kind, "backend": backend, "endpoint": endpoint, "auth": auth,
               "permissions": list(permissions) if isinstance(permissions, (list, tuple)) else permissions}
    if auth != "none":
        profile["credential_ref"] = secrets.token_hex(16)
    _profile(profile_id, profile)
    private = _credentials(profile, credentials)
    if default_bsim and kind != "bsim":
        _fail()
    with _store(directory, write=True) as fd:
        manifest = _manifest(fd, new=True)
        old = manifest["profiles"].get(profile_id)
        if replace != (old is not None):
            _fail("CONNECTION_PROFILE_INVALID", "Profile already exists or cannot be replaced.")
        if manifest.get("default_bsim") == profile_id and kind != "bsim":
            _fail("CONNECTION_PROFILE_INVALID",
                  "Remove the default BSim profile before changing its kind.")
        document = _credential_document(fd, new=True)
        _prune(manifest, document)
        manifest["profiles"][profile_id] = profile
        if len(manifest["profiles"]) > 1024:
            _fail()
        if default_bsim:
            manifest["default_bsim"] = profile_id
        if private:
            document["credentials"][profile["credential_ref"]] = private
        # Old credentials remain until the manifest publication succeeds. A crash
        # can leave harmless orphans, never a new profile with absent credentials.
        _atomic(fd, "credentials.json", document)
        _atomic(fd, "profiles.json", manifest)
        _prune(manifest, document)
        _atomic(fd, "credentials.json", document)
    return _metadata(profile_id, profile)


def rotate_credentials(profile_id, directory, credentials):
    """Atomically replace a credential entry without changing endpoint or grants."""
    with _store(directory, write=True) as fd:
        manifest = _manifest(fd)
        profile = _selected(manifest, profile_id)
        if profile["auth"] == "none":
            _fail("CONNECTION_AUTH_REQUIRED", "Local H2 profiles do not have credentials.")
        private = _credentials(profile, credentials)
        document = _credential_document(fd)
        _prune(manifest, document)
        profile["credential_ref"] = secrets.token_hex(16)
        document["credentials"][profile["credential_ref"]] = private
        _atomic(fd, "credentials.json", document)
        _atomic(fd, "profiles.json", manifest)
        _prune(manifest, document)
        _atomic(fd, "credentials.json", document)
    return _metadata(profile_id, profile)


def remove_profile(profile_id, directory):
    """Remove an approved endpoint and its no-longer-referenced credentials."""
    with _store(directory, write=True) as fd:
        manifest = _manifest(fd)
        _selected(manifest, profile_id)
        credentials = _credential_document(fd)
        del manifest["profiles"][profile_id]
        if manifest.get("default_bsim") == profile_id:
            del manifest["default_bsim"]
        _atomic(fd, "profiles.json", manifest)
        _prune(manifest, credentials)
        _atomic(fd, "credentials.json", credentials)
