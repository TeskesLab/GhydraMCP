# Native Ghidra Server repositories

Ghydra connects to a **native Ghidra Server**, not another Ghydra HTTP plugin. A human provisions a `ghidra` connection profile under the worker identity using the [connection setup workflow](GHYDRA_CONNECTIONS.md). The profile selects one existing repository (`ghidra://host:port/repository`) and grants `read`, `checkout`, and/or `checkin`. Commands accept the opaque profile ID, never a server URL, username, password, certificate, or private key.

The worker must have a full Ghidra installation, including its native FileSystem APIs, and an explicitly configured protected connection directory. It performs native authentication within the profile's credential scope. Native exception details, server identities, and credential references are not returned.

## Browse and open

```sh
ghydra repositories status --profile team-repository
ghydra repositories list-files --profile team-repository --path / --limit 100
ghydra repositories open --profile team-repository --path /samples/program
ghydra repositories open --profile team-repository --path /samples/program --version 2
```

Listings contain the immediate folder's files and subfolders, not a recursive walk. `count`, `total`, `offset`, `has_more`, and `truncated` describe the page; `--limit` is between 1 and 1000. Use `--offset` or follow the returned `next` link for later entries. Follow a folder path to browse deeper. Repository links are not followed, and paths must be absolute, without traversal, empty components, backslashes, or percent escapes.

Opening activates the native program in the existing GUI ProgramManager or the headless worker's active-program selection. It never closes or discards a changed active program: save or close that program first. Editing requires a current **exclusive** local checkout plus profile and native repository permissions; stale or nonexclusive writable selections are refused. Historical versions and read-only profiles remain read-only. Merely opening a program never checks it out.

Read-only versions use Ghidra's compatibility-aware copy-on-write loader. Minor
language updates affect only that local view, not the stored program or repository
version. Native `Program.isChangeable()` may be true for these views; Ghydra rejects
agent mutations and analysis independently with `403 REPOSITORY_READ_ONLY`.
Protection follows the view until native close, even if another GUI retains it
after the originating service stops. Saving an unchanged view remains a no-op.

## Explicit checkout, save, and check-in

```sh
# The file must be closed and not already checked out.
ghydra repositories checkout --profile team-repository --path /samples/program --exclusive
ghydra repositories open --profile team-repository --path /samples/program

# Make the intended changes, then save to the independent local checkout.
ghydra project save-program

# Publish a new repository version, retaining the open program's checkout.
ghydra repositories checkin --profile team-repository --path /samples/program \
  --comment 'Reviewed analysis updates' --keep-checked-out
```

**Save is local persistence, not check-in.** Check-in requires an explicit nonblank comment (at most 4096 characters), saved changes, the latest repository version, a valid checkout, and native write permission. It never saves automatically, merges, overrides a conflict, hijacks a file, terminates another checkout, or forces a lock. A read-only native server/repository is enforced by the service, even if a profile grants writes.

Checkout and check-in support native program files only. Other repository content may be listed, but is not published through this no-merge program workflow.

Check-in requires an **exclusive checkout**. Ghidra's baseline `DomainFile.checkin` can automatically merge a concurrently updated nonexclusive checkout; its compatibility overload does not provide a reliable no-merge guarantee. Nonexclusive checkout is supported, but cannot be published through this API. Resolve existing nonexclusive checkouts/conflicts through native Ghidra workflows; this API does not automatically upgrade them to exclusive checkouts.

`keep_checked_out` defaults to false. Native Ghidra silently retains a checkout while its program is open; Ghydra instead rejects that request with `REPOSITORY_CONFLICT`. Close the program first, or explicitly use `--keep-checked-out`. No program is automatically closed to satisfy a check-in. Successful responses verify both the new repository version and the requested retained/released checkout state.

## Independent workspace and lifetime

The worker creates or reopens an independent shared local project beneath:

```text
<connections-directory>/repositories/instance-<port>/<profile>/checkout.gpr
```

It never converts or changes the user's active project. Workspace directories must remain private, owned by the worker, and free of symlink redirection. The workspace is persistent: shutdown does not delete local checkout files, undo checkouts, or release repository checkouts without an explicit successful check-in. Use a stable worker port to reopen the same local project. Do not run two workers concurrently against the same profile/instance workspace; native project locks fail safely.

A profile binding cannot change underneath an active workspace; use a new profile or restart the worker. The same native server with different identities requires separate workers rather than reusing a cached authenticated adapter.

After switching selection, clean inactive views with only the service consumer
are released instead of accumulating every visited program/version. Dirty views
and programs retained independently by a GUI remain protected.

The service pins its programs through admitted HTTP work. GUI shutdown drains requests off the EDT, then leaves ProgramManager's save/discard decisions and remaining consumers in control of project closure. Managed mutations reject closed/ownerless programs, native save locks, and active modal GUI dialogs at the actual EDT write boundary. Headless shutdown checks for unsaved work before disabling HTTP; save failures leave the API available. Normal stop timeouts retain the process and state, never force-kill analysis.

## HTTP routes

All routes require `profile`. POST bodies reject unsupported fields and query parameters; GET routes reject unsupported or duplicate query parameters.

| Method | Route | Parameters/body |
| --- | --- | --- |
| GET | `/repositories` | `?profile=ID` |
| GET | `/repositories/files` | `?profile=ID&path=/&offset=0&limit=100` |
| POST | `/repositories/open` | `{"profile":"ID","path":"/program","version":-1}` |
| POST | `/repositories/checkout` | `{"profile":"ID","path":"/program","exclusive":false}` |
| POST | `/repositories/checkin` | `{"profile":"ID","path":"/program","comment":"Reviewed","keep_checked_out":false}` |

Responses use the normal Ghydra response envelope. CLI output follows the existing formatter, including root `--json` selection. Service errors distinguish invalid paths/arguments (`REPOSITORY_PATH_INVALID`), missing entries (`REPOSITORY_NOT_FOUND`), conflicts (`REPOSITORY_CONFLICT`), native read-only policy (`REPOSITORY_READ_ONLY`), missing native APIs (`REPOSITORY_UNSUPPORTED`), and a stopped service (`REPOSITORY_CLOSED`). Profile/authentication/store failures use the shared `CONNECTION_*` codes.
