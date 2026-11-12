# Worker connection profiles

Remote BSim databases and native Ghidra Server repositories are approved by a
**human operator out of band**, not provisioned through MCP or HTTP. A profile
binds one credential identity, backend, endpoint and permission set. Agents send
only a profile ID and an operation; they cannot supply another server or password.
Remote databases and repositories must already exist. Local H2 remains supported.

## Required isolation and supported platform

Run the credential-bearing Ghidra JVM/headless launcher under a **separate OS
principal**, or on a separate POSIX worker, from the agent and its shell tools.
Provision that identity and the authenticated transport using your established
administration procedures. These commands do not create users, run as root,
install services or change host authentication. Never run setup from an agent
terminal, and never paste credentials into chat.

Filesystem permissions cannot hide secrets from a shell, debugger, arbitrary
code, or process inspection running as the **same OS identity** as the worker.
A directory mode of 0700 is not a sandbox. A local agent with the worker's UID
can read `credentials.json`, key files and JVM memory regardless of API redaction.
Do not mount the private store into the agent container or share the worker's UID.
Restrict worker access, process debugging, backups, crash dumps and audit logs.
The operating system/administrator remains trusted; deleted/replaced files do
not guarantee secure erasure from snapshots, storage or memory.
Provision a **fresh private worker home/configuration/state** before the first
start: directories 0700, logs 0600, and an operator shell with `umask 077`.
Native Ghidra messages can contain login identities or private paths; they are
operator-only logs, not agent output. Do not reuse world-readable native logs or
expose their directories through shares, backups, shell access or log collectors.
Changing permissions later does not revoke an already-open file descriptor.

Credential-bearing workers and Python provisioning support isolated POSIX
deployments only. Windows worker setup fails closed because this implementation
does not establish and verify equivalent private Windows ACLs. Windows clients
may access an isolated Linux/macOS worker's bounded HTTP API through an
authenticated transport. Do not work around this check with permissive ACLs or a
shared user account.

## Private storage and explicit configuration

Choose an absolute directory under an existing trusted, nonsymlink parent. Setup
creates only the final directory. The directory must belong to the worker UID and
have mode **0700**; `profiles.json`, `credentials.json` and `.lock` must be owned
by that UID, mode **0600**, regular files with a single hard link. Path traversal,
symlink components, unsafe owners/modes and untrusted writable ancestors are
rejected. Root-owned sticky temporary parents are allowed for synthetic tests;
prefer persistent private storage in deployment. Identity files for SSH/PKI also
must be nonsymlink regular 0600 files in a private 0700 directory.

Operator setup requires `--directory`. Agent-side `ghydra connections list`
instead reads the safe catalog from the selected HTTP worker. Operator setup
does not search `~/.ghydra`, normal CLI configuration, environment variables
or arbitrary credential stores.
The worker JVM selects the same directory with
`-Dghydra.connections.dir=/srv/ghydra-worker/connections`, or its documented
`GHYDRA_CONNECTIONS_DIR` directory setting. That setting carries a **path only**,
never a secret. Keep it fixed in operator-controlled worker configuration.
Set this environment variable or an actual JVM `-D` option **before application
initialization**, then start a fresh JVM. Ghidra application-level `-D` arguments
are processed too late. The TLS module initializer runs before native project
login because the JDK caches RMI socket factories; enabling profiles after a
native connection cannot repair that cache.

The shared JSON contract is:

```json
{"version":1,"default_bsim":"corpus","profiles":{"corpus":{"kind":"bsim","backend":"postgresql","endpoint":"postgresql://db.example:5432/corpus","auth":"password","credential_ref":"opaque-generated-reference","permissions":["query"]}}}
```

`credentials.json` is a separate private document with version 1 and a
`credentials` object keyed by generated references. Password entries hold
`username` and `password`; identity entries hold `username`, `key_store` and
`key_store_password`. It is **worker-only credential storage**, not an ordinary
user config. Do not hand-edit, display, copy into examples, commit or return that
file through MCP/HTTP. References and usernames never appear in the catalog.

Writes use new private temporary files, fsync, atomic replacement and a shared
`.lock` POSIX record lock (compatible with JVM FileChannel locks). Two human
setup processes serialize read-modify-write operations. Credential publication
precedes profile publication; old references are removed afterward. Interrupted
writes can leave an unused credential entry, not a manifest requiring an
unpublished secret. Restart/retry administration under the same lock rather than
manually deleting files. Malformed JSON and native failures must be reported with
fixed sanitized errors, not raw input, URLs or exception strings.

## Endpoint and authentication matrix

| Kind / backend | Approved endpoint | Authentication | Grants |
| --- | --- | --- | --- |
| BSim / `h2` | Absolute local database path, e.g. `/srv/ghydra-worker/corpus` | `none` | `query`, `ingest` |
| BSim / `postgresql` | `postgresql://host[:port]/database` | `password`, `pki` | `query`, `ingest` |
| BSim / `elasticsearch` | `elastic://host[:port]/index` or `https://host[:port]/index` | `password` | `query`, `ingest` |
| Ghidra / `ghidra` | `ghidra://host[:port]/repository` | `password`, `ssh`, `pki` | `read`, `checkout`, `checkin` |

IDs are ASCII `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`. Remote endpoints have a validated
DNS/IP host, an optional port 1–65535 and exactly one database/index/repository
component. Component names use ASCII letters/digits, underscore, dot and hyphen;
`.` and `..` are forbidden. No userinfo, passwords, query strings, fragments,
percent-encoded names, backslashes or traversal are accepted. H2 paths must be
absolute and cannot contain JDBC parameters/traversal. Use a dedicated profile
for each approved endpoint/identity/policy; selection never rewrites global
configuration.

PKI uses a private identity store whose native format and certificate chain are
supported by the installed Ghidra/backend version; setup validates the private
path, not the cryptographic contents. Username explicitly selects the PostgreSQL
role / requested native server identity. PKI store passwords may be empty only
when that is valid for the actual store. SSH uses an unencrypted native-supported
private key: encrypted SSH key passphrases are not supported by the upstream
headless client and are rejected. Protect keys with worker filesystem/process
isolation. Elasticsearch PKI is not offered without confirmed native backend
support; this matrix intentionally does not imply support from an auth label.

## TLS and network boundary

Provision certificates, trust anchors and server-side authentication **before**
creating profiles. Profile-enabled workers enforce strict TLS with JVM default
trusted roots, or an operator-supplied public PEM CA bundle configured as
`-Dghidra.cacerts=/worker/path/ca.pem`. The bundle contains public trust anchors,
not a private identity or password; keep its path and contents operator-controlled.
Server certificates must chain to the configured trusted CA and be valid for the
profile endpoint's hostname. Do not disable certificate or hostname verification,
use trust-all managers or bypass a failed trust check.

Use the installed Ghidra/PostgreSQL native TLS configuration and JVM identity
stores; never put TLS passwords or driver options in a URL, argv or agent
environment. PostgreSQL's native client must enforce encrypted transport and
server certificate/hostname validation. The native Elasticsearch client must use
HTTPS for both `elastic://` and `https://` profile forms; cleartext HTTP
authentication is not permitted. Native `ghidra://` uses Ghidra Server's
authenticated protocol, not an HTTP credential URL. PKI/SSH authentication is not
itself proof of server trust. Test the installed native client/server trust setup
out of band; fail closed on certificate/authentication errors.

Credential workers bind to loopback by default. An explicit
`-Dghidra.mcp.bind.host` or `GHYDRA_BIND_HOST` selects another interface.
Put remote access behind authenticated TLS/mTLS or an authenticated private
tunnel, with firewall rules limiting the agent to that API. Never expose a
credential-bearing worker on an unauthenticated public listener. Protect
endpoint allowlists and server TLS configuration from agent modification.
The profile's endpoint binding is not a substitute for network egress policy,
DNS integrity or server trust.

**Server-side scripts are prohibited on profile-enabled workers.** Both `/scripts`
and `/scripts/run` must be unconditionally blocked even if `allowScripts` is set.
Frontend tool filtering is not a security control: arbitrary server scripts could
read secrets as the worker identity. Do not add shell/script/general-code-execution
features to the broker or grant agents a shell on that worker.

## Human operator commands

Run these in a genuine interactive terminal as the worker identity. Only
nonsecret metadata appears in command arguments. Username, password, private
identity path and PKI store password are prompted **without echo**. There is no
`--password`, `--username`, `--key-store`, secret environment option or MCP setup
tool; piped credential input is rejected.

### Nix and SSHFS checkouts

Run operator provisioning as the worker identity, never through an agent terminal.
If the checkout is on SSHFS and launching `.venv` fails with `Operation not permitted`,
keep the environment on a local filesystem and invoke the CLI module:

```sh
UV_PROJECT_ENVIRONMENT="$HOME/.cache/ghydra-dev-venv" \
UV_LINK_MODE=copy \
nix-shell -p uv python3 --run \
  'uv run --python python3 python -m ghydra.cli --help'
```

Replace `--help` with the `connections --directory ... create ...` commands below.
No password belongs in that command or environment. This changes only the Python
environment location; it does not isolate credentials from an agent with the same UID.
Use Nix's Python rather than a uv-managed interpreter. The hardlink warning alone
is harmless; an SSHFS environment execution/canonicalization error is not.

### Profile provisioning

```sh
# Read-only BSim query identity (database is already provisioned).
ghydra connections --directory /srv/ghydra-worker/connections create corpus \
  --kind bsim --backend postgresql \
  --endpoint postgresql://db.example:5432/corpus --auth password \
  --permission query --default-bsim

# Local H2 needs no credential entry.
ghydra connections --directory /srv/ghydra-worker/connections create local \
  --kind bsim --backend h2 --endpoint /srv/ghydra-worker/local-corpus \
  --auth none --permission query --permission ingest

# Native repository reader; writes must be deliberately granted separately.
ghydra connections --directory /srv/ghydra-worker/connections create repo-reader \
  --kind ghidra --backend ghidra --endpoint ghidra://repo.example:13100/project \
  --auth pki --permission read

ghydra connections --directory /srv/ghydra-worker/connections list
ghydra connections --directory /srv/ghydra-worker/connections inspect repo-reader

# Replace only credentials, preserving endpoint and grants.
ghydra connections --directory /srv/ghydra-worker/connections rotate corpus

# Full replacement must repeat all metadata and prompts for fresh credentials.
ghydra connections --directory /srv/ghydra-worker/connections update corpus \
  --kind bsim --backend postgresql \
  --endpoint postgresql://db.example:5432/corpus --auth password --permission query

ghydra connections --directory /srv/ghydra-worker/connections remove repo-reader
```

`list` returns only ID, kind, backend and grants. `inspect` additionally returns
the credential-free endpoint and auth mode, never a credential reference,
identity, private path or secret. Setup/rotation/removal output is a fixed status
message. Removing the selected default also clears `default_bsim`. Updating the
existing default preserves that selection; `--default-bsim` selects a new one.
Changing that selected default to a non-BSim kind is refused before any store
update. Remove it explicitly first if its kind must change.

Create distinct server identities for query versus ingest and repository readers
versus writers. Native backend ACLs remain mandatory: profile grants only reduce
access, never grant rights missing on the server. `query` gates query/apply/diff;
`ingest` is explicit and never auto-creates remote databases. Repository `read`,
`checkout` and `checkin` are separate operations; saving is not check-in. Grant
only necessary permissions and repository scope. Rotate both the native server
credential and worker entry under an operator-controlled maintenance procedure,
then **restart the credential-bearing worker**: native authentication caches mean
updating the private file alone does not replace an already authenticated identity.
No passwords are shown to verify rotation.

Native identity caches also constrain deployment: use **one native Ghidra identity
per server host:port** and **one PKI certificate per JVM**. Profiles must not be
used to switch identities within those cache boundaries. Run separate isolated
workers/JVMs when different identities or PKI certificates are needed, including
distinct reader/writer identities on the same native Ghidra server.
Native servers that disable username selection must use the worker's native
default username for password/SSH profiles. A mismatch fails before any password
or signature is supplied; an authenticated account must match the profile.
Concurrent native logins with different authentication modes require separate
workers because native SSH-availability callbacks have no endpoint parameter.

## Python interfaces and launcher use

`ghydra.connections` exposes these explicit-directory APIs:

- `catalog(directory)` → list of `{id, kind, backend, permissions}`.
- `load_profile(profile_id, directory, kind=None, permission=None)` →
  `{id, kind, backend, endpoint, auth, permissions}`; enforces the requested kind
  and grant before returning metadata.
- `save_profile(profile_id, directory, *, kind, backend, endpoint, auth,
  permissions, credentials=None, replace=False, default_bsim=False)` → metadata.
- `rotate_credentials(profile_id, directory, credentials)` → metadata.
- `remove_profile(profile_id, directory)` → `None`.

The mutation APIs are **operator implementation interfaces**, not MCP/HTTP
provisioning APIs. The CLI obtains their credentials solely from hidden prompts.
`ConnectionError` is a `ValueError` with a stable safe message and `.code`.

The headless launcher never reads credentials. It starts an empty local worker
project and selects the remote program through opaque-profile HTTP operations;
only the Java worker reads private identities in its native authentication scope.
No native login username, password or identity path enters argv, stdin,
environment or persisted launcher state. Python setup can write/rotate credentials
only as the trusted human operator; it exposes no credential-read interface.
