# Releasing Ghydra

A release is one tag: `vX.Y.Z`. That tag drives two workflows — one per hosting
platform — and both publish the same artifact set.

| Platform | Workflow | Produces |
| --- | --- | --- |
| GitHub | `.github/workflows/release.yml` | GitHub Release: Ghidra 11.x and 12.x builds, `SHA256SUMS`, `bridge_mcp_hydra.py` |
| Forgejo | `.gitea/workflows/release.yml` | Forgejo Release: the same set |

The tag has to reach **both** remotes. A GitHub-hosted runner cannot reach the
Forgejo instance on the local network, so neither platform can publish on
behalf of the other.

## 1. Prepare (local)

```bash
python scripts/prepare_release.py --version 3.1.0
```

This is the step that is easy to get wrong by hand, so the script does it:

- moves the `## [Unreleased]` notes into a dated `## [3.1.0] - <today>` section;
- writes the version into all five places that carry it —
  `ApiConstants.PLUGIN_VERSION`, `bridge_mcp_hydra.py`'s `BRIDGE_VERSION`,
  `pyproject.toml`, `ghydra/__init__.py` and `extension.properties`;
- leaves `API_VERSION` alone — it only moves on breaking API changes;
- re-reads everything and refuses to leave the tree in a state the CI rejects.

It fails loudly if `Unreleased` is empty or the version already has a section.

Use `--dry-run` to see what it would do without writing anything.

## 2. Commit and tag

```bash
git add -A
git commit -m "chore(release): v3.1.0"
git tag v3.1.0
```

## 3. Push the tag to both platforms

```bash
git push github main && git push github v3.1.0
git push forgejo main && git push forgejo v3.1.0
```

The tag push is the trigger. From there everything is automatic: guard, build,
publish, verify.

## What the workflows check

Both platforms run the same guards, from the same scripts, before anything is
built or published:

| Guard | Fails when |
| --- | --- |
| `scripts/version.py --check` | the five version constants disagree, or the plugin's `API_VERSION` and the bridge's `REQUIRED_API_VERSION` disagree |
| `scripts/version.py --check --expect <version>` | the constants do not match the tag |
| `scripts/release_notes.py --version <version>` | `CHANGELOG.md` has no non-empty `## [<version>]` section — this is what used to ship a release with an empty body |

Then, on GitHub:

- `build.yml` is called as a reusable workflow and builds the Ghidra 11.x and
  12.x matrix, stamping each zip with the Ghidra version it targets
  (`Ghydra-…-ghidra12.1.2.zip`);
- the release gets a `SHA256SUMS` file and the bridge script;
- a final step re-reads the release and fails if the assets are missing.

## Re-running a release

If a release half-published, re-run it. Both workflows are idempotent: an
existing release is updated with `--clobber` (GitHub) or left alone (Forgejo)
instead of failing.

```bash
gh workflow run release.yml -f version=3.1.0
```

The `workflow_dispatch` input also accepts `dry_run`, which runs the guards and
the whole build but publishes nothing.

Note that Forgejo cannot delete a tag that already has a release, so a bad
release has to be replaced by a new version rather than by re-tagging.

## After the release

Open a new `## [Unreleased]` section at the top of `CHANGELOG.md` and leave the
version constants alone until the next `prepare_release.py` run — the guard
allows the tree to carry the released version until then.
