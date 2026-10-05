# How a release runs

A release of `arcaeon` is built and uploaded by one GitHub Actions workflow,
`.github/workflows/release.yml`, using PyPI Trusted Publishing. No PyPI API
token is stored anywhere for it. PyPI trusts one thing: this workflow file, in
the `Arcaeon-io/arcaeon` repository, running in a named GitHub environment.
Files uploaded this way carry a PEP 740 attestation that says which workflow
uploaded them.

Releases up to and including 0.9.1 were uploaded with a token from a laptop and
carry no attestation (PyPI shows `provenance: null` for them).

## The jobs

1. **build** (read-only). Checks out the tagged commit and runs the version
   guard, `tools/release_guard.py`: the tag must be exactly `v` + the version in
   `pyproject.toml`, and that must equal `arcaeon.__version__`. If any of the
   three disagree, the run stops here and nothing is built. Then
   `python -m build` makes the sdist and the wheel, `twine check --strict
   dist/*` checks them, and `tools/verify_published.py manifest` writes the
   sha256 of every built file to `release-manifest.json`. The files and the
   manifest are kept as two run artifacts, `dist` and `release-manifest`.
2. **publish-pypi** or **publish-testpypi**. Exactly one runs. It downloads
   the `dist` artifact and hands it to `pypa/gh-action-pypi-publish` with
   `attestations: true`. This is the only kind of job that gets the
   `id-token: write` permission, which is what lets it prove to PyPI who it is.
   It does not check out the repository or run any of its scripts.
3. **verify**. After the upload, in a clean venv, it runs
   `pip download arcaeon==<version> --no-deps` from the index just published to,
   once for the wheel and once for the sdist, and compares each file's sha256
   with the manifest from the build job. See "The verify gate" below.

How a run starts:

- **Push a tag `v*`** (for example `git tag v0.11.0 && git push origin v0.11.0`):
  builds and publishes to the real PyPI.
- **Run it by hand** (Actions, release, Run workflow): choose `testpypi` (the
  default) or `pypi`. A hand-started `pypi` run must be started on a `v*` tag;
  from a branch the version guard refuses it.

## The TestPyPI dry run

TestPyPI is PyPI's practice index. Use it to rehearse before a real release.

1. Set the version to a release candidate in both places, for example
   `0.11.0rc1` in `pyproject.toml` and in `src/arcaeon/__init__.py`. TestPyPI,
   like PyPI, never accepts the same version twice, so each rehearsal needs a
   new rc number.
2. Push that commit, then start the workflow by hand and choose `testpypi`
   (from the branch, or from a `v0.11.0rc1` tag; both are allowed for TestPyPI).
3. The run builds, uploads to `https://test.pypi.org/legacy/` from the
   `publish-testpypi` job (environment `testpypi`), and the verify job
   downloads from `https://test.pypi.org/simple/`.
4. On the TestPyPI file page for the rc, check that the files show provenance.

The local runbook `tools/publish.py` (token-based) still works and still has its
own `--test-pypi` dry run (docs/PUBLISH_DRY_RUN.md). It uploads without
attestations, so it is the fallback, not the normal path.

## The verify gate

`tools/verify_published.py fetch` downloads what the index now serves and
compares it with what the build job built, byte for byte:

- **VERIFIED** (exit 0): every file in the manifest came back with the same
  sha256, and nothing else came back.
- **BROKEN** (exit 1): a file came back with different bytes, or the index
  served a file this run did not build. The run fails. Do not announce the
  release; look at what the index has before anything else.
- **COULD NOT LOOK** (exit 2): a file in the manifest never came back. The
  index can take a little while to serve a new upload, so the gate retries,
  10 attempts 30 seconds apart, before it gives up. The run fails.

The comparison logic runs offline in the test suite (`tests/test_verify_published.py`)
against a local directory standing in for the index.

## How anyone can check an attestation

For a release published by this workflow:

- PyPI's simple JSON index lists a `provenance` link for each file:

  ```
  curl -s -H "Accept: application/vnd.pypi.simple.v1+json" https://pypi.org/simple/arcaeon/
  ```

  A file with `"provenance": null` has no attestation (every release up to
  0.9.1). A file with a URL there has one; that URL is PyPI's Integrity API,
  `https://pypi.org/integrity/arcaeon/<version>/<filename>/provenance`.
- The `pypi-attestations` tool checks the attestation cryptographically and
  checks that it names this repository:

  ```
  pip install pypi-attestations
  pypi-attestations verify pypi --repository https://github.com/Arcaeon-io/arcaeon pypi:arcaeon-<version>-py3-none-any.whl
  ```

  Its authors call the command-line interface experimental; if the syntax has
  moved, `pypi-attestations verify pypi --help` has the current form.
- The PyPI project page shows the same thing per file, under "Provenance".

`pip install` does not check attestations by itself.

## Two settings that are the owner's

The workflow needs two settings that only the owner of the PyPI project and the
GitHub repository can make. The tests never need them. Until they exist, a
release run fails at the publish step (PyPI refuses the upload), and nothing
else is affected: the build, the twine check and every test still run.

1. **PyPI trusted publisher.** On pypi.org: project `arcaeon` -> Manage ->
   Publishing -> Add a new publisher (GitHub): owner `Arcaeon-io`, repository
   `arcaeon`, workflow `release.yml`, environment `pypi`. Then the same on
   test.pypi.org for the `arcaeon` project there, with environment `testpypi`.
2. **GitHub environments.** On GitHub: repository `Arcaeon-io/arcaeon` ->
   Settings -> Environments -> New environment `pypi`, and another named
   `testpypi`. Optionally set "Required reviewers" to the owner, so each upload
   waits for a click.

The old package names (`shims/`) are not published by this workflow. They are
still published separately by `tools/publish.py` with a token, and carry no
attestation unless each gets its own trusted publisher and workflow later.

## Limits: what this cannot prove

- An attestation proves which workflow, in which repository, at which commit,
  uploaded the file. It does not prove the code is safe, correct or free of a
  malicious change that was committed and tagged.
- Trusted Publishing moves the trust onto the GitHub account and this workflow
  file. Someone who controls the account, or can edit `release.yml` and push a
  `v*` tag, can publish. The environment's required reviewer is a pause and an
  audit trail, not a second person, while there is one maintainer.
- The third-party actions are pinned to major-version tags (`actions/checkout@v4`,
  `actions/setup-python@v5`, `actions/upload-artifact@v4`,
  `actions/download-artifact@v4`, `pypa/gh-action-pypi-publish@release/v1`),
  not to commit SHAs. A tag can be moved by the action's owner; a SHA cannot.
  Pinning to SHAs is a later step, done from a machine that can look the SHAs up.
- The verify gate checks one moment: that the index served the bytes this run
  built. It says nothing about what the index serves later.
- No SLSA level is claimed yet. "SLSA Build L2 provenance" may be said only
  after an attested release has actually landed on PyPI and been checked with
  the commands above.
