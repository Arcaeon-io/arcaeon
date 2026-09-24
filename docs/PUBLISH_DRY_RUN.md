# TestPyPI dry run

A rehearsal of the release on TestPyPI, the practice copy of PyPI. Nothing
here touches the real PyPI.

**No upload happens without the owner's go.** Steps 1 to 3 are local and safe
to run any time. Step 4 is a public write (TestPyPI is public too), so it waits
for the owner to say go, like every publish. Steps 5 and 6 only read.

Run from the repo root, in Git Bash. `py` is
the Windows Python launcher; on another machine use `python3`.

## Credentials

Env var names only. Never paste a token into a command line, a file in this
repo, a log, or a chat.

- `TWINE_USERNAME`: the literal string `__token__` (the way PyPI API tokens
  log in).
- `TWINE_PASSWORD`: a TestPyPI API token. It is not the PyPI token: TestPyPI
  is a separate site with separate accounts. The owner creates one at
  test.pypi.org (Account settings, API tokens) and stores it in the machine's
  `.env` as `TESTPYPI_TOKEN`. As of 2026-09-24 that entry does not exist yet;
  the `.env` holds only `PYPI_TOKEN`, which is for the real PyPI and must not
  be used here.

Set them for one command only, reading the token from the env, so it never
appears in shell history:

```bash
TWINE_USERNAME=__token__ TWINE_PASSWORD="$TESTPYPI_TOKEN" py -m twine upload ...
```

## The script

`tools/publish.py` runs the release runbook end to end. Its default is a dry
run: it uploads nothing.

```bash
py tools/publish.py                        # dry run against PyPI's plan
py tools/publish.py --test-pypi            # dry run against TestPyPI's plan
py tools/publish.py --upload --i-mean-it   # the real thing. OWNER'S GO REQUIRED.
```

Each step prints one line, a check mark or the failure, and it stops at the
first failure (exit 1):

1. The git tree is clean and on `main`; prints the tip hash.
2. The version in pyproject.toml, `arcaeon.__version__` and what
   `arcaeon version --short` prints from a fresh build all agree, and every
   `shims/*/pyproject.toml` depends on `arcaeon>=0.9,<1` (extras allowed).
3. `tests/test_no_private_paths.py` and `tests/test_docs.py` pass.
4. Builds the sdist and wheel into a clean `dist/` and each shim wheel into
   `dist/shims/`, then `twine check` on all 15 (the shims warn about having no
   README; that is expected).
5. Installs the wheel into a fresh venv and runs `arcaeon selftest`,
   `arcaeon version --short` and the README's first-run commands, checking
   VERIFIED then BROKEN exactly as the README shows.
6. Scans every artifact for private names, home-directory paths and `.env`
   (as a word, so `os.environ` does not count). One reviewed mention is
   allowlisted: vet's own comment describing the `.env`-shaped line it hunts.
7. The upload order. A dry run prints it; `--upload` does it: the main package
   first, then it polls `pip download arcaeon==<version> --no-deps` for up to 5
   minutes until the index serves it, then the 13 shim wheels. Then it prints
   what is not its job: the MCP registry entry (`packageArguments: ["mcp"]`),
   the site's `products.yaml` flip to shipped plus `py site.py build` and the
   deploy, and the read-back (`pip install arcaeon` in a fresh venv, then
   `arcaeon version`).

`--upload` refuses (exit 2, nothing runs) unless `--i-mean-it` is also given
and the token is present by name: `PYPI_TOKEN`, or `TESTPYPI_TOKEN` with
`--test-pypi`, in the environment or the repo's `.env`. The script puts it in
the twine subprocess's env as `TWINE_USERNAME=__token__` / `TWINE_PASSWORD`
and never prints it. `--branch` lets a dry run rehearse on another branch;
`--upload` only runs on `main`.

The checklist below is the same runbook by hand.

## Checklist

- [ ] **1. Start clean.** On the branch being released, tests green, nothing
  uncommitted.

  ```bash
  git status --short
  py -m pytest tests -q
  ```

- [ ] **2. Build the sdist and the wheel** into a folder outside the repo.

  ```bash
  rm -rf /tmp/arcaeon-dist
  py -m build --outdir /tmp/arcaeon-dist .
  ```

  Expect: `Successfully built arcaeon-0.9.0.tar.gz and arcaeon-0.9.0-py3-none-any.whl`.

- [ ] **3. Check the metadata** (README renders, required fields present).

  ```bash
  py -m twine check /tmp/arcaeon-dist/*
  ```

  Expect `PASSED` for both files.

- [ ] **4. Upload to TestPyPI. OWNER'S GO REQUIRED.** Do not run this step
  until the owner has said go for this upload.

  ```bash
  TWINE_USERNAME=__token__ TWINE_PASSWORD="$TESTPYPI_TOKEN" \
    py -m twine upload --repository-url https://test.pypi.org/legacy/ /tmp/arcaeon-dist/*
  ```

  A version number can be uploaded once. If 0.9.0 is already on TestPyPI, bump
  to a dev version (for example `0.9.0.dev1`) in pyproject.toml and
  `src/arcaeon/__init__.py` for the rehearsal, and do not commit that bump.

- [ ] **5. Install from TestPyPI into a fresh venv.** `--no-deps` is safe
  because the base install has zero dependencies; it also stops pip pulling a
  look-alike package from TestPyPI.

  ```bash
  rm -rf /tmp/arcaeon-venv
  py -m venv /tmp/arcaeon-venv
  /tmp/arcaeon-venv/Scripts/python -m pip install --no-deps \
    --index-url https://test.pypi.org/simple/ arcaeon==0.9.0
  /tmp/arcaeon-venv/Scripts/python -m pip list
  ```

  (On Linux or macOS the venv's folder is `bin/`, not `Scripts/`.) Expect
  `pip list` to show `arcaeon` and `pip`, nothing else.

- [ ] **6. Run it.**

  ```bash
  /tmp/arcaeon-venv/Scripts/arcaeon selftest
  /tmp/arcaeon-venv/Scripts/arcaeon version
  ```

  Expect `selftest` to exit 0 with `"failed": []`, and `version` to print
  `arcaeon 0.9.0` followed by one line per part.

- [ ] **7. Write down what happened**: the TestPyPI URL, the two commands'
  last lines, and anything that differed from this page. Then fix this page.

## Already rehearsed locally (no upload)

On 2026-09-24, steps 2, 3 and 6 were run against a local build: `build`
produced both files, `twine check` said PASSED for both, and a fresh venv that
installed the local wheel had only `arcaeon` and `pip` in it, `arcaeon
selftest` returned `"failed": []`, and `arcaeon version` printed `arcaeon
0.9.0`. Steps 4 and 5 have not been run.

## After the dry run

The real release (PyPI, then the 13 shims, then the registry entry with
`packageArguments: ["mcp"]`) is a separate step with its own go. This page
does not cover it.
