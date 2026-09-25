# Publishing `io.arcaeon/arcaeon` to the MCP Registry

Prepared 2026-09-24. **Nothing here has been run against the registry.** Every
publish is a public write and waits on Daniel's go.

## What this folder holds

- `server.json`: the registry record for `io.arcaeon/arcaeon` 0.9.1, pointing at
  the PyPI package `arcaeon` 0.9.1, started as `arcaeon mcp`.
- `server.schema.2025-12-11.json`: a copy of the schema the record names
  (`https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json`,
  fetched 2026-09-24), so `tests/test_registry_entry.py` validates offline.

## Two things to settle before publishing

1. **The repository URL is a placeholder.** This code has no public repo yet
   (`git remote -v` in this repo prints nothing). `server.json` says
   `https://github.com/PLACEHOLDER-no-public-repo-yet/arcaeon`. Before publishing,
   either replace it with the real repo URL or delete the whole `repository`
   block (the field is optional). Publishing the placeholder would put a dead
   link on the public listing. The old listings point at
   `https://github.com/dan8433-user/ledger`, which does not hold the merged code.
2. **The runtime argument `--with mcp>=2.0.0,<3`.** The base package has no
   dependencies, and `arcaeon mcp` exits 2 without the MCP SDK (checked
   2026-09-24: the 0.9.0 wheel in a fresh venv printed
   `arcaeon mcp needs the MCP Python SDK: pip install 'arcaeon[mcp]'`, exit 2;
   after `pip install "mcp>=2.0.0,<3"` in the same venv, `arcaeon mcp --tools`
   listed 9 free and 2 paid tools, exit 0). A client that runs the record as
   `uvx arcaeon mcp` would get the exit-2 message. So the record adds
   `runtimeHint: "uvx"` plus the named runtime argument `--with mcp>=2.0.0,<3`,
   which a client renders as `uvx --with "mcp>=2.0.0,<3" arcaeon mcp`. Not
   tested through `uvx` itself (uv is not installed on this machine), and
   clients that ignore `runtimeArguments` will still hit the exit-2 hint. The
   other fix is in the package (make `arcaeon mcp` work on the base install);
   that is a design change to the zero-dependency base and is not made here.

## Order

1. **PyPI first.** The registry stores metadata only; it points at the PyPI
   package and checks it at publish time. It fetches
   `https://pypi.org/pypi/arcaeon/0.9.1/json` and looks for the exact string
   `mcp-name: io.arcaeon/arcaeon` in that version's description (the rendered
   README). The marker is now in `README.md` as a hidden comment, line 3:
   `<!-- mcp-name: io.arcaeon/arcaeon -->`. **0.9.1 must be built from a commit
   that has that line** (it does: README.md line 3). PyPI versions are
   immutable: a version that goes up without it can never be listed.
   `tools/publish.py --upload` handles the PyPI side (main package, then the 13
   shims); its closing notes list this registry step as next.
2. Confirm the marker is live (read-only):
   ```bash
   curl -s https://pypi.org/pypi/arcaeon/0.9.1/json | py -c "import json,sys; d=json.load(sys.stdin)['info']['description']; print('MARKER FOUND' if 'mcp-name: io.arcaeon/arcaeon' in d else 'MARKER MISSING')"
   ```
3. Confirm the domain proof is still served (read-only):
   `curl -s https://arcaeon.io/.well-known/mcp-registry-auth` should print a
   `v=MCPv1; k=ed25519; p=...` line.
4. Then the registry, below.

## The publish command the old entries used

`io.arcaeon/ledger` and `io.arcaeon/adapter` were published with the
`mcp-publisher` CLI (v1.8.1; the mcp-publisher binary, wherever it is installed),
logging in by **domain (HTTP) auth** for `arcaeon.io`, not GitHub (the
adapter listing has been live since 2026-09-23). From this folder, in Git Bash:

```bash
PUB=mcp-publisher   # the mcp-publisher binary, wherever it is installed
$PUB validate server.json          # schema check via the registry's validate endpoint; publishes nothing
$PUB login http --domain arcaeon.io --private-key "$PRIVATE_KEY"
$PUB publish server.json
curl -s "https://registry.modelcontextprotocol.io/v0.1/servers/io.arcaeon%2Farcaeon/versions"
```

What it needs, by name only:

- the Ed25519 private key for the `io.arcaeon` namespace, the file
  kept in the maintainer's private secrets directory, outside this repo,
  hex-decoded into the shell variable `PRIVATE_KEY` just for the login
  (`openssl pkey -in <key.pem> -noout -text` prints the `priv:` hex). It is never written into any file here and never printed.
- the matching public key served at `https://arcaeon.io/.well-known/mcp-registry-auth`.
- the saved registry session, `~/.config/mcp-publisher/token.json`, which the
  login refreshes. A stale one gives `401 Invalid or expired Registry JWT token`,
  and the 1.8.1 binary has been seen to print that and still exit 0, so read the
  output, and do the read-back in the last line.

`validate` checks the schema only. It passed an adapter record whose PyPI
version did not exist yet; the PyPI ownership check runs only at publish.

## The two old listings

Live on 2026-09-24 (read-only GET of `/v0.1/servers/<name>/versions`):

- `io.arcaeon/ledger`: 0.5.1, 0.5.3, 0.5.6 (latest), all `active`. PyPI has
  moved on to 0.8.0; the registry never followed.
- `io.arcaeon/adapter`: 0.1.4, 0.2.0 (latest), both `active`.

The connector's own record (`io.github.arcaeon-io/arcaeon`, in the old
connector project's `server.json`) was never published: the
registry returns 404 for it. There is no third listing to retire.

What the registry allows (its FAQ,
`docs/modelcontextprotocol-io/faq.mdx`, and `mcp-publisher status --help` on
the local 1.8.1 binary):

- **Versions are immutable.** A published version's metadata cannot be edited.
  A change is a new `server.json` with a new version string.
- **Status per version or all versions: `active`, `deprecated`, `deleted`**,
  with an optional message:
  `mcp-publisher status --status deprecated --message "..." <name> <version>`
  or `--all-versions` in place of the version. `deleted` hides the entry from
  default listings (still readable with `include_deleted=true`) and can be set
  back to `active`. Nothing is ever removed for good.
- There is no field that points one listing at another. The pointer can only
  be the status message, or a new version whose description says where to go.

Suggested, for Daniel's call (both need the same login as above, after the new
listing is live and reads back):

```bash
$PUB status --status deprecated --all-versions --message "Merged into io.arcaeon/arcaeon (PyPI: arcaeon). Run: arcaeon mcp" io.arcaeon/ledger
$PUB status --status deprecated --all-versions --message "Merged into io.arcaeon/arcaeon (PyPI: arcaeon). The adapter ships inside it." io.arcaeon/adapter
```

`deprecated` rather than `deleted`: the old packages still install (their last
shim versions depend on `arcaeon>=0.9,<1`), so existing users are better served
by a visible "moved" note than by the listing vanishing. `--all-versions` asks
for confirmation (`--yes` skips it). Leaving them `active` is also allowed; the
cost is two listings that describe the old split.

## Pre-flight checklist

- [ ] Daniel's go on the publish.
- [ ] `repository` replaced with the real repo, or removed.
- [ ] `py -m pytest -q tests/test_registry_entry.py` green.
- [ ] `server.json` `version` and `packages[0].version` equal the PyPI version.
- [ ] PyPI 0.9.1 live; the step 2 check prints `MARKER FOUND`.
- [ ] Step 3 prints the `v=MCPv1; k=ed25519; ...` line.
- [ ] `mcp-publisher validate server.json` prints valid.
- [ ] After publish, the read-back lists 0.9.1 as `active`, `isLatest: true`.
- [ ] Then, if agreed, deprecate the two old listings and read them back.
