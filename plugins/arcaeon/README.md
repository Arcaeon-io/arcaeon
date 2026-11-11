# Arcaeon

This plugin adds the Arcaeon MCP server to Claude Code. The server comes from
the `arcaeon` Python package, version 0.10.0. It is the same server that
`pip install "arcaeon[mcp]"` and then `arcaeon mcp` start, and the source is in
this repository under the MIT license.

The server keeps a record of what an agent did that the agent cannot quietly
rewrite. Every row is hash-chained to the row before it, so a changed, deleted
or swapped row shows up as a break at the line where it happened. Anyone you
hand the file to can run the same check without asking you for anything.

It also scans the source of a Python MCP server before you connect to it, and
keeps deal terms, mandates and second readings on the same kind of chained
ledger.

What a check does not prove: it says a record was not altered after it was
written. It does not say the record is true, or who wrote it.

## What you need

The plugin starts the server on stdio with this command:

```console
uvx --from "arcaeon[mcp]==0.10.0" arcaeon mcp
```

So you need [uv](https://docs.astral.sh/uv/), which provides `uvx`, and
Python 3.10 or newer (uv can fetch one for you). On the first start, uvx
downloads `arcaeon` 0.10.0 from PyPI with its `[mcp]` extra. The extra pulls
in the MCP Python SDK and its dependencies, about 30 packages. uv keeps them in
its cache for later starts.

This is a local server. It runs in Claude Code, and in Cowork in the Claude
Desktop app on your own machine. It does not run in claude.ai in a browser.

## Install from this repository

```console
claude plugin marketplace add Arcaeon-io/arcaeon
claude plugin install arcaeon@arcaeon
```

Then run `/mcp` in a session. The server shows as `plugin:arcaeon:arcaeon`.

## Tools

Seventeen tools are free and need no key:

- `ledger_append`: add one action record to the hash-chained log.
- `ledger_verify`: check the chain over the log.
- `ledger_prove_my_conduct`: log a batch of things the agent just did to its
  own ledger.
- `ledger_verify_peer_ledger`: check a ledger that another agent exported.
- `ledger_declare_break`: record that your own ledger was written to out of
  band.
- `vet_scan`: statically scan a Python MCP server source file.
- `vet_grade`: grade a Python MCP server source file.
- `vet_audit_verify`: check the chain over the vet tools' own call record.
- `deal_mandate`, `deal_commit`, `deal_dispute`: record a buyer's mandate and
  the agreed terms on each party's ledger, then compare the two ledgers. They
  record. They move no money and enforce nothing.
- `mandate_check`: say whether one call is inside a mandate file. It blocks
  nothing.
- `second_read_submit`, `second_read_compare`: file your own reading of a
  claim, and line up two sets of readings. No model is called.
- `evidence_pack_build`, `evidence_pack_verify`: build a folder of evidence for
  one agent and one time window, and verify a pack someone handed you.
- `arcaeon_status`: versions, the free and paid split, whether a key is set,
  and where the files are. Call it first if a tool refused you.

Two tools need a key:

- `witness_pin`: record your ledger head with the hosted witness, a party you
  cannot advance. This is what catches a log that was cut short, which a hash
  chain alone cannot.
- `witness_renew`: restate an unchanged head so a finished log does not look
  abandoned.

A pin shows the log was not cut short only relative to what the witness saw,
and only as of the last pin.

## The key

The two witness tools read a witness key from the `ARCAEON_KEY` environment
variable of the server process. This plugin does not ask for a key, store one
or set one. Without a key, those two tools send nothing and answer with a short
note on how to get one. Prices and plans are at https://arcaeon.io/pricing.

The server runs with the same environment variables as your other MCP servers.
So if `ARCAEON_KEY` is already set where Claude Code runs, the two witness
tools will use it.

The key is a bearer key. Anyone who holds it can pin and renew in your name.
Treat it like a password.

## What it writes on your machine

- A ledger, `agent.log.jsonl`, in the folder the server starts in, with
  per-namespace ledgers in a `ledgers` folder beside it. `ARCAEON_LEDGER_LOG`
  sets another path.
- Its own call record, `arcaeon.calls.jsonl`, beside the ledger. Each tool call
  adds one row with the tool name, the UTC time, a sha256 digest of the
  arguments and the outcome. The arguments themselves are not copied.
- When you use `vet_scan` or `vet_grade`, a call record for the vet tools at
  `~/.mcp_vet/audit.jsonl`. `MCP_VET_AUDIT_LEDGER` sets another path.
- Files at the paths you or Claude give a tool, such as a deal ledger or an
  evidence pack folder.

The tools read the files at the paths they are given. `MCP_VET_SCAN_ROOT`
limits what the vet tools may read to one folder. `arcaeon_status` shows the
exact paths in use.

## What it sends over the network

- On the first start, uvx downloads the packages from PyPI.
- `witness_pin` and `witness_renew`, only when a key is set: one HTTPS request
  to https://witness.arcaeon.io with the namespace, the row count and the chain
  hash of your ledger head, and the key in the Authorization header. No file
  content is sent.
- `evidence_pack_verify`, only when you set `remote` to true: an HTTPS request
  to the same witness for each remote pin in the pack, looking the pin up by
  namespace, row count and chain hash. No key is sent.

No other tool opens a network connection. `ARCAEON_WITNESS_URL` points these
requests at another witness, such as one you run yourself.

## License

MIT. See [LICENSE](LICENSE).
