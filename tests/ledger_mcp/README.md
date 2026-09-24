<!-- mcp-name: io.arcaeon/ledger-mcp -->

# arcaeon-ledger-mcp

**MCP server for [arcaeon-ledger](https://pypi.org/project/arcaeon-ledger/) — give any MCP agent a tamper-evident, hash-chained action log it can create, append to, and verify.**

Observability tools show you what your agent did. A ledger lets you _prove_ it:
every record is hash-chained to the one before it, so an edit, deletion, or
reorder anywhere in the history breaks every later link and `verify` names the
exact line. This package exposes that library over the Model Context Protocol,
built on the official MCP Python SDK.

## Tools

| Tool | Does | Returns |
| --- | --- | --- |
| `ledger_create(path)` | Open / report a ledger at a path (never overwrites; creation is lazy on first append). | `{path, exists, rows, verified, first_break}` |
| `ledger_append(path, record)` | Append one JSON action record, hash-chained to the prior row. | `{ok, chain, path}` |
| `ledger_verify(path)` | Verify the whole chain; name the exact first broken line if any. | `{ok, rows, chained, prechain, first_break}` |

## What it proves — and what it does not

- **Proves:** the log file was not **altered** after each row was written. Edit a
  row, delete one, or reorder history, and `ledger_verify` fails and points at
  the exact line.
- **Does NOT prove:** that the logged action was correct, wise, or truthful at
  write time — only that, once written, the entry stands unchanged. It also does
  not by itself stop a full rewrite of the chain from a chosen point forward; for
  that, anchor the head somewhere you don't control (a commit, a timestamp
  service, a witness).

## Install & wire in

```bash
pip install arcaeon-ledger-mcp
```

MCP client config (e.g. Claude Code `.mcp.json`):

```json
{
  "mcpServers": {
    "arcaeon-ledger": {
      "command": "python",
      "args": ["-m", "arcaeon_ledger_mcp.server"]
    }
  }
}
```

The server speaks MCP over stdio. Every tool takes an explicit `path`, so one
server instance can manage any number of ledger files.

## Relationship to `io.arcaeon/ledger`

`arcaeon-ledger` already ships a zero-dependency, hand-rolled MCP server
(published as `io.arcaeon/ledger`). This package is the **official-SDK**
implementation of the same free tools. Pick one listing before publishing — do
not register two servers for the same capability under colliding names.

MIT.
