# Gateways: verify a sealed tool result before the model reads it

An MCP gateway sits between the AI client and the tool servers. Two of them
have a hook that sees a tool's result after the call and before the model
does: Lasso mcp-gateway (`process_response`) and Docker MCP Gateway (`after:`
interceptors). arcaeon plugs into that hook. If the server sealed its result,
arcaeon checks the seal and applies the gate. If it did not, the result reads
COULD NOT LOOK.

**The gate is on by default.** With no setting it blocks: act, pay and
irreversible are refused on anything not VERIFIED. To opt out of blocking, set
`ARCAEON_GATE_MODE=warn` (or `"enforce": "warn"` in the config). In warn mode
the result is let through and its verdict says "would refuse in block mode".
There is no "off". The mode is read in this order: the config's `enforce`,
then `ARCAEON_GATE_MODE`, then the cached signed latest.json `block_after`
(read from the cache, never fetched), then block.

## Where the bundle rides

MCP 2026-07-28 gives every result and every content block an optional `_meta`.
arcaeon uses its own vendor prefix:

| key | where | holds |
|---|---|---|
| `dev.arcaeon/bundle` | `content[i]._meta` | the envelope (`arcaeon envelope seal`'s FILE.envelope.json object, or that object as a JSON string) sealing that block's bytes |
| `dev.arcaeon/bundle` | `result._meta` | the same, sealing the result's one content block (only when there is exactly one) |
| `dev.arcaeon/verdict` | `result._meta` | what arcaeon decided: `verdict`, `decision`, `action`, `tool`, `reason`, `reasons`, `could_not_check`, `would_refuse`, `warning`, `enforce_mode`, `enforce_source`, `enforce_detail`, `audience`, `deal`, `purpose`, `at`, `honest_limits`, and `parts` when more than one thing was checked |

The bytes a block offers: a text block's `text` as UTF-8; an image or audio
block's base64-decoded `data`; an embedded resource's `resource.text` as UTF-8,
or its base64-decoded `resource.blob`. A `resource_link` holds a link, not
bytes, so it reads COULD NOT LOOK.

Everything the model would read must be covered. That means every content
block is sealed, and `structuredContent`, if present, is the same JSON as one
sealed text block. MCP itself says a tool returning structured content SHOULD
also return it as serialized JSON in a text block. Anything left uncovered is
COULD NOT LOOK. If any part is BROKEN, the whole result is BROKEN.

## What happens to the result

| verdict | read | act, pay, irreversible |
|---|---|---|
| VERIFIED | passes | passes (needs `deal` and `purpose` in the config, else COULD NOT LOOK) |
| COULD NOT LOOK (no bundle, unsigned, a key you did not name, uncovered content) | passes | refused |
| BROKEN | refused | refused |

A pass leaves the result as it was and adds `_meta["dev.arcaeon/verdict"]`. A
refusal replaces the result with a normal MCP error result: `isError: true`
and one text block, `REFUSED by arcaeon: <word>. <reason> The tool's output
was withheld and not shown.` The tool's own content, structuredContent and
_meta are dropped, so none of it reaches the model. `resultType` is kept.
Warn mode turns every refusal into a pass that carries `warning`.

## Which action a tool result stands for

The receiver decides this, never the server. Set it per tool in the config's
`tools` map. Lasso looks up `"server/tool"` first, then `"tool"`. A tool that
is not listed gets `default_action`, which is **`act`** unless you change it.
That default fails closed: an unlisted tool's output is refused unless it is
VERIFIED and bound to your deal and purpose. List read-only tools as `read`
when an unsealed answer is acceptable for them.

## Config

One JSON object, used by both kits:

```json
{
  "audience": "agent-1",
  "signers": ["did:key:z6Mk..."],
  "deal": "d-7f3a",
  "purpose": "lookup",
  "enforce": null,
  "default_action": "act",
  "tools": {
    "search": "read",
    "payments/transfer": {"action": "pay", "deal": "d-9001", "purpose": "refund"}
  }
}
```

`audience` is who you are. `signers` are the keys whose seals count. `deal`
and `purpose` name the exchange. `enforce` is `"warn"`, `"block"` or null
(null means the order above). An unknown key, an unknown action word or an
unknown `enforce` word is a config error. The gateway is refused at load,
never quietly at call time.

## Lasso mcp-gateway (L4-02)

Lasso's plugins subclass `GuardrailPlugin` and register by name. Enable this
one with `-p arcaeon`:

```
pip install arcaeon[sign] mcp-gateway
export ARCAEON_GATEWAY_CONFIG=/path/to/arcaeon-gateway.json
mcp-gateway --mcp-json-path ~/.cursor/mcp.json -p arcaeon
```

The plugin is `arcaeon.connect.lasso.ArcaeonGuardrailPlugin` (plugin_name
`arcaeon`). `load(config)` reads the file named by `ARCAEON_GATEWAY_CONFIG`
and lays the dict Lasso passes over it, key by key. `process_request` passes
the arguments through unchanged. `process_response` runs the check above on
tool results; prompts and resources pass untouched. Lasso is not a dependency:
if it is not installed, a local shim stands in so the module still imports.

Not yet confirmed: how Lasso discovers a plugin from an installed package, and
whether it passes per-plugin config to `load`. The plugin was tested against
fixture responses in the hook shapes Lasso's plugins README documents. It has
not been run inside Lasso. Lasso's last release predates MCP 2026-07-28.

## Docker MCP Gateway (L4-03)

Docker MCP Gateway runs `after:` interceptors on every tool call. An `exec`
interceptor gets the tool-call response JSON on stdin, and whatever it prints
on stdout becomes the response:

```
docker mcp gateway run --interceptor 'after:exec:arcaeon gate mcp-after --config /cfg/arcaeon-gateway.json'
```

`arcaeon gate mcp-after` is the same command as `python -m
arcaeon.connect.docker_after`. Options:

- `--config FILE`: the config above. Default: `$ARCAEON_GATEWAY_CONFIG`, else an
  empty config, which holds every result to `act` with no signer named.
- `--tool NAME`: which tool's entry in `tools` applies.
- `--action WORD` and `--enforce warn|block`: override the config.

It accepts these on stdin:

| stdin | what happens |
|---|---|
| a CallToolResult | checked, printed back (passed or replaced) |
| a JSON-RPC response `{"jsonrpc", "id", "result"}` | its `result` checked and replaced in place; `jsonrpc` and `id` kept |
| `{"request": ..., "response": ...}` | `response` checked; the tool name read from `request.params.name` |
| a JSON-RPC error `{"jsonrpc", "id", "error"}` | passed through unchanged: there is no tool result to check |
| empty, not UTF-8, not JSON, a duplicate key, not an object, over 32 MiB | a COULD NOT LOOK refusal result |

The gateway always gets JSON back. For any stdin the exit code is 0. Bad
arguments or an unreadable config still print a refusal result, but exit 2,
with the reason on stderr. Each call writes one line to stderr naming the
verdict, the decision, the action and the mode, for the gateway's log.

The tool name comes from `--tool`, or from the input when it carries the
request. If the gateway hands neither, every result is held to
`default_action`. Not yet confirmed: the exact JSON Docker's gateway puts on
stdin, whether it includes the tool name, and how it splits the `exec:`
command line. This was tested with a subprocess against fixture JSON, not
inside Docker.

## What this cannot tell you

- It verifies only what the server sealed: these bytes, unchanged since a key
  you named sealed them, labeled for you and in date. It does not judge whether
  the content is true or safe. A server can seal a lie honestly.
- A server that seals nothing always reads COULD NOT LOOK. This kit adds no
  seal of its own and cannot make an unsealed server's output VERIFIED.
- A JSON-RPC error carries no tool result, so the Docker interceptor passes it
  through unchanged. Its message text is the server's own and is not checked.
- Only the key's word counts. A server's self-reported name (`serverInfo`)
  is not checked and does not count.
- Some gateways may strip `_meta` keys they do not know. In that case the
  result reads COULD NOT LOOK (fail closed), not VERIFIED. Run a sealed round
  trip through your gateway before relying on it.
