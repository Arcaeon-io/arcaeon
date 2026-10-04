# mcp-scan tool-hash adapter (D060 / TE-33)

`arcaeon.prove.mcp_scan` reads the JSON that mcp-scan (Invariant Labs, now Snyk
Agent Scan) prints, records one relayed row per scanned MCP tool with a digest of
the tool definition it scanned, and later answers one question: is the tool an
agent is about to call the same definition mcp-scan reported scanning?

Library only. This base has no `arcaeon connector` group (the connector package
lives on branch d011-connector-adapter), so there is no verb yet. Stdlib only.

```python
from arcaeon.prove.mcp_scan import ingest, verify_tool_called

rows = ingest(scan_json_bytes)                  # never raises; one row per tool
for row in rows:
    ledger.append(row)                          # chain rows like any other
verify_tool_called(tool_definition, rows)       # VERIFIED / BROKEN / COULD NOT LOOK
verify_tool_called(tool_definition, rows, server="weather")
```

## Sources (fetched 2026-10-04, HTTP GET only)

No WebFetch tool was available, so each file was fetched with `curl -sSL` (GET,
read only, nothing installed, nothing posted). The repository
`invariantlabs-ai/mcp-scan` now redirects to `snyk/agent-scan`
(`https://api.github.com/repos/invariantlabs-ai/mcp-scan` answered
`"full_name": "snyk/agent-scan"`), and the package is now `snyk-agent-scan`.

| URL | What it showed |
| --- | --- |
| https://raw.githubusercontent.com/invariantlabs-ai/mcp-scan/main/README.md | Renamed "Snyk Agent Scan". The CLI output "is experimental and may change without notice between releases"; v0.5.x is "planned for deprecation"; `--json` "Emit JSON; the response schema depends on the CLI version". |
| https://raw.githubusercontent.com/invariantlabs-ai/mcp-scan/main/docs/json-output.md | The two JSON shapes this adapter reads (below), the `Issue.reference` `[server_index, entity_index]` rule, the `ScanError` fields, the X001 to X009 failure codes, and that v0.6 `inspect --json` "never contacts the analysis API". |
| https://api.github.com/repos/invariantlabs-ai/mcp-scan/git/trees/main?recursive=1 | Current source is `src/agent_scan/`; no storage or whitelist module. `models/__init__.py`, `utils.py`, `cli.py`, `inspect.py` and `run.py` on main were also fetched: none hashes a tool. |
| https://raw.githubusercontent.com/invariantlabs-ai/mcp-scan/main/src/agent_scan/models/mcp.py | `ServerSignature` holds `prompts`, `resources`, `resource_templates`, `tools` (MCP SDK `mcp.types.Tool`), and `entities` = prompts + resources + resource_templates + tools. No hashing. |
| https://raw.githubusercontent.com/snyk/agent-scan/v0.5.17/src/agent_scan/models.py | Same `entities` order in the last v0.5 release; no `hash_entity`, no `md5`. |
| https://raw.githubusercontent.com/snyk/agent-scan/v0.3.0/src/mcp_scan/models.py | `hash_entity(entity)` = `md5(entity.description.encode()).hexdigest()`, None when there is no description. |
| https://raw.githubusercontent.com/snyk/agent-scan/v0.3.0/src/mcp_scan/StorageFile.py | Tool pinning: `check_and_update` compares the stored hash to the new one ("Entity %s has changed since last scan"); the whitelist maps `"{type}/{name}"` to that hash and `is_whitelisted` checks `hash in self.whitelist.values()`. |
| https://raw.githubusercontent.com/snyk/agent-scan/v0.3.30/src/mcp_scan/models.py | `hash_entity` now substitutes `"no description available"` for a missing description; same md5 over the description only. |
| https://raw.githubusercontent.com/snyk/agent-scan/v0.3.30/src/mcp_scan/MCPScanner.py | A changed hash is reported as issue `W003`, message `"Entity has changed. ..."`, `reference=(server_idx, entity_idx)`. |
| https://raw.githubusercontent.com/snyk/agent-scan/v0.4.18/src/agent_scan/models.py | No `hash` anywhere: the pin was gone by v0.4.18. |
| https://raw.githubusercontent.com/invariantlabs-ai/mcp-scan/main/docs/issue-codes.md | Current codes (E001 prompt injection in tool description, E002 tool shadowing, W0xx); W003 to W006 are no longer listed (json-output.md calls them v0.5.x "internal hints"). |

Not fetched: the PyPI package, release binaries, `docs/risks.md`,
`docs/failure-codes.md`, and any tag between v0.3.30 and v0.4.18 (so the exact
release that dropped the md5 pin is not known). The fixtures in
`tests/fixtures/mcp_scan/` are built from the documented shapes above, not
captured from a real run: no mcp-scan was installed or run.

## What mcp-scan prints, and what this reads

**v0.5.x scan and inspect** (and v0.6 `inspect`): an object keyed by absolute
path; each value is a `ScanPathResult` `{client, path, error, servers, issues,
labels}`; each server is `{name, config_path, server, signature, error}`;
`signature.tools[]` are MCP tool definitions (`name`, `description`,
`inputSchema`, ...). Issues point at a tool by `reference: [server_index,
entity_index]`, where entity_index counts prompts, then resources, then resource
templates, then tools. The adapter computes that offset.

**v0.6+ scan**: `{"scan_path_responses": [{client, path, server_risks,
skill_risks, error}]}`; each server risk lists `entities` by **name and type
only** and `risk_indexes` keyed by risk name with optional `affected_tools`
(indexes into `entities`). There is no description and no schema, so a v0.6 scan
row carries `tool.digest: null` and can never make `verify_tool_called` say
VERIFIED. Run `inspect --json` (or v0.5 `--json`) to get definitions.

Skills (`skill_risks`, `skills`) are not tools and are not read.

mcp-scan's JSON publishes **no hash of any kind**. Its old pin (md5 of the
description, v0.3.x) lived in its local storage file, never in `--json` output.

## The row

Same field names as `arcaeon.connector.core` on d011-connector-adapter
(7fea54d), restated self-contained here because that module is not on this base:
`kind: "check.verdict.relayed"`, `relayed: true`, `checked_by_us: false`,
`vendor: {"name": "mcp-scan", "adapter_version": "1"}`, `vendor_id: null`,
`vendor_word`, `relayed_verdict`, `mapping`, `subject`, `attestation`
(always `{"status": "NONE", ...}`: the output is unsigned, so every row is
reported by sender), `vendor_payload_digest` (raw bytes of the whole JSON),
`vendor_payload_bytes`, `received_at`, and `could_not_look` when it applies. No
bare `verdict` key.

One adapter-specific key, `tool`: `name`, `server`, `server_index`,
`entity_index`, `scan_path`, `client`, `format` (`v0.5-path-keyed` or
`v0.6-scan-response`), `findings` (the issue codes or risk names pointing at the
tool or its whole server), `digest`, `digest_parts`, `mcp_scan_hash`.

mcp-scan writes no per-tool verdict word, so `vendor_word` is the adapter's
summary of what mcp-scan reported, mapped by this table (the whole mapping):

| vendor_word | relayed_verdict | when |
| --- | --- | --- |
| `no_findings` | VERIFIED | analysed; no issue or risk points at the tool, its server or its path |
| `findings` | BROKEN | any non-X issue code or any risk index points at it (an unreadable `reference` counts against every tool) |
| `error` | COULD NOT LOOK | a path or server `error`, or only X* failure codes |
| `not_inspected` | COULD NOT LOOK | the server was configured but never connected to (`signature: null`) |
| `not_analyzed` | COULD NOT LOOK | inspect output (no `issues` key, or `ingest(..., inspect_only=True)`) |

`relayed_verdict` is mcp-scan's reading in our words. It is not our check.

## The digest

```
tool.digest = "sha256:jcs:v1:" + hex(SHA-256(JCS({"name": name,
                                                   "description": description or null,
                                                   "inputSchema": inputSchema or null})))
```

JCS is RFC 8785 (`arcaeon.prove.jcs`). Key order and extra fields do not change
it; an absent description and `null` digest the same. `digest_parts` holds the
SHA-256 of each of the three parts' JCS, so a BROKEN can name which part changed.
`subject.sha256` is the hex of `tool.digest`.

It does **not** match mcp-scan's own hash. mcp-scan v0.3.x pinned md5 over the
description alone; the adapter recomputes that as `tool.mcp_scan_hash`
(`{"alg": "md5", "over": "description", "value", "rule",
"published_by_mcp_scan": false}`) for cross-reference only. md5 over the
description misses a changed name or schema, which is why it is not ours.

A tool entry that is not an object, has no string name, has a non-string
description, a non-object `inputSchema`, a NaN or Infinity, or a lone surrogate
gets `digest: null` and a COULD NOT LOOK row (`reason_word: unreadable`); the
other tools in the payload still read.

## verify_tool_called(tool_definition, rows, *, server=None)

`tool_definition` is a dict or its JSON text or bytes. Rows are the mcp-scan
relayed rows (other vendors' rows are ignored).

- **VERIFIED**: a row of the same name (and server, if given) carries the same
  digest. The result also carries that row's `relayed_verdict` and `findings`:
  a VERIFIED match on a tool mcp-scan flagged (`relayed_verdict: BROKEN`) is
  the flagged tool, unchanged.
- **BROKEN**: rows of that name carry digests and none matches. The definition
  changed after the scan (a rug pull). `fields` names `description`,
  `inputSchema` (or `name`, or `digest` when the row has no parts).
- **COULD NOT LOOK**: the definition or rows cannot be read, no row has that
  name (`name_not_found`), or every row of that name has no digest (`missing`:
  v0.6 output, not inspected).

Never raises. With no `server`, a match on any server's row is VERIFIED.

## Limits

- Payloads over 8 MiB are digested, not read; nesting over 64 is refused; more
  than 10000 tools stops reading with a `bounded` row.
- Rows are taken as given. An edited row is caught by the chain it was
  appended to, not here.
- `inspect_only` cannot be inferred for v0.5: its inspect output carries
  `issues: []`, the same as a clean scan. Say so when you ingest inspect output.

## What this does not prove

- Scanned means scanned, not safe. VERIFIED says the called definition is the
  one mcp-scan reported scanning; `no_findings` says mcp-scan reported nothing,
  not that nothing is there.
- That mcp-scan ran at all, or ran on this machine: the JSON is unsigned and
  reported by sender. Anyone can write it.
- That the server behaves as its description says. The digest covers the
  definition text, not the code behind it; a server can return a clean
  definition and act differently.
- Changes to `title`, `annotations`, `outputSchema` or `_meta`: they are outside
  the digest.
- That two servers' tools with the same name are the same tool: without
  `server=`, any server's matching row is enough.
- Anything about prompts, resources or skills.
- That the JSON shapes stay as documented: the upstream README says the output
  may change without notice. An unknown shape reads COULD NOT LOOK.
