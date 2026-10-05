# Lakera Guard: public samples

Sources:
- https://docs.lakera.ai/docs/api/guard.md (served at https://docs.lakera.ai/docs/api/guard), the first "Response" block
- https://docs.lakera.ai/api-reference/lakera-api/guard/screen-content.md ("Examples", "Basic screening request", Response)

Retrieved: 2026-10-05 (docs pages; no commit id)
Licence: Lakera documentation, copyright Lakera; no licence stated. Two short
API response examples quoted for interoperability testing.
Trimming: none; the JSON blocks verbatim (the API reference's values are its
own placeholders, `"string"` and `1`).
Redaction: none.

| file | what it is |
|---|---|
| `guard_quickstart_flagged.json` | `flagged: true`, `action: "enforce"`, a `request_uuid` |
| `guard_api_reference.json` | the full response shape: `payload`, `breakdown`, `tools {flagged, breakdown}`, `dev_info`, `metadata` |

Findings (fixed, adapter version 2):
1. The API reference documents a `tools` block (the screening of the request's
   tool definitions, with its own `flagged` and `breakdown`). The adapter did not
   read it, so a detection on a tool definition made no row and could not stop a
   clean message-level response from relaying VERIFIED. It now writes
   `tools_flagged` and `tool_detector_detected` (BROKEN) rows, `tools_unreadable`
   (COULD NOT LOOK) for a block it cannot read, and any of these makes the
   response row `not_flagged_unsettled`.
2. The API reference documents `action` as the project's mode, `enforce` or
   `detect`. The adapter still takes the mode only from the caller, but a
   not-flagged response whose `action` names the other mode now reads
   `not_flagged_mode_conflict` (COULD NOT LOOK).

The hand-made fixtures are unchanged and still pass (they carry no `tools` or
`action` that conflicts).
