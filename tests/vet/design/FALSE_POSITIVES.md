# False-positive register

Every case where the checker said "finding" and the server was fine, or said
"clean" and it was not. One row per case, dated, with what the checker saw,
what was true, and what changed. A checker that cannot list its own misses is
asking to be trusted on its word; this file is the alternative.

Append-only. A fixed row stays; it is the record that the shape was once wrong.

| date | check | direction | what the checker saw | what was true | fix / status |
|---|---|---|---|---|---|
| 2026-09-02 | audit-record | false red | `projects/arcaeon_connector/test_connector.py` graded as a server at gate 0 in the very first `--ours-only` bench pass: it builds `{"method": "tools/call"}` as a dict value to DRIVE a server | a test file sends the message, it does not handle it; no audit trail is owed | `audit_record_applies()` (handlers + entrypoint) added 0.0.16; a file the check never asked is "not applicable", not "clean" and not "gate 0" (CHANGELOG 0.0.16) |
| 2026-09-02 | audit-record | false red | `_reachable` (checks.py ~808) follows only `_local_funcs(tree)`, so a handler that records through `from .audit import record` scored gate 0 | the record exists one file over, in the same package | board item M1 (same-package import resolution + two-file fixture), in progress 9/2; until it ships the blindness is named in `blind_spots` |
| 2026-09-02 | audit-record | false red | a handler wrapped in `@audited` / `@with_ledger` has no record call in its own body; the walk does not open decorator bodies | the decorator writes the record on every call | board item M2 (resolve decorator names, include their bodies), in progress 9/2; named in `blind_spots` meanwhile. Note: our own connector fix (K34) deliberately puts the record call in each handler BODY so the PUBLISHED checker, which strangers run, can see it |
| 2026-09-02 | audit-record | false red (class of) | `self._log(...)`, `with audit_span(tool):`, base-class recorders, construction-time middleware (`server.middleware(...)`) are all invisible to a body-and-local-helpers walk | each is a real record path in common SDK styles | board items M4 to M7; every shape not fixed by 0.0.17 stays enumerated in `blind_spots` (M8) rather than scoring gate 0 silently |
| 2026-09-02 | benchmark bucket | false red (attribution) | 49 of 100 sampled repos landed in `no-handler-found`, which reads as "their server has no handler" | our markers are Python/TS only; Go, Rust, Java, C# servers and monorepos we could not locate land there through OUR blindness | reported as its own count beside graded, never folded into the fail side (PLAN.md); split into three sub-reasons by M20 |

## How to add a row

A row needs the artifact the checker produced (a grade JSON, a bench row, or a
test name) and the artifact that proved it wrong. "Felt wrong" is not a row.
When a fix lands, edit the last column; never delete the row.
