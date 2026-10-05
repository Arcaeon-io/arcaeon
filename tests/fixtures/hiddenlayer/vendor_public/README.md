# HiddenLayer webhook: public samples

Source: https://docs.hiddenlayer.ai/docs/integrations/webhook_integrations.md ("Data Formats")
Retrieved: 2026-10-05 (docs page; no commit id)
Licence: HiddenLayer documentation, copyright HiddenLayer; no licence stated.
Four short webhook payload examples quoted for interoperability testing.
Trimming: none; the four JSON blocks verbatim.
Redaction: one. In `supply_chain_scan.json`,
`inventory.requesting_entity` was a real-looking email address at the vendor's
domain; it is replaced by `"REDACTED-EMAIL"`. Nothing else changed. The adapter
does not copy that field.

| file | what it is |
|---|---|
| `runtime_conviction.json` | runtime security conviction, severity `Low` |
| `supply_chain_scan.json` | model scan, status `done`, 3 detections, severity `high` |
| `runtime_policy_outcome.json` | policy outcome, action `BLOCK` |
| `audit_log.json` | audit log entry (`login`) |

Result: pass, no change. The adapter was written from this page; the three
alerts read BROKEN and the audit log reads COULD NOT LOOK (`not_an_alert`).
