# Fixtures: HiddenLayer alerts

Shape from public docs https://docs.hiddenlayer.ai/docs/integrations/webhook_integrations.md
(section "Data Formats"), not a live capture. Field meanings for the policy outcome
come from https://docs.hiddenlayer.ai/docs/products/runtime/agentic/policy_outcomes.md.
Read 2026-10-05. No account, no real tenant, no real request, no key or signature.

Used by `tests/test_connector_hiddenlayer.py` for `arcaeon.connector.hiddenlayer`.

- `conviction.json`: the "Runtime Security Convictions" example, verbatim from the
  doc. A conviction is a detection: BROKEN.
- `supply_chain_scan.json`: the "Supply Chain Scans" example, verbatim from the doc
  (status `done`, 3 detections, severity `high`): BROKEN.
- `supply_chain_scan_clean.json`: DERIVED from the scan example, not shown in the
  doc: detection counts set to 0, categories emptied, severity null, a made-up
  scan id and requester. It is the shape a finished scan with nothing found would
  have if the documented fields hold; the doc does not show one, so this is our
  reading, not HiddenLayer's example.
- `policy_outcome.json`: the "Runtime Policy Outcomes" example, verbatim from the
  doc (action `BLOCK`, highest threat level `HIGH`): BROKEN.
- `audit_log.json`: the "Audit Logs" example, verbatim from the doc. Not an alert:
  COULD NOT LOOK.

The verbatim examples carry HiddenLayer's own placeholder ids and example user
names as the doc prints them.
