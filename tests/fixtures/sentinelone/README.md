# Fixtures: SentinelOne alert export

Shape from public source, not a live capture. Every id, name and value here is
synthetic. No real tenant, alert, host, key or signature.

The shape is the Unified Alert Management (UAM) GraphQL alert as SentinelOne's
own public, MIT-licensed client reads it:

- https://github.com/Sentinel-One/purple-mcp/blob/main/src/purple_mcp/libs/alerts/models.py
  (the `Alert` model and its `Severity`, `Status` and `AnalystVerdict` enums)
- https://github.com/Sentinel-One/purple-mcp/blob/main/src/purple_mcp/libs/alerts/client.py
  (the `alerts { edges { node } cursor } pageInfo totalCount` list query and the
  `alert(id:)` get query)

Read only, for Batch 200 item L2-09, 2026-10-05. That source shows no
signature on an alert, so these rows are treated as unsigned (unconfirmed for
any other export path).

- `alerts_list.json`: a list response with five alerts: a true positive
  (BROKEN), a false positive (COULD NOT LOOK), an untriaged alert with a null
  verdict, an `UNDEFINED` verdict under review, and a true-positive verdict whose
  status says `FALSE_POSITIVE` (a conflict, COULD NOT LOOK).
- `alert_get.json`: a get response with one true-positive alert (BROKEN).
- `claims_signed.json`: an alert that claims `signedByVendor`, a standing, a
  signature and an attestation of its own; every one of them is ignored.
