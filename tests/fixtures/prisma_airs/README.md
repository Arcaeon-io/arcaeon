# Prisma AIRS fixtures

Shape from R15, not a live capture.

These files were written by hand from the published Prisma AIRS AI Runtime API
notes on pan.dev (the Python SDK usage page's sync scan response, the async scan
request page, and the "get scan results by scan IDs" and "get threat scan
reports" pages), as summarised in the Batch 200 research note R15. No scan was
run, no Palo Alto Networks account or key was used and nothing was sent
anywhere. Every id, profile name and detail string is synthetic.

- `sync_block.json`: a `POST /v1/scan/sync/request` response, `action` block,
  `category` malicious, one prompt detection flag true.
- `sync_allow.json`: the same shape, `action` allow, every detection flag false.
- `sync_allow_detected.json`: `action` allow with one detection flag true.
- `async_ack.json`: a `POST /v1/scan/async/request` response
  (`received`, `scan_id`, `report_id`); it carries no verdict yet.
- `scan_results.json`: a `GET /v1/scan/results` response, a list of
  `{req_id, status, scan_id, result}` items: one block, one allow, one with no
  `result` yet.
- `report.json`: a `GET /v1/scan/reports` response, a list of reports each with
  `detection_results[]{data_type, detection_service, verdict, action,
  result_detail}`.

What R15 marks unverified or does not show, and so what these fixtures cannot
settle: the full id format (R15 shows only the abridged `"0000.."` and
`"R0000.."`; these files use a UUID, with an `R` prefix for a report id), the
values of `status` and of a detection result's `verdict`, any `category` value
other than `malicious` (`benign` here is an assumption), the outer wrapping of
the reports response, and the query parameter names `scan_ids` and
`report_ids` (taken from SDK method names).
