# Prisma AIRS: public samples

Source: https://github.com/PaloAltoNetworks/pan.dev/blob/99cebaf212d9d2596d96f4277c19a7d35af19373/products/prisma-airs/api/airuntimesecurity/usecases.md
(served at https://pan.dev/prisma-airs/api/airuntimesecurity/usecases/)
Commit: 99cebaf212d9d2596d96f4277c19a7d35af19373
Retrieved: 2026-10-05
Licence: MIT (PaloAltoNetworks/pan.dev)
Trimming: none; three code blocks verbatim (the last two are fenced as `curl`
on the page but hold JSON).
Redaction: none. The page's request examples contain a made-up person's name
and salary; those request blocks were NOT taken, only responses.

| file | what it is |
|---|---|
| `sync_block_prompt_injection.json` | sync scan response: `action: block`, `category: malicious`, `prompt_detected.injection: true` |
| `scan_results_grounding.json` | `GET /v1/scan/results` list: one `block`, one `allow`, both `status: complete` |
| `scan_reports_grounding.json` | `GET /v1/scan/reports` list: `detection_results` with `allow`/`benign` and `block`/`malicious` |

Verdicts: pass, no change (block BROKEN, allow VERIFIED per row).

Finding (fixed, adapter version 3): the reports example names the transaction
`transaction_id` (not `tr_id`) and carries `req_id` at report level; the adapter
left both ids null on report rows. It now reads `req_id` and takes
`transaction_id` as `ids.tr_id` when `tr_id` is absent.
