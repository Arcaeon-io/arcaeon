# Lakera Guard fixtures

Shape from R15, not a live capture.

These files were written by hand from the published Lakera Guard API v2
reference (`POST /v2/guard` response and `/v2/guard/results`), as summarised in
the Batch 200 research note R15. No API was called, no Lakera account or key
was used and nothing was sent anywhere. Every id, detector name, label and
match text is synthetic.

- `flagged.json`: a screening response with `flagged: true`, `action`, one
  `payload` match span, a `breakdown` of three detectors (two `detected: true`),
  `dev_info` and `metadata.request_uuid`.
- `clean.json`: `flagged: false`, an empty `payload`, every `breakdown`
  detector `detected: false`, and a `request_uuid`.
- `detect_mode.json`: `flagged: false` while one detector says
  `detected: true`, the way a Detect-mode policy answers (R15: `flagged` is
  always false in Detect mode).
- `results_endpoint.json`: the `/v2/guard/results` shape, which makes no
  flagging decision and is not a screening result.

What R15 marks unverified or does not document, and so what these fixtures
cannot settle: the full set of `action` values and whether `action` names the
policy mode; the vocabulary of `detector_type` values (the names here are
placeholders); whether `breakdown` reports `detected: true` in Detect mode
exactly as shown; and the product terms on storing or sharing verdicts.
