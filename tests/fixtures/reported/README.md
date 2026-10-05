# Fixtures: reported by sender (generic)

Synthetic rows for `arcaeon.connector.reported` (tests/test_connector_reported.py).
No real vendor, no real request, no real key or signature.

- `one_row.json`: one sender row, the documented shape, with a claimed `input_sha256`.
- `rows.json`: a list of six rows: VERIFIED, the `fail` alias with input bytes
  (`input_b64`), the `pass` alias with bytes and a matching digest, `pass` with
  bytes and a digest that does NOT match them (BROKEN), an unknown word, and the
  word COULD NOT LOOK.
- `spoof_opa.json`: a row that names its vendor "opa" and carries OPA-looking
  fields; it must stay a generic reported row.
- `claims_signed.json`: a row that claims `signed_by_vendor: true`, a standing of
  its own, a signature and an attestation; every one of them is ignored.

The input bytes behind `input_b64` are the ASCII line
`synthetic input bytes for the reported adapter` plus a newline.
