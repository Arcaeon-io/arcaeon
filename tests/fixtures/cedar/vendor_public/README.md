# Cedar / Amazon Verified Permissions: public samples

Source: https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_IsAuthorized.html
("Examples": the first two response examples)
Retrieved: 2026-10-05 (AWS docs page; no commit id)
Licence: AWS documentation, copyright Amazon; the page states no licence for
its examples. Two short API response bodies are quoted for interoperability
testing.
Trimming: the HTTP status line and headers above each body were dropped; the
JSON bodies are verbatim.
Redaction: none (`SPEXAMPLE...` ids are AWS's placeholders).

| file | what it is |
|---|---|
| `avp_isauthorized_allow.json` | `ALLOW`, one determining policy, `errors: []` |
| `avp_isauthorized_deny.json` | `DENY`, no determining policies (implicit deny), `errors: []` |

Result: pass, no change. ALLOW reads VERIFIED with the policy id, DENY reads
BROKEN.

Cedar's own JSON answer: no verbatim public sample found. Searched
https://github.com/cedar-policy/cedar (commit
2cfa86bab4776d587e96e8da43a37fc44622411a): `cedar-policy/src/ffi/is_authorized.rs`
defines `{decision, diagnostics: {reason, errors}}` but its tests assert on Rust
values, not JSON text; `cedar-wasm/README.md` shows no answer. No CloudTrail
`IsAuthorized` event was taken either.
