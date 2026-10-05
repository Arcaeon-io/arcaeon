# in-toto Statement: public sample

Source: https://github.com/in-toto/attestation/blob/fd2609c16bcb0ac53443e2b4612977f997e8f9a5/spec/predicates/test-result.md ("Example")
Commit: fd2609c16bcb0ac53443e2b4612977f997e8f9a5
Retrieved: 2026-10-05
Licence: the repo's licence file is not an SPDX match (GitHub reports
NOASSERTION); the in-toto attestation spec is published for implementers. One
short spec example quoted.
Trimming: none; the JSON block verbatim.
Redaction: none.

| file | what it is |
|---|---|
| `test_result_statement.json` | an in-toto Statement v1 with predicateType `https://in-toto.io/attestation/test-result/v0.1`, result `PASSED` |

Result: pass, no change. `arcaeon.connector.intoto` is an exporter; its reader
`parse_statement` reads only our predicate type, so it refuses this statement
(`StatementError`, predicateType). Our exported Statement has the same top-level
keys and `_type` as this public one.
