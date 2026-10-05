# OPA bundle: public sample

Source: https://github.com/open-policy-agent/opa/blob/d179cdae407338d768da168ad67105645774e521/v1/download/testdata/signed.tar.gz
Commit: d179cdae407338d768da168ad67105645774e521
Retrieved: 2026-10-05
Licence: Apache-2.0 (open-policy-agent/opa)
Trimming: none; the tarball bytes as served (764 bytes, sha256
7fccf82798e6e627afd04144889570d966583788473db2888f0d0d325904d273).
Redaction: none.

OPA built this file with its own CLI; `v1/download/oci_download_test.go` line 25
in the same commit records the command:

    opa build -b --signing-alg HS256 --signing-key secret testdata/signed_bundle_data --output testdata/signed.tar.gz

and line 29 verifies it with the HMAC key `secret` (kid `default`). That is
OPA's published test key, not a secret of ours. The tarball holds
`/.manifest`, `/.signatures.json`, `/data.json` and one `.rego` file; it is read
in memory by the tests and never extracted.

Finding (fixed): the manifest is `{"revision":"","roots":[""],...}`, the
`opa build` default. `seal_bundle` refused an empty revision ("`.manifest`
revision is empty") and sealed the whole bundle COULD NOT LOOK, so a real,
correctly signed bundle could not be sealed. It now keeps `revision: ""` and
reads the bundle and its signature; the join (`opa.join_bundles`) already never
matches an empty revision. With the key, the seal is VERIFIED and all three
listed file hashes (including the structured `data.json` and `.manifest`)
match. No hand-made fixture or test depended on the old refusal.
