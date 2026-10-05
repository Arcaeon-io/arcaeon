# Kyverno PolicyReport fixtures

Shape from R14, not a live capture. Every file here was written by hand from the
fields the research note records (the Kyverno policy-reports page and the
upstream wg-policy-prototypes API doc). No cluster was run, no `kubectl` output
was copied, and every name, namespace and uid is synthetic.

| file | what it is |
|---|---|
| `policyreport.json` | a namespaced PolicyReport with one result of each word: pass, fail, warn, error, skip; summary agrees |
| `clusterpolicyreport.json` | a ClusterPolicyReport, one pass and one fail; summary omits the zero counts |
| `summary_mismatch.json` | a PolicyReport whose `summary` says 2 pass / 0 fail while `results[]` holds 1 pass / 1 fail |
| `signature_looking.json` | a PolicyReport with fields that look like a signature (`signature`, `signed_by_vendor`, `standing`, `attestation`, a cosign-style annotation); the adapter must ignore all of them |
| `report_list.json` | a Kubernetes `List` with two PolicyReports in `items[]` |

## What is not verified against a real Kyverno

- The `List` wrapper (`kind: List`, `items[]`) is the Kubernetes API list
  convention; R14 says reports are read "via the K8s API" but does not show a
  list body.
- That a `summary` omits zero counts (Kubernetes `omitempty`). The adapter reads
  a missing count as 0.
- `timestamp` as `{seconds, nanos}` integers: R14 names the two fields, not their
  JSON types.
- The `resources[]` entry shape (`apiVersion`, `kind`, `namespace`, `name`,
  `uid`): it is a Kubernetes ObjectReference by convention; R14 names the field
  only.
- Newer Kyverno releases put the checked resource in a report-level `scope`
  instead of per-result `resources[]`. R14 did not document `scope`; Kyverno's
  own reports guide does (`vendor_public/`), and since adapter version 2 the
  adapter reads it for the subject when a result names no resource.
- The `openreports.io/v1alpha1` group is named in R14 as alpha; its kind names
  are not, so only `PolicyReport` and `ClusterPolicyReport` are read under it.
- The kyverno CLI `apply` / `test` text and table output is not documented in
  R14 and is not read: such a body is one COULD NOT LOOK row.
- Severity values outside critical|high|medium|low|info are kept as written.
