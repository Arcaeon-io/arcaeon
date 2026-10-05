# Kyverno PolicyReport: public samples

Source: https://github.com/kyverno/website/blob/77f297fdd586483469c5a963d749383c22d6634f/src/content/docs/docs/guides/reports.md
(served at https://kyverno.io/docs/guides/reports/)
Commit: 77f297fdd586483469c5a963d749383c22d6634f
Retrieved: 2026-10-05
Licence: Apache-2.0 (kyverno/website)
Trimming: none by us. The `.yaml` files are the page's code blocks verbatim
(`polr_list_staging.yaml`: the output under `kubectl get polr -n staging -o
yaml`, without the command line; `policyreport_docs_example.yaml`: the first
PolicyReport example, which Kyverno itself trimmed with `# ...`). The `.json`
files are the same objects converted with `yaml.safe_load` and `json.dumps`
(indent 2); no value was changed (a test checks they are equal).
Redaction: none (names, uids and namespaces are the docs' own).

| file | what it is |
|---|---|
| `polr_list_staging.json` / `.yaml` | a `List` of two PolicyReports, one `fail`, one `pass`, from a ValidatingAdmissionPolicy; each report names its resource in `scope`, results carry no `resources[]` and no `rule` |
| `policyreport_docs_example.json` / `.yaml` | one PolicyReport whose `summary` (10 pass, 2 fail) counts results the docs cut out; two results shown |

Finding (fixed): real reports name the checked resource in the report-level
`scope`, not in `results[].resources[]`. The adapter did not read `scope`, so
every row had `subject: null`. It now uses `scope` when a result names no
resource (`kyverno.subject_from: "scope"`), adapter version 2. Verdict words
were already right: `fail` BROKEN, `pass` VERIFIED; the trimmed docs example
reads COULD NOT LOOK because its summary disagrees with its results. The
hand-made fixtures are unchanged and still pass.
