# OPA decision log: public sample

Source: https://github.com/open-policy-agent/opa/blob/d179cdae407338d768da168ad67105645774e521/docs/docs/management-decision-logs.md
(the "Decision Log Service API" example; the same page is served at
https://www.openpolicyagent.org/docs/management-decision-logs)
Commit: d179cdae407338d768da168ad67105645774e521
Retrieved: 2026-10-05
Licence: Apache-2.0 (open-policy-agent/opa)
Trimming: none. The JSON array is the code block verbatim, including the docs
template placeholder `"version": "{{ current_version }}"` in `labels`.
Redaction: none (`[::1]` is loopback; the input path names the docs' own
placeholder user).

| file | what it is |
|---|---|
| `decision_log_docs.json` | the one-event decision-log body the page shows |

Finding: the docs write `"result": "true"`, a JSON string, not the boolean a
live OPA writes for an allow rule. The adapter reads a non-boolean result as
COULD NOT LOOK (`non_boolean`) by design, even with the path declared in
`allow_paths`, so this sample reads COULD NOT LOOK. Not changed. The other two
JSON examples on the page are cut with a `8<` marker and are not valid JSON, so
they were not taken.
