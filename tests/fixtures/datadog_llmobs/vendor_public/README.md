# Datadog LLM Observability spans: public sample

Source: https://github.com/DataDog/documentation/blob/73e1d6777e9e7c8fd3db34ab08d97189b5427b58/hugo/content/en/llm_observability/instrument/api.md
("Spans API", Body data, "Example" tab; served at
https://docs.datadoghq.com/llm_observability/instrumentation/api/)
Commit: 73e1d6777e9e7c8fd3db34ab08d97189b5427b58
Retrieved: 2026-10-05
Licence: DataDog/documentation LICENSE, a BSD-style licence (copyright Datadog;
GitHub reports NOASSERTION).
Trimming: none; the code block between the Hugo `code-block` shortcodes,
verbatim, including the doc's placeholders (`<TEST_TRACE_ID>` and the like).
Redaction: none. The one email in the sample is at `example.com` (reserved for
examples).

| file | what it is |
|---|---|
| `spans_api_example.json` | a `POST /api/intake/llm-obs/v1/trace/spans` body with three spans (agent, workflow, llm) |

Arcaeon has no Datadog ingest: `arcaeon.prove.datadog_llmobs` exports. The test
checks our export has the example's shape: `{"data": {"type": "span",
"attributes": {"ml_app", "spans"}}}`, every span (theirs and ours) holds the
required Span fields and only documented Span and Meta fields, and a root span's
`parent_id` is `"undefined"`. Result: pass, no change.
