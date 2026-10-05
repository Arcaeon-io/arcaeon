# Datadog LLM Observability export: verdicts as spans

`arcaeon envelope export-datadog` turns arcaeon verdicts into the JSON body
of a Datadog LLM Observability spans request, so a team that watches its
LLM app in Datadog sees each arcaeon check as a span beside its other
traces. The library is
`arcaeon.prove.datadog_llmobs.to_llmobs(obj, now=None, ml_app="arcaeon", service=None)`.

It is an export only. It writes the body to stdout or a file and sends
nothing. It reads no key.

It reads the same inputs as the OCSF export ([OCSF.md](OCSF.md)), all JSON:

- an `arcaeon envelope verify` report;
- an `arcaeon gate decide --json` decision;
- a gate evidence pack's `evidence.json`;
- or a JSON list of any of these (one span each, at most 1000).

Anything else is refused: COULD NOT LOOK, exit 3, nothing exported.

## Where the field names come from

The body shape was read on 2026-10-05 from Datadog's public HTTP API page
for LLM Observability, section "Spans API":

- https://docs.datadoghq.com/llm_observability/setup/api/

As read there: the endpoint is `POST https://api.<your Datadog site>/api/intake/llm-obs/v1/trace/spans`
with headers `DD-API-KEY` and `Content-Type: application/json`. The body is
`{"data": {"type": "span", "attributes": {...}}}`. `attributes` requires
`ml_app` and `spans` and may carry `tags`. Each span requires `name`,
`span_id`, `trace_id`, `parent_id` (the page writes `"undefined"` for a root
span), `start_ns` (nanoseconds), `duration` (nanoseconds) and `meta`;
`status` (`"ok"` or `"error"`), `metrics` (string to float), `tags` (a list
of `key:value` strings) and `service` are optional. `meta` requires `kind`
(agent, workflow, llm, tool, task, embedding or retrieval) and may carry
`input` and `output` (each with a string `value`), `metadata` (values that
are strings, booleans or floats) and `error` (`message`, `stack`, `type`).
The page says the intake accepts spans with timestamps no more than 24 hours
old. No field name in the export is invented; every one is on that page.

## The mapping

One verdict is one span, in its own trace, with `meta.kind` `task`.

| verdict | `status` | tag | `meta.error` |
|---|---|---|---|
| VERIFIED | `ok` | `arcaeon.verdict:VERIFIED` | none |
| BROKEN | `error` | `arcaeon.verdict:BROKEN` | `type` `arcaeon.BROKEN`, a fixed message |
| COULD NOT LOOK | `ok` | `arcaeon.verdict:COULD_NOT_LOOK` | none |
| COULD NOT LOOK, gate refused | `error` | `arcaeon.verdict:COULD_NOT_LOOK` | none |

Every span carries exactly one `arcaeon.verdict` tag, written as the token
in the table (tags take no spaces, so `COULD NOT LOOK` is `COULD_NOT_LOOK`);
`meta.metadata["arcaeon.verdict"]` keeps the word with its spaces.

A COULD NOT LOOK on a gate input (a `gate decide --json` decision or an
`evidence.json`) whose decision is `refuse` is an `error` span: the gate
stopped the action, which a team watching error rates should see. This
matches the OCSF export, where the same case is a Medium alert. Any other
COULD NOT LOOK (a verify report, an allowed gate action) stays `ok`, with
the `arcaeon.verdict:COULD_NOT_LOOK` tag to filter on.

All three are exported. Unlike a SIEM finding, a trace of every check is
the point, so VERIFIED is not skipped.

A gate refusal of a VERIFIED envelope never reads VERIFIED, as in the OCSF
export: a `checker-broken` veto is BROKEN, any other veto is COULD NOT LOOK,
and the tag `arcaeon.envelope_verdict:VERIFIED` keeps the envelope's own
word.

| span field | value |
|---|---|
| `name` | `arcaeon.envelope.verify`, `arcaeon.gate.decide` or `arcaeon.gate.evidence_pack` |
| `trace_id` | 32 hex characters cut from a SHA-256 over the verdict record digest |
| `span_id` | a decimal string of a 63-bit number cut from another SHA-256 over the same digest |
| `parent_id` | `undefined` (a root span) |
| `start_ns` | the export time in nanoseconds (`--now` fixes it) |
| `duration` | 0: a verdict is a point in time, not a timed call |
| `status` | see the table above |
| `meta.input.value` | `sha256:` and the checked file's digest when the input carries it (a gate `evidence.json`, or a report with `file_sha256`), else the digest of the arcaeon input document as canonical JSON; `meta.metadata["arcaeon.input_digest_of"]` says which |
| `meta.output.value` | `sha256:` and the digest of the normalized verdict record |
| `meta.metadata` | `arcaeon.verdict` (the word, with its space), `arcaeon.source`, `arcaeon.input_digest_of`, `arcaeon.limits` (the limits line), and when present `arcaeon.envelope_verdict` and `arcaeon.checked_at` (the gate's check time) |
| `metrics` | `arcaeon.verified`, `arcaeon.broken`, `arcaeon.could_not_look` (1.0 or 0.0), `arcaeon.not_checked` (a count), and `arcaeon.checks_broken` on a gate input that carries the `--checks` answer |
| `tags` | `arcaeon.verdict`, `arcaeon.source`, `arcaeon.record_sha256`, and when present `arcaeon.envelope_verdict`, `arcaeon.action`, `arcaeon.decision`, `arcaeon.veto`, `arcaeon.could_not_look` (the reason word), `arcaeon.file_sha256`, `arcaeon.envelope_sha256` |
| `service` | `--service`, when given |

`attributes.ml_app` is `--ml-app` (default `arcaeon`), held to the page's
application naming rules: lowercase letters, digits, `_ - : . /`, at most
193 characters, no doubled or trailing underscore. `attributes.tags` is
`["arcaeon.export:dd-llmobs-v1"]`.

### Same check, same ids

The ids come from the digest of the verdict record, not from the clock. The
same check exported twice gives the same `trace_id` and `span_id`; only
`start_ns` moves. A different verdict, file digest or reason gives
different ids.

## Content never leaves

The span carries digests, verdict words and words from fixed sets: the
gate's four actions (`read`, `act`, `pay`, `irreversible`), `allow` or
`refuse`, the three vetoes and the COULD NOT LOOK reason words. A value
outside those sets is left out, not copied. It never carries:

- reasons, findings or the gate's reason text;
- the label, audience, deal or purpose;
- signer keys or sealer names;
- file names, envelope names or directories.

Someone who holds the arcaeon report can match it to the span by digest.
Someone who holds only the span learns the verdict and the digests, nothing
of the content.

## Use

```console
$ arcaeon envelope verify grades.csv --audience instructor-1 --signer did:key:z6Mk... > report.json
$ arcaeon envelope export-datadog report.json --ml-app checks --out spans.json
spans.json
```

Sending it is your pipeline's job, with your own key, for example:
`curl -X POST "https://api.<site>/api/intake/llm-obs/v1/trace/spans" -H "DD-API-KEY: $DD_API_KEY" -H "Content-Type: application/json" --data @spans.json`.
arcaeon does not run that line and has no flag that takes a key.

Exit codes: 0 written, 3 the input is not a readable arcaeon verdict
(nothing exported), 2 bad usage (an `--ml-app` or `--service` name outside
the rules, a bad `--now`). The exit code is about the export, not the
verdict: read the verdict from the `arcaeon.verdict` tag. Given the same
input and the same `--now`, the output is byte-identical (sorted keys).

## What it cannot prove

- Nothing was sent through a real Datadog intake. The shape tests and the
  fixtures (tests/fixtures/datadog_llmobs/, one body per verdict word) check
  the body against the field list on the page above, read on 2026-10-05.
  Passing them does not show that Datadog accepts the body, keeps every
  field, or shows it the way described here.
- Field names are as of that date. If Datadog changes the page, the export
  can drift until someone reads it again.
- Datadog's handling of tags (case, length, characters) and of a `duration`
  of 0 was not checked. The `span_id` and `trace_id` formats are our choice;
  the page only says "string".
- The intake takes spans no more than 24 hours old. The body uses the export
  time, so send it soon after you write it.
- A span restates a verdict; it adds nothing to the check. VERIFIED means
  the bytes are unchanged since the named key sealed them and are labeled
  for this receiver, never that the content is true or safe. BROKEN means a
  check came out wrong, not who is at fault. COULD NOT LOOK means something
  was not checked; it vouches for nothing.
- Once a span is in Datadog it is Datadog's stored copy. Nothing here signs
  the span or proves it was not changed after it arrived.
