# Connector adapters: relaying another vendor's verdict

A security scanner, a policy engine or a sandbox hands back a verdict about some
bytes: pass, flagged, denied. That verdict usually stays in the vendor's own
console. A connector adapter turns it into one row in your Arcaeon chain, with
its provenance attached, so the next agent can see that the check happened, on
which bytes, and that nobody edited the verdict after it arrived. The same row
can then be exported as an in-toto Statement that tools outside Arcaeon can read.

This is not the MCP connector (`arcaeon mcp`, the `arcaeon.mcp` package). It is
the library `arcaeon.connector`, phase 1: the adapter shape, one mock vendor
(`mockscan`), the mcp-scan adapter and the OPA decision-log adapter on the same
base class, and no command-line verb yet.

## What a relayed row says

`import_verdict(adapter, raw_bytes)` returns one dict, ready for `Ledger.append`:

| key | what it holds |
|---|---|
| `kind` | `check.verdict.relayed` |
| `relayed` | always `true`: this is someone else's verdict |
| `checked_by_us` | always `false`: we did not re-judge the bytes they judged |
| `vendor` | `{name, adapter_version}`: whose verdict, read by which mapping table |
| `vendor_id` | the vendor's own id for the check (scan id, request id), or null |
| `vendor_word` | the vendor's verdict word exactly as they wrote it (cut to 256 characters) |
| `relayed_verdict` | their word in our words: `VERIFIED`, `BROKEN` or `COULD NOT LOOK` |
| `mapping.rule` | `table`, `unknown_word`, `not_a_word` or `not_read` |
| `subject` | `{name, sha256}` of what the vendor says it checked, or null |
| `attestation` | `{status, checked_by_us, claimed}`: the vendor's own signature claim. `status` is `CLAIMED` or `NONE`, `checked_by_us` is `false` |
| `vendor_payload_digest` | `sha256:raw-bytes:v1:<hex>` over the payload exactly as received |
| `vendor_payload_bytes` | its length |
| `received_at` | our clock when it arrived |
| `vendor_payload` | the payload verbatim, only with `keep_payload=True` |
| `could_not_look` | `{looked_for, where, reason_word, reason}` when the verdict is COULD NOT LOOK |

The row has no bare `verdict` key on purpose. A script that looks for
`verdict == "VERIFIED"` must not mistake a vendor's pass for our own check.

**The one rule.** Only a word in the adapter's table can map to anything but
COULD NOT LOOK. An unknown word, a verdict that is not a string, two verdict
fields in one payload, a duplicate JSON key, a payload that is not JSON, not an
object, over 1 MiB, nested deeper than 32, or an adapter that crashes: all of
them read COULD NOT LOOK, with the reason. `import_verdict` never raises on what
a vendor sends.

## Re-checking a row

`recheck(row, raw_bytes)` (or `recheck(row)` when the row kept the payload):

- **VERIFIED**: the payload's digest matches the row, and reading it again with
  the same adapter gives the same row. This says the row is what the vendor
  sent. It says nothing about whether the vendor was right.
- **BROKEN**: the payload or the row was changed after import, or the row no
  longer says it is relayed. `fields` names what differs.
- **COULD NOT LOOK**: no payload to compare, no adapter by that vendor name, or
  a different adapter version than the one the row was read with.

## Exporting a row

`export_row(row, row_chain=..., ledger=..., pin=...)` gives an
[in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md):

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{"name": "report.pdf", "digest": {"sha256": "..."}}],
  "predicateType": "https://arcaeon.io/connector-verdict/v1",
  "predicate": {
    "relayed": true, "checked_by_us": false, "relayed_verdict": "BROKEN",
    "subject_is": "checked_artifact",
    "vendor": {"name": "mockscan", "adapter_version": "1"},
    "vendor_payload_digest": "sha256:raw-bytes:v1:...",
    "attestation": {"status": "CLAIMED", "checked_by_us": false, "claimed": {...}},
    "chain": {"ledger": "checks.jsonl", "row_chain": "...", "pin": null}
  }
}
```

The subject is the artifact the vendor names when it gives a sha256; otherwise
it is the vendor payload itself, and `subject_is` says `vendor_payload`. Our own
checks export through `statement_for_check(...)` with `relayed: false` and a
`verdict` key instead of `relayed_verdict`; a predicate never carries both.
`statement_bytes` writes RFC 8785 (JCS) canonical bytes; `parse_statement` reads
them back and refuses anything this predicate type does not define.

The statement is unsigned. Wrapping it in a DSSE envelope (payloadType
`application/vnd.in-toto+json`) and signing it is the envelope's job, not this
module's.

## Writing an adapter for a new vendor

An adapter is a name, a version, a table and one method:

```python
from arcaeon.connector import Extracted, VendorAdapter, import_verdict, recheck, register
from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, VERIFIED


class GateAdapter(VendorAdapter):
    name = "examplegate"          # the vendor, as it will appear in every row
    version = "1"                 # bump when the table or extract() changes
    table = {                     # their words, casefolded -> our three words
        "allowed": VERIFIED,
        "denied": BROKEN,
        "timeout": COULD_NOT_LOOK,
    }

    def extract(self, doc):
        # doc is already a parsed JSON object, size- and depth-checked.
        # Raise AdapterError for a payload that is not this vendor's shape.
        return Extracted(word=doc.get("decision"), vendor_id=doc.get("decision_id"),
                         subject_name=doc.get("input_name"),
                         subject_sha256=doc.get("input_sha256"),
                         attestation=doc.get("signature"))


gate = register(GateAdapter())
raw = b'{"decision": "denied", "decision_id": "d-17"}'
row = import_verdict(gate, raw)
print(row["relayed_verdict"], row["mapping"]["rule"], recheck(row, raw)["verdict"])
```

```text
BROKEN table VERIFIED
```

Rules for the table and `extract`:

1. Map only words the vendor documents. When a word could mean either pass or
   fail, leave it out; it then reads COULD NOT LOOK, which is the honest answer.
2. Never map an error, a timeout or a partial scan to VERIFIED.
3. If the payload can carry two verdict fields, refuse it (`AdapterError`)
   rather than pick one.
4. Hand the signature over as the vendor wrote it. The row records it as
   CLAIMED. Do not set anything that says it was checked.
5. Bump `version` whenever the table or `extract` changes. A row read with
   version 1 re-checks COULD NOT LOOK under version 2, never BROKEN, because the
   newer table cannot reproduce the older reading.
6. Keep the raw bytes, or pass `keep_payload=True`. Without them a later
   re-check can only say COULD NOT LOOK.

The table is checked when the adapter is built: a key that is not casefolded,
a key twice, or a value outside our three words raises `TypeError`.

## One base class

Every adapter subclasses `VendorAdapter` in `arcaeon.connector.core`: the mock
vendor (`arcaeon.connector.mockscan`), the mcp-scan tool-hash adapter
(`arcaeon.prove.mcp_scan`, see [MCP_SCAN.md](MCP_SCAN.md)) and the OPA
decision-log adapter (`arcaeon.connector.opa`, below), the generic reported-by-sender
adapter (`arcaeon.connector.reported`) and the HiddenLayer alert adapter
(`arcaeon.connector.hiddenlayer`). The base owns what
they share:

- the row skeleton (`base_row`), relayed, `checked_by_us: false`, attestation
  `NONE` unless the payload claims a signature, and COULD NOT LOOK until a
  table word is mapped;
- the COULD NOT LOOK marking (`mark_could_not_look`);
- the table check above;
- the content digest (`digest`, the function `jcs_digest`), below.

An adapter whose one payload becomes many rows (mcp-scan: one row per scanned
tool) sets `one_row_per_payload = False` and builds its rows with `base_row`.
`recheck` re-reads one-row adapters only; for the others it says COULD NOT LOOK.

## OPA decision logs

`arcaeon.connector.opa.ingest(body, allow_paths=..., deny_paths=...)` reads the
body OPA's decision-log plugin POSTs (a JSON array of decision events, gzipped
or plain, as the OPA Decision Logs page documents it) into one row per event:
`vendor_id` is the `decision_id`, `subject` is `opa:<path>` with the
`sha256:jcs:v1` digest of the input, and one adapter key `decision` holds the
path, timestamp, labels id and version, bundle revisions, erased and masked
pointers, and digests of the input and result. Client addresses, headers,
metrics and the input and result themselves are not copied.

A policy result is not a verdict word: `true` at an allow rule is a pass, at a
deny rule a refusal. So only a boolean result at a path the caller declared in
`allow_paths` or `deny_paths` maps (`allowed` VERIFIED, `denied` BROKEN). An
undeclared path, a non-boolean result (including the string `"true"`), an
undefined decision (no result) and an erased or masked result all read COULD NOT
LOOK. A gzip body that is truncated, has trailing bytes or inflates past 32 MiB
is one COULD NOT LOOK row. Decision logs are unsigned: every row is reported by
the sender. `recheck` says COULD NOT LOOK for these rows; re-run `ingest`.

## Reported by sender (generic)

For a checker that has no adapter of its own, `arcaeon.connector.reported.ingest(body)`
reads a small row the sender writes, one JSON object or a JSON array of them (at
most 1000; past that, one COULD NOT LOOK row says the rest were not read):

```json
{
  "vendor": "acme-scan",
  "verdict": "pass",
  "input_sha256": "<64 hex characters>",
  "input_b64": "<the judged bytes, standard base64>",
  "vendor_request_id": "req-0001",
  "at": "2026-10-05T10:00:00Z",
  "detail": "no findings"
}
```

| key | required | what is done with it |
|---|---|---|
| `vendor` | yes | free text, 1 to 64 characters after trimming; kept in `reported.vendor`. Never used to choose code: a row naming `opa` is still a generic row, read by this table. |
| `verdict` | yes | the checker's word, kept verbatim in `vendor_word`, mapped below |
| `input_sha256` | one of these two | 64 hex characters, the SHA-256 of the bytes the checker judged |
| `input_b64` | one of these two | the judged bytes; we compute their SHA-256 ourselves |
| `vendor_request_id` | no | the checker's own id; written to `vendor_id` |
| `at` | no | when the sender says the check ran; kept in `at`, not checked |
| `detail` | no | a short note, cut to 256 characters |

Any other key, including `signed_by_vendor`, `standing`, `signature` and
`attestation`, is not read; its name is listed in `reported.ignored_keys`.

The word, after trimming and casefolding:

| sender's word | relayed_verdict |
|---|---|
| `verified`, `pass`, `passed` | VERIFIED |
| `broken`, `fail`, `failed` | BROKEN |
| `could not look`, `could_not_look` | COULD NOT LOOK |
| anything else (`ok`, `true`, `allow`, ...), or not a string | COULD NOT LOOK |

`true` and `allow` are left out on purpose: a boolean or a policy word says
nothing about which way is a pass (see OPA above). When both `input_b64` and
`input_sha256` are given and they differ, the row is BROKEN whatever the word,
with `reported.reason` "claimed digest does not match the bytes", and
`input_sha256` is the digest of the bytes. A row with no input, a vendor name
that is missing or too long, or a digest or base64 that does not read is
COULD NOT LOOK. A body that is empty, not UTF-8 JSON, carries a duplicate key,
nests too deep or is over 8 MiB is one COULD NOT LOOK row; `ingest` never raises.

Every row carries `signed_by_vendor: false` and `standing: "reported_by_sender"`,
written by one final step over every row; `ingest` takes no argument that can
change them, and a row claiming a signature changes nothing. `rollup(rows)` is
never VERIFIED: BROKEN when any row is a relayed BROKEN, else COULD NOT LOOK. A
relayed BROKEN never becomes VERIFIED. These rows are unsigned, so the gate's
non-party check rule never counts them.

### What this cannot prove

This proves only that the sender said it, when, about which bytes: the sender
named a checker, gave its word, and pinned the input by digest at the time we
received the row. It does not prove the checker exists, that it ran, that it
said that word, or that the sender did not write the row alone. A VERIFIED here
is the sender's report, never a check of ours.

## HiddenLayer alerts

`arcaeon.connector.hiddenlayer.ingest(body)` reads what a HiddenLayer webhook
delivers, one JSON object or a JSON array of them (at most 1000), into one row per
alert. The shape is taken from HiddenLayer's public docs, "Data Formats" on
https://docs.hiddenlayer.ai/docs/integrations/webhook_integrations.md, with field
meanings from https://docs.hiddenlayer.ai/docs/products/runtime/agentic/policy_outcomes.md
(read 2026-10-05). It was not checked against a live alert.

HiddenLayer writes no pass or fail word, so the adapter writes its own:

| alert | when | relayed_verdict |
|---|---|---|
| runtime security conviction | severity `low`, `medium` or `high` | BROKEN (`conviction`) |
| supply chain scan | status `done`, detection count over 0, known severity | BROKEN (`scan_detections`) |
| supply chain scan | status `done`, detection count 0 in both places, files with detections 0, files failed 0, unknown files 0, file count over 0 and equal in both places, no scan error, no severity | VERIFIED (`scan_clean`) |
| supply chain scan | done but any of the above missing or not clean | COULD NOT LOOK (`scan_incomplete`) |
| supply chain scan | any status other than `done` | COULD NOT LOOK (`unknown_status`) |
| runtime policy outcome | action `BLOCK` | BROKEN (`policy_block`) |
| runtime policy outcome | `DETECT` or `REDACT` naming a detection | BROKEN (`policy_detect`, `policy_redact`) |
| runtime policy outcome | `DETECT` or `REDACT` naming none | COULD NOT LOOK (`policy_action_without_detection`) |
| runtime policy outcome | any other action | COULD NOT LOOK (`unknown_action`) |
| any | severity or threat level outside the documented words | COULD NOT LOOK (`unknown_severity`) |
| audit log, another schema, no known shape | | COULD NOT LOOK (`not_an_alert`) |

A runtime security conviction is, in HiddenLayer's words, when it "has determined
that a malicious event, or set of malicious events, has taken place", so it has no
clean form: there is no VERIFIED conviction. A policy outcome is emitted only when
a policy acts, so it has no clean form either. Only a finished model scan can read
VERIFIED, and only when every documented count says it finished with nothing found;
the docs show no clean scan, so that rule is our reading of the documented fields.

Each row carries `input_sha256` (SHA-256 of the exact bytes received),
`vendor_request_id` and `vendor_id` (the conviction id, scan id or outcome event
id), `at` (HiddenLayer's own time, as written) and one adapter key `alert` with
the source, id, severity or threat level, status, action, detection category or
names, counts, MITRE technique, engine and schema name. Requester, tenant,
sensor, session and project ids and model inventory are not copied. A body that
is empty, not UTF-8 JSON, carries a duplicate key, nests too deep or is over
8 MiB is one COULD NOT LOOK row; `ingest` never raises.

The webhook page documents custom headers for the receiver's own auth and no
payload signature, so every row carries `signed_by_vendor: false` and
`standing: "reported_by_sender"`; no argument or payload field changes that.
`standing_verdict(rows)` (also `rollup`) is BROKEN when any row is a relayed
BROKEN, else COULD NOT LOOK, never VERIFIED. `recheck` says COULD NOT LOOK for
these rows; re-run `ingest`.

### What this cannot prove

This proves only that someone handed us these bytes, when, and what the adapter
reads in them. It does not prove HiddenLayer sent them: the alert is unsigned (as
far as the public docs show), so anyone who can reach the webhook URL can write
one. It does not prove a detection was right, that a scan covered the model that
was later used, or that a clean scan means the model is safe; HiddenLayer can only
report what its own checks look for. A missing alert proves nothing: no outcome is
sent when a policy takes no action. The shapes were read from public docs, not a
live alert, so a field HiddenLayer renames reads COULD NOT LOOK until the adapter
is updated.

## The sha256:jcs:v1 digest

This is the one place the scheme is defined. `arcaeon.connector.core.jcs_digest`
is its one implementation; every adapter reaches it as `adapter.digest`.

```
digest = "sha256:jcs:v1:" + hex(SHA-256(JCS(value)))
```

- `value` is a JSON value (object, array, string, number, boolean, null).
- JCS is RFC 8785, the JSON Canonicalization Scheme (`arcaeon.prove.jcs`): keys
  sorted by UTF-16 code units, no whitespace, numbers in their shortest
  round-trip form, strings minimally escaped, encoded as UTF-8.
- `hex` is 64 lower-case hex characters.
- `v1` names this exact recipe. A change to any step is a new version, never a
  silent change to `v1`.

Two values that are equal as JSON (whatever their key order or spacing) have the
same digest. A value JCS refuses (NaN, Infinity, a lone surrogate, a non-JSON
type) has no digest: the caller records COULD NOT LOOK, never a guess.

This is a digest of content we hold, not of the bytes a vendor sent: the raw
payload keeps its own `sha256:raw-bytes:v1:` digest in `vendor_payload_digest`.

## Honest limits

- **A relayed verdict is the vendor's word, not ours.** `relayed_verdict:
  VERIFIED` means the vendor said pass. We did not scan anything. A receiver
  that needs our own check needs a row with `relayed: false`.
- **The vendor's signature is not checked.** Phase 1 records the claim
  (`CLAIMED`) and keeps the signature blob by digest. Checking it needs the
  vendor's public key, pinned and named, and is not built. Until it is, a sender
  could fabricate a payload with a made-up signature and the row would carry it
  faithfully, as CLAIMED. Treat an unsigned or unchecked relayed verdict as
  "reported by the sender."
- **The digest proves the bytes, not the source.** It shows the payload has not
  changed since we received it. It does not prove the vendor sent it.
- **A permissive scanner gives a permissive row.** Which vendors a receiver
  accepts is the receiver's policy; this module does not rank vendors.
- **The mock vendor is fake.** `mockscan` stands in for a real format. No real
  vendor's schema was read for this phase, so the first real adapter will need
  its own table written from that vendor's documentation.
- **No command-line verb, no network.** Import, re-check and export are library
  calls. Nothing is fetched from a vendor and nothing is sent to one.
