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
decision-log adapter (`arcaeon.connector.opa`, below). The base owns what
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

## Kyverno

`arcaeon.connector.kyverno.ingest(body)` reads a Kyverno `PolicyReport` or
`ClusterPolicyReport` (`wgpolicyk8s.io/v1alpha2`; also `reports.x-k8s.io/v1beta2`
and `openreports.io/v1alpha1`), or a Kubernetes `List` of them, into one row per
entry in `results[]`. `vendor_id` is the report's `metadata.uid`; `subject` is
`kyverno:<namespace>/<kind>/<name>` when the result names exactly one resource.
One adapter key `kyverno` holds the report identity (name, namespace, uid,
resourceVersion), policy, rule, source, scored, severity, category, message,
timestamp, up to 32 resources, a digest of `properties` and `summary_check`.
The kyverno CLI's text or table output is not read: it is one COULD NOT LOOK row.

| Kyverno `result` | `relayed_verdict` | why |
|---|---|---|
| `pass` | VERIFIED | the rule passed, as Kyverno says |
| `fail` | BROKEN | the rule failed, as Kyverno says |
| `warn` | COULD NOT LOOK | advisory, neither pass nor fail |
| `error` | COULD NOT LOOK | Kyverno could not evaluate the rule |
| `skip` | COULD NOT LOOK | the rule was not applied |
| any other word, or not a string | COULD NOT LOOK | not in the table |
| any word, when the report's `summary` disagrees with its `results[]` | COULD NOT LOOK | the report contradicts itself |

Every row carries `signed_by_vendor: false`, `standing: "reported_by_sender"`
and `input_sha256` (hex SHA-256 of the exact bytes given to `ingest`), written
by one final step over every row; `ingest` takes no argument that changes them,
and a field in the report that looks like a signature is not read. After that
step only a `pass` can relay as VERIFIED. `rollup(rows)` gives one word over a
set of rows and is never VERIFIED: BROKEN if any row is a relayed `fail`,
otherwise COULD NOT LOOK. Each row's `policy_ref` names the policy and rule,
with `version: null` and `join: COULD NOT LOOK`.

An empty body, one over 8 MiB (digested, not read), not UTF-8, not JSON, with a
duplicate key, nested past 64, or not a report is one COULD NOT LOOK row. More
than 10000 results stop with one `bounded` row. `recheck` says COULD NOT LOOK for
these rows; re-run `ingest`.

### What this cannot prove

- **That Kyverno said it.** Reports are not signed. The row proves which bytes
  arrived, not who wrote them; anyone who can write a PolicyReport object can
  write a `pass`.
- **Which policy text judged the resource.** A report names a policy and rule
  only: no policy version, resourceVersion or digest. `policy_ref` cannot be
  joined to a sealed policy, so it says COULD NOT LOOK. Pinning the
  ClusterPolicy spec seen at the time is a separate row, not built here.
- **That the report is complete.** Reports are merged from admission and
  background scans on Kyverno's schedule; a missing result is not a pass.
- **That the shape matches a live cluster.** The fixtures were written from
  Kyverno's and the wg-policy API documentation, not captured; see
  `tests/fixtures/kyverno/README.md` for what is unverified.

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
