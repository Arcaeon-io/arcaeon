# Connector adapters: relaying another vendor's verdict

A security scanner, a policy engine or a sandbox hands back a verdict about some
bytes: pass, flagged, denied. That verdict usually stays in the vendor's own
console. A connector adapter turns it into one row in your Arcaeon chain, with
its provenance attached, so the next agent can see that the check happened, on
which bytes, and that nobody edited the verdict after it arrived. The same row
can then be exported as an in-toto Statement that tools outside Arcaeon can read.

This is not the MCP connector (`arcaeon mcp`, the `arcaeon.mcp` package). It is
the library `arcaeon.connector`, phase 1: the adapter shape, one mock vendor
(`mockscan`), the mcp-scan adapter, the OPA decision-log adapter, the Snyk
agent-scan adapter and the Lakera Guard adapter on the same base class, and no
command-line verb yet.

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
(`arcaeon.prove.mcp_scan`, see [MCP_SCAN.md](MCP_SCAN.md)), the OPA
decision-log adapter (`arcaeon.connector.opa`, below), the Snyk agent-scan
adapter (`arcaeon.connector.snyk_agent_scan`, below), the Lakera Guard
adapter (`arcaeon.connector.lakera_guard`, below) and the Prisma AIRS adapter
(`arcaeon.connector.prisma_airs`, below). The base owns what they share:

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

### OPA bundles: which policy made the decision

A decision event names its policy only as `bundles.<name>.revision`, the string
in the bundle's `.manifest`. OPA signs bundles (a JWT in `.signatures.json`
listing every file's hash), never decisions. So the claim "this decision was
made under that signed policy" needs the bundle itself, sealed, and a join.

`arcaeon.connector.opa_bundle.seal_bundle(source, name=...)` seals one bundle:
`source` is the tarball's bytes, a path to a `.tar.gz`, or a bundle directory.
The statement (`kind: "policy.bundle.sealed"`) carries `bundle_sha256` over the
tarball's exact bytes (a directory: sha256 over its sorted `name NUL sha256`
lines, scheme `sha256:opa-bundle-dir:v1`), the `revision` and `roots` read from
`.manifest`, `opa_signatures_present`, a `file_hashes` block (each file the JWT
lists, rehashed from the bundle bytes with stdlib `hashlib`), and
`opa_signature_verified`. That last word is VERIFIED only when the caller
supplied `verification_key` and `key_algorithm`, the JWT verifies under it
(HS256/384/512 with stdlib `hmac`; RS, PS and ES with the optional
`cryptography` package), and every listed file hash matched. A file hash that
does not match, a listed file missing from the bundle, a bundle file the JWT
does not list (unless named in `exclude_files`), a JWT `alg` other than the
key's, or a bad signature is BROKEN. No key, no verifier installed, or two
signatures is COULD NOT LOOK.

The tarball is never extracted to disk: it is read in memory, and a member
named with `..`, a backslash, a drive letter, a link or device member, or a name
twice makes the whole bundle COULD NOT LOOK (`seal` and `revision` say so). A
malformed or missing `.manifest`, bytes that are not a gzipped tarball, and a
tarball over 16 MiB (digested, not read), inflating past 64 MiB or holding over
10000 members are COULD NOT LOOK too.

`arcaeon.connector.opa.join_bundles(rows, seals)` returns new decision rows,
each with `signed_by_vendor: false`, `policy_join`, `policy_bundle_sha256` and
`decision.policy_bundles` (per bundle name: revision, join word, digest,
signature word, reason). The relayed verdict is not changed. A seal may carry
`active_from` / `active_until`, the window the caller says the bundle was in
force.

| The decision's `bundles.<name>.revision` | `policy_join` |
|---|---|
| matches one sealed bundle of that name (and its window, if it has one, covers the decision time) | VERIFIED, with `policy_bundle_sha256` |
| matches, but that sealed bundle fails its own OPA signature (file hash or JWT BROKEN) | BROKEN |
| differs from the revision of a sealed bundle declared in force at the decision time | BROKEN |
| no sealed bundle of that name has this revision | COULD NOT LOOK |
| matches only a sealed bundle whose window excludes the decision time, or the decision has no readable timestamp to place in it | COULD NOT LOOK |
| two sealed bundles with different bytes share the revision | COULD NOT LOOK |
| absent or empty (no `bundles`, or no revision) | COULD NOT LOOK |

A decision naming several bundles takes the worst word (BROKEN over COULD NOT
LOOK over VERIFIED); `policy_bundle_sha256` is set only when it names exactly
one bundle and joined VERIFIED.

#### What this cannot prove

- **VERIFIED is a revision match, not proof OPA loaded those bytes.** The
  decision log carries no bundle hash, signature or key id; the revision is
  text OPA reports. A join says the revision the decision names is the
  revision of a bundle we hold, nothing more.
- **Revisions need not be unique.** OPA does not require it. Two different
  bundles with one revision are COULD NOT LOOK; a bundle we never sealed that
  reuses a sealed revision is invisible to the join.
- **File hashes without the key prove only that the bundle agrees with itself.**
  Whoever built the bundle wrote the JWT's file list. Without the signing key's
  public half, the JWT is COULD NOT LOOK, and so is `opa_signature_verified`.
- **JSON and YAML file hashes may not be recomputable.** OPA hashes structured
  files after parsing and sorting keys, but the exact bytes it hashes are not
  documented here. We try the raw bytes and two compact sorted forms; a match
  is a match, no match on a structured file is COULD NOT LOOK, never BROKEN.
  YAML is not parsed.
- **The window is the caller's word.** `active_from` / `active_until` come from
  whoever sealed the bundle; a wrong window makes a wrong BROKEN or COULD NOT
  LOOK. Without a window a different revision is never a conflict.
- **The decision log is not a complete record.** Drop rules, masking and rate
  limits mean decisions can be missing; a join covers only the rows we have.
- **Not checked against a real OPA.** The bundle shapes are from OPA's Bundles
  documentation; the tests build bundles from small in-test files, not a live
  `opa build` output.

## Snyk agent-scan

`arcaeon.connector.snyk_agent_scan.ingest(output_bytes, broken_at_score=...)`
reads the `--json` output of Snyk agent-scan (formerly Invariant mcp-scan), in
either published shape: v0.6+ `{"scan_path_responses": [...]}` with scored
`server_risks` and `skill_risks`, or the v0.5.x object keyed by config path with
`servers` and coded `issues`. It writes one row per finding, plus one row per
target that came back clean, errored or was never analysed. This is not the
mcp-scan adapter in [MCP_SCAN.md](MCP_SCAN.md): that one writes one row per tool
and pins tool definitions; this one writes one row per finding.

Every row carries, besides the base keys:

| key | what it holds |
|---|---|
| `signed_by_vendor` | always `false`. agent-scan does not sign its output; no argument, flag or payload field can set it |
| `standing` | always `reported_by_sender` |
| `input_sha256` | hex SHA-256 of the exact bytes read |
| `vendor_request_id` | an id the caller passes from the transport, else null. agent-scan's JSON carries no request or scan id, and nothing in it is read as one |
| `finding` | format, scan path, client, target kind and name, issue code and severity (v0.5) or risk name, score and threshold (v0.6), affected tool indexes, and a digest of the evidence text |

agent-scan writes no per-finding verdict word, so the adapter writes its own.
A v0.6 score runs from 0 to 1000 and agent-scan documents no cut-off, so the
caller declares one in `broken_at_score`; without it no score maps. A v0.5 code's
first letter is its class: E and W are findings, X means the scan itself failed.

| adapter word | relayed as | when |
|---|---|---|
| `no_findings` | VERIFIED | the target was analysed and nothing points at it |
| `issue_error` | BROKEN | a v0.5 E code |
| `issue_warning` | BROKEN | a v0.5 W code |
| `risk_at_or_over_threshold` | BROKEN | a v0.6 score at or over `broken_at_score` |
| `scan_failure` | COULD NOT LOOK | a v0.5 X code |
| `unknown_code` | COULD NOT LOOK | a v0.5 code not shaped like E, W or X and three digits |
| `risk_below_threshold` | COULD NOT LOOK | a v0.6 score under `broken_at_score`; a low score is not a pass |
| `risk_no_threshold` | COULD NOT LOOK | a v0.6 score with no `broken_at_score` declared |
| `risk_unscored` | COULD NOT LOOK | a v0.6 risk with no number score from 0 to 1000 |
| `error` | COULD NOT LOOK | a path or target error |
| `not_analyzed` | COULD NOT LOOK | the target was listed but never analysed |

Output that is empty, not UTF-8 JSON, carries a duplicate key, nests deeper than
64, is over 8 MiB, or has neither shape is one COULD NOT LOOK row, still with its
`input_sha256`. `ingest` never raises on scanner output.

`standing_verdict(rows)` says what these rows can say on their own: BROKEN when
any row relays BROKEN, otherwise COULD NOT LOOK. It never says VERIFIED, and a
relayed BROKEN stays BROKEN whatever else the row claims.

### What this cannot prove

- **That the scan happened.** The rows are reported by the sender with
  `signed_by_vendor: false`. Anyone can write this JSON by hand.
- **That a clean target is safe.** `no_findings` relays that agent-scan reported
  nothing; on its own it never makes a VERIFIED.
- **Which scan this was.** agent-scan returns no request or scan id and no
  service offers a lookup, so a receiver cannot ask Snyk to confirm it.
- **What a score means.** The cut-off is the caller's, not the vendor's.
- **That the output shape is current.** The fixtures are shaped from the
  published notes, not a live capture; v0.5 and v0.6 already differ.
- **Privacy of the scan.** agent-scan sends tool names, descriptions and skill
  files to Snyk for analysis. This adapter sends nothing; it reads output you
  already hold.

## Lakera Guard

`arcaeon.connector.lakera_guard.ingest(response_bytes, policy_mode=...)` reads
the response body of a Lakera Guard API v2 screening call (`POST /v2/guard`):
`flagged`, `action`, and, when the request asked for them, the `breakdown` of
per-detector results and the `payload` of match spans. It writes one row for
the response, plus one row per detector that says `detected: true` and one per
match span. v2 has no `categories` field; a detector's `detector_type` is its
category.

Every row carries, besides the base keys:

| key | what it holds |
|---|---|
| `signed_by_vendor` | always `false`. Lakera does not sign its responses; no argument, flag or payload field can set it |
| `standing` | always `reported_by_sender` |
| `input_sha256` | hex SHA-256 of the exact response bytes read |
| `request_sha256` | hex SHA-256 of the request body, when the caller passes it as `request_body`, else null |
| `vendor_request_id` | `metadata.request_uuid` from the response, else an id the caller passes, else null; `vendor_request_id_source` says which, and `ids` keeps both |
| `finding` | which part (response, breakdown or payload) and its index; for the response `flagged`, `action`, the declared policy mode, detector and match counts, model version; for a detector its project, policy and detector ids, `detector_type`, `result`, `message_id`; for a match span `detector_type`, labels, offsets and a digest of the matched text |

`flagged` is always false in Detect mode; only an Enforce-mode policy flags.
The response does not document which mode ran, so the caller declares it in
`policy_mode` (`"enforce"` or `"detect"`). "Not flagged" relays VERIFIED for its
one row only when the caller declared `"enforce"` and nothing else in the
response points the other way. Lakera writes a boolean, not a word, so the
adapter writes its own:

| adapter word | relayed as | when |
|---|---|---|
| `flagged` | BROKEN | `flagged` is true, whatever mode was declared |
| `detector_detected` | BROKEN | a breakdown entry says `detected: true` |
| `payload_match` | BROKEN | a payload match span |
| `not_flagged` | VERIFIED | `flagged` is false, no detector hit, no match span, nothing unreadable, and the caller declared `"enforce"` |
| `not_flagged_detect_mode` | COULD NOT LOOK | `flagged` is false and the caller declared `"detect"` |
| `not_flagged_mode_undeclared` | COULD NOT LOOK | `flagged` is false and no mode was declared |
| `not_flagged_unsettled` | COULD NOT LOOK | `flagged` is false but a detector hit, a match span or an unreadable entry points the other way |
| `flagged_unreadable` | COULD NOT LOOK | `flagged` is missing or not a boolean |
| `detector_unreadable` | COULD NOT LOOK | a breakdown entry that is not an object or has no boolean `detected` |
| `payload_unreadable` | COULD NOT LOOK | a payload entry that is not an object |
| `results_not_screening` | COULD NOT LOOK | a `/v2/guard/results` body, which makes no flagging decision |

A response that is empty, not UTF-8 JSON, carries a duplicate key, nests deeper
than 64, is over 8 MiB, or has neither shape is one COULD NOT LOOK row, still
with its `input_sha256`. `ingest` never raises on the response.

`standing_verdict(rows)` says what these rows can say on their own: BROKEN when
any row relays BROKEN, otherwise COULD NOT LOOK. It never says VERIFIED, and a
relayed BROKEN stays BROKEN whatever else the row claims.

### What this cannot prove

- **That the screening happened.** The rows are reported by the sender with
  `signed_by_vendor: false`. Anyone can write this JSON by hand.
- **That a not-flagged request is safe.** `not_flagged` relays what Lakera
  reported, under a policy mode the caller declared; on its own it never makes a
  VERIFIED.
- **Which policy mode ran.** The response does not say; the caller's
  `policy_mode` is the caller's word, not Lakera's.
- **Which request was screened.** `request_uuid` names the call, but Lakera
  offers no lookup by it: `/v2/guard/results` screens again rather than
  returning the earlier answer. `request_sha256` is only as good as the bytes the
  caller hands in.
- **That the response shape is current.** The fixtures are shaped from the
  published API reference, not a live capture; the full set of `action` values
  and `detector_type` names is not documented there.
- **Privacy of the screening.** A Lakera call sends the screened messages to
  Lakera. This adapter sends nothing; it reads a response you already hold, and
  keeps matched text by digest only.

## Prisma AIRS

`arcaeon.connector.prisma_airs.ingest(response_bytes)` reads a Palo Alto Prisma
AIRS (AI Runtime Security) API response in any of four shapes: a sync scan
response (`action`, `category`, `prompt_detected`, `response_detected`,
`scan_id`, `report_id`, `tr_id`), an async scan acknowledgement (`received`,
`scan_id`, `report_id`), a scan results list (`[{req_id, status, scan_id,
result}]`), or a threat scan report (`detection_results[]` with `data_type`,
`detection_service`, `verdict`, `action`, `result_detail`). It writes one row
per scan, results item or detection result.

Every row carries, besides the base keys:

| key | what it holds |
|---|---|
| `signed_by_vendor` | always `false`. Prisma does not sign its verdicts; no argument, flag or payload field can set it |
| `standing` | always `reported_by_sender` |
| `input_sha256` | hex SHA-256 of the exact bytes read |
| `vendor_request_id` | the `scan_id`, else the `report_id`, as Prisma wrote it; else null |
| `ids` | `scan_id`, `report_id`, `tr_id` and `req_id` |
| `refetch` | the re-fetch description below for this row's id, or null when no id has the documented shape |
| `finding` | format, status, action, category, profile name, the names of detection flags that are true, and for a report the data type, detection service, verdict and a digest of `result_detail` |

The adapter writes its own word from Prisma's `action`, and reads the detection
flags and category so that an allow which names a threat is not taken as a pass:

| adapter word | relayed as | when |
|---|---|---|
| `allow` | VERIFIED | action allow, no detection flag true, category (or report verdict) not `malicious` |
| `block` | BROKEN | action block, whatever else the response says |
| `allow_with_detection` | COULD NOT LOOK | action allow, but a detection flag is true or the category or report verdict is `malicious` |
| `detection_unreadable` | COULD NOT LOOK | action allow, a detection map or flag that is not true or false |
| `unknown_action` | COULD NOT LOOK | action missing, not a string, or not allow or block |
| `pending` | COULD NOT LOOK | an async acknowledgement, or a results item with no result yet |

A response that is empty, not UTF-8 JSON, carries a duplicate key, nests deeper
than 64, is over 8 MiB, or has none of the four shapes is one COULD NOT LOOK
row, still with its `input_sha256`. `ingest` never raises on vendor output.

Prisma is the one vendor here that serves a stored result by id.
`refetch_request(id)` returns a description of that request and nothing more:
for a scan id (a UUID) `GET /v1/scan/results` with `scan_ids=<id>`, for a report
id (`R` and a UUID) `GET /v1/scan/reports` with `report_ids=<id>`. It names no
host, carries no key and makes no network call; any other id raises
`ValueError`. A receiver with its own Prisma AIRS key can send it. A re-fetch is
a second report from the same vendor, not a signature.

`standing_verdict(rows)` says what these rows can say on their own: BROKEN when
any row relays BROKEN, otherwise COULD NOT LOOK. It never says VERIFIED, and a
relayed BROKEN stays BROKEN whatever else the row claims.

### What this cannot prove

- **That the scan happened.** The rows are reported by the sender with
  `signed_by_vendor: false`. Anyone can write this JSON by hand.
- **That an allow is safe.** `allow` relays that Prisma let the content
  through; on its own it never makes a VERIFIED.
- **That a re-fetch settles it.** A re-fetch by id shows what Prisma says now,
  from the same vendor, with no signature. It can raise a receiver's confidence
  that the sender did not invent the id; it cannot make a VERIFIED.
- **That the id format and field values are current.** The fixtures are shaped
  from the published API notes, not a live capture. The full id format,
  `status` values, report `verdict` values, categories other than `malicious`
  and the re-fetch query parameter names are not confirmed.
- **Privacy of the scan.** Prisma AIRS receives the prompts and responses it
  scans. This adapter sends nothing; it reads responses you already hold.

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
