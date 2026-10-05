# Cedar / Verified Permissions fixtures

Shape from R14, not a live capture. Every file here was written by hand from the
fields the research note records (the cedar-policy `Response` docs, the Amazon
Verified Permissions `IsAuthorized` API reference, and the Verified Permissions
CloudTrail page). No Cedar program or CLI was run, no AWS call was made, and
every id, account number and entity name is synthetic (`111122223333` is the AWS
documentation placeholder account).

| file | what it is |
|---|---|
| `cedar_allow.json` | Cedar `Allow`, one reason policy id, no errors |
| `cedar_deny.json` | Cedar `Deny`, one reason policy id, no errors |
| `cedar_allow_with_errors.json` | Cedar `Allow` with one evaluation error |
| `avp_allow.json` | AVP `ALLOW`, one determining policy, `errors: []` |
| `avp_deny_implicit.json` | AVP `DENY` with no determining policies (implicit deny) |
| `avp_errors.json` | AVP `DENY` with one `errorDescription` |
| `avp_capitalised.json` | AVP `ALLOW` whose determining policy uses `PolicyId` (as two AWS doc samples do) |
| `cloudtrail_isauthorized.json` | one CloudTrail data event for `IsAuthorized`, decision in `additionalEventData` |
| `cloudtrail_batch.json` | one CloudTrail data event for `BatchIsAuthorized`, three `results[]` entries (ALLOW, DENY, an unknown word) |
| `signature_looking.json` | a Cedar `Deny` with fields that look like a signature or a verdict (`signature`, `signed_by_vendor`, `standing`, `attestation`, `relayed_verdict`); the adapter must ignore all of them |

## What is not verified against a real Cedar or AWS

- The Cedar JSON wire shape. R14 documents the Rust API (`Response.decision()`,
  `diagnostics().reason()`, `diagnostics().errors()`), not a JSON serialisation.
  The keys `decision`, `diagnostics`, `reason`, `errors` and the words
  `Allow`/`Deny` follow that API; a binding that wraps the response (for example
  in a `{"type": "success", "response": ...}` envelope) or writes `allow`/`deny`
  in lower case is not documented in R14. Case is ignored; an envelope is read as
  no shape (one COULD NOT LOOK row).
- The shape of one Cedar error. R14 names `errors()` only, so the adapter counts
  and digests the list and reads nothing inside an entry.
- The Cedar CLI `authorize` output and exit codes: not documented in R14, not read.
- AVP `errors[].errorDescription` beyond its name; the adapter only counts and digests.
- That AVP always returns an `errors` key. The adapter treats a missing key as
  "errors not reported" (COULD NOT LOOK), never as empty.
- The AVP `BatchIsAuthorized` API response body: R14 does not document it, so it
  is not read. The only batch shape read is the CloudTrail
  `additionalEventData.results[{request, decision}]`.
- CloudTrail delivery wrappers (the `{"Records": [...]}` file, EventBridge
  envelopes): not in R14, not read. One event object per body.
- That `requestParameters.policyStoreId` appears in a batch event (R14 shows it
  for the single call). Absent, the row's `policy_store_id` is null.
- `eventName`, `eventID` and `requestID` are read as CloudTrail's standard keys;
  R14 lists `requestID` and `eventID` in its example and names the event names,
  not the `eventName` key itself.
