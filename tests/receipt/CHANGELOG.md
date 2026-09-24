# Changelog

## 0.2.0 — 2026-09-23: first public upload

- **First release on PyPI.** 0.1.0 was never uploaded (PyPI returned 404 for `arcaeon-receipt` on 2026-09-23); the number is skipped, not lost. This tree adds the `call_proxy --tape` flags, changes the printed verdict words (VERIFIED / BROKEN / COULD NOT LOOK) and fails inputs that used to pass (duplicate JSON keys, contradicting attachments), so anyone who installed "0.1.0" from a source checkout can tell the two apart by number. Every section below this heading ships in 0.2.0.
- **The archive README's browser verifier is a live link.** `archive.VERIFIER_PAGE_URL` named `web/verify-receipt.html` in github.com/Arcaeon-io/arcaeon-receipt, which returned 404 on 2026-09-23 (the repo has no public remote). It is now https://arcaeon.io/verify-receipt (200 the same day; its bytes equal the private monorepo's site copy, which passes the parity test against this tree). `examples/class_archive_example.zip` rebuilt with its original stamp: only `README.txt` and its `MANIFEST.json` digest changed.
- **What the wheel ships, said plainly.** The wheel is the library and the `arcaeon-receipt` command. `web/`, `examples/`, `tests/fixtures/` and `docs/` ship in the sdist, and the README now says so under the install line, with the hosted verifier URL. Only `verify-receipt` is hosted; `verify-any` and `authorship-recorder` are sdist-only for now.
- **sdist fix.** The example receipts and witness sidecars are tracked but match `.gitignore`, which hatch's sdist honours, so the sdist had `examples/ballots/` without a single `.receipt.json`. `[tool.hatch.build.targets.sdist] artifacts` now carries them; `RELEASE_*.md` (internal notes) is excluded.
- **Packaging.** New extra `tape = ["arcaeon-adapter>=0.2.0"]` for `call_proxy --tape` (the writer is imported lazily; without it the proxy still forwards and receipts). The `Source` URL is dropped (it pointed at the 404 repo; PyPI metadata is permanent per version) and `Verifier` added.

## Vocabulary follow-ups (2026-09-23, branch vocab-followups, local only)

- **Single view, canonicalization refused:** `web/verify-receipt.html`'s single-receipt view now says COULD NOT LOOK, with the reason, for an input the canonicalizer refuses (a float that overflows to Infinity), matching the batch view and verify-any. It said BROKEN before; BROKEN is kept for a digest that does not match. A duplicate key stays BROKEN everywhere. C14N and cross-check blocks byte-identical. The differential in `tests/test_universal_checker.mjs` now drives the single view too (two refused inputs plus a duplicate-key control) and goes red against the previous page.
- **Example archive line endings:** `examples/.gitattributes` pins the cohort sources to `text eol=lf` and the zip to `binary`; `examples/class_archive_example.zip` rebuilt from the LF checkout (no CR byte in any entry; a build from `git archive HEAD` matches it entry for entry). `test_the_committed_example_archive_matches_a_fresh_build` passes byte for byte on Windows; a new test names CRLF directly if it returns. Manifest digests 30/30 match; the extracted cohort verifies 12 VERIFIED, 0 BROKEN, 0 COULD NOT LOOK.
- Suite: 346 passed, 0 failed, 3 xfailed.

## Vocabulary pass: one set of words on every surface (2026-09-23, branch vocabulary-2026-09-23, local only)

Four verdict languages had grown across the Arcaeon tools in one night (Fable audit 2026-09-22, section 1). The helm's decision: VERIFIED for a pass in one run, BROKEN for a failure, COULD NOT LOOK for "this run did not get to look"; PASS, FAIL (as a printed word) and UNDETERMINED are retired from what a person reads. CLAIMED stays as a field label.

- **Printed words changed, machine values not.** `verify --batch` rows and summary, the roster-report summary line, the archive summary line and the archive README now say VERIFIED / BROKEN / COULD NOT LOOK. `row["verdict"]` (`ok` / `FAIL` / `undetermined`), the roster CSV `verdict` column and its `verified` / `failed` / `undetermined` header keys, the archive manifest's `verdict_counts` and every exit code (0 / 2 / 4 / 1) are unchanged, so no script that reads them breaks. `verify_batch.SAY` is the one map from value to word.
- **verify-receipt.html:** the body tag, the batch rows, counts and summary, the legend, the attestation-signature tag (was MISMATCH) and the witness notice (was INCONSISTENT) use the same three words. The pinned C14N and cross-check blocks are byte-identical; their extraction test passes.
- **verify-any.html:** a non-core row the page cannot reach (value NOT LOOKED, unchanged) prints as COULD NOT LOOK in grey; the record line says BLIND (was NEVER CHECKED), the audit-state word for "nobody has checked", and `UC.NEVER_CHECKED` now carries that word.
- **Example archive:** `examples/class_archive_example.zip` got the new README only (entry and its manifest digest); every other entry is byte-for-byte the committed one. `test_the_committed_example_archive_matches_a_fresh_build` still fails on this Windows checkout for the reason it failed before this pass (a committed CRLF exhibit), not on the README.
- Tests updated to the new words, none deleted: 344 passed, 1 failed (the pre-existing one above), 3 xfailed, before and after; `tests/test_universal_checker.mjs` 90 cases, all ok, before and after.

## Universal checker, slice 3: the Arcaeon arm runs verify-receipt's own cross-checks (2026-09-22)

Closes a disagreement between two of our own checkers. After `receipt-fix-round2`, `web/verify-receipt.html` failed a receipt whose witness block contradicts its ledger block, its own pin or the pin's `self` digest, and one whose attestation signature names another body digest. The Arcaeon arm of `web/verify-any.html` only checked the body digest and marked the witness NOT LOOKED, so on those receipts verify-any said VERIFIED where verify-receipt said FAIL. The slice 1 differential did not see it: no Arcaeon fixture carried a contradicting attachment.

- **One source, not a second implementation.** The cross-check functions (`getField`, `asString`, `prettyNode`, `pyDefaultDumps`, `sameValue`, `checkWitness`, `checkAttestationSignature`) now sit in one marked block of `verify-receipt.html`, `// CROSSCHECK-START` to `// CROSSCHECK-END`, moved there unchanged. `tools/extract_c14n.py` writes that block byte for byte to `web/universal/crosscheck_pinned.js`, the same mechanism as `c14n_pinned.js`, and `verify-any.html` loads it before `fmt_arcaeon.js`. Why extraction and not a `<script src>` in verify-receipt.html: the site copy may not load any script (the private monorepo's parity test refuses `<script src>` on that page), and the private monorepo's conformance test runs the page's single inline script under node:vm. The C14N block is unchanged; `extract_c14n.py --check` and the c14n pin test pass.
- **Verdicts on the Arcaeon arm**, the words verify-receipt.html renders: an inconsistent witness block is BROKEN; an attestation signature over another digest (or not `signed_over: body_digest`, or not an object) is BROKEN; a signature value that names this digest is COULD NOT LOOK on its own row (no key, no scheme in format 0.1) and does not fail the run; the ledger, the witness and the anchor are otherwise NOT LOOKED, labelled CLAIMED. When the body cannot be read the cross-checks are not reached, as in verify-receipt.
- **Fixtures** (5 new, 90 cases, 74 refusals): `arc_witness_inconsistent`, `arc_witness_pin_self_mismatch`, `arc_ledger_edited_witnessed`, `arc_signature_mismatch` (all BROKEN, each with the body digest still matching), and `arc_signature_value_unchecked` (VERIFIED, not a refusal, listed so the gap is visible). The Python `verify_receipt` refuses the four as well. Only the new files and the manifest were kept from the generator run; the ECDSA fixtures' bytes were restored.
- **Differential, the test that was missing.** Every `arc_*` fixture plus 19 attachment edits made in memory (33 inputs) goes through verify-receipt.html's own `verifyOneText`, the Arcaeon arm and `UC.verifyAny`; all three must agree, and at least six of the refusals must come from an attachment alone (13 do). New break arm `always-consistent` (both cross-checks replaced by ones that always say consistent): the set goes red with a false VERIFIED on all four new BROKEN cases, and the differential goes red on 13 inputs. New pytest pins: `crosscheck_pinned.js` equals the block (shown red by editing one comparison in the pinned file), verify-any loads the pinned blocks in order, and no other universal module defines its own cross-check.

Tests: `node tests/test_universal_checker.mjs`: all ok, 90 cases, 74 refusals, every break arm caught; the pytest wrapper's six `--red` runs each exit 1. `pytest tests/test_universal_checker.py`: 22 passed. Full suite: 344 passed, 3 xfailed, 1 failed (the known `test_archive` line-ending case in a fresh worktree). The private monorepo, with `ARCAEON_RECEIPT_ROOT` pointed at this tree: `test_verify_page_parity_copy.py` 7 passed, `test_verify_receipt_conformance.mjs` 122 passed, 0 failed, 10 xfail. The site copy `projects/arcaeon_site/verify-receipt.html` was mirrored byte for byte (chrome kept) and left uncommitted in the private monorepo; its byte-for-byte leg fails against an arcaeon-receipt checkout that does not have this change yet. Local only, nothing deployed.

## Universal checker, slice 2 review fixes (2026-09-22)

An independent reviewer's changes to the SCITT Receipt arm, applied before merge.

- **Tree size and leaf index must be CBOR uints.** RFC 9942 s5.2 types both as `uint`. The decoder turns a float into a Number and 7.0 into 7, so `typeof === "number"` let a float through, and an integral one verified. `UC.proofUintCheck` now reads the proof's own bytes and requires major type 0 for both; `Number.isInteger` and `>= 0` stay as a second fence. Three new cases, all BROKEN: `scitt_receipt_float_tree_size` (7.5), `scitt_receipt_float_tree_size_integral` (7.0, otherwise a valid receipt, so only a major-type check catches it), `scitt_receipt_float_leaf_index` (5.0). New break arm `float-as-uint` (the major-type check removed) goes red on the two integral-float cases with a false VERIFIED.
- **The attached-root mismatch names the entry rule**, the same sentence the signature-failure branch uses ("Entry rule used: the statement with an empty unprotected header (RFC 9943 s6.3)."), since there too a different entry rule looks the same as a different statement.
- **Tree size and leaf index are labelled as the receipt's unsigned claims** in the VERIFIED text: they sit in the unprotected header, and the root is what is signed.
- **Other proofs beside the inclusion proof get a NOT LOOKED row** (a consistency proof at -2, or a label the IANA registry does not name for vds 1) instead of silence. The Transparent Statement path now judges each receipt by its core claims only, so a coverage row cannot demote a receipt that verified.
- **The service identity row no longer says "the key is the one you supplied" when no key was supplied.**

Tests: 85 cases, 70 refusals. `node tests/test_universal_checker.mjs`: all ok; every `--red` arm (always-arcaeon, always-verified, skip-signature, claimed-root, float-as-uint, lenient-base64) exits 1. `pytest tests/test_universal_checker.py`: 14 passed. Full suite: 323 passed, 4 xfailed, 1 failed (the known `test_archive` line-ending failure in a fresh worktree). The receipt fixtures were regenerated as one consistent set (ECDSA re-signing changes their bytes, not their verdicts); the slice 1 fixture bytes were restored after the run. The new NOT LOOKED rows and the no-key wording were checked by hand against the built page, not by a manifest case (a case asserts only the verdict).

## Universal checker, slice 2: SCITT Receipts with the inclusion proof recomputed (2026-09-22)

Slice 1 said SCITT Receipts were NOT LOOKED, and its own report said the gap claim against Microsoft's scitt-verifier held only if inclusion proofs got checked. They do now. `web/verify-any.html` reads an RFC 9942 COSE Receipt for the one registered verifiable data structure, RFC9162_SHA256 (vds 1), and checks it the way RFC 9942 s5.2.1 orders it: the inclusion proof is applied to the statement's own leaf to recompute the Merkle root (RFC 9162 s2.1.3.2), then the transparency service's COSE_Sign1 signature is checked over that recomputed root through WebCrypto with a key the reader supplies. An attached root is allowed (RFC 9942 s4.4 says SHOULD detach) and must equal the recomputed one before any signature is looked at.

Two ways in: a receipt on its own plus the statement it claims to include (new optional file input), or a Transparent Statement carrying its receipts at 394 (RFC 9943 s7), whose receipts are now core claims: its claim to be transparent is why it carries them, so with no service key it is COULD NOT LOOK, not VERIFIED. With several receipts, one that verifies under the reader's key is enough (RFC 9943 s7.1) and the rest are shown, not counted.

The detector tells a receipt from a statement by the two markers RFC 9942 makes mandatory, vds (395) protected and vdp (396) unprotected. One without the other, or a receipt that carries receipts of its own, is COULD NOT LOOK ("ambiguous"), never a guess.

The entry rule, stated because it is a reading and not a quote: neither RFC 9942 nor RFC 9162 says which bytes of a SCITT statement are the log entry. This checker takes RFC 9943 s6.3 ("the unprotected header of a Signed Statement MUST be set to an empty map before the Signed Statement can be included") and uses the statement's own bytes, sliced not re-encoded (`UC.cborItemEnd`), with the unprotected header replaced by `a0`; the leaf is SHA-256(0x00 || entry). A service that logs something else will read as BROKEN here, and every signature failure says which rule was used, because from the bytes alone a wrong proof, a different statement, a wrong key and a different entry rule look the same.

COULD NOT LOOK by construction: any VDS but 1 (the CCF ledger profile is 2, an Internet-Draft, not in the IANA registry), consistency-only receipts, more than one inclusion proof under one signature, a tree head algorithm WebCrypto does not run, no service key, no statement. NOT LOOKED: who the service key belongs to, and validity periods. BROKEN: a proof that does not fit its own tree (index past size, a path hash short or long, a hash not 32 bytes; caught before any key or statement is needed), an attached root the path does not reach, a signature that does not verify over the recomputed root, missing alg or vdp.

Tests: 29 new cases (82 total, 67 refusals), built by `tools/make_universal_fixtures.mjs` because the RFC examples are elided: a seven-entry log from the RFC 9162 recursive definitions, root cross-checked by the s2.1.2 stack algorithm, path re-walked by recursion, every tree head signature re-checked with node:crypto; the service key's private scalar is the SHA-256 of a published string. The slice 1 fixture bytes were restored after the run (ECDSA re-signing changes them; their verdicts do not). New spec sweep: the checker's s2.1.3.2 loop equals the recursive Merkle Tree Hash at all 561 index/size pairs for sizes 1 to 33, and a path one hash long or short is refused at every one. New break arm `claimed-root` (a proof step that returns the root the receipt claims, the failure RFC 9942 s4.4 names): the suite requires it to be caught by a false VERIFIED, and it is, on the two attached-root cases. `node tests/test_universal_checker.mjs`: all ok. `pytest tests/test_universal_checker.py`: 14 passed. Full suite: 323 passed, 4 xfailed, 1 failed (the known `test_archive` line-ending failure in a fresh worktree, same as before this change: 322 passed then). Nothing installed, downloaded, run from outside, or deployed.

## Fields the issuer only asserts are CLAIMED, never shown as checked; attachments that contradict the receipt fail (2026-09-22, branch `receipt-fix-round2`)

Picks up the four strict xfails the failure-conformance suite left open. Local only, not deployed.

- **Edited witness pin values (fixed).** `core.verify_receipt` now checks the witness block against the ledger block (rows, chain, namespace), against its own embedded pin, and, for a WitnessStore pin, against the pin's own `self` digest (recomputed with arcaeon-ledger's own `_digest_record`). A contradiction is `witness.verdict: "inconsistent"` and `ok` is False, with or without the ledger file. `verify_batch` reports it as FAIL.
- **Attestation signature over another digest (fixed).** A detached signature whose `body_digest` is not this receipt's, or whose `signed_over` is not `body_digest`, is `attestation_signature.verdict: "mismatch"` and fails. The value alone cannot be checked: the format carries no key and no scheme. That verdict is `could_not_look`, reported in the result and in the exhibit, and the value-only case stays a strict xfail.
- **Witness relabelled local -> hosted (half fixed).** Kind, independence, url and status are reported as `claimed` (a `claimed` list on every result, `witness=claimed` on batch lines, "(claimed, not verified)" in the exhibit) and are never what earns ok. The relabel itself still verifies, because nothing in 0.1 says who made a pin. Stays a strict xfail.
- **Re-minted receipt without the ledger (proposal only).** Every result now carries `issuer: claimed`. Failing it needs an issuer signature, so it stays a strict xfail.
- The three remaining xfails each need a format change, written up in `FORMAT_CHANGE_PROPOSAL.md` (issuer signature, witness-signed pin, keyed attestation signature). None was made.
- `web/verify-receipt.html`: the same rules in the browser. The witness, ledger and anchor panels say CLAIMED, and the hosted notice no longer says "pinned to a third-party service". New checks: the witness block against the ledger block and its pin, the pin's `self` digest recomputed in the page with Python's default-separator recipe (and the Python-issued fixture's digest matches), and a new Attestation signature panel showing COULD NOT LOOK or MISMATCH. Batch rows FAIL on an inconsistent witness or a mismatched signature, and PASS rows name what was only claimed. The C14N block is unchanged. Mirrored byte for byte into the private monorepo's `projects/arcaeon_site/verify-receipt.html`.
- `verify_batch.render`: an anchor status the run did not check prints as `anchor=<status>(claimed)`.
- Tests: `test_conformance_failure.py` has 4 new core reject cases (so the break arm covers them), real tests for the fixed and half-fixed items, and 3 strict xfails with updated reasons. `test_ab1405_fields.py` asserts `could_not_look`. Suite 335 passed, 3 xfailed, 1 failed (the `test_archive` CRLF case, which fails in a fresh Windows worktree before this change too; content is identical after CRLF normalization).

## Universal checker, slice 1: one page, any receipt, honest answers (2026-09-22)

New page `web/verify-any.html` (needle candidate 2 in private monorepo `projects/online_business/NEEDLE_RESEARCH_2026-09-22.md`). Paste or drop a receipt from any vendor; the page says VERIFIED, BROKEN, or COULD NOT LOOK for your run, lists every claim with NOT LOOKED rows for what it cannot reach, and reports the record axis separately as NEVER CHECKED (no check record is published for anything yet). An unrecognized or ambiguous input is COULD NOT LOOK, never BROKEN.

Why a new page and not inline growth: `verify-receipt.html` is held byte-identical to the site copy by the private monorepo's `test_verify_page_parity_copy.py`, and its whole `<script>` is lifted into node:vm by the site's conformance test. Any edit there breaks both until a deploy. So `verify-receipt.html` is untouched, and the new page loads plain modules from `web/universal/` by `<script src>`. The json-c14n v1 canonicalizer is not forked: `tools/extract_c14n.py` copies the C14N-START..END block into `web/universal/c14n_pinned.js`, and `tests/test_universal_checker.py` fails if the two ever differ (shown red by hand-editing one byte).

Formats and depth:
- **Arcaeon receipts**: body digest, through the pinned canonicalizer. Differential test: agrees with `verify-receipt.html`'s own `verifyOneText` on every Arcaeon fixture.
- **Agent Receipts (Obsigna) v0.5.0**: schema (required fields, enums, patterns), then Ed25519 over RFC 8785 JCS of the receipt without `proof`, key from a did:key or supplied by the reader. did:agent and other DID methods are COULD NOT LOOK (the spec leaves resolution open, s9.6). Chain links and RFC 3161 timestamps are NOT LOOKED.
- **SCITT Signed Statements (RFC 9943, was draft-ietf-scitt-architecture)**: strict CBOR, tag 18, CWT Claims iss and sub, header types, COSE Hash Envelope rules (RFC 9995), payload digest against a supplied original, signature over the COSE Sig_structure through WebCrypto (ES256/384/512, EdDSA/Ed25519, PS256-512, RS256-512) with a supplied key or the embedded x5chain leaf. Detached payloads need the payload. Certificate chains and Receipts (RFC 9942 inclusion proofs) are NOT LOOKED.
- **Signet**: recognized, answered "could not look: no published schema". Its co-signed (v3) record is described only in a Draft RFC that says the signable bodies live inside its code.

Found while building: a base64 decoder that ignores the unused bits of the last character lets an edited `proofValue` decode to the same signature bytes and verify. `UC.fromBase64` refuses non-zero leftover bits; case `ar_tampered_signature_padding_bits` and the `lenient-base64` break arm hold it.

Tests: `tests/fixtures/universal/` is a published failure-first conformance set (53 cases, 42 refusals; README lists each with its expected verdict; fixtures from `tools/make_universal_fixtures.mjs`, which shares no code with the checker and re-checks every signature with node:crypto). `tests/test_universal_checker.mjs` runs spec vectors (RFC 8785 examples, Agent Receipts did:key vectors), the set, the differential, and four break arms (always-our-format detector, always-VERIFIED, signature always passes, lenient base64), each of which must turn the suite red. `tests/test_universal_checker.py` wraps it for pytest and re-verifies the Arcaeon fixtures with the Python `verify_receipt`. Nothing installed, nothing downloaded or run, nothing deployed.

The fixtures folder carries `.gitattributes` `* -text`: a fresh Windows checkout had rewritten the hash-envelope preimage to CRLF and broken its digest case, which only a clean re-checkout showed.

## call_proxy tapes invalid ids as `invalid_id`, the adapter's rule (completeness slice 2, 2026-09-23, local only)

Why: call_proxy taped a `tools/call` with a boolean JSON-RPC id (`id: true`) as an ordinary call and paired the upstream's answer to it, while the arcaeon-adapter ignored it. A clean stream carrying a boolean id reconciled as MISSING on the agent side. JSON-RPC 2.0 says an id is a string, a number, or null.

What (THE RULE, identical to arcaeon-ledger `completeness-slice3` `SeamObserver` + `TapeWriter.invalid_call`): a `tools/call` whose id is not a string, number or null (true, false, an object, an array) is an INVALID call. It was sent, so it gets exactly one tape row, written at once, `status: "invalid_id"`, `resp: null`, `rpc_id` as compact JSON; it is never queued, and `_tape_answers` ignores answers carrying such an id, so no answer pairs to it. A null or absent id is still a notification (no row). NEW `_valid_rpc_id()` (the adapter's predicate, kept here because the tape writer is optional) and `_ToolTape._invalid()`; with a tape writer from before `invalid_call` the row is still written, closed with no answer (`unanswered`). The relay is unchanged: the caller still gets the upstream's answer to the invalid call.

Tests (`tests/test_call_proxy_tape.py`, 33 -> 36, run red on 228f340): ids true, 1, "x" then false, {"k":1}, [1], 2 are 7 rows, the four invalid ones `invalid_id` with no answer, nothing held to session end; cross-repo, the adapter (`--http-forward`, a real process) and this proxy reconcile ids [true, 1, "x"] `MATCHED 3 of 3` (SKIPs with the reason when the ledger checkout's tape has no `invalid_call`; on the old proxy the tool tape read `(1, None, ok)`); break arm: the pre-fix predicate (every id valid) fails both checks. Full suite 345 passed, 4 xfailed, 1 failed (base 342/4/1; the failure is the pre-existing test_the_committed_example_archive_matches_a_fresh_build, a CRLF checkout artifact).

## call_proxy's tape pairs duplicate ids FIFO, the adapter's rule (completeness slice 2, 2026-09-23, local only)

Why: a review of the completeness recorders found both tapes mishandled a reused JSON-RPC id, differently. This proxy's `_tape_answers` kept the FIRST answer per id (`setdefault`), so both calls of a duplicated id were taped with the same answer; the adapter overwrote the first call and taped the second with the first answer. Reconcile then reported the index as altered on a clean run. Duplicate ids violate JSON-RPC, but a completeness recorder must not lose or double-count a call over it.

What (THE RULE, identical to arcaeon-ledger `completeness-slice3` `SeamObserver`): open calls are queued per (scope, id) in send order; an answer pairs with the OLDEST open call of its id; a call never overwrites another; every sent call gets exactly one tape row and one seam row; a call still unpaired at session end is `unanswered` (here: exactly one tape row; the seam row is the adapter's). `_tape_answers` now returns every answer in order as `[(id key, answer)]`; `_ToolTape` keeps one queue of open calls per (`Mcp-Session-Id`, id), covering both in-flight calls and calls a 202 left open (it replaces `_waiting`, whose "a new call takes the id over" rule is retired: a reused id now queues behind the open call). An exchange that does not end in a 202 closes its own still-open calls `unanswered`, as before.

Tests (`tests/test_call_proxy_tape.py`, 28 -> 33, the new ones run red on cae439e): a batch with ids 1,1,2 is 3 rows, each with ITS answer, all closed by the response; a second call reusing a 202-open id queues behind it and both GET-stream answers close their own calls; cross-repo, the adapter (`--http-forward`, a real process) and this proxy reconcile the same batch `MATCHED 3 of 3` (SKIPs with the reason when the ledger checkout's adapter does not pair FIFO; against the old proxy it read `ALTERED at call 2`). Break arms: the pre-fix first-answer-per-id reading, and an overwriting `_enqueue`, each fail. The existing break-arm liars were updated to the list shape. Full suite 342 passed, 4 xfailed, 1 failed (base 337/4/1; the failure is the pre-existing test_the_committed_example_archive_matches_a_fresh_build, a CRLF checkout artifact).

## call_proxy's tape agrees with the adapter's on 202s and compressed answers (completeness slice 2, 2026-09-22, local only)

Why: reviewing the adapter's HTTP forward mode (arcaeon-ledger completeness-slice3) found two places the two tapes disagreed about the SAME call, which reconcile would report as tampering on a clean run. (a) A `202` closed the call `unanswered` on the tool side at once, while the adapter leaves it open for the answer that Streamable HTTP delivers later on the session's GET stream: a call answered that way read `ok` on the agent tape and `unanswered` on the tool tape. (b) The tool side parsed a gzip/deflate body raw, found no answer, and wrote `unanswered`, while the adapter decompresses a copy and reads it.

What: `KEEP_OPEN_STATUSES = {202}` (the adapter's rule and name). A 202 leaves its calls open, keyed by (`Mcp-Session-Id`, id); an answer for that key on any later response in the same session (the GET stream) closes it with the real response digest; a call still open when the proxy stops is written `unanswered` then (`writer.flush()`, as `main()` already did). Any other response without the answer (an error status, an unreadable body, upstream down) still closes it `unanswered` then. NEW `_decoded()`: gzip/x-gzip/deflate undone with stdlib zlib on a COPY before answers are matched; the caller still gets the encoded bytes and the receipt still digests them; an unknown coding reads as no answer. Because this proxy reads each response whole before relaying it (unchanged, see BYTE FIDELITY), a GET stream's answers reach the tape when that response ends.

Tests (`tests/test_call_proxy_tape.py`, 18 -> 28, the new ones run red on the old proxy first): a 202 answered later on the GET stream is taped with that answer and holds call 2 behind it until then; a later answer in ANOTHER session does not close it; a 202 never answered is `unanswered` at session end; a non-202 without the answer (500) closes it at once; gzip JSON, gzip SSE and deflate JSON answers taped from the decompressed copy with the caller's bytes identical to the upstream's. Break arms: a proxy that closes on a 202 (`KEEP_OPEN_STATUSES` emptied) and one that reads compressed bytes raw (`_decoded` as identity) each fail those checks. The cross-repo chain no longer uses `tests/_http_bridge.py` (deleted; nothing else used it): it runs `arcaeon-adapter --http-forward` as a real process, `client -> adapter (agent tape) -> hop -> call_proxy (tool tape) -> HTTP MCP server`, and SKIPs with the reason when the ledger checkout has no `--http-forward`. Full suite: 337 passed, 4 xfailed, 1 failed (pre-existing `test_the_committed_example_archive_matches_a_fresh_build`, CRLF checkout artifact; base was 327/4/1). From the ledger side, the 202-answered-later case now reconciles `MATCHED 2 of 2` (arcaeon-ledger `test_cross_repo_a_202_answered_later_matches_on_both_tapes`).

## call_proxy keeps the tool-side tape (completeness slice 2, 2026-09-22, local only)

`--tape PATH [--tape-namespace NS]` makes call_proxy write the TOOL side's call tape (`arcaeon-tape/1`): one chained row per MCP `tools/call` it forwards, with the digest of the request and of the answer as this side saw them. Same writer (`arcaeon_adapter.tape.TapeWriter`) and same digests as the agent-side tape the arcaeon-adapter keeps, so `arcaeon-ledger reconcile agent.tape tool.tape` lines them up: MATCHED n of n, MISSING at k, ALTERED at k, COULD NOT LOOK.

Why: the completeness design (private monorepo `projects/online_business/COMPLETENESS_DESIGN_2026-09-22.md`) needs a second recorder on the far end of the call, in a process the agent's model does not own. This proxy already sits there for receipts.

How: one call on each side of `_forward()` in `_proxy()`. `open_call` per `tools/call` in the request body (a batch opens one per call, in order); `close_call` with the answer matched by JSON-RPC id, read from an `application/json` body or the `data:` events of a `text/event-stream` body. An answer this side cannot find (202, upstream down, unparseable) is written `unanswered`, never guessed. Non-MCP traffic is not taped.

Not vendored: the writer is imported lazily from `arcaeon-adapter` (arcaeon-ledger repo, stdlib only). Without it the proxy still forwards and receipts every call, warns on stderr, and `/_arcaeon/health` carries `tape: {"on": false, "reason": ...}`. A tape failure never costs a call or its receipt; failures are counted in health. No new required dependency.

Tests: `tests/test_call_proxy_tape.py` (18), written first and run red. Includes the cross-repo chain `client -> arcaeon-adapter (agent tape) -> tests/_http_bridge.py -> call_proxy (tool tape) -> HTTP MCP server`, reconciled with the ledger's own CLI: clean is `MATCHED 5 of 5`, an answer changed between the tapes is `ALTERED at call 2`. Break arms swap in a proxy that loses the answer or digests bytes instead of content, and the same checks fail. Needs an arcaeon-ledger checkout with the tape writer and reconcile at `$ARCAEON_LEDGER_REPO` (or `../arcaeon-ledger`); without it 16 tests SKIP with that reason and the 2 fallback tests still run. Full suite with it: 327 passed, 4 xfailed, 1 failed (pre-existing: `test_the_committed_example_archive_matches_a_fresh_build`, a CRLF checkout artifact, fails identically on the base).

## The hosted witness pin refuses a ledger that does not verify (2026-09-19)

`core._witness_pin`'s hosted branch POSTed `head.rows` / `head.chain` straight to the witness API. With arcaeon-ledger 0.7.5, `head()` on a corrupt file returns `chain="genesis", rows=0` without raising, so a damaged log could have been published as a brand-new one: the one artifact a stranger is meant to be able to trust. Found by the arcaeon-ledger fix worker while listing callers.

Now the hosted branch reads the verdict first (from `Head.ok` when the installed ledger has it, from `verify_file` when it does not) and returns `status: "pin_refused"` with the first break and NO network request when the verdict is an explicit False. A bounded or declared verdict still pins. `web/verify-receipt.html` learned `pin_refused`, and any hosted witness status it does not recognise is now shown as NOT witnessed rather than falling through to the ordinary notice.

Tests: `tests/test_witness_pin_refuses_unverified.py`, with a must-pass control (a healthy ledger IS pinned) beside the two refusal cases, and the refusals assert that no request left the machine. 242/242.

## call_proxy /health: the status code is the verdict (2026-09-19)

`GET /_arcaeon/health` answered HTTP 200 in both of its failure shapes. An
unreadable ledger got `200 {"ok": false, ...}`, which any probe that reads
only the status line scores as healthy. Worse, a CORRUPT ledger got
`200 {"ok": true, "rows": 0, "chain": "genesis"}`, because
`Ledger.head()` (arcaeon-ledger 0.7.5) discards `verify_file`'s verdict and
returns a genesis head without raising. A corrupted log was indistinguishable
from a brand-new one.

Now: `verify_file` runs first; a ledger that does not verify, or cannot be
read, is a 503 with `ok: false` and the first break in `error`. New test
`test_health_endpoint_goes_non_200_when_the_ledger_is_unreadable` is the
planted-dead arm (it asserts the fixture really broke the ledger before it
asserts the status, which is how the second shape was found). 239/239.

Not fixed here, because it is published API: `Ledger.head()` itself. See
private monorepo `memory/AUTONOMOUS_QUEUE.md`, task 156.

## Two new receipt shapes on the existing adapters: Receipted Phone Call, Artifact Approval (2026-09-17)

The existing `call` and `approval` adapters (built 2026-09-11 for the
marketplace-call and action-approval-gate buyers) don't cover two other
shapes the same buyers' neighbors need: proof a *phone call* happened
(not an x402 HTTP round trip), and proof a *named party signed off on a
specific artifact* (not a propose/decide/execute action sequence). Both
are additive functions on the same core (`build_receipt`/`verify_receipt`/
`render_exhibit`) with their own `kind` and scope block — nothing existing
changed shape.

- **`call.phone_call_receipt()`** (`kind="receipted-phone-call"`): opaque
  participant ids, ISO-8601 start/end timestamps, a duration derived from
  them (never separately asserted, so the two can't disagree), and a
  transcript hash the caller computes — the transcript text itself is
  never accepted or stored. A participant id that looks like a raw phone
  number (mostly digits, phone-shaped punctuation) is refused at build
  time, not silently digested. Scope: proves a call occurred between the
  recorded ids for the recorded duration with the recorded transcript
  hash; does not prove the truth of anything said, the real identity
  behind an id, or consent.
- **`approval.artifact_approval_receipt()`** (`kind="artifact-approval"`):
  an artifact hash, an approver id, a timestamp, and an approval-text hash
  — the literal approval statement is hashed inside the function and never
  stored raw. `approval.hash_artifact()` is a convenience for callers who
  have the artifact's bytes rather than a pre-computed hash. Scope: proves
  this approver's credential signed this artifact hash at this time,
  attested by the approval-text hash; does not prove authority,
  competence, or that the artifact is good.

`tests/test_receipts.py` (2 new tests): each builds, verifies, and then
tampers every check field one at a time (plus a scope-sentence tamper) and
asserts `body_digest_ok` goes false for every one; each also asserts the
raw transcript/artifact/approval text never appears in the serialized
receipt, and that the phone variant refuses a phone-number-shaped
participant id and an end-before-start call at build time. Full suite:
236 → 238 passing.

## AB 1405 report-element fields: optional, backward-compatible (2026-09-15)

Four new fields carrying the four AB 1405 (Cal. Gov. Code §11549.83(d)(1))
report elements that `arcaeon_receipt/core.py` did not already have a home
for — mapped in `projects/arcaeon/AB1405_REPORT_ELEMENT_MAP_2026-09-15.md`.
Elements (B) results/documentation and (E) audit limitations already existed
(`checks`/`subject`, and the mandatory `scope["does_not_prove"]`).

- **(A) scope/objectives at engagement level**: `extra.engagement_scope`,
  built by `core.engagement_scope()`.
- **(C) remediation per deficiency**: `checks[].remediation`, an optional
  string the caller sets on a flagged check — the statute's own "if
  appropriate" qualifier, never generated by this tool.
- **(D) adherence to internal safety standards**: `subject.internal_standards_ref`
  (which standard) plus `checks[].adherence` (`"adhered"` / `"not_adhered"` /
  `"not_assessed"`, validated by `build_receipt()` against
  `core.ADHERENCE_VALUES`) — the finding itself is always the auditor's.
- **(F) signed, dated compliance statement**: `extra.attestation`, built by
  `core.attestation()` (statement, auditor name, optional registry id,
  signed-at), plus a separate detached `receipt["attestation_signature"]`
  (`core.attach_attestation_signature()`) carrying the actual signature over
  the body digest.

All four are ordinary keys under `subject`/`checks`/`extra` — already-digested
`BODY_FIELDS` — so no digest-path or verifier change was needed for them to be
tamper-evident: edit one after issue and `body_digest_ok` goes false, the same
as every other body field. The one field that is deliberately NOT
tamper-evident this way is the detached signature itself: a signature computed
over the body digest cannot also be one of the digest's own inputs, so it
lives as a fourth top-level attachment beside `ledger`/`witness`/`anchor`,
outside `BODY_FIELDS`, by construction, and `verify_receipt()`'s `ok` verdict
never depends on any of these four fields' presence or contents — filling
them in is never rendered or treated as a compliance claim. `render_exhibit()`
prints an "AB 1405 REPORT ELEMENTS" block only when at least one is present;
an old receipt's exhibit is byte-identical to before. `tests/test_ab1405_fields.py`
(15 tests): build+verify with all four present, tampering each one breaks
verification, an old receipt without them still verifies, the detached
signature does NOT break verification when tampered, and the verifier's
verdict semantics are unchanged either way. Full suite: 221 → 236 passing.

## Zapier "mint a receipt" action, spec only (2026-09-14)

`ZAPIER_ACTION_SPEC.md` (new) — L-021 (BATCH_500 lane L), the #2-ranked idea
in `memory/RESEARCH_overlooked_bindings_2026-09-12.md`. Spec, not built: no
code, no Zapier developer-platform integration, and blocked on the issuing
API `docs/VENDOR_PACKAGE_SPEC.md` §2.4 already lists as unbuilt. Inputs,
outputs, the receipt type it mints (reuses existing adapters, no new kind),
proposed auth model, error handling, and the honest limit that a Zapier
platform failure reads as our failure to the buyer. Reader: Daniel/Fable,
before any developer-platform effort is committed.

## Bulk export: the class in one portable file, verifiable offline (2026-09-13)

`arcaeon-receipt archive <cohort-dir|class-ledger.jsonl> --out class.zip`
(library: `archive.build_archive()`). The last unbuilt cheap piece of
VENDOR_PACKAGE_SPEC 2.5, and the one that makes the sentence in it true: the
class "in a form they own and can hand to anybody, **including us going
away**." One zip a training coordinator gives an auditor, a records
department, or a successor. `MANIFEST.json` at the root (archive version,
generated-at, issuer, cohort, source, every file's sha256 and byte count,
every receipt's verdict, the verdict counts, the pass structure, and the
scope block verbatim), `README.txt` beside it, the roster report CSV, and
`cohort/` holding every receipt, every exhibit, the ledger files those
receipts name, and the witness sidecars. Exit codes match the rest of the
family: 0 / 2 / 4, and 1 for a target holding no receipts.

**It verifies offline, and that is tested by doing it.** The suite extracts
the archive into a temp directory, monkeypatches `socket.socket` and
`socket.create_connection` to raise, and runs the real bulk verifier over the
extracted files: 12 receipts, 12 `ok`, every one `ledger=consistent`.
`consistent` is the load-bearing word -- a receipt whose ledger did not
travel verifies its body and reports `undetermined`, so asserting only on the
verdict would let an archive that forgot the ledger pass.

**`cohort/` is flat, and the whole ledger file travels.** A receipt finds its
ledger by looking for that basename beside itself
(`verify_batch.resolve_ledger`), so sorting receipts into `receipts/` and
ledgers into `ledger/` would make every extracted receipt come back
`undetermined` for want of a ledger nobody could find. And a hash chain
cannot be subset: `arcaeon_ledger.verify_file` walks the file from its first
row, so a ledger holding only this class's rows would fail its own chain
check and every receipt would read `FAIL` for a reason that is an artifact of
the packing.

**Nothing is mutated on the way in, asserted rather than intended.** After
the zip is written and before the function returns, every entry is read back
out of the finished archive and its sha256 compared twice: against the
manifest, and against the file still on disk. A receipt re-serialized in
transit -- same values, different key order -- would still verify and would
still be the wrong artifact, and `ArchiveIntegrityError` fires instead of a
success line. Proven by the round-trip test over all 31 files.

**A FAIL is packed.** One tampered receipt in the example cohort: the archive
still builds, the bad receipt is inside it byte-identical to the tampered
file, the manifest reads `{"receipts": 12, "ok": 11, "FAIL": 1,
"undetermined": 0}` with the failing row carrying its trainee label and
`body digest mismatch`, and the CLI exits 2. Sabotaged to prove the test can
fail: making the builder drop failing receipts turned it red --
`AssertionError: 11 receipts: 11 verified, 0 failed, 0 undetermined; 30 files
in class.zip` / `assert 0 == 2` -- and reverting turned it green (1 passed).
The third verdict travels the same way: an unreachable ledger row is packed
as `undetermined` at exit 4.

**Verdict counts. Never a statistic about scores.** Same rule as the roster
report and the same reason: the scope block denies "the score is correct" and
an average, a rate or an ordering asserts its opposite by arithmetic. Held by
a grep over every text file in a real archive (manifest, README, roster CSV,
every exhibit) and over every manifest key. Sabotaged: adding a
`class_average` key to the manifest turned both red --
`AssertionError: ('MANIFEST.json', 'average')` and
`AssertionError: class_average` -- and removing it turned them green (2
passed).

**Deterministic.** Same cohort, same stamp, byte-identical zip files: fixed
entry order, `FIXED_ZIP_DATE` instead of the wall clock in every entry header
(a zip otherwise stamps the current time into each one), a fixed
`create_system`, and one clock reading taken once and shared by the manifest
and the roster report. Two runs with different stamps differ in
`generated_at` and in exactly two digests -- the roster CSV and the README,
which both carry the stamp -- and in nothing else.
`examples/class_archive_example.zip` is a real archive over the committed
examples, regenerated by `arcaeon-receipt archive examples/ballots/` and held
to that command entry-by-entry by the suite.

**The cap pages, it does not refuse**, through `roster_report.build_report`,
for the reason recorded in that module's docstring: the refusal exists to
stop a partial pass being reported as a finished one, which cannot happen
when every receipt is verified and the pass structure is printed on the face
of the report. If the cap is ever re-read as a commercial limit rather than
an anti-truncation rule, this moves with the report.

**The README points at the verifier that exists.** `VERIFIER_PAGE_URL` is the
public repo path to `web/verify-receipt.html` rather than a hosted page:
searched this repo's `*.md`, `*.py`, `*.html`, `*.toml` and `*.json` on
2026-09-13 for `arcaeon.io`, `/verify` and `verify.<tld>`, and every hit was
that local file, the drafts in `docs/`, or the witness API's `/api/verify`
route, which verifies a ledger pin and not a receipt. The page runs entirely
in the reader's browser, so a downloaded copy is the same verifier as a
hosted one. One string to change on the day a page is deployed.

Spec updated: 2.5's status line (both halves now exist; the two DOES NOT
EXIST YET bullets under it are historical) and §6 limit 5, which now says one
of the five components is unbuilt -- the issuing API -- and adds the honest
half that was missing: the four that exist are a Python CLI on the vendor's
own machine, not a service. Tests: 205 -> 221.

## Roster reporting: one row per trainee, verdict counts and no score statistics (2026-09-13)

`arcaeon-receipt roster-report <cohort-dir|class-ledger.jsonl> [--out report.csv]
[--json]` (library: `roster_report.build_report()`). The third piece of the
cohort family, and the fifth component VENDOR_PACKAGE_SPEC 2.3 has been
selling: the driver mints a class, bulk verify answers over a class, and this
is the page the person who RUNS the class opens. One row per trainee: receipt
id (the body digest), issuer, cohort, the trainee label as the ballot carries
it, scenario, the score as the receipt states it, issued-at, verdict
(`ok` / `FAIL` / `undetermined`), ledger status, anchor status when present,
and the reason behind any verdict that is not `ok`. Header rows carry issuer,
cohort, generated-at, receipts counted, the three verdict counts, the pass
structure, and the scope block's own sentences read verbatim out of the
receipts rather than restated here. Exit codes match `verify --batch`: 0 / 2 /
4, and 1 for a target holding no receipts (refused, never reported as a clean
class of zero).

**Verdict counts. Never a statistic about scores.** No class average, no pass
rate, no ranking. The reason is the spec's, quoted rather than paraphrased --
the scope block's `does_not_prove` denies "the score is correct", the package
"sells everything that sits around that verdict and never the verdict itself"
(§1), and §6.1 says it "does not grade, and it does not improve grading.
Everything about whether a rubric measures dispatcher competence is untouched
by this package and unaddressed by it. A receipted 91 is the same 91, sealed."
An average or a pass rate asserts the opposite of that denial by arithmetic,
which is exactly the overclaim the whole product is built to not make.
Enforced by a grep over the real rendered output in both formats AND over the
committed example, and the grep was proven able to fail: adding a
`class_average` column to `roster_report.py` turned it red --
`AssertionError: ('average', '# report,arcaeon-receipt roster report...` and
`AssertionError: class_average / assert 'average' not in 'class_average'` --
and removing the column turned it green again (16 passed).

**A FAIL is a row.** Same columns, same trainee label, same stated score as
any passing row: never dropped, never footnoted, never summarized away.
Finding the one document that stopped verifying is the only reason to run
this. One edited receipt in the ten-row example cohort gives exactly one FAIL,
counts of 9 verified / 1 failed / 0 undetermined, exit 2; restoring the
receipt byte-for-byte gives 10 / 0 / 0 and exit 0, so the failure was the edit
and not a side effect of having touched the file.

**It pages; it does not truncate.** A report is not the "pass" the cap of 20
was written for, so a 25-seat class is verified in two passes of 20 and 5 and
the header says so on its face: `2 passes of at most 20 (20, 5); every receipt
was verified`. The refusal exists, in `verify_batch`'s own words, because
"verifying the first 20 of 21 and printing a summary would hand back a page
that looks like a finished answer for a class that was never fully checked" --
an anti-truncation rule, not a meter. Here every receipt is verified and the
pass structure is printed, so that failure cannot occur. Each page still goes
through `verify_batch.verify_batch(..., cap=PAGE)`, so a pass can never exceed
the published cap; a paging bug surfaces as the refusal rather than as a
quietly widened cap. Watched rather than asserted: the test spies on every
call and sees `[(20, 20), (5, 20)]`. The honest counter-argument is recorded
in the module docstring -- if the cap is ever re-read as a commercial limit on
free verification per command rather than as anti-truncation, this refuses
instead of paging, and that is a pricing decision, not a code one.

**Verification is imported, not reimplemented.** `verify_batch.verify_batch`,
`collect_paths` and the three verdicts do the work; this module reads the
receipts for what they STATE (issuer, cohort, trainee, scenario, score,
issued-at) and never derives anything. `score_of()` mirrors `ballot._line()`'s
fallback chain (`overall.score`, bare `score`, the seq scorer's `seq_pct`) and
a test holds the two together against every committed example, so the number
on the report is the number on the trainee's own exhibit.

**JSON mirrors the CSV exactly** -- same header keys, same columns, same rows,
every value a string. The same table for a machine, not a richer one that
could disagree with the CSV about a type. Proven with a FAIL row in the batch.

`examples/ballots/roster_report_example.csv` is a real report over the twelve
committed receipts, generated by `arcaeon-receipt roster-report
examples/ballots/` and held to that command by a test, so a change here that
would make the shipped example wrong goes red before a buyer opens it.

Suite: 189 before, 205 after.

## Bulk verification: a whole class in one pass, with a third verdict and a cap that refuses (2026-09-13)

`arcaeon-receipt verify --batch <dir|glob|paths...>` and multi-file drop in
`web/verify-receipt.html`. The mirror of the cohort driver: that one turns a
roster into twenty sealed receipts with one command, this one turns twenty
sealed receipts back into one answer. VENDOR_PACKAGE_SPEC 2.5 has been
selling this since the spec was written; until today the CLI's `verify` took
one path and the page read `e.dataTransfer.files[0]`, so the published cap of
20 constrained a feature nobody had built. It exists now.

**Three verdicts, not two.** `ok` and `FAIL` cannot carry a file that will not
open, or a receipt whose ledger nobody in the run could find. Folding either
into `ok` overclaims; folding it into `FAIL` accuses a receipt that may be
perfectly good. `undetermined` is its own count with its own exit code (0 all
ok, 2 a definite FAIL, 4 undetermined-only, 1 the batch refused), so a
coordinator scripting a gate can tell "this is bad" from "I could not check
this" without parsing text. A determinable negative still outranks an
undetermined one: a broken body digest is a FAIL even when the ledger is also
missing, proven by its own test.

**The cap is a refusal, not a truncation.** Past 20 receipts the pass verifies
NOTHING and says so, naming the cap and the count. Showing 20 rows for 21
files hands back something that looks like a finished answer for a class that
was never fully checked -- the same failure `ballot.read_roster` refuses from
the other direction. Proven in both directions: a 21-file batch is refused
with nothing read (one of the 21 is deliberate garbage and produces no row),
20 exactly is accepted, and the cap was sabotaged to 100 to watch the refusal
test go red and restored to watch it go green. The page's own cap was
sabotaged the same way, and at 100 the page verified all 21 -- so both caps
are load-bearing, not decoration.

**Ledger resolution.** With `--ledger`, one ledger covers the batch. Without
it, each receipt is checked against the ledger named on its own face if that
file sits beside it -- exactly the shape of a bulk export directory. Only the
basename is ever used, so a receipt cannot point the verifier at an arbitrary
path on the checker's disk. A receipt claiming a row nobody could check is
`undetermined`, never `ok`.

**The hashing did not move.** `web/verify-receipt.html` gained a batch panel,
a multi-file input and a drop handler; its canonicalizer block between the
`C14N-START` / `C14N-END` markers is byte-for-byte unchanged, now pinned by
sha256 in `tests/test_verify_batch.py` and checked to contain none of the new
UI identifiers. `tests/test_verify_page_parity.py` was not touched and still
passes.

And the page's batch logic is RUN, not read: the shipped `<script>` is
extracted and executed under Node against a small DOM shim, over the same four
cases the CLI is held to (eleven good, one edited, one unreadable,
twenty-one). Grepping a HTML file for the word "UNDETERMINED" proves the word
is in the file; it does not prove a dropped batch produces that verdict.

Suite: 162 -> 189.

## Four examples re-minted because an input carried a name the privacy rule forbids; anchored twin re-stamped (2026-09-13)

`examples/ballots/inputs/{01,02,03,10}.json` carried, in the oral-board
`baseline_provenance` field, the employing agency of the subject-matter expert
who set the rubric baseline. A standing privacy rule keeps that name out of
every output and applies retroactively; the phrase now reads
`(Daniel, dispatch-side SME)` and nothing else in those four inputs changed.
Found by the task-087 worker while reading the examples, not by an instrument.

The string was sealed **inside the body digest** of examples 01, 02, 03 and 10
and of the anchored twin of 01, so editing the five `.receipt.json` files in
place would have produced five receipts that fail verification. That is the
product working. The only honest fix is a new mint, so all five were re-minted
through the real CLI from their corrected inputs, each with the subject,
grader, namespace and timestamp its own receipt declares, and all five
exhibits regenerated.

**The ledger was appended to, never rewritten.** `examples/ballots/ledger.jsonl`
went from eleven rows to fifteen: rows 1, 2, 3 and 10 are the superseded
receipts and no file matches them now; the re-mints are rows 12-15. All eleven
receipts in the directory (the ten plus the branded #11) still verify
`ok: true`, `ledger.status: "consistent"` against the appended chain --
re-checked one by one. Deleting a chain row in the directory that exists to
demonstrate an honest chain would have been the exact tamper this product is
sold against. Consequence worth stating: for those four, ledger order (12-15,
written today) and `issued_at` order (Sept 6-11, carried from the originals)
disagree. Both are true and they answer different questions.
`01_oral_board_pass_clean.anchored.ledger.jsonl` has three rows for the same
reason -- row 2 is an aborted re-mint of mine that came out with a null
`checks[0].timestamp`, left in place rather than erased.

**The anchor is a new stamp, not a carried-over one.** The anchored twin was
re-minted with a fresh `ots stamp` against the four public calendars
(alice/bob.btc.calendar.opentimestamps.org, btc.calendar.catallaxy.com,
finney.calendar.eternitywall.com), and `arcaeon-receipt verify ... --ots`
reconstructed the stamped file from the receipt's own `anchor.ots_b64` alone
and got "Pending confirmation in Bitcoin blockchain" from each --
`body_digest_ok: true`, `ledger.status: "consistent"`, `anchor.status:
"pending"`, `ok: true`, exit 0. Nothing verifiable was lost: the previous
stamp was still `pending-calendar` and had never upgraded to a Bitcoin
attestation. Its `issued_at` is the real clock at re-mint
(`2026-09-13T23:11:07Z`) rather than an override, so the receipt does not
claim to predate its own stamp.

**The byte-identity test was updated, not weakened.**
`tests/test_ballot_cohort.py::test_unbranded_receipt_byte_identical_to_pre_branding_example`
re-mints each example from its own committed input and requires an identical
body and `body_digest`, so input and receipt had to move together --
deliberately, both sides, which is the fixture update. Proved it is still live
rather than passing vacuously: reverting input 02 to its pre-scrub bytes while
leaving the new receipt in place fails that example, and only that example.
One sentence added to the test's docstring recording the re-mint and why. No
test skipped, no assertion relaxed; suite 162 green.

`examples/ballots/README.md` gains a re-mint banner and a row-by-row table of
what lives where on the fifteen-row chain.
`examples/ballots/WHAT_THESE_DO_NOT_SHOW.md` gains section 11 (the re-mint,
the append-not-rewrite decision, and the miss itself: these examples shipped
2026-09-12 with that string in five artifacts, and the only reason it went
nowhere is that this repo has no git remote -- distribution luck, not a
control that worked). Sections 3, 9 and the one-line summary corrected where
they claimed ten ledger rows or an untouched unanchored twin.

Repo-wide grep for the forbidden string outside `.git`: **0**.

## Vendor-branded ballots, issued across a class (2026-09-13)

The first sellable component of `docs/VENDOR_PACKAGE_SPEC.md` (2.1 and 2.2),
built on primitives that already existed. An academy's name on the document a
trainee hands to a hiring center, and one command for a whole class instead of
a shell loop somebody writes by hand.

**Branding rides inside the digest.** `ballot_receipt()` gains optional
`issuer` and `cohort` arguments, carried through `core.build_receipt()`'s
`extra` dict -- which has always been one of the seven digested `BODY_FIELDS`.
A vendor name printed outside the digest is a name anyone can retype; a vendor
name inside it cannot be changed without breaking verification, which is the
only version of branding worth selling. Proven by sabotage in
`tests/test_ballot_cohort.py`: edit one word of the academy name on a minted
receipt and `body_digest_ok` goes false with "body digest mismatch: a body
field was altered after issue"; restore it and the same receipt verifies again.
The reverse is covered too -- an unbranded receipt cannot be *stamped* with an
academy's name after issue, which is what would otherwise let anyone hand out
that academy's paper.

Both default to `None`, and an absent or whitespace-only value writes no key at
all, so an unbranded ballot keeps `extra: {}`. That is checked, not asserted:
each of the ten receipts committed in `examples/ballots/` **before** branding
existed is re-minted from its own committed input and must reproduce an
identical body and an identical `body_digest`, field by field.

**The exhibit carries it.** `ballot.exhibit()` titles a branded receipt
`<ISSUER> - BALLOT RECEIPT` and prints `Issued by:` / `Class:` under the issue
time, with a line saying the pair is sealed in the digest below. An unbranded
receipt renders exactly as before: the same hardcoded `BALLOT RECEIPT` title
and not one extra line. The insert happens in `ballot.py`, not in
`core.render_exhibit()`, so core stays the one generic renderer every adapter
shares. The scope block is untouched -- still never "correct".

**The cohort driver.** `arcaeon-receipt ballot --roster roster.csv --issuer X
--cohort Y --namespace NS --ledger L [--out-dir DIR]` mints one receipt and one
exhibit per roster row into ONE ledger under ONE namespace, so the chain itself
proves the order the class was issued in. Roster columns: `trainee`,
`ballot_path` required; `scenario`, `grader`, `timestamp` optional, each falling
back to the run-wide flag. Output is one summary line with the count and the
ledger tip. Library entry points are `ballot.read_roster()` and
`ballot.mint_cohort()`.

A malformed row refuses the WHOLE roster, naming the row number as the file
line number the coordinator sees when they open the CSV, and refuses it BEFORE
anything is minted. Refusing row 7 halfway through leaves six sealed receipts, a
chain that stops mid-cohort, and nobody able to tell from the outside which
trainees are missing paper. Refused: empty trainee, empty `ballot_path`, a
ballot file that is missing or is not readable JSON, a row with no scenario and
no `--scenario`, two trainees whose names collide on the same output filename,
and a roster with no rows. A wholly blank line is treated as spacing.

**The verifier did not change.** A branded receipt verifies on the CLI and in
`web/verify-receipt.html` with no edit to either, because `extra` was already
canonicalized by the page. `tests/test_verify_page_parity.py` now round-trips a
full branded receipt through the page's own extracted canonicalizer and checks
the issuer string is present in the canonical text the page hashes -- so if a
future change ever moved branding somewhere the page does not canonicalize,
that test fails instead of the claim quietly becoming false.

**Examples.** `examples/ballots/11_branded_academy_cohort.{receipt,exhibit}`
plus its input, minted through the real CLI into the same shared example ledger
as the first ten (row 11; the first ten still verify `consistent` against the
appended chain). `examples/ballots/roster_example.csv` is a working ten-row
roster over the committed inputs. Academy and trainee names are fictional.

Suite: 128 -> 162.

## Ballot pin absorption ceiling, counted (2026-09-13)

The 2026-09-13 pricing sitting (motion M5, approved by Daniel at 6:49 AM)
made ballot issuance and verification free forever and put the OPTIONAL
witness pin under a $25/month absorption ceiling, deliberately separate from
the $50 AI ceiling so neither can hide inside the other. The sitting's own
condition was that the ceiling be a COUNTED number before the next sitting
cites it as a control. This entry is that count.

**`ballot.py` -- the counter.** Every pin REQUEST (`witness=True`) appends one
row to `bridge/state/ballot_pin_ledger.jsonl` in the private monorepo, path
overridable via `ARCAEON_BALLOT_PIN_LEDGER`: `{at, month, receipt_id,
pin_kind, est_usd, pin_status}`. Keyed off the request, not the receipt --
an unpinned ballot is free to issue and charges the ceiling nothing, so
counting receipts would count the wrong thing. A failed hosted pin is counted
too: the request left the building. The rate is ONE constant with its date and
source -- `PIN_RATE_USD_PER_1000 = 5.0` (hosted-witness Mini rate as of
2026-09-13, `PRICING_MOTION_2026-09-13_HELD_NUMBERS.md` M5, "$25/month ... about
5,000 pins at Mini rate"). A local-file pin costs $0.00 because no hosted credit
is spent; it still counts as a pin. A ledger write that fails never breaks
receipt issuance, and never fails silently either -- it says so on stderr.

**`ballot.py` -- the reader.** `pin_ceiling_status(month)` returns `{month,
pins, billable_pins, est_usd, ceiling_usd: 25.0, pct, status}` where status is
`ok` / `warn` (>=80%) / `red` (>=100%). A missing OR empty ledger returns
`pins: 0` with `ledger_present: false` and status `unknown` -- never a silent
zero, because "no pin was requested" and "nobody read the file" are different
facts and only one of them is good news.

**The scheduled reader.** the private monorepo's 3-day council driver
(`projects/online_business/LANE_COUNCIL/pricing_review.py`) imports that reader
in `read_signal()` and prints it in the SIGNAL block:
`ballot pins this month: N ($X.XX of $25.00) -- OK|WARN|RED`, or
`ballot pin ledger: NOT PRESENT (not read is not zero)`. The reader is imported,
never reimplemented; a second copy of the ceiling arithmetic is how two numbers
start disagreeing about the same month. No artifact without a reader.

**Tests** (`tests/test_ballot_pin_counter.py`, 7 new): a pin request counts and
a plain issuance does not; hosted costs and local does not; the status flips at
exactly 80% (4,000 pins = $20.00) and at 100% (5,000 = $25.00); the count is
per-month and last month does not bleed in; an absent ledger and an empty
ledger both report ABSENT; unparsed lines are named, not dropped. Sabotage
proof: `PIN_WARN_FRACTION` 0.80 -> 0.90 and the red threshold to `* 2`; the
ceiling test went red (`assert at_warn["status"] == "warn"` with 4,000 pins at
$20.00 reporting `ok`), reverted, green again. Suite 121 -> 128 passed, none
weakened.

## Lane A, A-023 through A-040 (2026-09-13)

18 items, all 18 addressed (real code/test changes, confirmed-already-
satisfied, or findings, as below). Baseline 121 passed before this entry's
own tests are counted redundantly -- 113 green going in (per the prior
A-002/A-022 entry), 121 green after: 8 new/hardened tests, 0 weakened or
deleted. Every test added below was proven able to fail (sabotaged inline,
confirmed red, reverted, confirmed green) before being left in place.

**A-023**: added `test_authorship_ingest.py::test_rolling_hash_avalanches_on_a_single_character_edit`
-- two event streams differing by one character in one pasted span must
produce `rolling_hash` values differing across a large share of their hex
characters (not a near-collision), both via `authorship.replay` directly
and through the full `from_export` path. Sabotaged `authorship._fold` to
hash only the event's `op` (dropping the span digest and the running
chain from the input); test went red, reverted, green again.

**A-024**: added `test_call_proxy.py::test_receipt_survives_added_and_reordered_headers`
-- two requests with the identical body and the identical `X-PAYMENT`
value, but a different number of surrounding headers in a different
insertion order, must produce the same `payment_header_digest` and
`request_digest`: `call.py`'s digest only ever touches the body and the
one recognized payment header's value, never header order or count.
Sabotaged `call._payment_header` to only inspect the first header in
iteration order; test went red (both requests' extracted header value
collapsed to `None` because neither had the payment header listed first),
reverted, green again.

**A-025**: added `test_approval_mcp.py::test_agent_cannot_self_approve_via_tool_arguments`
-- neither `approval_propose`'s nor `approval_executed`'s MCP `inputSchema`
carries a `principal`/`decision` field, and neither handler reads one out
of `args`; stuffing `principal`/`decision` into the SAME tool call instead
of dropping a file in `--decisions-dir` must have zero effect (proposal
stays pending, `approval_executed` still refused). Sabotaged
`_approval_executed` to skip the pending-refusal when `args.get("decision")
== "approved"`; test went red (the sneaky call was no longer refused and
actually minted a receipt), reverted, green again.

**A-026 / A-040**: this entry.

**A-027**: `LICENSE` (MIT, "Arcaeon" as copyright holder) matches
`pyproject.toml`'s `license = { text = "MIT" }` and its MIT classifier.
No mismatch, no change needed.

**A-028**: `.pytest_cache/README.md` read (stock pytest content, "do not
commit this"); `.gitignore` already excludes `.pytest_cache/` (A-019
confirmed this same line last pass) and `git status --short` shows nothing
under `.pytest_cache/` tracked or staged. No change needed.

**A-029**: `cite_batch.py` has no cap on the NUMBER of citations in a
batch -- only a character-length cap per chunk (`cite.MAX_TEXT`) and a
bounded retry loop (`MAX_RETRY_ROUNDS`, already covered by the existing
`test_retry_bounded_leaves_unchecked_after_max_rounds`). A hard citation-
count cap would work against the module's actual job (an arbitrarily long
real filing), so this is a finding, not a fix: added
`test_cite_batch.py::test_batched_lookup_scales_linearly_and_terminates_with_many_citations`,
300 citations forced into many small chunks, asserting the transport call
count is bounded by chunk count (not citation count, not unbounded) and
every citation still resolves. Sabotaged `check_citations_batched` to
append each chunk's checks twice; test went red (600 checks instead of
300), reverted, green again.

**A-030**: added `test_authorship_ingest.py::test_from_export_handles_zero_events_without_raising`
-- an export with zero edit events (`events: []`) must produce a valid,
verifiable receipt, not a `ZeroDivisionError` in the `pasted_share`
calculation. Sabotaged `authorship_ingest.py`'s `pasted_share` line to
drop its `if total_in else None` guard; test went red
(`ZeroDivisionError: division by zero`), reverted, green again.

**A-031**: every module in `arcaeon_receipt/` already carries a one-line-
scope module docstring (checked programmatically via `ast.get_docstring`
across all 15 `.py` files) -- no module was missing one. No change needed.

**A-032**: `test_receipts.py::test_local_witness_labels_itself` already
existed and already asserted the local-file self-controlled label; it
relied on the ambient shell not happening to carry
`ARCAEON_WITNESS_URL`/`ARCAEON_WITNESS_KEY`, which is not the same as
testing "no hosted key configured." Hardened with explicit
`monkeypatch.delenv` on both variables so the test is deterministic
regardless of the environment it runs in. Sabotaged `core._witness_pin`'s
local-file branch to claim `"third-party-timestamped public commits"`
independence; test went red, reverted, green again.

**A-033**: added `test_receipts.py::test_anchor_b64_roundtrips_with_no_project_code`
-- the receipt's `anchor.ots_b64` must be a plain, stdlib-`base64`-decodable
blob of exactly the bytes `ots stamp` produced (README's "reconstructible
from the receipt alone" claim), and the file a stranger reconstructs to
verify it is exactly `body_digest + "\n"`, derivable from the receipt's own
`body_digest` field. `core._run_ots` faked to write a known fixed byte
string (no network/real `ots` binary touched). Sabotaged `_ots_stamp` to
append `b"CORRUPTED"` to the stored bytes; test went red, reverted, green
again. (Task 070, same day, additionally exercised this exact round trip
for real against the live public calendars -- this test covers the
structural guarantee without a network dependency.)

**A-034**: `cli.py`'s subcommand `--help` text named only a one-line
summary, never what the receipt does NOT prove -- a real gap. Added
`cli._does_not_prove()`, pulling straight from each adapter's own `SCOPE`
dict, wired into the `cite` and `ballot` subparsers' `description=` (the
only two receipt-issuing top-level subcommands; `call`/`approval`/
`authorship` are library/MCP-only, no CLI subcommand exists for them to
add this to). Added `test_receipts.py::test_cli_help_names_what_it_does_not_prove`,
asserting every `does_not_prove` sentence appears in `--help` output
(whitespace-normalized, since argparse line-wraps). Sabotaged by reverting
`ballot`'s parser to drop `description=`; test went red, reverted, green
again.

**A-035**: added `test_call_proxy.py::test_zero_byte_response_is_receipted_honestly`
-- a real 200 with zero response bytes (distinct from the existing 502
upstream-failure path) must receipt a real digest of empty bytes, not
`None` or a crash. Added an `/empty` route to the test upstream. Sabotaged
`call._digest_any` to return `None` for `None`-or-empty-bytes input; test
went red (`response_digest` was `None`), reverted, green again.

**A-036**: this machine has no Python 3.9 interpreter installed (`py -0`
lists only 3.13 and 3.14), so the literal ask -- install into a fresh venv
against the `>=3.9` floor and confirm it runs -- could not be done and is
NOT claimed as done. Partial check performed instead: an AST scan of every
file in `arcaeon_receipt/` found zero `match` statements (3.10+-only) and
a grep found zero runtime (non-annotation) `isinstance(..., X | Y)` union
usage that would require 3.10+ at call time; every `X | Y` in this codebase
lives inside a `from __future__ import annotations`-deferred annotation,
which is inert at import time regardless of interpreter version. This is
static-analysis confidence, not a run.

**A-037**: `README.md`'s "Library" usage example imported only
`cite, call, approval, authorship` even though the adapter table above it
lists five adapters including `ballot` -- confirmed the import itself
resolves fine either way (`from package import submodule` implicitly
imports the submodule; verified directly), so this was a documentation
completeness gap, not a broken example. Added `ballot` to the import line
and one `ballot.ballot_receipt(...)` call to the example.

**A-038** [AUDIT-A2]: read this entire file. One absolute claim found --
"`verify_receipt` is typed and never raises" (0.1.0 entry) -- spot-checked
against a nonexistent `ledger_path` (a real way to misuse the function);
it returned a typed `chain_broken` result with the OSError text folded
into `first_break`, not a raise. Held up under this check. No other
sentence in this file was found asserting a guarantee (proves/does-not-
prove wording, coverage, or capability) stronger than what the referenced
code/tests actually show; process narration ("no test weakened", "passed
clean") is a claim about this pass's own diligence, not about the
product's guarantees to a buyer, and is out of this item's scope.

**A-039**: `tools/c14n_vectors.py`'s `generate_vectors` is imported and
consumed by `tests/test_verify_page_parity.py` (confirmed via
`pytest --collect-only`, which lists the `kind_*_check_shape` cases it
generates as real parametrized test IDs) -- not a dead fixture file. No
change needed.

**Real vs. target: 18 of 18** items in this worker's A-023-through-A-040
slice were addressed this pass (5 real test/code additions with proven-
failing sabotage, 1 hardened existing test, 2 doc/CLI-text fixes, 1
finding written up instead of a cap that would fight the module's job, 1
honestly-partial check disclosed as such, and 7 read/confirm-only items
where nothing was missing). The "(40 of 90)" A-040's own instruction named
is `memory/BATCH_500_2026-09-12.md`'s own Lane A scoping note (that file's
line 105/107): Lane A's original target was 90 items, and the batch's
author scoped it down to 40 real, concretely-actionable items *before any
of this work started*, because "90 assumed a build-out that doesn't exist
yet at that grain" -- 40 was never a claim this worker is making about its
own output, it is the already-reduced total item count for the whole lane
(A-001 the baseline count plus A-002 through A-040, 39 actionable items).
Combined with the prior pass's 21-of-21 (A-002 through A-022),
all 39 actionable items in Lane A (A-002 through A-040) are now addressed
across the two passes -- 39 of 39 against the lane's own already-scoped-
down 40-item total (A-001 counted, not actioned), not 40 of 90.

## Task 070 -- one real OpenTimestamps anchor on a ballot receipt (2026-09-13)

`examples/ballots/01_oral_board_pass_clean.anchored.receipt.json` (+
matching `.exhibit.txt` and its own `.ledger.jsonl`/`.witness.jsonl`, not
the shared `ledger.jsonl` the other ten rows live in) is a second receipt
for the same ballot object as example #01
(`inputs/01_oral_board_pass_clean.json`), minted through the real CLI with
anchoring on (`ballot_receipt(..., anchor=True)`, the CLI default absent
`--no-anchor`) instead of the `--no-anchor` every one of the original ten
used. `opentimestamps-client` 0.7.2 was already installed
(`arcaeon_receipt/core.py`'s `_ots_stamp`/`ots_verify` already existed --
no new anchoring code was written, only invoked). The stamp is real: `ots
stamp` reached four public calendars (alice/bob.btc.calendar.opentimestamps.org,
finney.calendar.eternitywall.com, btc.calendar.catallaxy.com) over the
network, and `arcaeon-receipt verify ... --ots` reconstructed the stamped
file from the receipt's own `anchor.ots_b64` alone and got back "Pending
confirmation in Bitcoin blockchain" from each calendar --
`body_digest_ok: true`, `ledger.status: "consistent"`, `anchor.status:
"pending"`, `ok: true`. The original `01_oral_board_pass_clean.receipt.json`
is untouched beside it. `examples/ballots/WHAT_THESE_DO_NOT_SHOW.md`
(section 3 + the one-line summary) and `examples/ballots/README.md`
updated to say exactly which file is anchored and that the anchor proves
only that the body digest existed by the calendar's attestation time --
not that the score is correct, the trainee is who they say, or the ballot
was fairly graded (`ballot.py`'s own `SCOPE`, unchanged and un-widened).

## Lane A, A-002 through A-022 (2026-09-12)

Baseline (A-001): 105 green before this pass; 113 green after. Real work,
not the padded target -- 21 of the 21 items in this range were addressed
(satisfied-and-skipped items say why below), no test weakened or deleted.

**A-002** (scope enforcement, single call site): confirmed every adapter
(`cite`/`call`/`approval`/`authorship`/`ballot`) issues through
`core.build_receipt()`, and the mandatory `proves`/`does_not_prove`
non-empty-list check is enforced in exactly one place --
`arcaeon_receipt/core.py` lines 192-193 (`if not isinstance(scope, dict) or
not scope.get("proves") or not scope.get("does_not_prove"): raise
ValueError(...)`). No adapter re-implements or bypasses it.

**A-003** [AUDIT-A2]: read README.md top to bottom for a "proves" sentence
without a paired "does not prove" on the same page. None found: the
document's only bare use of "proves" (the intro line, "what it proves and
what it does not") explicitly names its own pairing, and every substantive
proves-claim lives in the adapter table's `proves` column directly beside
its `does not prove` column. Logged for Fable's Monday re-read.

**A-004/A-005** skipped, already satisfied: the item named the wrong test
file (`test_cite_extract.py`, which only reads file FORMATS -- .txt/.pdf/
.docx -- and has no citation-matching logic to test against). The actual
negative tests already exist and are thorough:
`test_receipts.py::test_cite_flags_what_the_service_silently_drops`
(unrecognized reporter -> flagged `not_recognized_by_service`, not
dropped) and `test_cite_batch.py::test_citation_receipt_batched_builds_a_receipt`
(one known-fake mixed with a real citation, only the fake flagged).

**A-006** -- finding, not a test-as-assumed: the batch item asked for "a
malformed x402 header refuses rather than emitting a partial receipt", but
`call.py`'s own SCOPE says on its face "the payment header is digested,
not verified. Payment verification belongs to the facilitator" -- there is
no "required field" concept anywhere in this codebase for a header to be
malformed against, and adding refusal logic would mean the proxy silently
taking on a payment-verification job its scope explicitly disclaims. Not a
small, obvious fix, so not done. Added
`test_call_proxy.py::test_malformed_payment_header_is_digested_not_refused`
documenting the actual, intentional contract instead. One small, genuinely
obvious bug WAS found and fixed while writing it: `call.py`'s
`call_receipt()` and `call_proxy.py`'s upstream-failure branch both computed
`_digest_any(pay) if pay else None`, which treats an empty-but-present
payment header the same as no header at all (Python's empty-string
falsiness). Fixed to `if pay is not None else None` in both places, so an
empty header now digests to a real (if unhelpful) digest, distinct from
"absent". Residual, left as a finding: `_payment_header()` returns on the
FIRST recognized header name it meets in header order even if that
header's value is empty, so a client sending a stale empty `X-PAYMENT`
alongside a real `PAYMENT-SIGNATURE` would have the real one silently
ignored -- which header should win when more than one is present is a
product decision, not a bug fix.

**A-007**: `approval_mcp.py`'s executed-while-pending refusal
(`_approval_executed`, the one line the whole gate exists for) was already
tested for `isError` + a `"pending"` substring; strengthened to assert the
exact refusal text verbatim, so a future edit that keeps the word
"pending" in some unrelated message can no longer slide past this test.

**A-008**: added
`test_authorship_ingest.py::test_paste_then_immediate_edit_does_not_collapse_into_one_event`.
Neither `authorship.py` nor `authorship_ingest.py` has any event-merging
logic today -- every call appends its own dict unconditionally -- but a
future "helpful" adjacency-merge optimization would silently corrupt
typed/pasted counts, so this is now a named regression guard.

**A-009**: new `docs/cli-exit-codes.md` -- the exit-code matrix (0/1/2/3
per subcommand) as a table, cross-referenced from the tests that cover
each cell.

**A-010**: added
`test_receipts.py::test_cite_cli_subprocess_exit_3_on_flagged_receipt` --
`cite` invoked as a real subprocess (`python -m arcaeon_receipt.cli`), the
only subcommand that can produce exit 3, matching the pattern
`test_ballot.py`'s subprocess test already used for 0/1.

**A-011/A-012** [AUDIT-A2]: `test_verify_page_parity.py`'s own note (from
K-011) already documents that `web/verify-receipt.html` has no per-kind
rendering logic to round-trip separately -- it renders generically off the
7 `BODY_FIELDS`, so the ballot full-receipt round trip plus the generic
c14n vectors already exercise the one path every kind shares. Rather than
four redundant subprocess round trips re-proving the same generic
canonicalizer, extended the real per-adapter DIGEST SHAPE coverage
instead (A-013), which is the part that actually varies by kind.

**A-013**: added `kind_cite_check_shape`, `kind_call_check_shape`,
`kind_approval_check_shape`, `kind_authorship_check_shape` vectors to
`tools/c14n_vectors.py` (previously only `kind_ballot_check_shape`
existed) -- every adapter's real check-object shape now has a
canonicalization parity vector, not just synthetic primitives.

**A-014 through A-020** (read/audit-only, no gaps needing a code change
beyond what's noted): A-015 pyproject.toml's `0.1.0` matches CHANGELOG's
`0.1.0` foundation entry. A-016 docs/citation-receipt-page.md's language
matches the existence-checks-only scope. A-017's premise doesn't hold --
`authorship-recorder.html` never touches the Clipboard API or a `paste`
event listener; it reads `event.inputType` off the standard `input` event,
which fires regardless of clipboard permission state, so there is no
denied-permission path to degrade from. A-018: `web/README.md` documented
only `verify-receipt.html`; added a matching section for
`authorship-recorder.html`. A-019: `.gitignore` already excluded
`.pytest_cache/`; added `.env`/`.env.*` defensively (no dotenv dependency
exists in this repo today, but the pattern is zero-cost insurance). A-020:
fresh-venv smoke (`pip install -e .`, `import arcaeon_receipt`, `--help`)
passed clean. Drive-by fix while in pyproject.toml for A-015/A-020:
`description` still said "one receipt, four buyers" from before the
ballot adapter shipped; updated to five, matching README.md's own header.

**A-021**: added
`test_receipts.py::test_mismatched_reporter_not_conflated_with_correct_citation`
-- a real case name attached to the wrong reporter (`347 F.3d 483` next to
the real `347 U.S. 483`) is flagged on its own merits and never inherits
the real citation's clusters/case name, since the reporter token is part
of `_shape_key()`'s identity.

**A-022**: `tests/fixtures/brief.txt`'s planted "100 Cal. 200" (a real,
unambiguous case -- Austin v. Dick, per
`memory/FINDING_courtlistener_silently_drops_unrecognized_citations_2026-09-11.md`'s
residual) replaced with the genuinely nonexistent "88 Zzq. 12". This
rippled further than the one line: `tests/fixtures/courtlistener_planted.json`
(shared by `test_receipts.py`/`test_cite_mcp.py`'s SHORT inline `BRIEF`,
which also contained the same "100 Cal. 200" literal) was reverted to its
original 4-entry scope rather than left carrying phantom entries for
citations that short brief never mentions; a new, separate
`tests/fixtures/courtlistener_planted_full.json` (8 entries) now backs the
FULL `tests/fixtures/brief.txt` demo referenced by README.md and
`docs/citation-receipt-page.md`, completed to cover every real citation the
full brief actually contains (Anderson v. Liberty Lobby, Celotex, Story
Parchment, Bigelow -- previously absent from the fixture and, before this
pass, silently flagged as unrecognized by the doc's own stale, uncommitted
"real, unedited tool output" transcript). Both `README.md` and
`docs/citation-receipt-page.md` updated to point at the new filename, and
the docs transcript regenerated for real against it (9 detected, 3
flagged, exit 3). `test_receipts.py` and `test_cite_mcp.py`'s assertions
updated to match the corrected fixture -- a strengthening (three flagged
citations instead of two, `ambiguous` no longer silently excluded from the
flagged count), not a weakening.

## Ballot adapter, the seam (K lane, 2026-09-12)

**Shipped (K-001 through K-015, K-021):** `arcaeon_receipt/ballot.py` --
`ballot_receipt()`, same `build_receipt(kind="ballot", ...)` shape as
`cite.py`/`call.py`. Scope wording locked verbatim: `proves` = "the score
and the ballot are unaltered since the timestamp"; `does_not_prove` = "the
score is correct" / "the sim was not attempted before". Tests
(`tests/test_ballot.py`): tamper detection on a changed score digit, the
scope-enforcement raise firing specifically through `ballot_receipt`, two
timestamped ballots for the same trainee/scenario both receipting cleanly
(no anti-redo claim made, matching `does_not_prove`). CLI `ballot`
subcommand + subprocess exit-code test. `web/verify-receipt.html` +
`tests/test_verify_page_parity.py`: ballot added to the supported-kind
list with its own round-trip. `tools/c14n_vectors.py`: ballot digest-shape
vector added. `README.md`: ballot row in the adapter table, scope wording
verbatim (K-013, AUDIT-A2). `docs/ballot-receipt-page.md`: landing draft,
not published. `docs/ballot-wiring-note.md` (K-015): the cross-repo
language-boundary decision -- the grading-path mint (`grade_board.js`,
Node/Vercel) is JavaScript, `ballot.py` stays the reference implementation,
the shared canonicalization vector is the parity test both must pass.
Design only; no JS mint written.

**Still open, not this pass:**
- The JS mint itself at `grade_board.js` -- `docs/ballot-wiring-note.md`
  names the digest-parity question as decided and the ledger/witness/anchor
  replication question as explicitly undecided. Whoever implements the
  mint answers that second question first.
- K-020 (a `price` config field on the ballot adapter) is HELD-H1 --
  pricing authority is Fable's Monday call. No number, no field, added by
  this pass.
- MCP wrappers for the ballot adapter (a `ballot_mcp.py` mirroring
  `cite_mcp.py`/`call_mcp.py`) were not asked for in this lane and were not
  built.

**Real vs. target (K-024):** Lane K's own target band was 20-30 items;
24 were real and traceable to a concrete file/test/decision. All 24 are
accounted for above or in `arcaeon-witness`'s CHANGELOG (K-017 through
K-019, K-022 land there, not here -- bulk verify is a witness-side change).

Tests: `py -m pytest -q tests` -- 105 passed (baseline confirmed clean
before this lane's first commit, K-023).

## 0.1.0 (2026-09-11), foundation night

One core, four adapters, built in one sitting: the foundation by the apex seat, the build-out by six parallel workers on disjoint files, every diff read before commit.

**Core** (`core.py`): build / verify / exhibit. `scope.proves` and `scope.does_not_prove` are mandatory and live inside the body digest; the exhibit prints them before the results. Ledger row per receipt (arcaeon-ledger), witness pin (hosted arcaeon-witness when `ARCAEON_WITNESS_URL`/`ARCAEON_WITNESS_KEY` are set, otherwise a local file that labels itself self-controlled), OpenTimestamps stamp carried as base64 and reconstructible from the receipt alone. `verify_receipt` is typed and never raises. A live stamp against the public calendars took 1.8s and verified as pending.

**cite**: CourtListener v4 citation-lookup transport, status map (200 found / 404 not_found / 400 invalid_reporter / 300 ambiguous / 429 not_checked_rate_limit), planted-fake fixture, exit 3 on a flag. `cite_batch`: paragraph-boundary splitting under the 64k cap, span re-basing to full-text offsets, bounded re-submission of only the rate-limited paragraphs (3 rounds, stragglers stay marked not_checked). `cite_extract`: .txt/.md/.pdf (PyMuPDF, optional)/.docx (stdlib). `docs/citation-receipt-page.md`: landing-page draft, existence-only on the first screen, three verified 2025-2026 standing orders cited. Not published.

**call**: request/response/payment-header digests, `error=` for a transport failure that is still receipted. `call_proxy`: stdlib reverse proxy, x402 headers forwarded unchanged, `X-Arcaeon-Receipt` + `X-Arcaeon-Receipt-URL` on the way back, `GET /_arcaeon/receipt/<digest>` (64-hex tail validated before any filename is built), `/_arcaeon/health`, 502 path receipted with `upstream_error`, bodies never stored unless `--raw-payloads` (loud warning).

**approval**: `ApprovalGate.propose / decide / executed`, `executed_as_approved` in one field; ValueErrors carry a `bad_decision:` / `empty_principal:` prefix. `approval_mcp`: stdio JSON-RPC MCP server; decisions arrive only through a side channel (a decisions directory a human writes into), execute-while-pending is refused, rejected decision files carry a `.reason.txt` sidecar, pending state survives a restart.

**authorship**: rolling sha256 over edit events, ledger checkpoints, typed vs pasted, final text bound; `event()` accepts a precomputed `span_digest`, `close()` accepts `extra`. `web/authorship-recorder.html`: browser recorder emitting the same schema, fold proven identical to the Python fold under Node. `authorship_ingest`: rebuilds a session from an export and reports whether the export's rolling hash matches.

**web/verify-receipt.html**: static verifier, WebCrypto sha256 over a JS canonical-JSON matched to Python's `json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False)`; parity vectors in `tools/c14n_vectors.py`.

Tests: `py -m pytest -q tests`.
