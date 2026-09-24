<!--
Written alongside the first ten ballot receipts, 2026-09-12. Purpose: stop
us overclaiming to a buyer. Read this before anyone shows the ten examples
in this directory to a hiring center, a partner, or a prospect. Specific
and unflattering on purpose -- a gap named here plainly is smaller than one
a buyer finds themselves.
-->

# What these ten do not show

A hiring center looking at `examples/ballots/` could reasonably conclude
more than these ten receipts actually support. Here is the specific list
of what is NOT demonstrated, so nobody -- us included -- reaches for one
of these ten as proof of something it isn't.

## 1. None of this ran through production

Every input in `inputs/*.json` is hand-authored to match the real shape
`grade_board.js` and `seq_scorer.js` emit -- it is not the output of an
actual sim session, an actual Gemini call, or an actual trainee typing an
actual answer. No account, no Supabase auth, no daily-cap gate, no
Gemini spend, no real transcription noise. These ten prove the *receipt
mechanism* works against realistic data. They prove nothing about whether
a real trainee's real session produces data this clean, this well-formed,
or this convenient to grade.

## 2. The JS mint does not exist yet, and nothing here tests it

Per `docs/ballot-wiring-note.md`, the production path is a JavaScript mint
inside `grade_board.js`, checked against this Python reference by a shared
canonicalization vector -- that JS mint is **design-only** and has not been
written. Every one of these ten receipts was minted by
`arcaeon_receipt.ballot.ballot_receipt()`, in Python, run by hand from a
CLI. Nothing here demonstrates that a JS-minted receipt would produce the
same digest, that the shared canonicalizer module exists, or that the
parity-vector test the wiring note calls for has ever been run. A buyer
seeing "it works" here is seeing the reference implementation work, not the
thing that will actually run in production.

## 3. No third-party proof of when any of these were made -- except one, now

All ten of the original examples used `--no-anchor`. None of them carries
an OpenTimestamps stamp. The `issued_at` field on every one of those ten
is self-reported by whoever ran the CLI, and the ledger chain only proves
those ten's *order relative to each other* -- it does not prove any of
them existed before any particular external date. Someone controlling the
issuing machine could produce a batch like this after the fact and
backdate every timestamp; nothing in those ten files would catch that,
because nothing in them is anchored to a clock nobody here controls. The
`anchor` field says `status: skipped` on every one of the original ten for
exactly this reason -- it is not hidden, but it is easy to miss if a
reader only reads the exhibit's top half.

**One exception, added 2026-09-13:** `01_oral_board_pass_clean.anchored.receipt.json`
and its exhibit (`01_oral_board_pass_clean.anchored.exhibit.txt`) are a
second, separately-minted receipt for the same underlying ballot object
(`inputs/01_oral_board_pass_clean.json`, same trainee/scenario/grader as
the original `01_oral_board_pass_clean.receipt.json`) minted with anchoring
turned ON. This one carries a real OpenTimestamps stamp
(`anchor.kind: "opentimestamps"`, `anchor.status: "pending-calendar"`),
produced by an actual `ots stamp` call against the public OpenTimestamps
calendar servers on 2026-09-13 (`https://alice.btc.calendar.opentimestamps.org`,
`https://bob.btc.calendar.opentimestamps.org`,
`https://finney.calendar.eternitywall.com`,
`https://btc.calendar.catallaxy.com`) -- not a placeholder, not a
`--no-anchor` skip relabeled. **The stamp now in the file is the second one:**
this receipt was re-minted late on 2026-09-13 (see section 11) and re-stamped
with a fresh `ots stamp` call against those same four calendars. Nothing
verifiable was lost in the swap -- the first stamp was still
`pending-calendar` and had never upgraded to a Bitcoin attestation, so no
confirmed attestation was discarded, only an unconfirmed one superseded. Its
`issued_at` is now the real clock at re-mint time (`2026-09-13T23:11:07Z`),
not an override, so the receipt does not claim to be older than its own
stamp. Re-verifying it
(`arcaeon-receipt verify 01_oral_board_pass_clean.anchored.receipt.json
--ledger 01_oral_board_pass_clean.anchored.ledger.jsonl --ots`) reconstructs
the stamped file from the receipt's own `anchor.ots_b64` field alone --
no contact with whoever minted it -- and runs `ots verify` against those
same calendars, which currently answers "pending confirmation in Bitcoin
blockchain" from each one. A calendar-pending OTS stamp proves the body
digest existed at or before the calendar's attestation time (currently
2026-09-13, hours before it upgrades to a Bitcoin-block attestation via
`ots upgrade`) -- **it does not prove the score is correct, that the
trainee is who they say, or that the ballot was fairly graded.** Those
three limits are exactly the ones `ballot.py`'s own `SCOPE` already states
(`"the score and the ballot are unaltered since the timestamp"` /
`"the score is correct"` / `"the sim was not attempted before"`); anchoring
does not add a fourth thing this receipt proves, it only makes the *when*
half of the existing claim independently checkable instead of
self-reported. The unanchored `01_oral_board_pass_clean.receipt.json` sits
beside its anchored twin, so a reader can diff the two receipts and the two
exhibits and see the only real difference is the `anchor`, `body_digest`,
`ledger`, `issued_at`, and `checks[0].timestamp` fields -- the `ballot` object
itself, the `scope` block, and the trainee/scenario/grader are byte-identical
between them. (Both halves of that pair were re-minted on 2026-09-13; section
11 says why, and the diff claim was re-checked after.) The other nine examples
still carry `anchor.status: "skipped"`.

## 4. The witness is self-controlled on all ten

`witness.kind` is `local-file` and `witness.independence` literally reads
`none (self-controlled file)` on every receipt here. No hosted
`arcaeon-witness` pin, no public commit, nothing outside the issuer's own
filesystem. This exercises the code path; it does not exercise the
independence the hosted witness is supposed to provide. A skeptical reader
handed one of these ten and told "it's witnessed" is being told something
technically true and substantively thin.

## 5. Grading quality is completely out of scope, on all ten

Nothing in `arcaeon-receipt` grades anything, checks the LLM judge's
consistency, audits the rubric, or verifies that an 87 and a 91 mean what
they claim to mean. The `does_not_prove` list says this in two sentences on
every receipt; that list is short and exhaustive by design. Everything
about whether `ascenvo.vcs.oral_board` or `call_taking.seq_scorer` actually
measure dispatcher competence is a completely different -- and completely
unaddressed -- question. A receipted 91 is not a better answer than an
unreceipted 91. It is the same 91, sealed.

## 6. The re-attempt pair (#01 / #03) can be shown selectively, and the receipt cannot stop that

#03 is the same trainee, same scenario, five days after #01, scoring
higher. The `does_not_prove` clause covers this explicitly ("the sim was
not attempted before") -- but that clause only protects a reader who
receives *both* receipts, or who knows to ask. Nothing about #03 in
isolation discloses that #01 exists, that it scored lower, or that this was
attempt number two rather than attempt number one. A trainee motivated to
mislead a hiring center could hand over only the higher-scoring receipt,
and the receipt itself gives no signal that a worse prior attempt was
discarded. This is not a bug in the receipt -- the scope statement warns
about exactly this -- but it is a real, current gap in what the *document*
can force into view on its own, and it is the single easiest way this
product could be misused by the person it is meant to protect a hiring
center from.

## 7. One unicode/emoji case is not a canonicalization fuzz test

#06 exercises one accented character and one emoji, hand-picked. It says
nothing about astral-plane characters beyond that one emoji, right-to-left
text, zero-width joiners, or NFC/NFD normalization mismatches between what
a browser sends and what the canonicalizer receives. `tools/c14n_vectors.py`
is the place that kind of coverage belongs; this directory is ten realistic
examples, not a canonicalization test suite, and should not be cited as one.

## 8. No adversarial input testing

All ten inputs are well-formed JSON shaped like a real grader's real
output. Nobody here tried to break the CLI with truncated JSON, deeply
nested objects, multi-megabyte free-text fields, null bytes, or a ballot
object designed to produce a canonicalization collision. That is a
legitimate and different kind of testing (fuzzing / adversarial), it has
not been done here, and this directory's clean 10/10 pass rate says
nothing about robustness against a bad actor targeting the seal itself
rather than the grading.

## 9. Fifteen rows is not a ledger under load

The shared `ledger.jsonl` in this directory has fifteen rows (ten original,
one branded, four appended by the 2026-09-13 re-mint; see section 11), built serially,
by one process, with no concurrent writers. It says nothing about
behavior under concurrent appends, file-lock contention (`ledger.jsonl.lock`
exists here but was never actually contended), ledger growth at real
volume, or recovery from a corrupted or truncated ledger file mid-chain.

## 10. Every timestamp was manually supplied

All ten receipts were minted with an explicit `--timestamp` override
rather than the CLI's default (system clock at run time). That is real,
tested functionality -- but it is a different code path from the one a
live sim invocation will actually use, and this batch does not exercise
the default-clock path at all.

## 11. Four of these are re-mints, and the ledger row numbers say so

Examples 01, 02, 03 and 10 -- and the anchored twin of 01 -- were re-minted
on 2026-09-13. Their inputs' oral-board `baseline_provenance` field named the
employing agency of the subject-matter expert who set the rubric baseline. A
privacy rule here forbids that name in any output and is retroactive, so the
phrase was changed to `(Daniel, dispatch-side SME)`. The string was sealed
inside the body digest, which is the whole point of the product: editing the
four `.receipt.json` files in place would have produced four receipts that
fail verification. Minting new ones was the only honest fix.

Three things a reader should take from that, none of them flattering:

- **The ledger was appended to, not rewritten.** `ledger.jsonl` has fifteen
  rows. Rows 1, 2, 3 and 10 are the superseded receipts; no file in this
  directory matches them any more. The anchored twin's own ledger has three
  rows for the same reason (row 2 is an aborted re-mint that came out with a
  null timestamp). Nothing was deleted, because deleting a chain row in the
  directory that exists to demonstrate an honest chain would be the exact
  tamper this product sells against.
- **Ledger order and `issued_at` order now disagree for those four.** They
  were re-minted with the `issued_at` their originals declared (Sept 6-11) but
  written to the chain today, so they sit at rows 12-15 behind receipts issued
  later. Both fields are true and they answer different questions. Anyone
  reading a row number as an issue date will get this wrong.
- **The privacy miss was ours and it was caught late.** These examples shipped
  on 2026-09-12 with that string sealed into five artifacts. This repo has no
  git remote, so nothing left the machine, and that is luck about distribution
  rather than a control that worked. A buyer-facing directory is exactly where
  a name that should not travel gets read by someone outside.

## The one-line version

These ten prove the seal is real: change one digit anywhere in a sealed
ballot and the receipt stops verifying, ten times out of ten, with an
identical, honest scope statement every time. They do not prove the
grading is fair, that the production JS path exists or matches, that
anyone outside this issuer can independently confirm *when* these were
made, or that a determined trainee couldn't still cherry-pick which
receipt to show. Say all four of those limits before anyone asks. One
exception as of 2026-09-13: `01_oral_board_pass_clean.anchored.receipt.json`
carries a real, network-verified OpenTimestamps calendar stamp, so for
that one file specifically, the *when* half is independently checkable --
it still does not prove the score is correct, that the trainee is who they
say, or that the ballot was fairly graded (see section 3, "One exception,
added 2026-09-13"). The other ten limits, and the same three limits on
that tenth anchored file, all stand -- section 11 included: four of these
ten are re-mints, and the ledger row numbers are the record of that, not a
cover for it.
