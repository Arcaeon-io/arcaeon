# The first ten ballot receipts

Ten receipted ballots, minted end to end through the real CLI
(`arcaeon-receipt ballot`) against ballot objects shaped exactly like
`api/grade_board.js` (oral-board panel) and the call-taking sequence
scorer (`seq_scorer.js`) produce. Nobody had run one of these all the way
through and looked at the artifact before this directory existed. This is
that look.

All ten trainees are synthetic (no real names, no PII). All ten share one
ledger (`ledger.jsonl`, `ledger.jsonl.witness.jsonl`) so the hash chain
across them is real and inspectable, not ten isolated one-row chains.

> **Re-minted 2026-09-13 — 01, 02, 03, 10.** Their inputs' oral-board
> `baseline_provenance` field named the employing agency of the subject-matter
> expert who set the rubric baseline. The privacy rule says that name appears
> in no output, and it is retroactive; the phrase now reads
> `(Daniel, dispatch-side SME)`. Because the input is sealed verbatim inside
> the body digest, fixing a character of it means minting a new receipt — a
> text edit to the four `.receipt.json` files would have left four receipts
> that no longer verify, which is the product working as designed. So the four
> were re-minted from their corrected inputs, each with the subject, grader and
> timestamp its own receipt declares, and their exhibits regenerated. The
> anchored twin of 01 was re-minted and re-stamped the same way. Read
> "The shared ledger has fifteen rows, not ten" below before quoting a row
> number out of this directory.

## How to read one

Each numbered example is a pair:

- `NN_name.exhibit.txt` -- the plain-text document a hiring center reads.
  Scope statement first, subject, one result line, then the integrity
  block (body digest, ledger position, witness).
- `NN_name.receipt.json` -- the JSON a stranger verifies. Contains the
  ballot object *verbatim* (never reshaped) plus the digest/ledger/witness
  wrapper `core.build_receipt()` adds.
- `inputs/NN_name.json` -- the raw graded-ballot object fed in, before
  wrapping. This is the file `arcaeon-receipt ballot <this> --trainee ...`
  was actually pointed at.

To re-verify any of them:

```
cd examples/ballots
arcaeon-receipt verify 01_oral_board_pass_clean.receipt.json --ledger ledger.jsonl
```

Change one character inside a `.receipt.json` and re-run: `body_digest_ok`
flips to `false` and `ok` follows it. That is the entire product.

## The ten

| # | trainee | scenario | grader | score | what it exercises |
|---|---|---|---|---|---|
| 01 | j. alvarez | oral_board.set1 | ascenvo.vcs.oral_board | 87 EXCELLENT | baseline clean pass, all four questions answered |
| 02 | m. chen | oral_board.set2 | ascenvo.vcs.oral_board | 23 UNSATISFACTORY | **failing score** + **partial/incomplete answer set** (two of four questions blank, `meta.source:"blank"`) |
| 03 | j. alvarez | oral_board.set1 | ascenvo.vcs.oral_board | 91 OUTSTANDING | **re-attempt**: same trainee, same scenario as #01, five days later, higher score -- the receipt says nothing about which attempt this is; see WHAT_THESE_DO_NOT_SHOW.md |
| 04 | r. kowalski | call_taking.gen43_cold_car_burglary | call_taking.grader | 95 STRONG | clean pass on the deterministic (non-LLM) call-taking grader |
| 05 | t. nguyen | call_taking.gen90_suicidal_caller | call_taking.grader | 38 WEAK | second **failing score**, different grader family (deterministic, not evaluative) |
| 06 | a. dubois | call_taking.gen79_noise_late_music | call_taking.grader | 64 THIN | **accented character + emoji in a free-text field** (`raw_comment_excerpt` quotes "Sra. Peña ... 🙄"); exercises canonicalization -- the digest covers the literal bytes, coaching text quotes the emoji back at the trainee on purpose (the tool that graded it is calling out the tone, not stripping it) |
| 07 | k. patel | call_taking.hero01_welfare_weapon.sequence | call_taking.seq_scorer | 100 STRONG | sequence-scorer shape (`seq_pct`/`seq_verdict_label`, no `score`/`overall`) at its best case -- exercises the FINDING below |
| 08 | s. omar | call_taking.hero01_welfare_weapon.sequence | call_taking.seq_scorer | 55 RETRAIN | sequence-scorer shape with a **fatal omission** (`fatal_omissions` non-empty, `seq_overridden:true`) |
| 09 | d. okafor | call_taking.gen61_traffic_stop_backup.sequence | call_taking.seq_scorer | 45 NEEDS WORK | third sequence-scorer example: **partial/incomplete** performance (two required steps MISS, one SKIPPED_OK) short of the fatal case in #08 |
| 10 | l. fischer | oral_board.set3 | ascenvo.vcs.oral_board | 75 GOOD | oral-board panel where **the served model varied across answers on the same board** (`judge_identity` reads "gemini-2.5-flash-002 + gemini-2.5-flash-003 (SERVED MODEL VARIED...)") -- the exact scar `grade_board.js`'s judge-declaration comment names, sealed instead of hidden |

## The shared ledger has fifteen rows, not ten

A ledger that can be rewritten is not a ledger, so re-minting **appended**.
`ledger.jsonl` now carries fifteen rows and every one of the eleven receipts
in this directory still verifies `consistent` against it:

| ledger row | receipt |
|---|---|
| 1, 2, 3, 10 | the pre-scrub 01, 02, 03, 10 — **superseded**, no file in this directory matches these rows |
| 4–9 | 04, 05, 06, 07, 08, 09 (untouched, original rows) |
| 11 | 11 (the branded example, untouched) |
| 12, 13, 14, 15 | the re-minted 01, 02, 03, 10 |

Rows 1, 2, 3 and 10 are deliberately still there. They carry body digests and
nothing else — no ballot text, no provenance string, nothing that needed
scrubbing — and deleting them would have meant rewriting a hash chain in the
one directory that exists to show a hash chain being honest. What they now
record is true: four receipts were issued on those dates and later superseded.
The `issued_at` on the four re-minted receipts is unchanged from the original
mint, so the ledger order (12–15, appended today) no longer matches the
`issued_at` order (Sept 6–11). That is the correct reading of both fields: the
ledger says when a row was written, the body says when the ballot was issued,
and they are different facts.

`01_oral_board_pass_clean.anchored.ledger.jsonl` follows the same rule and has
three rows: the pre-scrub original at row 1, an aborted re-mint at row 2 (minted
without its `--timestamp`, so its exhibit read `at None`), and the shipped
anchored twin at row 3.

## A FINDING, not normalized silently

Building #07 and #08 first surfaced a real bug: `arcaeon_receipt/ballot.py`'s
`_line()` (the function that renders the one human-readable result line in
the exhibit) only ever looked for `overall.score`/`overall.verdict` or a
bare `ballot.score`/`ballot.verdict`. The sequence-scorer shape carries
neither -- it reports `seq_pct` and `seq_verdict_label` instead -- so every
seq-scored exhibit printed `score=(no score field)` even though the ballot
docstring says this adapter accepts "any other trainer's finished-run
object" verbatim, and even though the receipt itself (digest, ledger,
witness) was correct throughout. The digest and verify path never touched
the bug; only the line a human actually reads was blind to a second real
grader shape the adapter already claims to support.

Fixed in `arcaeon_receipt/ballot.py`'s `_line()`: falls back to
`seq_pct`/`seq_verdict_label` before giving up. #07 and #08's `.exhibit.txt`
files were regenerated against the fixed code (`arcaeon-receipt exhibit
<receipt.json>`) after the fix -- their `.receipt.json` bodies are
untouched (the bug was never in the sealed data, only in the reader), and
re-verifying both after the regeneration still passes. #09, built after the
fix, was correct on the first run.

This is exactly the class of gap "113 tests green" cannot catch on its own:
`tests/test_ballot.py`'s fixtures apparently never included a bare
seq-scorer object with no `overall` key, so the suite exercised one grader
shape thoroughly and the other not at all. Ten real examples, read by a
human, found it in minutes.

## Verify + tamper counts (run 2026-09-12, re-run 2026-09-13 after the re-mint)

- **10 / 10** receipts verify clean (`ok: true`, `body_digest_ok: true`)
  against `ledger.jsonl`. Re-checked after the 2026-09-13 re-mint: **11 / 11**
  (the ten plus the branded #11) still return `ok: true` and
  `ledger.status: "consistent"` against the now-fifteen-row chain.
- **10 / 10** tampered copies (one score digit changed inside the sealed
  `ballot` object -- `score`+1 or `seq_pct`+1 depending on shape) correctly
  **fail** verification (`ok: false`, `body_digest_ok: false`). The
  tampered copies are not checked into this repo (nothing to gain from
  shipping ten broken receipts); the test is reproducible from any receipt
  here by editing one digit and re-running `arcaeon-receipt verify`.
- Scope block (`proves`/`does_not_prove`/`method`) is **byte-identical**
  across all ten receipts -- confirmed by hashing each receipt's `scope`
  object; one distinct value across ten files.

## The eleventh file: one real anchor, added 2026-09-12/13

`01_oral_board_pass_clean.anchored.receipt.json` +
`01_oral_board_pass_clean.anchored.exhibit.txt` +
`01_oral_board_pass_clean.anchored.ledger.jsonl(.witness.jsonl)` are a
second receipt for the same ballot object as example #01
(`inputs/01_oral_board_pass_clean.json`), minted with a real OpenTimestamps
anchor instead of `--no-anchor`. Diff it against the unanchored
`01_oral_board_pass_clean.receipt.json` beside it and the only differences are
`issued_at`, `checks[0].timestamp`, `body_digest`, `ledger`, and `anchor`; the
`ballot` object and `scope` block are identical. See
WHAT_THESE_DO_NOT_SHOW.md section 3 for exactly what the anchor does and does
not add. This one uses its own ledger file
(`01_oral_board_pass_clean.anchored.ledger.jsonl`), not the shared
`ledger.jsonl` the other ten rows live in, so minting it did not touch the
shared chain the rest of this directory depends on.

**Both halves of the pair were re-minted 2026-09-13** for the provenance scrub
above, so the anchored twin carries a fresh `ots_b64` from a new `ots stamp`
call made that day, not the earlier one. Nothing verifiable was lost: the
earlier stamp was still `pending-calendar` and had never upgraded to a Bitcoin
attestation. The twin's `issued_at` is the real clock at re-mint
(`2026-09-13T23:11:07Z`), not a carried-over override, so the stamp is not
older than the thing it stamps.

## The twelfth file: the first BRANDED ballot, added 2026-09-13

`11_branded_academy_cohort.receipt.json` + `.exhibit.txt` (input:
`inputs/11_branded_academy_cohort.json`) is the first receipt here carrying
vendor branding: `extra: {issuer: "Westbrook Regional Training Academy",
cohort: "WRTA-2026-OB-14"}`. Both names are fictional, same as every trainee
in this directory. It is row 11 on the SHARED `ledger.jsonl`, deliberately:
appending it left all ten earlier receipts verifying `consistent`, which is
the append-only property the chain is supposed to have and now has a worked
example of.

Read its exhibit beside any of the first ten. The academy's name is in the
title line and in an `Issued by:` / `Class:` block under the issue time, and
those strings live inside the body digest -- change one character of the
academy name in the `.receipt.json` and `body_digest_ok` flips false, exactly
as it does for a tampered score. That is the whole reason branding is worth
selling: a vendor name outside the digest is a letterhead anyone can retype.

What it does NOT prove is that the academy is who it says it is. The receipt
binds the name against later edits; it authenticates nobody. A stranger who
wants more than that needs the issuer's own ledger namespace and witness, not
a stronger sentence on the exhibit.

`roster_example.csv` beside it is a working ten-row roster over the inputs in
this directory. From `examples/ballots/`:

```
arcaeon-receipt ballot --roster roster_example.csv \
    --issuer "Westbrook Regional Training Academy" --cohort WRTA-2026-OB-14 \
    --namespace wrta-ob-14 --ledger /tmp/wrta-ob-14.jsonl --out-dir /tmp/class
```

Ten receipt/exhibit pairs into one chain, one summary line back. Point the
ledger and out-dir somewhere temporary: the committed chain in this directory
is an artifact, not a scratch file.

## What NOT to read into these ten

See `WHAT_THESE_DO_NOT_SHOW.md` in this directory. Read it before showing
any of this to a buyer.
