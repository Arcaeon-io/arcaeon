<!--
DRAFT technical/landing copy for arcaeon.io, same shape as
docs/citation-receipt-page.md. Not published. Plain English, no em dashes,
no exclamation marks, no claim of correctness anywhere on the page: the
receipt attests that the score and ballot are unaltered since the
timestamp, and the first screen says so before anything else. Unlike the
citation page, this one carries no "why now" section built on secondary
stats -- there is no equivalent verified regulatory/news hook for training-
sim ballots today, and inventing one would be exactly the kind of claim
this product exists to refuse. Written for a stranger reading cold.
-->

# Ballot Receipt

### Proof your score is the one the sim produced, unaltered, at the time you finished.

A trainee finishing a graded simulation -- an oral-board panel, a call-taking
run, a radio drill -- gets a results screen. A screenshot of that screen is
easy to make and easy to doubt: a hiring center reading it has no way to
tell a real result from an edited one, or a fresh run from a retry quietly
substituted for a worse one. A Ballot Receipt is the paper you produce
instead of the screenshot.

**What this receipt proves:** the score and the ballot object your sim
produced are unaltered since the timestamp on the receipt. Change one digit
of the score, one word of the grader's notes, or the timestamp itself, and
the receipt no longer verifies.

**What it does not prove:** that the score is correct, or that this was
your first attempt at the scenario. This is not a claim about grading
quality and not a claim about how many times you ran the sim before this
one. It is an integrity check on one finished result, stated as one, on the
face of the document, before anything else.

---

## Why this exists

Training simulators grade with a mix of deterministic scoring (a sequence
checker, a phonetic-alphabet checker) and evaluative scoring (an LLM judge
applying a rubric, the way `api/grade_board.js`'s oral-board panel does). A
hiring center reading a candidate's self-reported score has no way to
distinguish an honest result from an edited one, and no way to know from the
score alone whether the grade came from a fixed rubric or a judged read.
This receipt does not change how the grading works or vouch for the grading
engine's quality; it seals the finished result the same way the other four
Arcaeon receipts seal their own subject, so a hiring center gets an
integrity check instead of a screenshot.

---

## How it works

Run it after a sim closes, against the graded object the sim already
produced:

```
arcaeon-receipt ballot ballot.json --trainee "a. writer" --scenario "oral_board.set1" \
  --grader "ascenvo.vcs.oral_board" --exhibit ballot.exhibit.txt
```

The tool wraps the graded object verbatim (score, verdict, per-item
detail, whatever the grading engine returned) into the check, so the digest
covers exactly what a trainee would show a hiring center: nothing is
reshaped or summarized before it is sealed. It writes two files: a JSON
receipt (what a stranger verifies) and a plain-text exhibit (what a hiring
manager reads).

There is no flagged-check concept for a ballot the way there is for a
citation (a ballot is already a finished, already-graded object, not a set
of individual checks that can each pass or fail), so the CLI only ever
exits 0 (receipt built) or 1 (bad input).

### What the exhibit looks like

This is real, unedited tool output (`ballot.ballot_receipt()` called
directly with `witness=False, anchor=False`, the same fixture shape
`tests/test_ballot.py` uses):

```
BALLOT RECEIPT  (arcaeon-receipt)
Issued (UTC): 2026-09-12T08:00:00Z

WHAT THIS RECEIPT PROVES
  - the score and the ballot are unaltered since the timestamp
WHAT THIS RECEIPT DOES NOT PROVE
  - the score is correct
  - the sim was not attempted before

SUBJECT
  trainee: a. writer
  scenario: oral_board.set1
  grader: ascenvo.vcs.oral_board

RESULTS (1 check)
  a. writer  oral_board.set1  score=82 GOOD  grader=ascenvo.vcs.oral_board  at 2026-09-12T08:00:00Z

INTEGRITY
  body digest: sha256:json-c14n:v1:2a9d02a79198b4282cc3296e668f9f0bc03e68ad499ff0a2e55fe6e66be73671
  ledger: namespace=ballot rows=1 chain=15e9481ac319fdb784b03f2ea2d98925
  witness: local-file (none (self-controlled file))
  anchor: none status=skipped
```

The scope statement prints before the results, the same as every other
adapter here: the first thing a reader sees is what the document is not
claiming.

### Verifying it without contacting us

Same mechanism as every other Arcaeon receipt: a sha256 body digest over the
score, the ballot, the scope statement and the issue time, recomputable from
the receipt's own fields.

```
arcaeon-receipt verify ballot.receipt.json --ledger receipts.log.jsonl
```

No call home required. Change one field, the digest no longer matches.

---

## What it does not do

Said once here plainly, because it is the whole product, not fine print:

- It does not grade anything. Grading is the sim's job, before this receipt
  ever runs.
- It does not check whether an evaluative (LLM-judged) score was assigned
  fairly or consistently. It seals whatever the grading engine returned.
- It does not know or claim how many times the trainee ran the scenario
  before this attempt.
- It does not replace a hiring center's own interview or verification
  process, and does not try to.

If a ballot was graded generously and sealed accurately, this receipt will
verify and be entirely correct to do so. Grading quality and result
integrity are different questions. This tool answers one of them, honestly,
and says which one on every page it produces.
