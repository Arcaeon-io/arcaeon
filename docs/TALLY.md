# The tally (TE-43, TE-44)

clean means unchanged and labeled, never true.

The tally reads exchange reaction chains ([EXCHANGE.md](EXCHANGE.md), one
chain per account key) and prints, per ID, facts in columns: a recent window
and all time, side by side. It does not add them up. There is no score, no
weight and no ranking.

```console
$ arcaeon tally build a.jsonl b.jsonl c.jsonl --now 2026-10-04T12:00:00Z
clean means unchanged and labeled, never true
tally VERIFIED: 3 chain(s) verify and every reaction row checks under its chain's key; 3 ID(s)
...
did:key:z6MkC...  BROKEN DISPUTED unrated
  unrated: 2 exchanges, under 10; 1 days old, under 14
  first row 2026-10-03T12:00:00Z, age 1 days
                                             30d               all
  flags                          BROKEN DISPUTED   BROKEN DISPUTED
  broken                                       1                 1
  said VERIFIED                           1 of 1            1 of 1
  ...
  received VERIFIED                       1 of 2            1 of 2
  received BROKEN                              1                 1
  paired clean                            0 of 2            0 of 2
  ...
```

The library is `arcaeon.prove.tally.build(paths, *, window="30d",
settled_only=False, checked_only=False, groups=None, aliases=None, now=None)`.
It returns a dict of kind `arcaeon.tally/v1` and does not raise on hostile
input: a chain that cannot be read is COULD NOT LOOK, a chain that does not
verify is BROKEN. Only a bad `window` or `now` raises `TallyError`, before
anything is read.

## Why no weighting

Anything that counts more can be bought. A score turns many facts into one
number, and the cheapest way to move that number becomes the thing people
do. So every fact stays in its own column, and every share is printed with
its count beside it ("9 of 10", never "90%"). A reader who wants a ranking
has to make one, and has to say how.

The order of IDs is: any ID with a BROKEN flag first, then by key text. That
order is not a ranking.

## The columns

Each ID has the same block for each window (`--window`, default `30d`) and
for `all`, side by side:

| column | where it comes from |
|---|---|
| `flags` | `BROKEN` first if anything broken is in the window, then `DISPUTED` if a current DISPUTED claim is |
| `broken` | broken findings: this ID's chain does not verify or holds a BROKEN row (these have no trusted date, so they count in every window), a counterparty said BROKEN about an exchange with it, or a paired exchange with it is `broken` |
| `said` | **its own reactions**: the words this ID wrote in its own chain, its latest non-superseded row per exchange. `VERIFIED`, `COULD NOT LOOK`, `BROKEN`, `total`, `share_verified` ("9 of 10") |
| `received` | **what counterparties said**: the latest row per exchange of every other chain among the inputs that names this ID. Same five fields |
| `paired` | **paired outcomes**: exchanges where both parties' chains are among the inputs, lined up as `arcaeon exchange pair` does: `clean`, `mismatch`, `missing`, `not_verified`, `broken`, `total`, `share_clean` |
| `exchanges` | distinct paired exchanges (counterparty has its own chain among the inputs), self-trades excluded |
| `counterparties_with_records` | distinct other IDs in paired exchanges. A counterparty counts only if a chain it owns is among the inputs |
| `disagreements` | paired exchanges whose status is `mismatch` or `missing` |
| `disputed` | current DISPUTED claims by or about this ID, self-trades excluded (each claim is listed in `claims`) |
| `excluded` | self-trades in the window, each listed in `excluded` with its reason |

So the three words are counted twice, kept apart: from its own reactions
(`said`) and from what others said about it (`received`), and the paired
outcomes beside them. A BROKEN this ID said about someone else's file is in
its `said` column and does not flag it; it flags the other party, through
their `received` column, when their chain is among the inputs.

A row is in a window when its signed `at` is at or after the window start and
not after now (the start is inclusive). A paired exchange is dated by the
later of its two rows. A row dated after now is in no window and is noted.

Beside the windows, per ID: `keys` (more than one when an alias applied),
`first_row_at` and `age_days` (earliest signed `at` of any of its keys, to
now), `unrated` and `unrated_because`, `record_broken`, `claims`, `excluded`,
`filtered_out`, `findings`.

Every output, text and JSON, carries the sentence "clean means unchanged and
labeled, never true" (`sentence` in JSON).

## Unrated

An ID is `unrated` while it has fewer than 10 exchanges (all time, paired,
self-trades excluded) or is under 14 days old. Its facts are still printed;
`unrated` says there are not yet enough of them to read. Rows naming keys
with no chain among the inputs never count toward the 10: anyone can write
rows naming made-up keys.

## Gaming rules

**(a) Self-trades do not count.** A row is a self-trade when it names its own
key as the counterparty, when both keys are one ID by a signed alias, or when
both IDs are in one group of `--groups FILE`. It is left out of every count
and share, and listed in `excluded` with the reason, on both sides. The
groups file is JSON, `{"groups": [{"name": "acme", "members": [DID, DID]}]}`
(a bare list of DID lists also reads). It is declared by whoever hands it to
the tally and is not signed: a group can only take counts away, never add
them, and what it took away is listed.

**(b) BROKEN shows first.** In `flags` and in the text, BROKEN is the first
word, and BROKEN IDs come first in the list.

**(c) Windows side by side.** The recent window and all time are printed
next to each other, so an old break is not hidden by a clean month, and a
clean month is not hidden by an old break.

**(d) History cannot reset by key change, if the alias exists.** An alias
entry says a new key inherits an old key's record:

```json
{"kind": "arcaeon.tally.alias/v1", "old": DID, "new": DID, "at": "2026-10-03T12:00:00Z",
 "sig_old": BASE64, "sig_new": BASE64}
```

Both keys sign the same bytes: Ed25519 over the DSSE v1 PAE of
`application/vnd.arcaeon.tally.alias.v1+json` and the json-c14n v1 bytes of
`kind`, `old`, `new`, `at`. `arcaeon tally alias --old-key K1 --new-key K2`
prints one. Pass a file of them with `--aliases FILE` (`{"aliases": [...]}`
or a list). An applied alias makes the new key's rows part of the old ID;
the ID keeps the old key as its name and lists both keys. An entry whose
signature fails is BROKEN (the tally verdict is BROKEN) and is not applied;
a malformed entry, a second alias for the same new key, or one that closes a
loop is not applied and says why.

We implement **signed by both keys**, not owner-declared. Signed by the old
key alone would let the holder of a fresh key with a bad record push that
record onto someone else's key; an unsigned declaration would let anyone
claim a good record. **The limit:** an owner with a bad record will not sign
an alias. A fresh key with no alias cannot be stopped; it is shown as a new
ID, unrated, with its age from its first row. The tally makes reset visible
(new, unrated, young), not impossible.

## Filters

Reader options. They only drop rows, never add or reweigh them; what was
dropped is counted in `filtered_out`.

- `--checked-only`: keep rows whose reaction is VERIFIED or BROKEN (someone
  looked). A COULD NOT LOOK row is dropped, and so is any paired exchange
  holding one.
- `--settled-only`: keep exchanges with a current row from both parties (both
  chains among the inputs) and neither row DISPUTED. Every other row is
  dropped, including every row whose counterparty's chain is not here.

## The verdict

The tally's own `verdict` is about the record, never about an ID: BROKEN if a
chain does not verify, holds a BROKEN row, or an alias signature fails; else
COULD NOT LOOK if a chain, the groups file or the aliases file could not be
read, or no chain was given (an unreadable groups or aliases file prints no
IDs: counts that miss the exclusions you asked for would be wrong); else
VERIFIED. Exit 0 VERIFIED, 1 BROKEN, 3 COULD NOT LOOK, 2 bad usage.

## Limits

- **Clean means unchanged and labeled, never true.** The tally counts what
  parties said, not whether any file was true.
- **Self-trades are caught only when declared or shared.** Two keys run by one
  owner who never says so look like two parties.
- **A fresh key cannot be stopped,** only shown as new and unrated.
- **`at` is the writer's clock,** signed, not witnessed. An owner can backdate
  rows to look older. Pin chain heads outside your control (`arcaeon pin`).
- **The tally sees only the chains you give it.** A counterparty with no chain
  among the inputs is not counted, and a truncated or re-minted chain still
  verifies (see EXCHANGE.md).
- **A key is not a person.** An ID is a `did:key`.
