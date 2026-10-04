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
| `broken` | broken findings: this ID's chain does not verify or holds a BROKEN row (these have no trusted date, so they count in every window), a counterparty whose chain does not read BROKEN said BROKEN about an exchange with it, or a paired exchange with it is `broken` |
| `said` | **its own reactions, paired only**: the words this ID wrote in its own chain, its latest non-superseded row per exchange, counted ONLY when the counterparty pairs (a chain it owns is among the inputs and holds a current row for the same exchange). `VERIFIED`, `COULD NOT LOOK`, `BROKEN`, `total`, `share_verified` ("9 of 10") |
| `said_unpaired` | the same words for every other exchange: a counterparty with no chain here, an account id with no binding row, or no answering row. `VERIFIED`, `COULD NOT LOOK`, `BROKEN`, `total`. Shown apart, never folded into `said` or its share: an invented counterparty cannot move `said` |
| `received` | **what counterparties said**: the latest row per exchange of every other chain among the inputs that names this ID. Same five fields |
| `paired` | **paired outcomes**: exchanges where both parties' chains are among the inputs, lined up as `arcaeon exchange pair` does: `clean`, `mismatch`, `missing`, `not_verified`, `broken`, `total`, `share_clean` |
| `exchanges` | distinct paired exchanges (counterparty has its own chain among the inputs), self-trades excluded |
| `counterparties_with_records` | distinct other IDs in paired exchanges. A counterparty counts only if a chain it owns is among the inputs |
| `disagreements` | paired exchanges whose status is `mismatch` or `missing` |
| `disputed` | current DISPUTED claims by or about this ID, self-trades excluded (each claim is listed in `claims`) |
| `excluded` | self-trades in the window, each listed in `excluded` with its reason |
| `retracted` | `said`: BROKEN rows this ID wrote and later superseded with another word; `received`: the same by a counterparty about an exchange with this ID. One per exchange, dated by the retracted row's `at`. The current row is what counts elsewhere; the retraction stays visible here |
| `from_broken_chain` | rows from a chain that reads BROKEN, about this ID: `received` (words it would have received) and `paired` (exchanges it would have paired). They credit nothing and flag nothing; they are counted here, never silently dropped |

**Rows from a BROKEN chain credit nobody.** When a chain reads BROKEN (its
hash chain fails or it holds a BROKEN row), its owner is flagged BROKEN
(`record_broken`) as before, and its rows do not enter any counterparty's
`received`, `paired`, `exchanges` or `counterparties_with_records`, and its
DISPUTED claims about others are listed but not counted. Each such row is
counted in the counterparty's `from_broken_chain` instead. The owner's own
`said` still counts its own rows (it is flagged BROKEN beside them).

`retracted` and `from_broken_chain` are marks: they are counted before the
`--checked-only` / `--settled-only` filters, which never hide them.

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

## The tally chain (TE-47)

A tally printed today can be printed differently tomorrow. The tally chain
makes each tally you publish a row nobody can edit afterwards without it
showing, and ties that row to the exact exchange logs it read.

```console
$ arcaeon tally seal a.jsonl b.jsonl --log TALLY_CHAIN.jsonl --out tally.json
sealed row 5f0c... in TALLY_CHAIN.jsonl: tally VERIFIED, tally_sha256 9a1e...
$ arcaeon tally pin --log TALLY_CHAIN.jsonl --dry-run --out S.json
$ arcaeon tally verify --log TALLY_CHAIN.jsonl --inputs a.jsonl b.jsonl --statement S.json
VERIFIED: the tally chain verifies: 1 snapshot(s), well formed, in order; ...
```

**`seal`** runs `tally build` with the same options, replaces every local
path in the result with the file's name, and appends one row through
`Ledger.append` (the writer the exchange, deal and gate rows use):

```json
{"kind": "tally.snapshot", "v": 1, "tally_kind": "arcaeon.tally/v1",
 "tally_sha256": HEX64, "tally_verdict": "VERIFIED",
 "options": {"window": "30d", "settled_only": false, "checked_only": false,
             "now": "2026-10-04T12:00:00Z", "groups": null, "aliases": null},
 "inputs": [{"name": "a.jsonl", "sha256": HEX64, "sha256_of": "lf", "rows": 12,
             "chain_tip": "..."}],
 "at": "2026-10-04T12:00:03Z", "ts": "2026-10-04T12:00:03Z", "chain": "..."}
```

`tally_sha256` is sha256 of the json-c14n v1 bytes of the tally with paths
replaced by names (`--out` writes exactly that tally). Each input is named by
its file name only, never a path, with the sha256 of its LF-canonical bytes
(every CRLF read as LF; a missing final LF supplied), its row count and the
`chain` value of its last row. `options.groups` and `options.aliases` are
`null` or `{name, sha256, sha256_of}`. Two inputs with one file name are
refused (the row could not tell them apart); an input that cannot be read is
refused and nothing is written (exit 3). A BROKEN or COULD NOT LOOK tally is
still sealed: the row records the tally's own verdict in `tally_verdict`.

**`verify`** reads the tally chain with the ledger's strict verify and checks
each row is a well-formed snapshot (a row of any other kind is BROKEN). `at`
and the ledger's `ts` must never go backwards from one row to the next; an
earlier `at` is BACKDATED and an earlier `ts` is REORDERED, both BROKEN, so a
re-minted chain with its rows swapped is caught even though its hashes link.
Equal seconds are fine. With `--inputs`, each snapshot's inputs are matched by
file name against the logs given: the sealed rows must be an exact prefix of
the log now (rows appended since are fine and are named as not covered); a
past row edited, removed or re-serialized is BROKEN, a log with fewer rows is
TRUNCATED (BROKEN), and an input that was not given or cannot be read is
COULD NOT LOOK. When every input matches, the tally is rebuilt from the
sealed prefixes with the sealed options and must hash to `tally_sha256`
(BROKEN otherwise). A snapshot that used a groups or aliases file is rebuilt
only when you pass the same file (`--groups`, `--aliases`; a different file
is BROKEN); without it the rebuild is skipped and says so.

**`pin --dry-run`** prints the pin statement for the tally chain's current
tip, and with `--out` writes it to a new file (an existing file is never
overwritten). It writes nothing else. `--dry-run` is the only mode: without
it the verb refuses (exit 2) and says why. A chain that does not verify gets
no statement (exit 1); a missing or empty one is exit 3. **The live pin is
the operator's scheduled task, not this verb's:** the Bitcoin timestamp and
the public mirror copy are done by the operator's own witness job, on its
schedule. This verb ships the dry-run entry only.

The statement is the v2 pin statement of the operator's canon witness,
reproduced field for field from `bridge/witness/seal_chain.py`
(`build_pin_statement_v2`, `statement_canonical`) and checked as
`bridge/witness/verify_pins.py` checks it, both at commit `25a88340` of the
operator's witness repository (not public):

```json
{"chain": "arcaeon-tally", "chain_values_sha256": HEX64, "file_sha256": HEX64,
 "file_sha256_of": "lf", "prev_pin_sha256": null, "rows": 3,
 "stated_at": "2026-10-04T12:10:00+00:00", "tip": "...", "v": 2}
```

- `chain`: `--chain-id`, default `arcaeon-tally`.
- `chain_values_sha256`: sha256 of every row's `chain` value, rows 1..N in
  order, each followed by one LF.
- `file_sha256`: sha256 of the chain file's LF-canonical bytes;
  `file_sha256_of` is `lf`.
- `prev_pin_sha256`: `--prev-pin-sha256` (the previous pin statement's
  sha256), else `null`.
- `stated_at`: the sealer's clock, `+00:00` form; never a proof time.
- Serialized with sorted keys, `,` and `:` separators, UTF-8, not
  ASCII-escaped; the statement's sha256 is over exactly those bytes.
  `public_listing_sha256` (the witness's listing of earlier pin folders) is
  not built here; `verify --statement` accepts a statement that carries it.

`verify --statement S.json` checks the statement commits to this chain:
`rows` no more than the chain has, `tip` is row N's chain value, and
`chain_values_sha256` and `file_sha256` match rows 1..N. A statement for an
older tip of the same chain still verifies and names the rows after it as
not covered; any mismatch is BROKEN; a file that is not a v2 pin statement is
COULD NOT LOOK. `tests/test_tally_chain.py` holds a statement the witness
builder produced and checks this builder's bytes equal it.

**Un-editable, not un-gameable.** The chain proves a tally was not changed
after it was sealed and which exchange-log bytes it read. It does not prove
those exchanges were real. A wash trade between two keys one owner runs is
sealed faithfully, as a wash trade, forever: the seal makes the record
permanent, it does not make it honest. The gaming rules above still decide
what counts. `at` and `ts` are the sealer's clock: going backwards is caught,
a wrong clock is not. And a truncated or re-minted tally chain still verifies
on its own; only a pin of its tip held outside your control closes that gap.

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
- **An account id pairs only through a binding row.** `acct:NAME@arcaeon.io`
  is the confirmed account form (EXCHANGE.md). A row naming an account
  resolves to a key ONLY when exactly one chain among the inputs holds a
  valid signed binding row for it (the account's own chain, signed by its
  `did:key`, naming the account; `arcaeon exchange bind`). Then it pairs like
  a row naming that key. Without one the binding is COULD NOT LOOK and the
  row is `said_unpaired`; a binding signed by another key is a BROKEN row
  (the tally is BROKEN) and never resolves; two chains binding one account
  resolve to neither. Each account is listed under `bindings` with
  `applied` and a finding. A binding is the key holder's claim: arcaeon.io's
  own record is not consulted here.
