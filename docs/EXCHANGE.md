# Exchange reactions (TE-42)

After an exchange, each party writes one row about it under its own account
key, into its own hash-chained log. Anyone holding both logs can line the
rows up and see whether the two parties said the same thing about the same
bytes.

```console
$ arcaeon exchange react --exchange ex-17 --counterparty did:key:z6MkB... --file grades.csv --reaction VERIFIED --key a.key --log a.jsonl
$ arcaeon exchange pair a.jsonl b.jsonl
VERIFIED: both chains verify and every reaction row checks under its log's key; 1 clean, ...
ex-17: clean
```

The library is `arcaeon.prove.exchange_log`: `react(...)` writes a row and
`pair(log_a, log_b)` returns the report as a dict and never raises.

## The row

One row per reaction, kind `exchange.reaction`, appended with
`arcaeon.record.ledger.Ledger.append` (which adds `ts` and `chain`):

| field | what |
|---|---|
| `kind`, `v` | `exchange.reaction`, `1` |
| `exchange_id` | the exchange, one line of text |
| `counterparty` | the other party's ID: their account key, an Ed25519 `did:key`, or their arcaeon.io account id `acct:NAME@arcaeon.io` (see below), stored as given |
| `file_sha256` | sha256 of the file this party reacted to |
| `reaction` | `VERIFIED`, `BROKEN` or `COULD NOT LOOK`, the verifier's three words |
| `disputed`, `reason` | `true` and a reason when this party disputes; else `false` and `null` |
| `supersedes` | `null`, or the row digest of an earlier row of this log for the same exchange |
| `at` | UTC time, `YYYY-MM-DDTHH:MM:SSZ` |
| `signer` | this party's `did:key` |
| `sig` | base64 Ed25519 signature |

**The signature** is Ed25519 over the DSSE v1 pre-authentication encoding
`PAE("application/vnd.arcaeon.exchange.reaction.v1+json", C)`, where `C` is
the json-c14n v1 bytes (sorted keys, `,` and `:` separators, UTF-8, no NaN)
of the eleven fields above from `kind` to `signer`. `sig`, `ts` and `chain`
are not signed. Any other key in the row is a field outside the signature
and makes the row BROKEN. The key file is the envelope's: a 32-byte seed,
base64, one line (`arcaeon[sign]`).

**The counterparty ID.** The ID is the arcaeon.io account, and the account
binds the `did:key` (TE-41). `counterparty` takes either form. The account id
is `acct:NAME@arcaeon.io`, the RFC 7565 `acct:` URI under the arcaeon.io
host; `NAME` is 1 to 64 characters of dot-separated labels, each lower-case
`a-z`, `0-9` and `-`, not starting or ending with `-`. That form is defined
once, as `ACCOUNT_ID_RE` in `arcaeon.prove.exchange_log`. Anything else is
refused before writing (exit 2). Nothing resolves an account over the
network: the row holds the text given. An account id pairs **only** through a
binding row (below); without one, `pair` and `tally` treat `acct:...` and
`did:key:...` as two distinct IDs, a row that names the account reads
`mismatch` on counterparty, and the finding says which key it binds is COULD
NOT LOOK here.

## The binding row (D077)

`acct:NAME@arcaeon.io` is the confirmed account form. An account id pairs
with a log ONLY through a signed account-to-`did:key` binding row in that
log: the account's own chain, signed by its `did:key`, naming the account.

```console
$ arcaeon exchange bind --account acct:dealer-7@arcaeon.io --key b.key --log b.jsonl
```

The row is kind `exchange.binding`, v `1`, appended with `Ledger.append`:

| field | what |
|---|---|
| `kind`, `v` | `exchange.binding`, `1` |
| `account` | `acct:NAME@arcaeon.io` |
| `at` | UTC time, `YYYY-MM-DDTHH:MM:SSZ` |
| `signer` | the bound `did:key`, which must own the log |
| `sig` | base64 Ed25519 over `PAE("application/vnd.arcaeon.exchange.binding.v1+json", C)`, `C` the json-c14n v1 bytes of the five fields above |

The rules:

- With a valid binding row in log B for `acct:X`, a row in log A naming
  `acct:X` reads as naming B's key, and the exchange can pair `clean`.
- Without one, that side is COULD NOT LOOK (as before): `mismatch` on
  counterparty, and the finding says log B holds no binding row for it.
- A binding row signed by any key other than the log's owner, a changed
  field, or a field outside the signature is a BROKEN row, so the log and the
  pair read BROKEN. A forged binding never resolves.
- If more than one log among the inputs binds the same account, it resolves
  to none of them (COULD NOT LOOK) and the finding says so.
- `bind` refuses (exit 2) a malformed account id or a key that does not own
  the log.

**The limit:** a binding is the key holder's own signed claim. It proves the
key said "I am `acct:X`", not that arcaeon.io agrees. Two keys claiming one
account among your inputs are caught (neither resolves); one key claiming an
account it does not hold, with no rival among the inputs, is not. The
arcaeon.io account record is not consulted here unless you give one.

**Holding a binding to the account service (L3-02, opt-in).** `pair
--accounts FILE --account-key DID` (both, or neither; `--account-key`
repeats) reads FILE as an account store or a list of binding statements
(docs/ACCOUNT_ID_API.md) and trusts only the binding key(s) named on the
command line, never a key named in the file. Each account a log binds is
held to it at the binding row's `at` (a row the service wraps as the
agent's possession proof is read at the issue time) and at the `at` of the
newest reaction row that key signed in its log (one whose signature checks):

| account service says | word | the pairing |
|---|---|---|
| the key held that account under that owner at the binding row's time and at its newest reaction row's time | VERIFIED | stands |
| revoked or rotated out at or before the binding row's time or the newest reaction row's time; bound to another owner or another account; a service row whose signature fails or is by a key you did not name | BROKEN (the pair reads BROKEN, the reason named; a late reaction is named by its time and exchange id) | dropped |
| no record for the key; no trusted key named; a key that is not an Ed25519 `did:key` (length checked before any decode) | COULD NOT LOOK | dropped |

A dropped pairing reads `mismatch` on counterparty, and its finding says the
log binds the account by a signed binding row and names the account
service's word and reason (not "holds no signed binding row", which is kept
for a log with no binding row at all). A COULD NOT LOOK drop does not move
the pair's verdict; a BROKEN one does.

A FILE that is missing, over the size cap or not JSON makes the pair COULD
NOT LOOK. Each binding's answer is listed under `account_service.bindings`.
Without `--accounts`, nothing changes: `account_service.consulted` is false
and the report says "account service not consulted".

**The row digest** is `sha256:json-c14n:v1:` + sha256(`C`). `react` prints
it; `--supersedes` takes it.

**Append only.** A change is a new row whose `supersedes` names the old one.
Editing a row in place breaks the chain, and editing a signed field breaks
the signature too. The pair reader reads, per party and exchange, the latest
row that no later row supersedes; if a party left two rows unsuperseded it
reads the last and says so.

**A retracted BROKEN leaves a mark.** When a row that said BROKEN is
superseded and the current row says another word, the current row is read
and the head carries `retracted` (how many BROKEN rows were superseded) and
`retracted_at` (the latest one's `at`). `pair` lists the side under the
exchange's `retracted`, adds a finding, and counts them in the report's
`retracted`. A BROKEN superseded by another BROKEN is not a retraction.

**DISPUTED is a claim, not a verdict.** `--disputed REASON` signs a claim with
a reason. `pair` lists claims apart from the statuses and never turns one into
a fourth word: a hash proves what a party said and when, not what the other
party meant.

## What `pair` reports

The verdict is about the record: BROKEN if either chain does not verify
(strict: every row chained from genesis), any reaction row is BROKEN (bad
shape, a field outside the signature, a signature that does not verify, a
signer other than the log's owner, a `supersedes` that points at nothing
earlier for the same exchange), any binding row is BROKEN, or both logs
belong to one key. COULD NOT LOOK
if a log is missing, empty, not UTF-8, not a chained ledger or too big, or if
the install cannot check Ed25519. Else VERIFIED. A broken row is listed with
its line, never dropped. Exit 0 VERIFIED, 1 BROKEN, 3 COULD NOT LOOK.
With `--strict`, a VERIFIED record holding any `mismatch` or `missing`
exchange exits 1 instead of 0 (`not_verified` stays 0; 3 and 2 are
unchanged); without it the exit codes are as above.

A log's owner is the key you name (`--owner-a`, `--owner-b`), else the signer
of its first row that verifies (trust on first use: say which key you expect
when you know it). Naming the owner closes trust on first use: if the log's
first row that verifies is signed by another key, the whole log is refused,
BROKEN (exit 1), with `owner_refused: {"named", "first_row"}` on that log and
no exchange lined up from either log. It is BROKEN, not COULD NOT LOOK,
because the log was read and checked: it is a well-signed log of a key other
than the one you named. Without a named owner, `owner_refused` is null and
nothing changes.

Per exchange, `status` is:

- `clean`: both said VERIFIED, about the same sha256, each naming the other's key
  (or an account the other's log binds by a valid binding row);
- `mismatch`: the reactions, the sha256 or the counterparty differ (`differs` names which);
- `not_verified`: both said the same word, and it is not VERIFIED;
- `missing`: one party wrote nothing for it;
- `broken`: a row for it in either log is BROKEN.

Anything but `clean` is the mark. A VERIFIED verdict with mismatches in it
means the record is sound and the parties disagree.

## Disagreement classes

On top of the status, each exchange where the two sides disagree carries one
class word in `disagreement` and one plain sentence in
`disagreement_reason`. An exchange where they agree carries `null` in both;
so does a `broken` one (its record does not check, so no disagreement is read
from it). `disagreements` counts each word, and the text output's first line
ends with the four counts. `status` and its values are unchanged.

| word | what it means | what it cannot prove |
|---|---|---|
| `missing` | one log has no record of the exchange; the other does | that the silent party never saw it, or that a row was not dropped by truncating the log (pin each head) |
| `mismatched` | both logs have it, and a field differs: `reaction`, `file_sha256` or `counterparty`, named in the reason and in `differs` | which side is right |
| `retracted` | a side superseded an earlier BROKEN for this exchange with another word (the retraction above); the old row stays in its log | why it changed its word |
| `late` | both agree, but one row's `at` trails the other's by more than `--late-after SECONDS` | when either row was really written: `at` is each writer's own clock, signed, not witnessed |

One word per exchange, in this order: `missing`, `mismatched`, `retracted`,
`late`. A retracted exchange that is also mismatched reads `mismatched`; the
side still shows under `retracted`.

**The late window** defaults to 86400 seconds (one day): `at` is each
writer's own clock and a reaction is often written by a scheduled job after
delivery, so a day separates "answered in the same cycle" from "answered
after the fact" without marking clock drift or a nightly batch as late. Set
it with `--late-after SECONDS` (0 marks any gap). Every valid row carries a
signed `at`, so the class is always readable; if two rows ever carried no
comparable time, the exchange could not be `late` and its findings would say
so.

**Retraction** is the existing one: a BROKEN superseded by another word. There
is no separate withdraw row; a party that wants to take a reaction back writes
a new row that supersedes it.

**`--strict`** marks `mismatched` and `missing` only (exit 1), as before.
`late` and `retracted` are not marks under `--strict`: the current rows agree.

**The dispute packet from the pair.** `arcaeon exchange packet A.jsonl
B.jsonl --exchange ID` reads both logs with the same reader and puts one
exchange on a page (kind `arcaeon.dispute.pair_packet/v1`): each side's own
signed row (or "no record"), the status, the class word and its reason, the
field that differs, DISPUTED claims for it, and the limits below. File names
only, no directories. `--json` prints the JSON, `--out DIR` writes
`dispute-packet.md` and `dispute-packet.json`. Exit 0 written; 2 bad usage,
or nothing to dispute (the two sides agree and nobody disputes); 3 COULD NOT
LOOK (a log cannot be read, or the exchange is in neither log). The library
call is `arcaeon.prove.dispute_packet.from_pair`.

**The MCP tool.** `exchange_pair_reconcile` takes `log_a`, `log_b` and
optionally `exchange` (one exchange id), `late_after`, `owner_a`, `owner_b`,
and answers the same JSON as `pair --json` with `exit` added. Like every tool
on the connector it leaves one call-record row.

**What the classes cannot prove.** A class says how the two records differ,
not which party is right or at fault, and not that either record is true.
Everything under "What it does not prove" below still holds.

## What it proves

Each row was written by the key that owns its log, in the order the chain
records, and says what that party said about which bytes and when. Two
`clean` rows mean both parties said VERIFIED about the same bytes and named
each other.

## What it does not prove

- **That the file is true or safe.** Two clean rows mean both said VERIFIED
  about the same bytes, not that the bytes say anything true.
- **That the parties did not collude.** Two parties who agree to lie write two
  clean rows. The pair reads what was said; it cannot see why.
- **What either party meant.** A DISPUTED reason is the disputer's sentence.
- **Who holds a key.** A `did:key` is a key, not a person or a company.
- **That a log was not truncated or re-minted.** Drop the newest rows, or
  re-mint a whole log, and what remains verifies. The re-minter need not hold
  the key: the hash chain carries no signature, so a third party holding a
  party's log can rebuild one from a subset of that party's signed rows, and
  each row still verifies under the party's key. Pin each
  log's head outside your own control (`arcaeon pin`).
- **The `at` time.** It is the writer's clock, signed, not witnessed.
