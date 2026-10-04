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
| `counterparty` | the other party's account key, an Ed25519 `did:key` |
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

**The row digest** is `sha256:json-c14n:v1:` + sha256(`C`). `react` prints
it; `--supersedes` takes it.

**Append only.** A change is a new row whose `supersedes` names the old one.
Editing a row in place breaks the chain, and editing a signed field breaks
the signature too. The pair reader reads, per party and exchange, the latest
row that no later row supersedes; if a party left two rows unsuperseded it
reads the last and says so.

**DISPUTED is a claim, not a verdict.** `--disputed REASON` signs a claim with
a reason. `pair` lists claims apart from the statuses and never turns one into
a fourth word: a hash proves what a party said and when, not what the other
party meant.

## What `pair` reports

The verdict is about the record: BROKEN if either chain does not verify
(strict: every row chained from genesis), any reaction row is BROKEN (bad
shape, a field outside the signature, a signature that does not verify, a
signer other than the log's owner, a `supersedes` that points at nothing
earlier for the same exchange) or both logs belong to one key. COULD NOT LOOK
if a log is missing, empty, not UTF-8, not a chained ledger or too big, or if
the install cannot check Ed25519. Else VERIFIED. A broken row is listed with
its line, never dropped. Exit 0 VERIFIED, 1 BROKEN, 3 COULD NOT LOOK.

A log's owner is the key you name (`--owner-a`, `--owner-b`), else the signer
of its first row that verifies (trust on first use: say which key you expect
when you know it).

Per exchange, `status` is:

- `clean`: both said VERIFIED, about the same sha256, each naming the other's key;
- `mismatch`: the reactions, the sha256 or the counterparty differ (`differs` names which);
- `not_verified`: both said the same word, and it is not VERIFIED;
- `missing`: one party wrote nothing for it;
- `broken`: a row for it in either log is BROKEN.

Anything but `clean` is the mark. A VERIFIED verdict with mismatches in it
means the record is sound and the parties disagree.

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
  re-mint a whole log under the same key, and what remains verifies. Pin each
  log's head outside your own control (`arcaeon pin`).
- **The `at` time.** It is the writer's clock, signed, not witnessed.
