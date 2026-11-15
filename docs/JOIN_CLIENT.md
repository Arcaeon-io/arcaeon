# The join, client side: arcaeon and the desktop's witness client

This page is a spec. Nothing in it is built yet, and no code goes in until
the owner has read it. It says what two clients do when the hosted witness at
`witness.arcaeon.io` takes contract pins under `/witness/v1`:

- **arcaeon**, this package: `arcaeon pin --remote`, `arcaeon seal`, the MCP
  tools `witness_pin` and `witness_renew`, and the HTTP paid lane, all of
  which reach the witness through `arcaeon.remote`.
- **The desktop's witness client**, `witness/client.py` in the witness
  sandbox repository, which the desktop app ships and runs.

The server side is the witness sandbox's docs/JOIN_SPEC.md (sandbox pull
request 64, at its commit `71ff6cf`), called "the server spec" below, with
its section numbers. The objects are those of docs/CONTRACT.md (version 2),
called "the contract". Where this page and either of them differ, they win
and this page is wrong.

## 1. What changes and what does not

What changes:

- Both clients can send a **contract pin** to `https://witness.arcaeon.io/witness/v1/pins`
  and get back a **contract receipt** signed by the live witness's new
  contract key (server spec 10).
- A pin may carry a bearer key (`ARCAEON_KEY` in arcaeon, a bought key file
  on the desktop). With one, the bearer key pays. Without one, the pin draws
  on the free allowance of the key that signed it (server spec 8 and 9).
- Both clients check every receipt before keeping it (section 6) and say
  plainly why a pin was refused (section 7).

What does not change:

- The plain pin path, `POST /api/pin` with `{namespace, rows, chain}`, and
  everything in arcaeon that uses it today. arcaeon keeps it as the default
  until the owner decides otherwise (open question 1).
- The base install of arcaeon has no dependencies. Nothing in this page adds
  one to it.
- `arcaeon buy`. It still reads the price list and prints only what the list
  marks live (section 8 says the one line it gains).
- No price, pack name or payment link appears in any line either client
  prints for a contract pin.

## 2. Built in values

Each client carries, in its code, the address and the identity of the
witness it trusts. Neither is ever fetched and believed.

| Value | arcaeon | desktop client | Rule |
|---|---|---|---|
| Witness address | `WITNESS_ENDPOINT` in `src/arcaeon/remote/offers.py`, already `https://witness.arcaeon.io` | `WITNESS_URL` in the desktop's `onewitness.py` | The client adds `/witness/v1` to it. |
| Witness key id | new `CONTRACT_WITNESS_KEY_ID` in `src/arcaeon/remote/witness.py` | `WITNESS_KEY_ID`, passed to the client as `--witness-key-id` | 64 lower case hex, copied at release time from the key's recovery note (server spec 10.1, 11). Empty until the key exists. |
| Next key id | new `CONTRACT_NEXT_WITNESS_KEY_ID` | `NEXT_WITNESS_KEY_ID` | Optional, 64 lower case hex, never equal to the key id. Used only during a rotation overlap (server spec 10.5). |

Overrides, for a person who runs their own witness:

- arcaeon: `ARCAEON_WITNESS_URL` (exists today) moves the address.
  `ARCAEON_WITNESS_KEY_ID` (new) replaces the built in key id and must be 64
  lower case hex; anything else is refused naming `witness_key_id` before any
  request. Setting the address without the key id makes every contract pin
  refuse naming `witness_key_id`: a moved address is never trusted under the
  built in identity.
- desktop: the person's own typed settings, as today (server spec 12.2).

While the built in key id is empty, arcaeon refuses every contract pin with
one line, `the witness's contract key is not set in this build`, exit 3, and
sends nothing.

## 3. The head arcaeon pins

The contract head is `{"chain", "kind": "head", "n", "v": 1}` with `chain` 64
lower case hex and, for an empty ledger, `n` 0 and 64 zeros (contract, "The
head"). An arcaeon ledger's head does not have that shape today:

- its chain value is 32 lower case hex (`src/arcaeon/record/row.py`, the
  link is cut to 32 characters);
- an empty ledger's chain is the word `genesis`.

So arcaeon needs one fixed rule for the contract head of a ledger. The
proposal (open question 2):

- `n` is the ledger's verified row count.
- For `n` 0, `chain` is 64 zeros.
- For `n` above 0, `chain` is the lower case hex SHA-256 of the ASCII bytes
  `arcaeon-ledger-head/v1:` followed by the 32 hex chain value of row `n`.
- A ledger that does not verify is never pinned: arcaeon refuses, as
  `pin --remote` refuses today, before any request.

The same rule is the only way a checker compares an arcaeon ledger with a
receipt, so it lives in one function (`arcaeon.record.ledger.Head.contract_head()`)
and the selftest checks it against fixed vectors.

The desktop pins the seal's own head, which is already a contract head. It
needs no rule.

## 4. The pinner key and the namespace

A contract pin is signed by the ledger owner's key (contract, "Pins and
receipts").

- arcaeon makes that key once, on first use, at `<ARCAEON_HOME or ~/.arcaeon>/witness/owner.key`,
  created exclusively, readable by the person only, holding the 32 byte
  Ed25519 seed as 64 lower case hex. It is never sent, printed or logged.
  Its public half travels in the `Public-Key` header; its SHA-256 is the
  pin's `key_id`.
- The desktop uses the key its switch makes (`owner.key`), as today.
- Signing and checking need Ed25519. arcaeon's base install has none; the
  `arcaeon[sign]` extra brings it. Without the extra, a contract pin refuses
  with one line naming the extra, exit 3, and nothing is sent. Plain pins
  are unaffected.
- **The namespace** carries the first 16 hex characters of the pinner key id,
  so a stranger cannot claim it first (server spec 7.7). arcaeon's default
  is `<ledger name part>-<first 16 hex of key_id>`; `--ns` still picks one.
  A 422 naming `key_id` means another key owns that name: arcaeon says the
  name is taken and never retries into it.

## 5. The pin call

In this order. The first step that fails is the answer, and nothing after it
runs.

1. **Read the head** (section 3). Refuse a ledger that does not verify.
2. **Ask the witness who it is**: `GET /witness/v1/key`. The answer must be
   exactly `{"key_id","public_key"}` as canonical bytes, `public_key` 64 lower
   case hex, and `key_id` the SHA-256 of it.
3. **Check the identity before anything is sent**: `key_id` must equal the
   built in key id, or the next key id during an overlap. Otherwise refuse
   naming `witness_key_id`: the answer did not come from our witness, so
   nothing was kept or sent. The bearer key and the pin are never sent to a
   witness that failed this step.
4. **Make the pin**: kind `pin`, `v` 1, `namespace`, `head`, `issued_at` (the
   client's clock, `YYYY-MM-DDTHH:MM:SSZ`, UTC, whole seconds), `key_id`, and
   `sig`, Ed25519 over the canonical bytes of the pin without `sig`. The body
   is the pin's canonical bytes and nothing else (contract, "Canonical bytes"
   and "Transport").
5. **Send it**: `POST /witness/v1/pins` with `Content-Type: application/json`,
   `Content-Length`, `Public-Key: <64 lower case hex>`, and
   `Authorization: Bearer <key>` only when a bearer key is set, only over
   HTTPS (loopback excepted, for tests), and only after step 3 passed. No
   query string. No redirect is followed.
6. **Limits**: the whole call, steps 2 to 5, gets 10 seconds in all, on the
   same background thread rule `arcaeon buy` uses. An answer body larger than
   8 KB is refused naming `receipt` and not read further.
7. **Read the answer**: 201 or 200 go to section 6. A refusal goes to section
   7. Any other status, or no answer, is COULD NOT LOOK: nothing was kept.

## 6. The receipt check

A receipt is kept only after every check below passes. The first one that
fails is refused naming its field, and the receipt is not kept.

1. **Canonical bytes**: the body is byte for byte the canonical bytes of the
   object it parses to: UTF-8, no byte order mark, keys sorted by UTF-16 code
   units, no white space, no trailing newline, integers only, no null. A body
   that parses but is not canonical is refused naming `receipt`.
2. **Exactly eight fields**: `head`, `key_id`, `kind`, `namespace`,
   `received_at`, `sig`, `v`, `witness_seq`, and no other. A missing or
   unknown field is refused at that field.
3. **Kind and version**: `kind` is `receipt`, `v` is 1.
4. **The head**: exactly its four fields, and equal field for field to the
   head that was sent.
5. **The namespace**: equal to the pin's.
6. **The witness**: `key_id` equal to the built in key id (or the next one
   during an overlap, and then equal to what step 2 of section 5 answered).
   A receipt under any other key id is never counted.
7. **The signature**: `sig` is 128 lower case hex and verifies as Ed25519
   over the canonical bytes of the receipt with `sig` taken out, under the
   public key whose SHA-256 is that built in key id. The public key comes
   from section 5 step 2 and is used only because its hash matched.
8. **The time**: `received_at` is `YYYY-MM-DDTHH:MM:SSZ`, a real calendar
   date, no :60. It is a label, never an order (contract, "Time").
9. **The order**: `witness_seq` is a whole number from 1, and above every
   receipt already kept for this namespace and this witness key id. A 200
   whose receipt is byte for byte one already kept is the same point sent
   again: nothing new is kept and the pin counts as done.

Where receipts are kept:

- arcaeon: `<ARCAEON_HOME or ~/.arcaeon>/receipts/<witness key id>/<namespace>.<witness_seq>.json`,
  the bytes exactly as received, created exclusively, never replaced. A
  receipt for a key id gets its own folder, so a rotation never mixes two
  witnesses' receipts (server spec 12.2).
- desktop: as today, with the receipts folder named for the witness key id
  (server spec 12.2, 13).

What arcaeon prints after a kept receipt, one line each:

```
pinned <namespace>: head n <n>
the witness took it as number <witness_seq> at <received_at>, signed by <first 16 hex of key id>
receipt kept at <path>
```

## 7. Refusals, in plain words

A refusal body is exactly `{"field","reason","status":"REFUSED"}` (server spec
4.3). Neither client shows the witness's own `reason` text as its main line:
the witness may change its wording, and the line must stay plain and stable.
Each client picks its line from the status and the field, and shows the
witness's reason after it as `(the witness said: ...)`, cut to one line.

Exit codes are arcaeon's one table: 0 pinned, 1 refused by the witness, 2
bad usage, 3 COULD NOT LOOK.

| Status and field | arcaeon line | Exit |
|---|---|---|
| 402 `plan`, no bearer key sent | `Could not pin: the free pins for this key are used for this month. They start again on the first of the month (UTC). A bought plan adds pins; arcaeon buy lists them.` | 1 |
| 402 `plan`, bearer key sent | `Could not pin: your key has no pins left. A bought plan adds pins; arcaeon buy lists them.` | 1 |
| 401 `bearer` | `Could not pin: the witness does not know this ARCAEON_KEY, or it was revoked. Nothing was charged.` | 1 |
| 403 `bearer` | `Could not pin: this ARCAEON_KEY's plan could not be read by the witness. Nothing was charged.` | 1 |
| 429 `bearer` or `address` | `Could not pin: too many pins in a short time. Try again in <n> seconds.` (from `Retry-After`; without it, `try again later`) | 3 |
| 422 `key_id` | `Could not pin: the name <namespace> belongs to another key. Pick another name with --ns.` | 1 |
| 422 `head.n`, `head.chain` or `root` | `Could not pin: the witness already holds a later or different point for <namespace> (field <field>). Your ledger may have been rewritten; check it with arcaeon verify.` | 1 |
| 409 `namespace` | `Could not pin: the witness's stored record for <namespace> does not check out, so it takes no more pins for it.` | 3 |
| 422 or 400 at any other field | `Could not pin: the witness refused the pin at field <field>. This is a fault in arcaeon; please report it.` | 1 |
| 503 or 507 at any field | `Could not pin: the witness could not store the pin just now. Nothing was charged. Try again later.` | 3 |

Notes:

- The out of pins choice is made by whether a bearer key was sent, never by
  reading the reason text. The server spec has the desktop pick by the
  reason (server spec 13); this page asks that the desktop use the same rule
  as arcaeon (open question 3).
- No refusal line carries a price, a pack name or a link. It names the
  command `arcaeon buy`, which reads the live list.
- The desktop's card sentences are those of server spec 13, with the same
  meaning as the first two rows, and "Could not pin: the answer did not come
  from our witness, so nothing was kept or sent. Try again later." for
  section 5 step 3.

## 8. The free allowance line

The server gives each pinner key a free allowance per UTC month, and a
bearer key its own (server spec 9). The number belongs to the price list,
not to either client.

- **Where it is read**: the price list's structured field for the free
  allowance (the owner's site item; today `arcaeon buy` falls back to the
  hosted witness description's own words). Neither client types the number.
- **The line**, the same in both clients:
  `Free: <N> pins a month for each key, no purchase needed; the count starts again on the first of the month (UTC).`
- **Where arcaeon prints it**: first in `arcaeon buy`'s list, in place of
  today's free line, and once after a 402 `plan` with no bearer key, when the
  price list could be read within its usual 3 seconds. When the list cannot
  be read, or states no number, the line is left out; it is never guessed
  and never remembered from an older list past the 10 minute cache.
- **Where the desktop shows it**: under the Witness card's switch, from the
  same field, read the same way.

## 9. Retries

- A pin whose answer was lost is sent again as it is. The witness answers 200
  with the same receipt bytes and charges nothing (server spec 6). The client
  keeps nothing new.
- A refusal wrote nothing and charged nothing, so a retry is a new pin.
- Neither client retries on its own after 402, 401, 403 or any 422. After a
  429 or a 503, arcaeon does not retry within the same run; the MCP tools say
  so in their answer.

## 10. Tests to add

The shared conformance file is the server spec's `vectors/join_v1.json`,
copied byte for byte into each client's tests with its SHA-256 held in the
test, so a change is deliberate (server spec 14). A test witness on
127.0.0.1 answers each request with the vector's bytes.

### arcaeon (this repository)

| Test file (new) | What it holds |
|---|---|
| `tests/test_join_head.py` | The contract head rule of section 3: fixed ledgers give fixed heads; an empty ledger gives n 0 and 64 zeros; a ledger that does not verify is refused before any request. |
| `tests/test_join_receipt.py` | Each check of section 6, one failing case each, refused at its field: a receipt with white space, keys out of order, a trailing newline, a ninth field, a missing field, kind or v wrong, another head, another namespace, another key id, a bad signature, a received_at with a fraction or :60, a witness_seq not above the kept ones. A good receipt from the vectors is kept as its exact bytes, created exclusively; the same receipt again keeps nothing new. |
| `tests/test_join_pin_call.py` | The order of section 5: a key answer under another key id is refused naming `witness_key_id` and the test witness sees no pin and no `Authorization`; no bearer key is sent over plain HTTP to a non loopback address; the body sent is byte for byte the vector's pin bytes for the vector's key and clock; an empty built in key id refuses with exit 3 and sends nothing; an answer over 8 KB is refused; the 10 second limit holds against a witness that answers one byte at a time. |
| `tests/test_join_refusals.py` | Every row of section 7's table: the exact line and exit code, the witness's reason shown after it, the 402 choice made by whether a bearer key was sent, and no `$`, pack name or link in any line. |
| `tests/test_join_free_line.py` | Section 8: the line from a list with the structured field; no line without it; no line when the list does not answer; the number never appears in the package's source. |
| `tests/test_join_keys.py` | The owner key is made once, exclusively, readable by the person only, and never appears in output, logs or the activity journal; `ARCAEON_WITNESS_URL` without `ARCAEON_WITNESS_KEY_ID` refuses; a malformed key id is refused before any request; without `arcaeon[sign]` a contract pin refuses naming the extra and the plain pin still works. |

The existing plain pin tests run unchanged.

### The desktop's witness client (witness sandbox repository)

| Test file | What it holds |
|---|---|
| `tests/test_client_witness_key_id.py` (new) | `--witness-key-id`: a key answer under another id is refused naming `witness_key_id` before the pin or the bearer key is sent; the next id is taken during an overlap and only then. |
| `tests/test_client.py` (extended) | `--bearer-file` as server spec 13 says: read from the file, sent only on the pin, only over HTTPS or loopback, only after the key check, never printed, logged or kept. |
| `tests/test_client_refusals.py` (new) | The 402 lines picked by whether a bearer file was given; each row of section 7's table has a stable line; the witness's reason is shown after it, cleaned to one line. |
| `tests/test_join_vectors.py` (server spec 14) | Already listed by the server spec; the client's pin and receipt bytes match the vectors. |

## 11. Open questions for the owner

1. **Plain or contract by default.** Should `arcaeon pin --remote`, `seal`
   and the MCP tools move to contract pins at once, behind a flag first, or
   stay on the plain path until the desktop has moved?
2. **The head rule.** Is section 3's rule (64 zeros for an empty ledger,
   otherwise the SHA-256 of a fixed label and the 32 hex chain) right, or
   should arcaeon's ledger move to a 64 hex chain in a new row version?
3. **The 402 choice.** The server spec has the desktop pick its sentence from
   the reason text; this page picks it by whether a bearer key was sent. One
   rule for both?
4. **One owner key or one per ledger.** This page makes one arcaeon owner
   key per home. A key per ledger keeps ledgers unlinkable at the witness,
   but each gets its own free allowance, which the server spec counts per
   key (server spec 9 and its open question 1).
5. **Ed25519 in the base install.** Keep it in the `[sign]` extra, as this
   page says, or carry a small pure Python verifier in the base install so
   any install can check a receipt it is handed?
