# The labeled-exchange envelope

When one agent hands another agent a file, the receiver has to decide whether
to act on it. The envelope is a small file that travels beside the handed
file and lets the receiver check, offline and before acting, three things:
that the bytes are the bytes that were sealed, who sealed them (which key),
and that they were sealed for this receiver, this deal and this purpose, and
are still in date.

It does not check whether the content is true. Read
[What VERIFIED does not prove](#what-verified-does-not-prove) before relying on it.

```console
$ arcaeon envelope seal grades.csv --label "week 3 grades" \
    --audience instructor-1 --deal d-7f3a --purpose grading \
    --not-after 7d --key seal.key
$ arcaeon envelope verify grades.csv --audience instructor-1 --signer did:key:z6Mk...
```

`seal` writes `grades.csv.envelope.json` beside `grades.csv`. `verify` answers
in one word: VERIFIED, BROKEN or COULD NOT LOOK.

## Not a new format

The envelope is made from published formats; nothing in it is ours except
the predicate's field names.

- The claim is an **in-toto Statement v1**: `subject` names the file by its
  sha256, `predicateType` says what kind of claim it is, `predicate` holds
  the claim.
- The Statement is carried in a **DSSE envelope** (Dead Simple Signing
  Envelope): the Statement's bytes are base64 in `payload`, and each
  signature is over DSSE's pre-authentication encoding (PAE) of the payload
  type and payload, never over re-serialized JSON.
- The whole thing is one JSON object beside the file, the way a Sigstore
  bundle travels beside an artifact. It is **not** a conformant Sigstore
  bundle: it carries no certificate and no transparency-log entry, and it
  says so with its own media type.

### The sidecar

```json
{
 "mediaType": "application/vnd.arcaeon.envelope.v1+json",
 "dsseEnvelope": {
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<base64 of the Statement>",
  "signatures": [{"keyid": "did:key:z6Mk...", "sig": "<base64 Ed25519 signature>"}]
 }
}
```

No other keys are allowed at either level. A key outside the signed payload
could say anything, and a reader might believe it, so `verify` reads one as
BROKEN.

### The Statement

```json
{
 "_type": "https://in-toto.io/Statement/v1",
 "subject": [{"name": "grades.csv", "digest": {"sha256": "<64 hex>"}}],
 "predicateType": "https://arcaeon.io/labeled-exchange/v1",
 "predicate": {
  "version": 1,
  "label": "week 3 grades",
  "sealed_by": {"name": "grading-agent", "key": "did:key:z6Mk..."},
  "sealed_at": "2026-10-04T15:28:28Z",
  "chain": "ledger-1a2b3c4d5e6f",
  "pin_ref": "sha256:json-c14n:v1:<64 hex>",
  "witness_ref": "https://witness.example/pins/...",
  "flags": ["reviewed"],
  "binding": {
   "audience": "instructor-1",
   "deal": "d-7f3a",
   "purpose": "grading",
   "not_after": "2026-10-11T15:28:28Z"
  },
  "bytes": 1234
 }
}
```

The payload is the Statement as compact JSON with sorted keys. A verifier
reads the bytes it was given; it never re-serializes them.

The `predicateType` is `https://arcaeon.io/labeled-exchange/v1`, the name of
this spec. Any earlier draft that gave the envelope's predicate as
`witness-pin/v1` is superseded; a Statement with any other `predicateType`
reads COULD NOT LOOK (`unreadable`).

**A duplicate key inside the payload is unreadable**, the same as a duplicate
key in the sidecar: `verify` answers COULD NOT LOOK (`unreadable`), even when
the signature over those exact bytes is valid. JSON leaves duplicates to the
parser, and most keep the last one, some the first: two receivers would read
two different labels or bindings from one signed payload, so this verifier
reads neither.

| field | what it is | required |
|---|---|---|
| `label` | what the file is, in the sealer's words (`--label`) | yes |
| `sealed_by.name` | who sealed it, in the sealer's words (`--by`); a claim, not checked | no |
| `sealed_by.key` | the did:key that signed; must be the signature's key | set when signed |
| `sealed_at` | the sealer's clock, UTC | yes, written by `seal` |
| `chain` | the sealer's chain or ledger id (`--chain`) | no |
| `pin_ref` | a digest of the sealer's chain-tip pin statement (`--pin-ref`, `sha256:<64 hex>`, `sha256:json-c14n:v1:<64 hex>` or `sha256:raw-bytes:v1:<64 hex>`) | no |
| `witness_ref` | where that pin is witnessed (`--witness-ref`, an `https://` URL or a `urn:`) | no |
| `flags` | short lower-case words (`--flag`, repeatable) | no |
| `binding.audience` | the receiver it is for | **yes** |
| `binding.deal` | the deal or exchange id | **yes** |
| `binding.purpose` | what the receiver may use it for | **yes** |
| `binding.not_after` | when it stops being good (RFC 3339 with a zone, or a span at seal time: `7d`, `12h`, `30m`) | **yes** |
| `bytes` | the file's size when sealed | written by `seal` |

### Why the binding is mandatory

A genuine sealed file can be replayed: handed to a different receiver, or
reused in a different deal, or kept and used after the exchange it was made
for. A signature alone cannot see that, because the replayed file is the
real one. Binding the Statement to an audience, a deal, a purpose and a
not-after time is what stops it. This is the rule card networks already
apply to signed agent requests: specific to the merchant and purpose, and
time-bound.

So `seal` refuses to write an envelope without all four (exit 2, nothing
written), and `verify` reads a Statement without all four as BROKEN: an
unbound envelope is refused, never accepted with a warning.

### Binding fields compare as exact bytes

`audience`, `deal` and `purpose` are compared as exact bytes (exact Unicode
code points, as UTF-8): no Unicode normalization (NFC and NFD forms of the
same word are different), no case folding, no whitespace trimming, no
homoglyph mapping. `seal` stores them exactly as given. So `Instructor-1`,
`instructor-1 ` (trailing space) and `instru`+Cyrillic `с`+`tor-1` are each a
different receiver from `instructor-1`, and `verify` answers BROKEN naming
the field (`audience: sealed for ...`). Any folding rule would let one
envelope bind two receivers that a human cannot tell apart; a receiver that
wants a looser match must canonicalize its own id before sealing and before
checking, the same way on both sides.

## Signing

Ed25519, over DSSE's PAE:

```text
"DSSEv1" SP len(payloadType) SP payloadType SP len(payload) SP payload
```

The key id is a `did:key`: the public key is inside the id, so a verifier
needs no directory to find it. Signing and checking use the `[sign]` extra
(`pip install 'arcaeon[sign]'`), the same backend the vet grade receipts use;
the base install stays standard-library only and loads it only when a
signature is made or checked.

The key is a 32-byte seed, base64 on one line, in a file you name with
`--key`. `seal` reads no environment variable and has no default key path.
Keep the seed where the sealing agent can read it and nothing else can. One
way to make one (prints nothing; the seed goes only into the file):

```console
$ python -c "import base64,secrets; open('seal.key','w').write(base64.b64encode(secrets.token_bytes(32)).decode())"
```

The did:key to give your receivers is printed by `seal` (`"signer"`).

**Without `--key` the envelope is UNSIGNED.** `seal` still writes it and says
so on stderr; `verify` answers COULD NOT LOOK on it. The digest in an unsigned
envelope still catches accidental damage, but anyone who can change the file
can write a matching sidecar, so it says nothing about who sealed the bytes.

## Verify before act

```console
$ arcaeon envelope verify FILE --audience ME --signer did:key:z6Mk... [--deal ID] [--purpose TEXT] [--require-witness] [--pins DIR]
```

`verify` prints a JSON report on stdout and one line on stderr: the word,
then the reason. The report lists each step's own word (`envelope`,
`signature`, `file`, `binding`, `witness`), the sealed fields, the findings,
and what was not checked.

| word | exit | what the receiver does |
|---|---|---|
| VERIFIED | 0 | act |
| BROKEN | 1 | refuse, and keep the file and the envelope as evidence |
| COULD NOT LOOK | 3 | do not act on money or an irreversible step |

**BROKEN** (something checked came out wrong):

- the file's sha256 is not the one sealed (the bytes changed);
- a signature does not verify over the payload (the payload or the
  signature was changed), or the `sealed_by.key` is not the key that signed.
  **With several signature entries, any one that fails is BROKEN**, even when
  another entry, by a signer you named, verifies: a failing entry is tamper
  evidence, and the envelope is refused rather than read around it. An entry
  that is not an object, or has a keyid that is not an Ed25519 did:key, or a
  sig that is not base64, counts as failing;
- the envelope is signed, but not by any `--signer` you named;
- a key sits outside the signed payload;
- the Statement has no subject digest, no label, or no complete binding (an
  unbound envelope is refused);
- `not_after` has passed (expired), or is not a time with a zone;
- `--audience`, `--deal` or `--purpose` was given and the envelope was sealed
  for another;
- a `pin_ref`, `witness_ref` or `chain` is recorded in the wrong shape;
- with `--pins DIR`: the pin folder the `witness_ref` names is in the clone
  and its statement digest is not the `pin_ref` (with or without
  `--require-witness`).

**Expired and wrong-audience are BROKEN, not COULD NOT LOOK.** The check ran
and the answer is no: this envelope is not good for you, now.

**COULD NOT LOOK** (nothing wrong was found, and not everything that decides
the answer could be checked):

- no sidecar beside the file (`missing`), or one that cannot be read: not
  UTF-8, not JSON, a duplicate key, over 1 MiB, not this media type, not a
  DSSE envelope with an in-toto payload (`unreadable`). Never a traceback;
- a duplicate key inside the payload, or a payload that is not an in-toto
  Statement of this `predicateType` (`unreadable`);
- the file itself is not there or cannot be read;
- the envelope is unsigned (`missing`);
- it is signed, but you named no `--signer` (`bounded`): a valid signature
  from a key you did not choose says only that some key signed it;
- you gave no `--audience` (`bounded`): an envelope not checked against its
  receiver is the replay this design exists to stop;
- this install has no Ed25519 backend (`missing`);
- with `--require-witness`: the pin and witness refs are not resolved, or none
  was recorded (`network`); with `--pins DIR` too, the pin is not in the
  clone (`missing`), the clone holds no pin folder (`empty`), it or a
  statement cannot be read (`unreadable`), or several same-named pins and none
  matches (`bounded`).

Without `--deal` or `--purpose` the verdict can still be VERIFIED; the report
names each one under `not_checked` with the value it was sealed with. A
receiver that holds a deal id should pass it. The gate (`arcaeon gate
decide`, VERBS.md) holds one rule on top of this word: `read` is the only
action an unbound check allows. `act`, `pay` and `irreversible` without
`--deal` and `--purpose` are COULD NOT LOOK there (refuse, exit 3), so an
envelope sealed for one exchange cannot be replayed into another.

### Pin and witness refs: recorded, resolved only against a local clone

`pin_ref` and `witness_ref` are recorded in the signed Statement and checked
for shape. They are **not resolved**: fetching the pin, checking its proof
and finding the sealer's chain tip in it needs the network and is out of
scope for this version. When either is present, the `witness` step reads
COULD NOT LOOK and `not_checked` says why; it never reads VERIFIED. When
neither is present the step reads NOT CLAIMED. The overall verdict leaves the
witness step out unless you pass `--require-witness`, which turns it into
COULD NOT LOOK unless `--pins` resolves the pin.

**`--pins DIR`** (library `verify(pins=DIR)`, `resolve_pin`) resolves the
`pin_ref` offline against a local clone of a pins repo laid out as
`tips/<chain>/<YYYY-MM-DD>T<HHMM>Z/statement.json` (the statement's canonical
bytes, exactly as hashed). DIR may be the clone root, `tips/`, a `<chain>/`
folder or one pin folder; nothing is fetched. The digest compared is sha256
of the `statement.json` bytes (`sha256:` and `sha256:raw-bytes:v1:` refs) or
of its json-c14n:v1 form (`sha256:json-c14n:v1:` refs). The first
`<YYYY-MM-DD>T<HHMM>Z` segment of the `witness_ref` (URL or urn) names the
pin folder; the segment before it picks between same-named folders.

| what the clone shows | `witness` step |
|---|---|
| the named pin (or, with no stamp in the `witness_ref`, any pin) has the `pin_ref` digest | VERIFIED |
| the named pin is there with another digest | BROKEN |
| the named pin is not there; no stamp named and no pin has the digest; DIR missing, not a folder, holds no pin, or a statement unreadable | COULD NOT LOOK |

With no stamp in the `witness_ref`, a digest the clone does not hold is
COULD NOT LOOK, never BROKEN: a clone older than the pin cannot be told from
a pin never made. A VERIFIED witness step says the clone holds a pin statement
with the sealed digest. It does not check the pin's `.ots` proofs, that the
clone is a faithful copy of the public pins, or anything at the `witness_ref`
URL; `not_checked` names these. A `witness_ref` with no `pin_ref` stays COULD
NOT LOOK. Without `--pins` nothing changes. The report adds `pin` (`folder`,
`statement_sha256`, `pin_ref`, or null) only when `--pins` is given.


## What VERIFIED proves

The file's bytes are the bytes the key you named sealed, under this label, for
this audience, deal and purpose, and the not-after time has not passed.

## What VERIFIED does not prove

- **That the content is true or safe.** A sealer can seal a false or
  poisoned file honestly; the seal proves who and when, never true. A
  perfectly sealed file can carry a prompt injection. Checking content is
  other tools' job; the envelope only says which bytes they would be judging.
- **That the key belongs to who the label says.** `sealed_by.name` is the
  sealer's own claim. Which did:key stands for which party is the receiver's
  decision (`--signer`); this version has no key register and no revocation.
  A stolen key signs anything, and nothing here can tell.
- **When it was sealed.** `sealed_at` is the sealer's clock. Only a resolved
  witness pin could fix the time from outside, and refs are not resolved yet.
- **That it has not expired, by anyone's clock but the receiver's.**
  `not_after` is judged by the receiver's clock. A receiver whose clock is
  behind accepts an expired envelope; one whose clock is ahead refuses a good
  one. Keep the receiving machine's clock synced.
- **That nobody can spoil it.** A third party who can edit the sidecar can
  turn VERIFIED into BROKEN (add a bad signature entry, a stray key, change a
  byte) but never into VERIFIED: every change it can make without the
  sealer's key is caught. BROKEN therefore means "do not act, keep the
  evidence", not "the sealer lied".
- **That it was not replayed within its own binding.** Inside one audience,
  deal, purpose and validity window, the same envelope can be presented twice.
  A receiver that must act once keeps the envelopes it has acted on.
- **Anything about colluding parties.** If the sealer and the receiver are
  the same owner, the envelope records their agreement, not the truth.
- **That the verifier is the real one.** Run your own copy.
- **That the sidecar is a Sigstore bundle.** It is shaped like one and is not
  one: no certificate, no transparency-log entry.

## In code

```python
from arcaeon.prove import envelope as E

E.seal("grades.csv", key_file="seal.key", label="week 3 grades",
       audience="instructor-1", deal="d-7f3a", purpose="grading", not_after="7d")
report = E.verify("grades.csv", audience="instructor-1", signers=["did:key:z6Mk..."])
report["verdict"]        # "VERIFIED", "BROKEN" or "COULD NOT LOOK"
```

`seal` raises `SealError` on any refusal, before anything is written.
`verify` never raises.
